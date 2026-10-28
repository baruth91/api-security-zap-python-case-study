"""Owned, loopback-only crAPI processes and ZAP passive observation."""

import base64
import html
import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import quote, urlparse
from uuid import uuid4

import psycopg
import requests
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from scripts.prepare import LOCK, ROOT, WORK, java

ACTORS = json.loads((ROOT / "config/actors.json").read_text(encoding="utf-8"))
DEFAULT_DSN = "postgresql://qa_user:qa_demo_password@127.0.0.1:55432/qa_lab"


def local_url(url):
    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("The lab accepts only loopback HTTP targets")
    return url


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for(condition, label, timeout=150, process=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"{label} exited early; inspect ignored .work/runtime logs")
        try:
            result = condition()
            if result:
                return result
        except requests.RequestException:
            pass
        time.sleep(0.3)  # Bounded readiness polling, never a substitute for test assertions.
    raise RuntimeError(f"Timed out waiting for {label}; inspect ignored .work/runtime logs")


def redact(value, tokens):
    text = json.dumps(value, default=str)
    for token in tokens:
        text = text.replace(token, "[REDACTED_TOKEN]")
    text = re.sub(r"Bearer [A-Za-z0-9_.-]+", "Bearer [REDACTED_TOKEN]", text)
    return json.loads(text)


class Lab:
    def __init__(self, report_dir):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.runtime = WORK / "runtime" / uuid4().hex
        self.runtime.mkdir(parents=True)
        self.dsn = os.environ.get("QA_DATABASE_URL", DEFAULT_DSN)
        self.schema = "qa_security_" + uuid4().hex
        self.processes = []
        self.logs = []
        self.tokens = {}
        self.observations = []
        self.urls = {}
        self.zap_url = None
        self.session = requests.Session()
        self.session.trust_env = False
        self.created_schema = False

    def spawn(self, name, args, env=None):
        output = (self.runtime / f"{name}.log").open("w", encoding="utf-8")
        self.logs.append(output)
        process = subprocess.Popen(
            list(map(str, args)),
            env=env,
            stdout=output,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        self.processes.append(process)
        return process

    def start(self):
        db = conninfo_to_dict(self.dsn)
        if db.get("host") not in {"127.0.0.1", "localhost"} or db.get("dbname") != "qa_lab":
            raise ValueError("Use a loopback PostgreSQL database named qa_lab for this lab")
        with psycopg.connect(self.dsn, connect_timeout=5) as conn:
            conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.created_schema = True
        jwks = base64.b64encode((WORK / "crapi/services/identity/jwks.json").read_bytes()).decode()
        env = {
            **os.environ,
            "DB_NAME": db["dbname"],
            "DB_USER": db["user"],
            "DB_PASSWORD": db.get("password", ""),
            "DB_HOST": db["host"],
            "DB_PORT": db.get("port", "5432"),
            "LOG_LEVEL": "WARN",
            "JWKS": jwks,
            "SPRING_DATASOURCE_URL": f"jdbc:postgresql://{db['host']}:{db.get('port', '5432')}/"
            f"{quote(db['dbname'])}?currentSchema={self.schema}",
            "SMTP_FROM": "lab@example.com",
            "SMTP_AUTH": "false",
            "SMTP_HOST": "127.0.0.1",
            "SMTP_PORT": "9",
            "SMTP_EMAIL": "lab@example.com",
            "SMTP_PASS": "unused-lab-value",
            "SMTP_STARTTLS": "false",
            "MAILHOG_HOST": "127.0.0.1",
            "MAILHOG_PORT": "9",
            "MAILHOG_DOMAIN": "example.com",
            "ENABLE_SHELL_INJECTION": "false",
            "API_GATEWAY_URL": "http://127.0.0.1:9",
            "TLS_ENABLED": "false",
            "TLS_KEYSTORE_TYPE": "PKCS12",
            "TLS_KEYSTORE": "classpath:certs/server.p12",
            "TLS_KEYSTORE_PASSWORD": "unused",
            "TLS_KEY_PASSWORD": "unused",
            "TLS_KEY_ALIAS": "lab",
        }
        for variant in ("vulnerable", "corrected"):
            port = free_port()
            self.urls[variant] = local_url(f"http://127.0.0.1:{port}")
            jar = WORK / variant / "build/libs/identity-service-1.0-SNAPSHOT.jar"
            if not jar.is_file():
                raise RuntimeError("Run python -m scripts.prepare before pytest")
            process = self.spawn(
                variant,
                [java(), "-Xmx384m", "-jar", jar, "--server.address=127.0.0.1"],
                {**env, "SERVER_PORT": str(port)},
            )

            def login_ready(variant=variant):
                for actor in ACTORS.values():
                    response = self.session.post(
                        self.urls[variant] + "/identity/api/auth/login",
                        json={"email": actor["email"], "password": actor["password"]},
                        timeout=3,
                    )
                    if response.status_code != 200 or not response.json().get("token"):
                        return False
                return True

            wait_for(login_ready, f"{variant} and deterministic upstream seed", process=process)
            self.tokens[variant] = {}
            for alias, actor in ACTORS.items():
                response = self.session.post(
                    self.urls[variant] + "/identity/api/auth/login",
                    json={"email": actor["email"], "password": actor["password"]},
                    timeout=10,
                )
                response.raise_for_status()
                self.tokens[variant][alias] = response.json()["token"]

        zap_port = free_port()
        self.zap_url = local_url(f"http://127.0.0.1:{zap_port}")
        zap_home = self.runtime / "zap-home"
        zap_home.mkdir()
        jar = WORK / f"ZAP_{LOCK['zap_version']}" / f"zap-{LOCK['zap_version']}.jar"
        process = self.spawn(
            "zap",
            [
                java(),
                "-Xmx512m",
                "-jar",
                jar,
                "-daemon",
                "-silent",
                "-host",
                "127.0.0.1",
                "-port",
                str(zap_port),
                "-dir",
                zap_home,
                "-config",
                "api.key=qa-lab-only",
                "-config",
                "autoupdate.checkOnStart=false",
            ],
        )
        version = wait_for(
            lambda: self.zap("core/view/version/").get("version"), "ZAP API", process=process
        )
        if version != LOCK["zap_version"]:
            raise RuntimeError("Unexpected ZAP runtime version")
        self.zap("core/action/setMode/", mode="safe")
        return self

    def zap(self, route, **params):
        response = self.session.get(
            self.zap_url + "/JSON/" + route, params={"apikey": "qa-lab-only", **params}, timeout=10
        )
        response.raise_for_status()
        return response.json()

    def location(self, variant, vehicle_id, actor="alice", invalid=False):
        headers = {}
        if actor is not None:
            token = "invalid-lab-token" if invalid else self.tokens[variant][actor]
            headers["Authorization"] = f"Bearer {token}"
        response = self.session.get(
            self.urls[variant] + f"/identity/api/v2/vehicle/{vehicle_id}/location",
            headers=headers,
            proxies={"http": self.zap_url},
            timeout=15,
        )
        self.observations.append(
            {
                "variant": variant,
                "actor": actor,
                "vehicle_id": vehicle_id,
                "status": response.status_code,
                "body": response.text,
            }
        )
        return response

    def export(self):
        wait_for(
            lambda: int(self.zap("pscan/view/recordsToScan/")["recordsToScan"]) == 0,
            "passive analysis queue",
            timeout=60,
        )
        alerts = []
        history_count = int(self.zap("core/view/numberOfMessages/")["numberOfMessages"])
        for variant, url in self.urls.items():
            for alert in self.zap("core/view/alerts/", baseurl=url, start=0, count=1000)["alerts"]:
                alerts.append({"variant": variant, **alert})
        secrets = [token for users in self.tokens.values() for token in users.values()]
        evidence = redact(
            {
                "upstream_revision": LOCK["revision"],
                "zap_version": LOCK["zap_version"],
                "scan_mode": "passive observation of explicit GET requests only",
                "zap_mode": "safe",
                "zap_session_message_count": history_count,
                "matrix_request_count": len(self.observations),
                "http": self.observations,
                "alerts": alerts,
            },
            secrets,
        )
        (self.report_dir / "security-evidence.json").write_text(
            json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
        )
        rows = "".join(
            "<tr><td>"
            + "</td><td>".join(
                html.escape(str(a.get(k, ""))) for k in ("variant", "risk", "alert", "url")
            )
            + "</td></tr>"
            for a in evidence["alerts"]
        )
        (self.report_dir / "zap-passive-summary.html").write_text(
            "<!doctype html><meta charset='utf-8'><title>Scoped ZAP passive results</title>"
            "<h1>Scoped ZAP passive results</h1><p>Alerts require contextual review. "
            "This report does not verify object ownership or certify the application.</p>"
            "<table><tr><th>Variant</th><th>Risk</th><th>Alert</th><th>URL</th></tr>"
            + rows
            + "</table>",
            encoding="utf-8",
        )

    def close(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for output in self.logs:
            output.close()
        self.session.close()
        if self.created_schema:
            assert re.fullmatch(r"qa_security_[a-f0-9]{32}", self.schema)
            with psycopg.connect(self.dsn, connect_timeout=5) as conn:
                conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(self.schema)))
