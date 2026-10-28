# Known BOLA in crAPI: reproduce, correct and regress

[![Scoped checks](https://github.com/baruth91/api-security-zap-python-case-study/actions/workflows/security.yml/badge.svg)](https://github.com/baruth91/api-security-zap-python-case-study/actions/workflows/security.yml)

A practical security QA case using the **real OWASP crAPI identity service**,
Python, Requests, pytest, PostgreSQL and ZAP. Two synthetic accounts demonstrate a
known broken object-level authorization weakness; an exact local Java patch prevents
cross-account disclosure while preserving legitimate access.

This is original community learning material from Phillip Baruth. The vulnerability
is intentional upstream training content, not a new discovery or a client finding.
No employer identities, production data or confidential code are included.

## The risk and observed behavior

The endpoint `/identity/api/v2/vehicle/{carId}/location` requires authentication,
but the original controller does not check that the authenticated caller owns the
requested vehicle. A valid token alone therefore permits another user's location,
email and name to be returned.

| Request | Original service | Locally corrected service |
| --- | --- | --- |
| Owner reads own vehicle | 200 with expected fixture details | Same legitimate result |
| Another account reads vehicle | 200 with the other user's protected details | 404 without protected data |
| Missing or invalid token | 401 without protected data | Same denial |
| Unknown vehicle UUID | 404 without protected data | Same denial |

The correction deliberately uses 404 for both an unknown object and an object owned
by someone else. This is an existence-concealment policy for this slice, not a
universal requirement that authorization failures always use 404.

## Run the case

Prerequisites: **Python 3.13, JDK 21, Git and a disposable PostgreSQL database**.
Set JAVA_HOME to your JDK. Docker Compose is an optional way to start PostgreSQL;
the Java services and ZAP run as local processes, not containers.

```sh
git clone https://github.com/baruth91/api-security-zap-python-case-study.git
cd api-security-zap-python-case-study
python -m venv .venv
```

Activate with `.venv\Scripts\Activate.ps1` in PowerShell, or
`source .venv/bin/activate` in Linux/macOS. Then:

```sh
python -m pip install -r requirements.txt
docker compose up -d --wait
python -m scripts.prepare
python -m pytest -v
docker compose down --volumes
```

Preparation checks the exact upstream revision, verifies Gradle/ZAP archives by
SHA-256, copies the identity service into two build directories, applies the patch
only to the corrected copy, and compiles both real Spring Boot jars. Downloads and
builds stay in ignored `.work/`. First preparation needs internet and several minutes.
Building bootJar does not run or claim coverage from the upstream unit-test suite.

For native/portable PostgreSQL, use a loopback database named qa_lab with permission
to create schemas. The default public lab DSN is
`postgresql://qa_user:qa_demo_password@127.0.0.1:55432/qa_lab`.
Set QA_DATABASE_URL to override the account/port:

```powershell
$env:QA_DATABASE_URL = 'postgresql://qa_user:qa_demo_password@127.0.0.1:55432/qa_lab'
```

```sh
export QA_DATABASE_URL='postgresql://qa_user:qa_demo_password@127.0.0.1:55432/qa_lab'
```

The earlier [PostgreSQL learning case](https://github.com/baruth91/python-api-database-qa-case-study)
documents a Windows portable option. Do not start two database instances on the
same port. Local verification used that portable PostgreSQL, not Docker on Windows.

## What pytest starts and verifies

One isolated generated PostgreSQL schema is shared by the two service variants
for a run. The original crAPI seed provides known synthetic users and vehicles.
The runner waits for both accounts to log in, starts ZAP with a new private home
directory, and sends the matrix's GET requests through its loopback proxy.

The baseline has **19 tests**: 14 real HTTP access-matrix cases across both variants
and five checks for target restrictions and evidence redaction. It intentionally
verifies the known disclosure in the original service and the denial in the corrected
service. A green baseline does not declare the vulnerable service secure.

The runner terminates the processes it started and drops only its generated schema.
It does not reset existing databases or install system services. Raw runtime/ZAP
session logs stay in ignored `.work/`; sanitized reports are under `reports/`.

## Demonstrate the failing security regression

```sh
python -m pytest tests/test_access_matrix.py -k cross_account --require-denial-on-vulnerable --junitxml=reports/vulnerable-gate.xml
```

This applies the corrected denial expectation to both versions. Expect **two
failures on the original service, two passes on the corrected service, exit code 1**.
The ordinary full suite restores the standard reproduction-plus-regression baseline.
No blanket skip, expected-failure marker or continue-on-error conceals the violation.

## ZAP's complementary role

ZAP 2.17.0 runs in daemon **safe mode**, with `-silent`, and passively observes only
the explicitly proxied test requests. No spider, active attack scan or external
target is invoked. Login setup uses the local service directly; credentials are not
written to the published evidence. This is not the official full crAPI scan plan.

The observed local passive run reported **zero alerts despite confirmed BOLA**.
The multi-account assertions establish the authorization finding. This demonstrates
the limits of this scan configuration; it does not claim ZAP can never detect an
authorization weakness with a different configuration.

## Inspect evidence and run online

Reports include JUnit XML, sanitized HTTP observations, ZAP version/session message
count, passive alerts and an escaped HTML summary. Tokens and authorization values
are redacted. The HTML summary is generated by this harness from ZAP's API data.

Open [Actions → Scoped crAPI authorization and passive ZAP checks](https://github.com/baruth91/api-security-zap-python-case-study/actions/workflows/security.yml)
and select **Run workflow → main → Run workflow**. The hosted Ubuntu job starts
PostgreSQL, builds the services, runs the real matrix and uploads sanitized artifacts
for seven days. Manual execution needs repository permission; learners can fork it.

## Learn and present

- [Finding and correction](docs/finding.md)
- [Risk map, standards and scope](docs/test-strategy.md)
- [Tutorial and exercises](docs/tutorial.md)
- [An 8–10 minute demo](docs/demo.md)
- [Implementation decisions](docs/decisions.md)
- [Validation record](docs/validation.md)

The first run also exposed an unrelated upstream behavior: 401 responses declare
JSON but contain a Java-style text representation. The confidentiality oracle
inspects raw content; it does not silently claim valid JSON. That issue remains
documented and outside the ownership patch.

## Boundaries and attribution

Only the identity service and selected read endpoint are exercised; the complete
crAPI application, other intentional authentication flaws, administrative privileges,
writes, TLS, active scanning and complete security compliance are outside this slice.
Do not interpret this one controller correction as whole-application hardening.

Read [NOTICE](NOTICE.md) for upstream attribution and patch licensing. Original
harness/tests/docs are MIT licensed; the derivative crAPI patch is Apache-2.0.
References: [crAPI challenges](https://github.com/OWASP/crAPI/blob/main/docs/challenges.md),
[ZAP crAPI guide](https://www.zaproxy.org/docs/testapps/crapi/),
[OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/).
