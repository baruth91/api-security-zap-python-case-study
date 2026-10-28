import json

import pytest

from scripts.lab import local_url, redact


@pytest.mark.parametrize("url", ["https://example.com", "http://example.com", "https://127.0.0.1"])
def test_lab_rejects_external_or_unconfigured_targets(url):
    with pytest.raises(ValueError, match="loopback"):
        local_url(url)


def test_nested_evidence_removes_known_tokens():
    token = "synthetic.header.signature"
    source = {"alerts": [{"evidence": token}], "body": f"Bearer {token}"}
    sanitized = json.dumps(redact(source, [token]))
    assert token not in sanitized
    assert "REDACTED_TOKEN" in sanitized


def test_bearer_value_is_removed_even_when_not_in_known_token_list():
    sanitized = json.dumps(redact({"evidence": "Authorization: Bearer a.b.c"}, []))
    assert "a.b.c" not in sanitized
    assert "REDACTED_TOKEN" in sanitized
