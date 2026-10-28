import pytest

from scripts.lab import ACTORS

VARIANTS = ["vulnerable", "corrected"]
PAIRS = [("alice", "bob"), ("bob", "alice")]


def assert_disclosure_matches(response, owner):
    assert response.status_code == 200
    body = response.json()
    expected = ACTORS[owner]
    assert body["carId"] == expected["vehicle_id"]
    assert body["email"] == expected["email"]
    assert body["vehicleLocation"]["latitude"] == expected["latitude"]
    assert body["vehicleLocation"]["longitude"] == expected["longitude"]


def assert_no_sensitive_data(response, owner):
    # The upstream 401 body is non-JSON despite its header. Inspect raw content
    # rather than coupling the confidentiality oracle to that unrelated defect.
    for key in ("vehicleLocation", "email", "fullName"):
        assert key not in response.text
    for field in ("email", "latitude", "longitude", "vehicle_id"):
        assert ACTORS[owner][field] not in response.text


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("actor", ["alice", "bob"])
def test_owner_access_remains_available(lab, variant, actor):
    response = lab.location(variant, ACTORS[actor]["vehicle_id"], actor)
    assert_disclosure_matches(response, actor)


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("actor, owner", PAIRS)
def test_cross_account_access(lab, request, variant, actor, owner):
    response = lab.location(variant, ACTORS[owner]["vehicle_id"], actor)
    if variant == "vulnerable" and not request.config.getoption("--require-denial-on-vulnerable"):
        # Reproduce the known intentional weakness and verify actual protected content.
        assert_disclosure_matches(response, owner)
    else:
        assert response.status_code == 404
        assert_no_sensitive_data(response, owner)


@pytest.mark.parametrize("variant", VARIANTS)
def test_anonymous_access_is_denied(lab, variant):
    response = lab.location(variant, ACTORS["alice"]["vehicle_id"], actor=None)
    assert response.status_code == 401
    assert_no_sensitive_data(response, "alice")


@pytest.mark.parametrize("variant", VARIANTS)
def test_invalid_token_is_denied(lab, variant):
    response = lab.location(variant, ACTORS["alice"]["vehicle_id"], invalid=True)
    assert response.status_code == 401
    assert_no_sensitive_data(response, "alice")


@pytest.mark.parametrize("variant", VARIANTS)
def test_unknown_vehicle_does_not_disclose_data(lab, variant):
    response = lab.location(variant, "00000000-0000-4000-8000-000000000000")
    assert response.status_code == 404
    assert_no_sensitive_data(response, "alice")
