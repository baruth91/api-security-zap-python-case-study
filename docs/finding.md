# Lab finding SEC-AUTHZ-001: cross-account vehicle disclosure

## Context and classification

Known intentional OWASP crAPI training vulnerability, reproduced in a private lab.
Upstream revision: 700f03d12a392d9e408260b4beae72ed02a4a1a4. The selected endpoint is
GET /identity/api/v2/vehicle/{carId}/location in the identity service.

Risk category: OWASP API1:2023, broken object-level authorization. Testing reference:
WSTG v4.2 ATHZ-04, insecure direct object references; supported by ATHZ-02 access
control testing. This finding does not claim a previously undisclosed issue.

## Preconditions and expected behavior

Two non-admin synthetic accounts have separate known vehicles. Local aliases Alice
and Bob map to the upstream test@example.com and robot001@example.com fixtures.
They have different seeded role labels; both can legitimately use this location
endpoint for their own vehicle. No administrative exception is part of this policy.

The caller must be authenticated and authorized for the requested vehicle. Known
fixture UUIDs are provided by setup; ID discovery/enumeration is not part of this case.

## Observed behavior

With Alice's valid token, requesting Bob's known vehicle returns HTTP 200 containing
Bob's fixture email and coordinates. The reverse direction also returns protected
data. Owner-access controls return the correct matching vehicle details.

The original controller passes the UUID to the service without tying it to the
requesting principal. The service returns the vehicle owner's details, not the
caller's authorized subset.

## Impact

In a real product with comparable behavior, another customer's location/contact
details could be disclosed. This lab uses only synthetic data. Severity depends on
the real deployment and business context; no unsupported CVSS score is assigned.

## Scoped correction

patches/owner-check.patch adds an ownership guard to the selected controller. It
looks up the vehicle and compares the owner's email with the authenticated
server-side principal name before calling the location service. It does not trust
an owner supplied in request parameters or treat possession of a UUID as permission.

For this lab's JWT path, Spring Security supplies the principal after its existing
authentication filter. Other intentional authentication weaknesses remain outside
this patch. The correction does not secure every authentication mechanism or caller.

An absent principal, absent vehicle, missing owner or ownership mismatch receives
the same 404-style result as an unknown object. Owner access continues to return
200 with the original expected fixture details.

## Retest and evidence

The full baseline asserts known disclosure on the original and denial on the patched
copy. The stricter regression exercise requires denial on both and demonstrates
two original failures versus two corrected passes. Tests also verify denial contains
no protected fields or seeded sensitive values, rather than relying on status alone.

See docs/validation.md and the workflow for actual execution outcomes. Sanitized
HTTP evidence is generated at runtime. Tokens are omitted/redacted from public
reports, and the upstream source is downloaded into ignored .work/.

## Separate observation

The upstream 401 response labels its body application/json but emits
CRAPIResponse(message=Invalid Token, status=401). This is not valid JSON. It is
documented separately and not changed by the authorization patch. The raw-body
confidentiality assertions remain meaningful for this behavior.
