# Security test strategy and traceability

## Objective and scope

Verify one object-ownership rule on the real crAPI identity service: authenticated
users may obtain location information only for their own vehicle. Reproduce the
known original defect, apply a local correction and preserve legitimate behavior.

The two seeded identities are fixed lab data. Fixture UUIDs are known in advance;
the test does not perform enumeration. Read-only matrix requests are GETs; local
authentication setup uses POST login. No password attack or active scan is included.

## Risk-to-test mapping

| ID | Risk/control | Oracle |
| --- | --- | --- |
| SEC-AUTHZ-001 | Cross-account disclosure | Original returns the other fixture's exact details; corrected returns 404 without fields/values |
| SEC-AUTHZ-002 | Overly restrictive correction | Both owners retain 200 with matching ID, email and coordinates on both variants |
| SEC-AUTHN-001 | Anonymous access | 401 and no protected fields/values |
| SEC-AUTHN-002 | Invalid bearer token | 401 and no protected fields/values |
| SEC-ERROR-001 | Unknown resource disclosure | Unknown UUID returns 404 and no protected values |
| SEC-EVIDENCE-001 | Token exposure in reports | Redaction controls and no recorded authorization headers |

The matrix has 14 parametrized HTTP cases and five harness-safety controls.
The default suite verifies both intentional reproduction and corrected behavior.
It does not label the original application secure because a reproduction passes.

## Standards

- [OWASP API1:2023 BOLA](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/): risk classification.
- [WSTG v4.2 ATHZ-04](https://owasp.github.io/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References): primary object-reference testing procedure.
- [WSTG v4.2 ATHZ-02](https://owasp.github.io/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema): supporting access-control procedure.
- [ASVS 5.0.0](https://asvs.owasp.org/): broader requirement-selection reference; this case does not claim a complete ASVS level or full compliance.

Project acceptance criterion: the server checks the authenticated principal's
permission for the requested object, denies cross-account disclosure and preserves
owner access. This is a specific control, not a complete security test checklist.

## Reproducibility and evidence

Source and tool archives are fixed by revision/hash. Each run creates a generated
database schema and fresh Java/ZAP processes. A bounded readiness poll waits for
actual seeded-account login, not an arbitrary sleep before assertions.

One schema is shared between the two read-only service variants so the same objects
and credentials provide before/after controls. Separate server ports and genuine
HTTP calls exercise authentication and the Java endpoint. Schema isolation is per
run, not per read case. The case is intentionally serial.

Response status alone is insufficient: cross-account reproduction checks real
fixture fields, while denial checks raw content for protected fields and values.
Raw-body inspection also avoids relying on the unrelated malformed 401 body.

## Scanner interpretation

ZAP observes explicit traffic in safe mode. Passive alerts are evidence for review,
not a stand-in for multi-identity business authorization checks. The local run's
zero alerts coexist with a confirmed vulnerability in the original endpoint.

The suite is gated by its explicit assertions and successful evidence collection.
It does not invent a scanner-alert acceptance threshold without triage. It does not
silently suppress a scanner startup/API/reporting failure.

## Limits

No administrative matrix, write endpoint, complete JWT/security audit, concurrent
ownership transfer, TLS, database crash recovery or full crAPI deployment is tested.
The controller guard does not establish service-wide enforcement across other
callers. These limits should remain visible in demonstrations and profile wording.
