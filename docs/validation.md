# Execution evidence

| Environment | Scope | Observed result |
| --- | --- | --- |
| Windows, Python 3.13.15, JDK 21, portable PostgreSQL 18.6, ZAP 2.17.0 | Full comparison baseline | 19 passed in 52.33 seconds: 14 real HTTP matrix cases and five harness controls |
| Same Windows lab | Strict cross-account denial gate | 2 original failures, 2 corrected passes in 37.33 seconds; exit code 1 as intended |
| Ubuntu 24.04 hosted runner | Same source, tools, real services and matrix | 19 passed in 29.05 seconds; sanitized evidence uploaded |

[Verified hosted run](https://github.com/baruth91/api-security-zap-python-case-study/actions/runs/40771803874)
executed commit `95f116a`. The first hosted preparation failed because a patch
created on Windows contained CRLF line endings. The patch and copied controller
are now normalized to LF before application; both real service builds and the
complete matrix then passed on Ubuntu. Local LF patch applicability was also checked.

Both service jars were compiled from the pinned real crAPI identity source, one
with the exact local controller patch. The upstream unit-test suite was not run.
The original source checkout remains unchanged. No Python replacement application
or fake HTTP response is used for the access matrix.

## What was confirmed

Both original cross-account requests returned 200 with the other fixture's vehicle,
email and coordinates. The corrected build returned 404 without protected fields
or values. Owner reads stayed available on both versions. Missing/invalid tokens
returned 401; an unknown UUID returned 404.

ZAP ran in safe mode with a fresh home directory and observed explicitly proxied
GET requests. Local and hosted passive reports contained zero alerts. The hosted
artifact records 14 matrix requests and 30 total ZAP session messages; the latter
is a global session count, not a per-variant coverage measure. This is not a full
active scan and does not contradict the directly demonstrated BOLA weakness.

The initial response oracle assumed JSON for the upstream 401. Actual response text
was CRAPIResponse(message=Invalid Token, status=401), despite its JSON header. The
confidentiality oracle was corrected to inspect raw content, preserving protected
field/value checks; the unrelated format defect is documented, not declared fixed.

The format-check configuration was also limited to owned source after an initial
formatter invocation reached downloaded Python files. Those files were restored;
the actual identity Java source and patch scope remain unchanged.

## Evidence and limits

Runtime JSON and HTML evidence plus JUnit XML are generated under reports/. Tokens
are redacted, and raw process/ZAP session logs stay in ignored .work/. Hosted
artifacts are retained for seven days. The strict gate uses a separate evidence
directory and JUnit file.

This validates the selected authenticated endpoint flow and local correction. It
does not establish full crAPI security, complete authentication coverage, safe
concurrent ownership transfers, TLS behavior or ASVS certification.
