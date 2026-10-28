# Architecture decisions

## Real upstream service, reduced deployment

The case builds the original identity service and a patched copy from one fixed
OWASP crAPI revision. It is not a replacement Python simulation. PostgreSQL is
real; Spring Security handles login and the selected authenticated HTTP endpoint.
The upstream seed supplies both accounts and known vehicles without email setup.

The full web UI, community, workshop, mail and chatbot services are unnecessary
for this selected read path and are not started. No claim is made about those
services. The lab credentials/keys are upstream educational fixtures, not secrets
from a real application.

## One controller patch

The guard compares the requested vehicle's server-loaded owner to the authenticated
principal before invoking the existing location service. A 404 concealment policy
keeps denied and missing-resource behavior aligned. The original service copy is
preserved for comparison and the patch applies only to the corrected copy.

This guard is scoped to that controller. A production design should review
service-wide enforcement, atomic ownership-scoped queries and concurrent ownership
changes. The selected tests do not establish those broader guarantees or fix the
lab's other intentional authentication weaknesses.

## Build and runtime tooling

Python 3.13 coordinates the lab. JDK 21 runs Gradle 8.14.3 and the upstream Java-17
targeted application. The Gradle and ZAP 2.17.0 archives are verified by SHA-256.
The PostgreSQL container uses a fixed version and image digest.

The pinned upstream build still resolves its own Maven/plugin dependencies; this
case does not claim hermetic, bit-for-bit builds or a complete dependency audit.
bootJar compiles the application; it does not imply upstream unit tests were run.
Gradle deprecation and upstream dependency warnings are retained as limitations.

## Native Java processes and disposable schema

Running the application jars and ZAP directly supports native Windows validation
without installing Docker. CI needs a container only for its database service.
All HTTP listeners bind loopback. JAVA_HOME controls the selected JDK; no service
or machine-wide runtime configuration is installed by the test runner.

Teardown terminates owned processes before dropping only the generated schema.
The helper validates the schema name and uses quoted SQL identifiers. The lab
database account owns its schema for setup/cleanup; this is not a production
least-privilege role design.

## Passive ZAP and sanitized reporting

ZAP starts with a separate home directory, silent startup and safe mode. Tests
explicitly proxy their GET matrix requests. The harness exports passive alert data
and escapes it in an HTML summary. It does not run the upstream full active plan.

Runtime logs and ZAP session files remain ignored; published artifacts contain the
sanitized observation report and JUnit XML. Login setup is not recorded. Known
tokens and bearer values are redacted, and redaction is independently tested.

## Preserve unrelated behavior

The original 401 response is non-JSON despite its header. The confidentiality oracle
therefore inspects raw content and the issue is recorded separately. The patch does
not quietly fix other issues, and no test claims JSON correctness for that response.
