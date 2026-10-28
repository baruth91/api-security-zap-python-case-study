# Attribution and modification notice

This case uses the OWASP crAPI identity service at revision
700f03d12a392d9e408260b4beae72ed02a4a1a4.
Upstream: https://github.com/OWASP/crAPI.

crAPI is intentionally vulnerable educational software maintained by its authors
and community. Its source is Apache-2.0 licensed; the original license is preserved
in licenses/crapi-apache-2.0.txt. Downloaded source remains under that license.

patches/owner-check.patch changes the selected VehicleController endpoint by
checking resource ownership against the authenticated server-side principal before
returning location data. This derivative patch is provided under Apache-2.0.
It is a local teaching correction, not an upstream fix or whole-application hardening.

The Python harness, original tests and learning documentation are independently
authored educational material under the repository's MIT license. Gradle, ZAP,
PostgreSQL, Java and Python dependencies retain their respective licenses.

The example vulnerability and seeded accounts are known upstream lab features.
This project does not claim discovery of a new vulnerability or reproduce employer
code, client data or confidential findings.
