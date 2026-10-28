# Learn the authorization testing loop

## 1. State the requirement

An authenticated identity can read its own vehicle location, not another user's.
Predict all rows of the README matrix before running anything. A valid token
establishes identity; it does not automatically establish permission for every UUID.

Checkpoint: explain why an unpredictable UUID does not replace authorization.

## 2. Read the original path

Open the pinned upstream VehicleController and VehicleServiceImpl in .work/crapi.
The controller receives carId and calls getVehicleLocation. The service locates
the vehicle and constructs a response using its owner's data. Identify the missing
relationship between the caller and that resource.

Checkpoint: locate the specific absence of a permission check rather than calling
all of the application's authentication broken.

## 3. Establish positive controls

Read config/actors.json. Alice/Bob are aliases for two upstream seeded accounts.
Owner tests check status, vehicle ID, email, latitude and longitude on both builds.
This prevents an apparent fix that simply blocks every caller.

Checkpoint: explain why a 404 on every request would fail this test strategy.

## 4. Reproduce the known cross-account weakness

Follow test_cross_account_access. The same known fixture object is requested using
the other account's token. In the original build, the test verifies actual protected
fields, not merely HTTP 200. The normal baseline explicitly records the lab's known
vulnerable behavior so the before/after comparison is reproducible.

Checkpoint: distinguish a successful vulnerability reproduction from a security pass.

## 5. Inspect the local correction

Read patches/owner-check.patch. The corrected controller loads the requested object
and compares its owner to the server-side authenticated principal. It returns the
chosen 404-style response for unauthorized/missing resources before retrieving
location details. The authenticated owner path remains available.

Checkpoint: explain why a client-supplied owner parameter would not be a trustworthy
authorization decision, and identify the broader enforcement limits in decisions.md.

## 6. Run a genuine red/green regression

Use the --require-denial-on-vulnerable command in the README. Expect two failures
on the original and two passes on the corrected build. Inspect the actual 200 versus
404 assertion evidence. Run the ordinary suite to return to the explicit comparison
baseline. No expected-failure decorator is involved.

Checkpoint: explain why silently ignoring all test failures would destroy the gate.

## 7. Inspect scanner evidence separately

Open reports/baseline/security-evidence.json and zap-passive-summary.html. ZAP observes
the explicit matrix in safe mode; the run is passive, not an active penetration
test. The local zero-alert result did not identify the confirmed ownership weakness.

Checkpoint: explain what this scanner configuration observed and what the explicit
multi-account assertions add. Do not generalize this result to all ZAP capabilities.

## 8. Review response-format and evidence issues

Inspect the 401 body. It contains Java-style text despite its JSON header. The
security assertion still checks that protected values are absent from raw content.
Report the format defect separately instead of expanding the ownership patch.

Review redaction tests and ignored runtime artifacts. A useful report should not
expose the bearer tokens used to exercise the lab.

## 9. Practice independently

Exercise A: write the access matrix in words and explain each row's business risk.
Exercise B: add a third seeded non-admin account and an ownership pair, keeping the
owner-access control. Exercise C: write a separate API-contract test for the malformed
401 body; label its known failure clearly instead of folding it into BOLA coverage.
Exercise D: propose a service-level ownership-scoped lookup and a concurrency test
contract before modifying the code.

Expected outcomes: A links identity/resource/permission; B denies the new cross-user
path after correction; C identifies a distinct contract defect; D defines ownership
transfer semantics rather than assuming the controller test proves concurrency.
These extensions are not counted in the baseline until implemented and executed.

## 10. Teach the result

Present risk → known reproduction → scoped correction → regression → scanner
limitations. Credit the upstream educational vulnerability and show only synthetic
accounts. Describe actual observed results and the endpoint's remaining boundaries.
