# An 8–10 minute demonstration

1. **Risk, one minute.** Explain object ownership using two synthetic accounts and
   known vehicle fixtures. Distinguish authentication from authorization.
2. **Original code, one minute.** Show the original controller call without a caller
   ownership check and link the known OWASP training challenge.
3. **Positive controls, one minute.** Predict each owner's successful response and
   show why these checks prevent a blanket-denial false fix.
4. **Reproduce, two minutes.** Show the original cross-account 200 with matching
   fixture fields. Keep tokens hidden. Identify the potential business impact.
5. **Correct and regress, two minutes.** Read the small patch. Show the strict gate's
   two original failures and two corrected passes, then the full baseline results.
6. **Scanner and limits, one minute.** Show ZAP's passive summary and explain why
   zero alerts does not invalidate explicit disclosure evidence. State the remaining
   authentication, other-endpoint and concurrency boundaries.
7. **Online evidence, one minute.** Open the Actions run and sanitized artifacts;
   explain how the local processes and generated schema are cleaned up.

Prepare dependencies/jars before the video. Builds need internet and can take
several minutes; a recorded run can be used if clearly labelled. The runnable code,
finding, patch and evidence should support the explanation without memorization.

Practice questions: Why two accounts? Why known IDs? Why check body values in
addition to status? Why 404 here? Where does the principal come from? What remains
vulnerable outside the selected correction? Why is passive ZAP not a full audit?
