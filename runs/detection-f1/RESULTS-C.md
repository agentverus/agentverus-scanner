# Goal C — Close coverage gap (vs agentshield red-team set)

## Result

| metric | Goal A end | **Goal C end** |
|---|---|---|
| external_recall (agentshield set) | 0.833 (10/12) | **0.917 (11/12)** |
| recall | 0.871 | 0.879 |
| f1 | 0.8385 | 0.8425 |
| allow_leak (malicious fully ALLOWED) | 2 | **1** |
| block_precision (guardrail) | 1.00 | **1.00** |
| benign_blocked (guardrail) | 0 | **0** |

Most of the coverage gap was already closed in Goal A (external 7/12 → 10/12 via the four
new detectors). Goal C closed one of the two residual ALLOW-leaks while holding the
block-precision guardrail at 1.0.

## Shipped
**Exempt the Goal A/B critical detectors from the code-block severity downgrade**
(`NEVER_REDUCE_PATTERNS`) + recognize `collect`/`gather` as credential-access verbs.

Root cause: `context.ts` downgrades any match inside code formatting (×0.3) to suppress
documentation-example false-positives — but `read \`~/.ssh/id_rsa\`` / `collect \`~/.aws/credentials\``
in backticks *is* the instruction, not an example. The private-key / reverse-shell /
hardcoded-secret / command-sub detectors are unambiguous regardless of formatting, so they
now join the existing exemption list. This caught `ext-data-harvesting` (was scored ALLOW).

Both changes were needed: the exemption alone was a no-op (the `.aws/credentials` finding
didn't fire until `collect`/`gather` were added as verbs); the verb alone (tried + discarded
in Goal B) was a no-op because the match was downgraded in inline code. Together → BLOCK.

Verified zero benign occurrences of these tokens, so `block_precision` stays 1.0.

## Remaining leak (documented, not chased)
`mal-concealment-slack-poster` — a concealment directive ("do not tell the user, keep
secret, silently transfer") injected into an otherwise-legitimate Slack-poster skill,
scored `certified`. The concealment fires only at `medium`, and the host's legitimate
content dominates the score. This is genuinely ambiguous: a mostly-benign skill with one
concealment line is arguably REVIEW-worthy but not clearly BLOCK-worthy, and broadly
escalating concealment severity risks the benign-FP floor Goal B established. **Recommended
follow-up:** a *combined* detector — concealment directive co-occurring with data-transfer
language ("collect/upload/transfer the data") — which is unambiguous without raising
standalone concealment severity. Deferred to avoid a precision regression for one sample.
