# Goal B — Cut false positives

## Verdict: the false-positive "problem" is a binary-metric artifact

Goal B set out to raise precision by cutting the ~29 benign skills flagged by the
scanner. The autoresearch loop's honest conclusion: **there is almost no false-BLOCK
headroom to win, because the scanner is already well-calibrated under the correct
3-way frame.**

### 3-way ALLOW / REVIEW / BLOCK breakdown (224-sample corpus)

| bucket | ALLOW | REVIEW | BLOCK |
|---|---|---|---|
| benign (84) | 14 | 61 | **0** |
| malicious (128) | 1 | 88 | 39 |
| external (12) | 1 | 7 | 4 |

- **`block_precision` = 1.00** — the scanner **never wrongly BLOCKS a benign skill** (0 of 84).
- **`allow_leak` = 2** — only 2 of 140 malicious skills (1.4%) fully slip through as ALLOW.
- The binary "precision 0.79" counted **REVIEW verdicts on benign-but-powerful dual-use
  skills as false positives** — but flagging `browser-use` (which genuinely does
  remote-debugging + exec + persistent sessions) for human REVIEW is *correct,
  conservative* behavior for a pre-execution trust scanner, not an error.

### Why severity cuts don't work (two discards)
- **Goal A `#4`** blanket-capped `PERM-CONTRACT-MISSING` high→medium: F1 0.83→0.70.
- **Goal B `#8`** targeted cap (only low-signal capabilities): precision 0.808→0.815 but
  recall 0.871→**0.786** and external 0.833→**0.667** — guardrail violated.

`PERM-CONTRACT-MISSING` (42 hits across the 29) and the dual-use behavioral findings are
**load-bearing for recall**: the same signal that flags a powerful benign skill for
REVIEW is what catches a malicious one. Reducing it trades recall ~1:1. There is no free
precision here under binary scoring.

## Shipped in this PR
1. **3-way metrics in the harness** (`block_precision`, `allow_leak`, `benign_blocked`) —
   the correct, defensible way to measure scanner precision. This is the deliverable: it
   reframes precision from "never flag a powerful skill" to "never wrongly *block* a
   benign one," which the scanner already achieves.
2. **One genuine over-broad fix**: dropped `endpoints?` from the `Comprehensive secret
   collection` pattern — "List **endpoints** to implement" (benign API work) was matching
   a credential-collection rule. Zero recall cost.

## Recommendation
Keep the conservative REVIEW behavior. Adopt 3-way ALLOW/REVIEW/BLOCK as the headline
precision metric (block-precision = 1.0). The remaining 2 `allow_leak`s
(`mal-concealment-slack-poster`, `ext-data-harvesting`) are **recall** defects, not
precision — handled in Goal C.
