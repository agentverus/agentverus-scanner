# detection-f1 — run results

Autoresearch run on `autoverus-scanner` detection quality, vs a labeled corpus built
to be head-to-head comparable with the rival **agentshield** (`ecc-agentshield@1.4.0`).

Branch: `autoresearch/detection-f1` (off shipped `main` / v0.8.0).

## Corpus (224 samples)
- **Benign (84):** 75 real skills fetched from reputable repos (anthropics/skills,
  browser-use, vercel-labs, baoyu, obra/superpowers, clawdirect) + 9 seed safe fixtures.
- **Malicious (128):** 110 injection-generated (10 attack classes × 12 benign hosts) +
  18 seed malicious fixtures.
- **External holdout (12):** agentshield `vulnerable-configs.ts` scenarios ported to
  SKILL.md form — **never tuned against** (realism gate).

Predicted-malicious = badge ∈ {rejected, suspicious}. 30% deterministic holdout by
filename hash; external bucket is always holdout.

## Result

| metric | seed (27) | full baseline | **best** | Δ |
|---|---|---|---|---|
| F1 (primary) | 0.94 | 0.7798 | **0.8304** | **+6.5%** |
| holdout_f1 | — | 0.7885 | 0.8333 | +4.5% |
| external_recall | — | 0.5833 | 0.6667 | +8.3pts |
| precision | 1.00 | 0.7883 | 0.8054 | +1.7pts |
| recall | 0.94 | 0.7714 | 0.8571 | +8.6pts |
| specificity | 1.00 | 0.6548 | 0.6548 | — |

All wins improved holdout **and** external (not overfit to the synthetic train set).
243 product tests pass at every kept commit.

## Kept improvements
1. **`@e4e1f0a` Private-key reads → critical.** Reading `id_rsa`/`id_ed25519`/`id_ecdsa`/
   `~/.aws/credentials` now scores `critical` (→ rejected), not `high` (→ conditional).
   Fixed the `undeclared-permissions` false-negative; generalizes.
2. **`@12eee2f` Reverse-shell / backconnect detection.** `bash -i >& /dev/tcp/…`, `nc -e`,
   `socket`+`pty.spawn` now `critical`. These scored **CERTIFIED** before — a total gap.
   Biggest single F1 mover (recall 0.77→0.86), zero benign cost.

## Discarded (with learning)
- **`#4` Cap PERM-CONTRACT-MISSING high→medium.** F1 0.83→0.70. The contract-mismatch
  severity is load-bearing for permission-abuse recall; a blanket cap trades too much
  recall for precision. Specificity *did* rise (0.655→0.702), confirming it is a FP
  driver — but the fix must be targeted, not blanket.

## Open frontier (precision)
- 29 benign FP remain. Drivers: the **behavioral** analyzer flags legitimate browser-
  automation skills (persistent-session-reuse, content-extraction, OS-input-automation)
  as `high`, plus `COMPREHENSIVE-SECRET-COLLECTION` firing on `mcp-builder`.
- **Metric-definition question:** these get badge `suspicious` = REVIEW, not BLOCK. The
  binary malicious/benign F1 counts a REVIEW on a powerful-but-legit dual-use skill as a
  false positive. A 3-way ALLOW/REVIEW/BLOCK scoring (as the prior `benchmark-plan.md`
  intended) may show much of this "FP gap" is defensible review behavior, not error.

## vs agentshield (measured)
On the 12 ported agentshield scenarios, agentverus@best catches **8/12** (was 7/12).
Misses: data-harvesting, keylogger (now partly caught), secrets-everywhere (hardcoded
`sk-ant-`/`AKIA` only reach conditional), mcp-hijacking, env-proxy-hijack — i.e.
agentshield's supply-chain/MCP/hardcoded-secret coverage is still ahead. These are the
next concrete detector targets if pursuing parity.
