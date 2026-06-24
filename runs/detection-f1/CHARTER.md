# CHARTER — autoresearch run: detection-f1

**Goal (outcome):** Make agentverus-scanner's malicious-skill detection measurably more accurate, and produce a labeled benchmark that substantiates the trust-badge positioning head-to-head vs agentshield.

**Domain adapter:** bug-finding variant inverted into a *detector-tuning* loop (mutate-and-measure on the analyzers; metric = classification quality on a fixed labeled corpus). Deterministic, fast, low-noise → `deterministic-delta` + MAD confidence.

## AutoResearch Triple

- **Artifact (mutated):** the six weighted analyzers (`src/scanner/analyzers/*` — permissions, injection, dependencies, behavioral, content, code-safety), their pattern lists, weights, and the `score-calibration` thresholds / badge-tier cutoffs. NOTHING else (parser, outputs, registry off-limits).
- **Objective (primary):** **file-level F1** on malicious-vs-benign classification, where "malicious" = badge ∈ {REJECTED, SUSPICIOUS} and "benign" = {CERTIFIED, CONDITIONAL}. This is the actual product output (the badge), so it can't be Goodharted away from product value.
- **Trial harness:** `measure.sh` scans every corpus sample, maps badge→predicted label, compares to ground-truth label, emits `METRIC f1=`, `METRIC precision=`, `METRIC recall=`, and per-category recall secondaries. Deterministic; runs in seconds; single pass (no re-run noise).

## Guardrails (a primary win that regresses any of these is a DISCARD)

1. **Precision floor: ≥ 0.90 on the benign set.** Blocks "flag everything" recall farming — the dominant failure mode for security scanners and the #1 complaint about agentshield.
2. **Per-category recall must not regress** across {secrets, permissions, hooks, mcp, injection}. Stops the loop from trading whole threat classes for aggregate F1.
3. **`checks.sh` = existing 243 tests + typecheck must pass.** Real product behavior can't break.

## Goodhart guards (corpus is the instrument AND I build it → circularity risk)

- **70/30 train/holdout split, seeded + frozen.** The loop proposes against TRAIN aggregate signal only; the **primary F1 that gates a keep and is reported is HOLDOUT F1.** Proposer never reads individual holdout samples.
- **External-validity holdout:** agentshield's own `corpus/vulnerable-configs.ts` scenarios, ported to SKILL.md form, held entirely out of tuning. If holdout F1 rises but external F1 doesn't, we overfit our own corpus → reject the run.
- **Phase-3 critic** every 5 trials: re-inspect kept changes for benchmark-special-casing (e.g., a pattern that matches a literal fixture string).

## Corpus plan (the gating build cost — confirm before spending)

| Bucket | Source | Approx N | Labeling |
|---|---|---|---|
| Benign | 9 existing safe fixtures + 10 cached public skills + sampled registry skills (spot-verified) | ~120 | benign |
| Malicious (authored) | 18 existing malicious fixtures + programmatic injection of known attack patterns into benign skills | ~120 | per-category positive |
| External holdout | agentshield `vulnerable-configs` ported to SKILL.md | ~15 | per-category, never tuned |

Target ~250 labeled samples → stable F1. Labels live in `runs/detection-f1/corpus/labels.json`.

## Budget & stop

- **Trial:** seconds (deterministic scan over ~250 files). Many trials/hour possible.
- **Stop on:** holdout-F1 plateau over K=5 consecutive trials within MAD noise, OR holdout F1 ≥ 0.92, OR 30-trial cap.
- **Cost unit:** agent tokens (corpus build is the big one-time cost; trials are cheap).

## Branch / reversibility

- Dedicated branch `autoresearch/detection-f1` off `main` (NOT `fix/mcp-dep-remediation`).
- `arl keep` = git commit (advances baseline); `discard` = git revert of analyzer code, `.auto/` preserved. Fully reversible.

## Open decisions for user review (before budget spend)

1. **Primary = file-level badge F1** (product-aligned) vs **category-label F1** (granular, head-to-head-with-agentshield, but ~3× labeling cost). Charter currently picks file-level + per-category recall guardrail as the compromise.
2. **Corpus scale:** ~250 samples (proposed) vs smaller/faster (~80) vs larger/slower (~600).
3. **Malicious authoring:** programmatic injection (cheap, many, but synthetic-looking) vs hand-authored realistic samples (expensive, fewer, higher external validity). Charter uses mostly injection + the external holdout as the realism check.
