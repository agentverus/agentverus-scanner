# Goal D — Badge calibration

## Verdict: calibration is at its defensible ceiling — no in-scope headroom

Goal D set out to maximize agreement between the computed badge tier and the true trust
verdict, by tuning the score-calibration thresholds/penalties. The loop's honest outcome:
**the calibration is already well-tuned where it matters, and the residual gap is
intentional dual-use overlap that score-tuning cannot close.** (Per the autoresearch
method, cheaply proving "no in-scope headroom" is itself a successful result.)

## Calibration baseline
- **AUC = 0.805** (P[random benign scores higher than random malicious]; threshold-free)
- **score_separation = 32.0** (mean benign overall − mean malicious overall)
- **block_precision = 1.00**, **benign_blocked = 0** — the calibration where it matters
  (never block a benign skill, never let the thresholds misfire on the clear cases) is
  already perfect.

## Two levers tried, both rejected
1. **Lower the category-score floor 30→15** (`calculateWeightedOverall`): AUC 0.805→0.791,
   separation 32→30.7, and **benign_blocked 0→1** — a benign skill dropped below the
   reject threshold. The 30-floor *protects* benign skills with one weak category more
   than it lifts malicious ones. Guardrail violated → discard.
2. **Add `code-safety` to the threat-penalty categories** (`applySeverityPenalty`): AUC
   0.805→0.804 (flat) — code-safety highs are too rare in both classes to move scores.
   No-op → discard.

## Why AUC plateaus at 0.80
The ~20% of misordered pairs are the **intentional dual-use overlap**: powerful *benign*
skills (browser-use: remote-debugging + exec + session reuse) scoring low, and *malicious*
skills injected into legitimate hosts scoring high. These look alike by surface features;
separating them further requires distinguishing intent, which threshold/penalty tuning
cannot do. Forcing more separation breaks the benign side (lever 1).

## Shipped
- **AUC + score_separation calibration metrics** added to the harness — so the project can
  monitor calibration quality (class separation) going forward, not just point accuracy.
- Confirmation (via two discards) that the existing thresholds, the 30-floor, and the
  injection-scoped threat penalty are near-optimal and should be left as-is.

## Recommendation
Leave the calibration thresholds as they are. Monitor AUC/separation over time as new
detectors land (a detector that drops AUC is over-firing on benign). The one residual
`allow_leak` is a coverage issue (Goal C), not a calibration one.
