import type { Finding, Severity } from "../types.js";

/**
 * Downgrade a finding severity by exactly one tier. Used when context softens a
 * match (inside a code block, a documentation example, a safety section, …).
 * `info` is the floor and stays `info`.
 *
 * This unifies the three previously-divergent per-analyzer helpers
 * (injection/behavioral/code-safety) into one source of truth.
 */
export function downgradeSeverity(severity: Severity): Severity {
	switch (severity) {
		case "critical":
			return "high";
		case "high":
			return "medium";
		case "medium":
			return "low";
		case "low":
			return "info";
		default:
			// "info" is the floor.
			return "info";
	}
}

/**
 * Recompute a category score from its final findings: start at `base` and
 * subtract each finding's deduction, clamped to [0, 100]. Deductions are
 * non-negative, so this is equivalent to the iterative
 * `score = Math.max(0, score - f.deduction)` loop the analyzers previously
 * each copy-pasted, while also guarding the upper bound.
 *
 * `base` defaults to 100; `content.ts` deliberately starts at 80 ("skills must
 * earn the top 20") and passes that explicitly.
 */
export function recomputeScore(findings: readonly Finding[], base = 100): number {
	const totalDeduction = findings.reduce((sum, f) => sum + f.deduction, 0);
	return Math.max(0, Math.min(100, base - totalDeduction));
}
