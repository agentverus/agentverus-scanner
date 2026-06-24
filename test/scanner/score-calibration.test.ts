import { describe, expect, it } from "vitest";
import {
	calculateOverallScore,
	determineBadge,
} from "../../src/scanner/score-calibration.js";
import type { Category, CategoryScore, Finding } from "../../src/scanner/types.js";

function finding(severity: Finding["severity"], opts: Partial<Finding> = {}): Finding {
	return {
		id: opts.id ?? "INJ-X-1",
		category: opts.category ?? "injection",
		severity,
		title: opts.title ?? "Test finding",
		description: "",
		evidence: "",
		deduction: opts.deduction ?? 0,
		recommendation: "",
		owaspCategory: "ASST-01",
		...opts,
	} as Finding;
}

function categories(overrides: Partial<Record<Category, CategoryScore>> = {}): Record<Category, CategoryScore> {
	const cat = (weight: number, score = 100): CategoryScore => ({ score, weight, findings: [], summary: "" });
	return {
		permissions: cat(0.2),
		injection: cat(0.25),
		dependencies: cat(0.15),
		behavioral: cat(0.15),
		content: cat(0.1),
		"code-safety": cat(0.15),
		...overrides,
	};
}

describe("determineBadge — score boundaries", () => {
	it("score < 50 → rejected (49 is rejected, 50 is suspicious)", () => {
		expect(determineBadge(49, [])).toBe("rejected");
		expect(determineBadge(50, [])).toBe("suspicious");
	});

	it("50..74 → suspicious; 75 → conditional", () => {
		expect(determineBadge(74, [])).toBe("suspicious");
		expect(determineBadge(75, [])).toBe("conditional");
	});

	it("75..89 → conditional; 90 with no highs → certified", () => {
		expect(determineBadge(89, [])).toBe("conditional");
		expect(determineBadge(90, [])).toBe("certified");
	});
});

describe("determineBadge — finding-driven overrides", () => {
	it("any critical finding → rejected regardless of score", () => {
		expect(determineBadge(100, [finding("critical")])).toBe("rejected");
		expect(determineBadge(95, [finding("high"), finding("critical")])).toBe("rejected");
	});

	it("config-tamper finding caps a high score at suspicious", () => {
		expect(determineBadge(100, [finding("high", { id: "BEH-CONFIG-TAMPER-1" })])).toBe("suspicious");
		expect(determineBadge(100, [finding("medium", { id: "CS-CONFIG-TAMPER-2" })])).toBe("suspicious");
	});

	it("high-finding count gates certified/conditional/suspicious at score ≥ 90", () => {
		expect(determineBadge(95, [])).toBe("certified");
		expect(determineBadge(95, [finding("high")])).toBe("conditional"); // 1..2 highs
		expect(determineBadge(95, [finding("high"), finding("high")])).toBe("conditional");
		expect(determineBadge(95, [finding("high"), finding("high"), finding("high")])).toBe("suspicious"); // >2 highs
	});
});

describe("calculateOverallScore — floor + penalty", () => {
	it("returns 100 when all categories are perfect with no findings", () => {
		expect(calculateOverallScore(categories())).toBe(100);
	});

	it("clamps the lower bound to 0 when penalties drive the raw score negative", () => {
		// every category 0 + a critical → weighted 0, minus drag(30) minus penalty(48) = -78 → clamps to 0
		const allCritical = categories();
		for (const key of Object.keys(allCritical) as Category[]) {
			allCritical[key] = {
				score: 0,
				weight: allCritical[key].weight,
				findings: [finding("critical", { category: key })],
				summary: "",
			};
		}
		expect(calculateOverallScore(allCritical)).toBe(0);
	});

	it("clamps the upper bound to 100 even if a category score exceeds 100", () => {
		const score = calculateOverallScore(categories({ injection: { score: 200, weight: 0.25, findings: [], summary: "" } }));
		expect(score).toBe(100);
	});

	it("floors a weak category at 30 when there are no criticals (exact value)", () => {
		const at0 = calculateOverallScore(categories({ injection: { score: 0, weight: 0.25, findings: [], summary: "" } }));
		const at30 = calculateOverallScore(categories({ injection: { score: 30, weight: 0.25, findings: [], summary: "" } }));
		// injection floored 0→30: 0.2·100 + 0.25·30 + 0.15·100·3 + 0.1·100 = 82.5 → round 83
		expect(at0).toBe(83);
		expect(at30).toBe(83);
	});

	it("a critical bypasses the floor (raw 0), then penalty+drag apply — exact value", () => {
		const withCritical = calculateOverallScore(
			categories({ injection: { score: 0, weight: 0.25, findings: [finding("critical")], summary: "" } }),
		);
		// hasCriticals ⇒ no floor: weighted 75; worst-category drag (60-0)/2=30; penalty 8 ⇒ 75-30-8 = 37
		expect(withCritical).toBe(37);
		expect(withCritical).toBeLessThan(83); // strictly below the floored (no-critical) case
	});

	it("threat-category high findings apply a severity penalty", () => {
		const clean = calculateOverallScore(categories({ injection: { score: 70, weight: 0.25, findings: [], summary: "" } }));
		const penalized = calculateOverallScore(
			categories({ injection: { score: 70, weight: 0.25, findings: [finding("high")], summary: "" } }),
		);
		expect(penalized).toBeLessThan(clean);
	});
});
