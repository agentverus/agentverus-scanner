import { describe, it, expect } from "vitest";
import {
	adoptionTierFromCombined,
	calculateAdoptionScore,
	calculateFreshnessScore,
	calculateMaturityScore,
	calculatePopularityScore,
} from "../../src/adoption/scoring.js";
import type { AdoptionSignals } from "../../src/adoption/types.js";

const NOW = new Date("2026-02-07T00:00:00Z");

function makeSignals(overrides?: Partial<AdoptionSignals>): AdoptionSignals {
	return {
		installs: 0,
		stars: 0,
		forks: 0,
		lastUpdated: null,
		createdAt: null,
		source: "test",
		...overrides,
	};
}

describe("adoption scoring", () => {
	it("should map popularity from installs (<10 => 0)", () => {
		expect(calculatePopularityScore(0)).toBe(0);
		expect(calculatePopularityScore(9)).toBe(0);
	});

	it("should map popularity from installs (10 => 10, 100 => 25, 500 => 40)", () => {
		expect(calculatePopularityScore(10)).toBe(10);
		expect(calculatePopularityScore(100)).toBe(25);
		expect(calculatePopularityScore(500)).toBe(40);
	});

	it("should map popularity from installs (1k => 55, 2k => 70, 5k => 85, 10k+ => 100)", () => {
		expect(calculatePopularityScore(1000)).toBe(55);
		expect(calculatePopularityScore(2000)).toBe(70);
		expect(calculatePopularityScore(5000)).toBe(85);
		expect(calculatePopularityScore(10000)).toBe(100);
	});

	it("should score freshness based on lastUpdated thresholds", () => {
		expect(calculateFreshnessScore(new Date("2026-02-05T00:00:00Z"), NOW)).toBe(100); // 2d
		expect(calculateFreshnessScore(new Date("2026-01-15T00:00:00Z"), NOW)).toBe(85); // 23d
		expect(calculateFreshnessScore(new Date("2025-11-15T00:00:00Z"), NOW)).toBe(65); // ~84d
		expect(calculateFreshnessScore(new Date("2025-09-01T00:00:00Z"), NOW)).toBe(40); // 159d
	});

	it("should score maturity based on createdAt thresholds", () => {
		expect(calculateMaturityScore(new Date("2026-02-06T00:00:00Z"), NOW)).toBe(5); // <1wk
		expect(calculateMaturityScore(new Date("2026-01-20T00:00:00Z"), NOW)).toBe(15); // <1mo
		expect(calculateMaturityScore(new Date("2025-12-15T00:00:00Z"), NOW)).toBe(30); // 1-3mo
		expect(calculateMaturityScore(new Date("2025-10-01T00:00:00Z"), NOW)).toBe(50); // 3-6mo
	});

	it("should compute combined score using the weighted formula and clamp 0-100", () => {
		const signals = makeSignals({
			installs: 10000, // 100
			lastUpdated: new Date("2026-02-06T00:00:00Z"), // 100
			createdAt: new Date("2024-01-01T00:00:00Z"), // 100
		});
		const score = calculateAdoptionScore(signals, NOW);
		expect(score.popularity).toBe(100);
		expect(score.freshness).toBe(100);
		expect(score.maturity).toBe(100);
		expect(score.combined).toBe(100);
		expect(score.tier).toBe("widely_used");
	});

	it("should classify a newly updated but very new repo as EARLY even with 0 installs", () => {
		const signals = makeSignals({
			installs: 0,
			lastUpdated: new Date("2026-02-06T00:00:00Z"), // 100
			createdAt: new Date("2026-01-25T00:00:00Z"), // <1mo => 15
		});
		const score = calculateAdoptionScore(signals, NOW);
		expect(score.combined).toBe(39);
		expect(score.tier).toBe("early");
	});

	it("should classify as NOT_ADOPTED when all signals are missing/zero", () => {
		const score = calculateAdoptionScore(makeSignals(), NOW);
		expect(score.combined).toBe(0);
		expect(score.tier).toBe("not_adopted");
	});

	it("should treat 70+ as WIDELY_USED and 40-69 as GAINING_ADOPTION", () => {
		expect(adoptionTierFromCombined(70)).toBe("widely_used");
		expect(adoptionTierFromCombined(69)).toBe("gaining_adoption");
		expect(adoptionTierFromCombined(40)).toBe("gaining_adoption");
		expect(adoptionTierFromCombined(39)).toBe("early");
	});
});
