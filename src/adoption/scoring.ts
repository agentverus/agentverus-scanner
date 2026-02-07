import type { AdoptionScore, AdoptionSignals, AdoptionTier } from "./types.js";

const WEIGHTS = {
	popularity: 0.4,
	freshness: 0.35,
	maturity: 0.25,
} as const;

const MS_PER_DAY = 24 * 60 * 60 * 1000;

function clampScore(score: number): number {
	return Math.round(Math.max(0, Math.min(100, score)));
}

export function adoptionTierFromCombined(combined: number): AdoptionTier {
	if (combined >= 70) return "widely_used";
	if (combined >= 40) return "gaining_adoption";
	if (combined >= 10) return "early";
	return "not_adopted";
}

export function calculatePopularityScore(installs: number): number {
	if (installs >= 10_000) return 100;
	if (installs >= 5_000) return 85;
	if (installs >= 2_000) return 70;
	if (installs >= 1_000) return 55;
	if (installs >= 500) return 40;
	if (installs >= 100) return 25;
	if (installs >= 10) return 10;
	return 0;
}

export function calculateFreshnessScore(
	lastUpdated: Date | null,
	now: Date = new Date(),
): number {
	if (!lastUpdated) return 0;

	const deltaMs = Math.max(0, now.getTime() - lastUpdated.getTime());
	const days = deltaMs / MS_PER_DAY;

	if (days <= 7) return 100;
	if (days <= 30) return 85;
	if (days <= 90) return 65;
	if (days <= 180) return 40;
	if (days <= 365) return 20;
	return 5;
}

export function calculateMaturityScore(
	createdAt: Date | null,
	now: Date = new Date(),
): number {
	if (!createdAt) return 0;

	const ageMs = Math.max(0, now.getTime() - createdAt.getTime());
	const days = ageMs / MS_PER_DAY;

	if (days < 7) return 5;
	if (days < 30) return 15;
	if (days < 90) return 30;
	if (days < 180) return 50;
	if (days < 365) return 75;
	return 100;
}

export function calculateAdoptionScore(
	signals: AdoptionSignals,
	now: Date = new Date(),
): AdoptionScore {
	const popularity = calculatePopularityScore(signals.installs);
	const freshness = calculateFreshnessScore(signals.lastUpdated, now);
	const maturity = calculateMaturityScore(signals.createdAt, now);

	const combinedRaw =
		popularity * WEIGHTS.popularity +
		freshness * WEIGHTS.freshness +
		maturity * WEIGHTS.maturity;

	const combined = clampScore(combinedRaw);
	const tier = adoptionTierFromCombined(combined);

	return {
		popularity,
		freshness,
		maturity,
		combined,
		tier,
	};
}

