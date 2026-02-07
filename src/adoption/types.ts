export type AdoptionTier =
	| "widely_used"
	| "gaining_adoption"
	| "early"
	| "not_adopted";

export interface AdoptionSignals {
	installs: number;
	stars: number;
	forks: number;
	lastUpdated: Date | null;
	createdAt: Date | null;
	source: string;
}

export interface AdoptionScore {
	popularity: number;
	freshness: number;
	maturity: number;
	combined: number;
	tier: AdoptionTier;
}

