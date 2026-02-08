/** Result of scanning a single skill from the registry */
export interface RegistryScanResult {
	/** Skill slug from the registry URL */
	readonly slug: string;
	/** Version string if available */
	readonly version: string;
	/** Download URL used */
	readonly url: string;
	/** Overall trust score 0-100 */
	readonly score: number;
	/** Badge tier */
	readonly badge: "certified" | "conditional" | "suspicious" | "rejected";
	/** Detected skill format */
	readonly format: string;
	/** Skill name from parsed content */
	readonly name: string;
	/** Category score breakdown */
	readonly categories: Record<
		string,
		{ readonly score: number; readonly weight: number; readonly findingCount: number }
	>;
	/** Top findings (limited to keep dataset manageable) */
	readonly findings: readonly RegistryFinding[];
	/** Scan duration in ms */
	readonly durationMs: number;
	/** Timestamp of scan */
	readonly scannedAt: string;
}

/** Compact finding for registry dataset */
export interface RegistryFinding {
	readonly id: string;
	readonly severity: string;
	readonly title: string;
	readonly category: string;
	readonly owaspCategory: string;
	readonly evidence?: string;
}

/** Summary statistics for a full registry scan */
export interface RegistryScanSummary {
	/** Total skills in the URL list */
	readonly totalSkills: number;
	/** Successfully scanned */
	readonly scanned: number;
	/** Failed to download/parse */
	readonly failed: number;
	/** Badge distribution */
	readonly badges: Record<string, number>;
	/** Average score */
	readonly averageScore: number;
	/** Median score */
	readonly medianScore: number;
	/** Score distribution buckets */
	readonly scoreDistribution: Record<string, number>;
	/** Top findings by frequency */
	readonly topFindings: readonly { readonly id: string; readonly title: string; readonly count: number }[];
	/** Skills flagged that VT would likely miss (text-based threats) */
	readonly vtGapSkills: readonly string[];
	/** Scan metadata */
	readonly scannerVersion: string;
	readonly scannedAt: string;
	readonly totalDurationMs: number;
	readonly concurrency: number;
}

/** Error entry for failed scans */
export interface RegistryScanError {
	readonly slug: string;
	readonly url: string;
	readonly error: string;
}
