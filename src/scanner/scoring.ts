import type {
	Category,
	CategoryScore,
	Finding,
	ScanMetadata,
	TrustReport,
} from "./types.js";
import { shapeReportFindings, sortFindingsBySeverity } from "./report-shaping.js";
import { calculateOverallScore, determineBadge } from "./score-calibration.js";

/**
 * Aggregate category scores into a complete TrustReport.
 * Overall score = weighted average of category scores plus calibrated penalties.
 */
export function aggregateScores(
	categories: Record<Category, CategoryScore>,
	metadata: ScanMetadata,
): TrustReport {
	const overall = calculateOverallScore(categories);
	const allFindings: Finding[] = sortFindingsBySeverity(
		Object.values(categories).flatMap((cat) => [...cat.findings]),
	);
	const badge = determineBadge(overall, allFindings);
	const reportFindings = shapeReportFindings(allFindings);

	return {
		overall,
		badge,
		categories,
		findings: reportFindings,
		metadata,
	};
}
