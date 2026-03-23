import { resolve } from "node:path";

import {
	findScannerReleaseIssues,
	findWebReleaseIssues,
	loadScannerReleaseSnapshot,
	loadWebReleaseSnapshot,
	type ScannerReleaseSnapshot,
	type WebReleaseSnapshot,
} from "./release-guard.mts";

interface Scenario {
	readonly name: string;
	readonly target: "scanner" | "web";
	readonly mutate: (
		scanner: ScannerReleaseSnapshot,
		web: WebReleaseSnapshot,
	) => ScannerReleaseSnapshot | WebReleaseSnapshot;
}

function replaceOnce(text: string, searchValue: string, replaceValue: string): string {
	if (!text.includes(searchValue)) return text;
	return text.replace(searchValue, replaceValue);
}

const scannerRoot = process.cwd();
const webRoot = resolve(process.cwd(), "../agentverus-web");
const scanner = loadScannerReleaseSnapshot(scannerRoot);
const web = loadWebReleaseSnapshot(webRoot);
const currentScannerVersion = JSON.parse(scanner.packageJsonText).version as string;
const previousScannerVersion = currentScannerVersion === "0.0.0" ? "0.0.1" : "0.0.0";
const currentWebVersion = JSON.parse(web.vendoredScannerPackageJsonText).version as string;
const previousWebVersion = currentWebVersion === "0.0.0" ? "0.0.1" : "0.0.0";

const scenarios: readonly Scenario[] = [
	{
		name: "scanner package/types mismatch",
		target: "scanner",
		mutate: (scannerSnapshot) => ({
			...scannerSnapshot,
			scannerTypesText: replaceOnce(
				scannerSnapshot.scannerTypesText,
				`SCANNER_VERSION = \"${currentScannerVersion}\"`,
				`SCANNER_VERSION = \"${previousScannerVersion}\"`,
			),
		}),
	},
	{
		name: "scanner README action tag mismatch",
		target: "scanner",
		mutate: (scannerSnapshot) => ({
			...scannerSnapshot,
			readmeText: replaceOnce(
				scannerSnapshot.readmeText,
				`actions/scan-skill@v${currentScannerVersion}`,
				`actions/scan-skill@v${previousScannerVersion}`,
			),
		}),
	},
	{
		name: "scanner changelog heading missing",
		target: "scanner",
		mutate: (scannerSnapshot) => ({
			...scannerSnapshot,
			changelogText: replaceOnce(
				scannerSnapshot.changelogText,
				`## [${currentScannerVersion}] -`,
				`## [${currentScannerVersion}-broken] -`,
			),
		}),
	},
	{
		name: "scanner action bundle version mismatch",
		target: "scanner",
		mutate: (scannerSnapshot) => ({
			...scannerSnapshot,
			actionBundleText: replaceOnce(
				scannerSnapshot.actionBundleText,
				`var SCANNER_VERSION = \"${currentScannerVersion}\";`,
				`var SCANNER_VERSION = \"${previousScannerVersion}\";`,
			),
		}),
	},
	{
		name: "scanner action source changed without rebuilding bundle",
		target: "scanner",
		mutate: (scannerSnapshot) => ({
			...scannerSnapshot,
			actionSourceText: `${scannerSnapshot.actionSourceText}\n// stale-bundle-sentinel\n`,
		}),
	},
	{
		name: "web vendored scanner mismatch",
		target: "web",
		mutate: (_scannerSnapshot, webSnapshot) => ({
			...webSnapshot,
			vendoredScannerPackageJsonText: replaceOnce(
				webSnapshot.vendoredScannerPackageJsonText,
				`\"version\": \"${currentWebVersion}\"`,
				`\"version\": \"${previousWebVersion}\"`,
			),
		}),
	},
	{
		name: "web docs action tag mismatch",
		target: "web",
		mutate: (_scannerSnapshot, webSnapshot) => ({
			...webSnapshot,
			docsText: replaceOnce(
				webSnapshot.docsText,
				`actions/scan-skill@v${currentWebVersion}`,
				`actions/scan-skill@v${previousWebVersion}`,
			),
		}),
	},
	{
		name: "web fallback version mismatch",
		target: "web",
		mutate: (_scannerSnapshot, webSnapshot) => ({
			...webSnapshot,
			configText: webSnapshot.configText.replaceAll(
				`\"${currentWebVersion}\"`,
				`\"${previousWebVersion}\"`,
			),
		}),
	},
];

const currentScannerIssues = findScannerReleaseIssues(scanner);
const currentWebIssues = findWebReleaseIssues(web);
const currentReleasePass = currentScannerIssues.length === 0 && currentWebIssues.length === 0;
let detectedScenarios = 0;

for (const scenario of scenarios) {
	const mutated = scenario.mutate(scanner, web);
	const issues =
		scenario.target === "scanner"
			? findScannerReleaseIssues(mutated as ScannerReleaseSnapshot)
			: findWebReleaseIssues(mutated as WebReleaseSnapshot);
	if (issues.length > 0) {
		detectedScenarios += 1;
	}
}

const releaseGuardSignals = detectedScenarios + (currentReleasePass ? 1 : 0);
console.log(`METRIC release_guard_signals=${releaseGuardSignals}`);
console.log(`METRIC detected_scenarios=${detectedScenarios}`);
console.log(`METRIC scenario_count=${scenarios.length}`);
console.log(`METRIC current_release_pass=${currentReleasePass ? 1 : 0}`);

const status = {
	currentReleasePass,
	detectedScenarios,
	scenarioCount: scenarios.length,
	scannerIssueCount: currentScannerIssues.length,
	webIssueCount: currentWebIssues.length,
};
console.log(JSON.stringify(status));
