import { execFileSync } from "node:child_process";
import { cp, mkdir, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";

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

async function writeText(path: string, content: string): Promise<void> {
	await mkdir(dirname(path), { recursive: true });
	await writeFile(path, content, "utf8");
}

async function runWebSyncAutomationScenario(
	scannerRoot: string,
	scanner: ScannerReleaseSnapshot,
	web: WebReleaseSnapshot,
	currentVersion: string,
	staleVersion: string,
): Promise<boolean> {
	const tempRoot = await mkdtemp(resolve(tmpdir(), "agentverus-release-sync-"));
	const tempScannerRoot = resolve(tempRoot, "scanner");
	const tempWebRoot = resolve(tempRoot, "web");

	try {
		await mkdir(tempScannerRoot, { recursive: true });
		await mkdir(tempWebRoot, { recursive: true });
		await writeText(resolve(tempScannerRoot, "package.json"), scanner.packageJsonText);
		await writeText(resolve(tempScannerRoot, "README.md"), scanner.readmeText);
		await cp(resolve(scannerRoot, "dist"), resolve(tempScannerRoot, "dist"), {
			recursive: true,
			force: true,
		});

		await writeText(
			resolve(tempWebRoot, "vendor/agentverus-scanner/package.json"),
			replaceOnce(
				web.vendoredScannerPackageJsonText,
				`\"version\": \"${currentVersion}\"`,
				`\"version\": \"${staleVersion}\"`,
			),
		);
		await writeText(
			resolve(tempWebRoot, "vendor/agentverus-scanner/README.md"),
			replaceOnce(
				web.vendoredReadmeText,
				`actions/scan-skill@v${currentVersion}`,
				`actions/scan-skill@v${staleVersion}`,
			),
		);
		await writeText(
			resolve(tempWebRoot, "src/lib/config.ts"),
			web.configText.replaceAll(`\"${currentVersion}\"`, `\"${staleVersion}\"`),
		);
		await writeText(
			resolve(tempWebRoot, "src/web/pages/docs.tsx"),
			replaceOnce(
				web.docsText,
				`actions/scan-skill@v${currentVersion}`,
				`actions/scan-skill@v${staleVersion}`,
			),
		);
		await writeText(
			resolve(tempWebRoot, "src/web/pages/partner-pages.tsx"),
			replaceOnce(
				web.partnerPagesText,
				`actions/scan-skill@v${currentVersion}`,
				`actions/scan-skill@v${staleVersion}`,
			),
		);
		await writeText(
			resolve(tempWebRoot, "CHANGELOG.md"),
			web.changelogText
				.replaceAll(`\`${currentVersion}\``, `\`${staleVersion}\``)
				.replaceAll(`\`v${currentVersion}\``, `\`v${staleVersion}\``),
		);

		execFileSync(
			"pnpm",
			[
				"tsx",
				resolve(scannerRoot, "scripts/release-sync-web.mts"),
				"--scanner-root",
				tempScannerRoot,
				"--web-root",
				tempWebRoot,
			],
			{ stdio: "pipe", cwd: scannerRoot },
		);

		const syncedWeb = loadWebReleaseSnapshot(tempWebRoot);
		return findWebReleaseIssues(syncedWeb).length === 0;
	} finally {
		await rm(tempRoot, { recursive: true, force: true });
	}
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
		name: "web vendored README action tag mismatch",
		target: "web",
		mutate: (_scannerSnapshot, webSnapshot) => ({
			...webSnapshot,
			vendoredReadmeText: replaceOnce(
				webSnapshot.vendoredReadmeText,
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

const automationSyncPass = await runWebSyncAutomationScenario(
	scannerRoot,
	scanner,
	web,
	currentWebVersion,
	previousWebVersion,
);

const releaseGuardSignals = detectedScenarios + (currentReleasePass ? 1 : 0) + (automationSyncPass ? 1 : 0);
console.log(`METRIC release_guard_signals=${releaseGuardSignals}`);
console.log(`METRIC detected_scenarios=${detectedScenarios}`);
console.log(`METRIC scenario_count=${scenarios.length}`);
console.log(`METRIC current_release_pass=${currentReleasePass ? 1 : 0}`);
console.log(`METRIC automation_sync_pass=${automationSyncPass ? 1 : 0}`);

const status = {
	currentReleasePass,
	detectedScenarios,
	scenarioCount: scenarios.length,
	automationSyncPass,
	scannerIssueCount: currentScannerIssues.length,
	webIssueCount: currentWebIssues.length,
};
console.log(JSON.stringify(status));
