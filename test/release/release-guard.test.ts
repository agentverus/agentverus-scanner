import { describe, expect, it } from "vitest";

import {
	findScannerReleaseIssues,
	findWebReleaseIssues,
	type ScannerReleaseSnapshot,
	type WebReleaseSnapshot,
} from "../../scripts/release-guard.mts";

function createScannerSnapshot(): ScannerReleaseSnapshot {
	return {
		packageJsonText: JSON.stringify({ version: "1.2.3" }),
		scannerTypesText: 'export const SCANNER_VERSION = "1.2.3";\n',
		readmeText:
			"- uses: agentverus/agentverus-scanner/actions/scan-skill@v1.2.3\n",
		changelogText:
			"## [Unreleased]\n\n## [1.2.3] - 2026-03-22\n\n[Unreleased]: https://github.com/agentverus/agentverus-scanner/compare/v1.2.3...HEAD\n[1.2.3]: https://github.com/agentverus/agentverus-scanner/compare/v1.2.2...v1.2.3\n",
		actionBundleText: 'var SCANNER_VERSION = "1.2.3";\n',
		actionSourceText: "console.log('scan');\n",
	};
}

function createWebSnapshot(): WebReleaseSnapshot {
	return {
		vendoredScannerPackageJsonText: JSON.stringify({ version: "1.2.3" }),
		configText:
			'return parsed.version?.trim() || "1.2.3";\nreturn "1.2.3";\n',
		docsText:
			"- uses: agentverus/agentverus-scanner/actions/scan-skill@v1.2.3\n",
		partnerPagesText:
			"- uses: agentverus/agentverus-scanner/actions/scan-skill@v1.2.3\n",
		vendoredReadmeText:
			"- uses: agentverus/agentverus-scanner/actions/scan-skill@v1.2.3\n",
		changelogText:
			"Vendored scanner package updated to `1.2.3`\nGitHub Action examples updated to `v1.2.3`\nScanner fallback version updated to `1.2.3`\n",
	};
}

describe("release guard", () => {
	it("accepts aligned scanner release files", () => {
		expect(findScannerReleaseIssues(createScannerSnapshot())).toEqual([]);
	});

	it("flags scanner action tag mismatches", () => {
		const snapshot = createScannerSnapshot();
		const mutated = {
			...snapshot,
			readmeText: snapshot.readmeText.replace("v1.2.3", "v1.2.2"),
		};
		expect(findScannerReleaseIssues(mutated)).toContain(
			"scanner README action tag 1.2.2 does not match release 1.2.3",
		);
	});

	it("accepts aligned web release files", () => {
		expect(findWebReleaseIssues(createWebSnapshot())).toEqual([]);
	});

	it("flags web fallback mismatches", () => {
		const snapshot = createWebSnapshot();
		const mutated = {
			...snapshot,
			configText: snapshot.configText.replaceAll("1.2.3", "1.2.2"),
		};
		expect(findWebReleaseIssues(mutated)).toContain(
			"web fallback scanner version 1.2.2 does not match vendored scanner 1.2.3",
		);
	});
});
