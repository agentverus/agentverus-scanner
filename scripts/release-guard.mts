import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export interface ScannerReleaseSnapshot {
	readonly packageJsonText: string;
	readonly scannerTypesText: string;
	readonly readmeText: string;
	readonly changelogText: string;
	readonly actionBundleText: string;
	readonly actionSourceText: string;
}

export interface WebReleaseSnapshot {
	readonly vendoredScannerPackageJsonText: string;
	readonly configText: string;
	readonly docsText: string;
	readonly partnerPagesText: string;
	readonly vendoredReadmeText: string;
	readonly changelogText: string;
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function computeContentHash(content: string): string {
	return createHash("sha256").update(content).digest("hex").slice(0, 16);
}

function parsePackageVersion(packageJsonText: string): string | null {
	try {
		const parsed = JSON.parse(packageJsonText) as { version?: unknown };
		return typeof parsed.version === "string" && parsed.version.trim() ? parsed.version.trim() : null;
	} catch {
		return null;
	}
}

function extractScannerVersion(scannerTypesText: string): string | null {
	const match = scannerTypesText.match(/SCANNER_VERSION\s*=\s*"([^"]+)"/);
	return match?.[1] ?? null;
}

function extractActionTagVersions(text: string): string[] {
	return Array.from(text.matchAll(/agentverus\/agentverus-scanner\/actions\/scan-skill@v(\d+\.\d+\.\d+)/g), (match) => match[1]);
}

function extractFallbackVersions(configText: string): string[] {
	return Array.from(configText.matchAll(/return(?:\s+parsed\.version\?\.trim\(\)\s*\|\|)?\s*"(\d+\.\d+\.\d+)";/g), (match) => match[1]);
}

function extractActionSourceHash(actionBundleText: string): string | null {
	const match = actionBundleText.match(/ACTION_SOURCE_HASH:([a-f0-9]{16})/);
	return match?.[1] ?? null;
}

function hasReleaseHeading(changelogText: string, version: string): boolean {
	return new RegExp(`^## \\[${escapeRegExp(version)}\\] - \\d{4}-\\d{2}-\\d{2}$`, "m").test(changelogText);
}

function hasUnreleasedCompareLink(changelogText: string, version: string): boolean {
	return new RegExp(`^\\[Unreleased\\]: .*?/compare/v${escapeRegExp(version)}\\.\\.\\.HEAD$`, "m").test(changelogText);
}

function hasReleaseCompareLink(changelogText: string, version: string): boolean {
	return new RegExp(`^\\[${escapeRegExp(version)}\\]: .*?/compare/v.+\\.\\.\\.v${escapeRegExp(version)}$`, "m").test(changelogText);
}

export function findScannerReleaseIssues(snapshot: ScannerReleaseSnapshot): string[] {
	const issues: string[] = [];
	const packageVersion = parsePackageVersion(snapshot.packageJsonText);
	const scannerVersion = extractScannerVersion(snapshot.scannerTypesText);

	if (!packageVersion) {
		issues.push("scanner package.json is missing a parseable version");
	}
	if (!scannerVersion) {
		issues.push("src/scanner/types.ts is missing SCANNER_VERSION");
	}
	if (packageVersion && scannerVersion && packageVersion !== scannerVersion) {
		issues.push(`scanner package version ${packageVersion} does not match SCANNER_VERSION ${scannerVersion}`);
	}

	const expectedVersion = packageVersion ?? scannerVersion;
	if (!expectedVersion) return issues;

	const readmeVersions = extractActionTagVersions(snapshot.readmeText);
	if (readmeVersions.length === 0) {
		issues.push("scanner README is missing a GitHub Action release tag example");
	}
	for (const version of new Set(readmeVersions)) {
		if (version !== expectedVersion) {
			issues.push(`scanner README action tag ${version} does not match release ${expectedVersion}`);
		}
	}

	if (!hasReleaseHeading(snapshot.changelogText, expectedVersion)) {
		issues.push(`scanner CHANGELOG is missing a ${expectedVersion} release heading`);
	}
	if (!hasUnreleasedCompareLink(snapshot.changelogText, expectedVersion)) {
		issues.push(`scanner CHANGELOG unreleased compare link is not anchored to v${expectedVersion}`);
	}
	if (!hasReleaseCompareLink(snapshot.changelogText, expectedVersion)) {
		issues.push(`scanner CHANGELOG compare links are missing the v${expectedVersion} release entry`);
	}

	const bundleVersion = extractScannerVersion(snapshot.actionBundleText);
	if (!bundleVersion) {
		issues.push("scanner action bundle is missing an embedded SCANNER_VERSION");
	} else if (bundleVersion !== expectedVersion) {
		issues.push(`scanner action bundle version ${bundleVersion} does not match release ${expectedVersion}`);
	}

	const actionSourceHash = computeContentHash(snapshot.actionSourceText);
	const bundledActionSourceHash = extractActionSourceHash(snapshot.actionBundleText);
	if (!bundledActionSourceHash) {
		issues.push("scanner action bundle is missing ACTION_SOURCE_HASH metadata");
	} else if (bundledActionSourceHash !== actionSourceHash) {
		issues.push(
			`scanner action bundle source hash ${bundledActionSourceHash} does not match action source ${actionSourceHash}`,
		);
	}

	return issues;
}

export function findWebReleaseIssues(snapshot: WebReleaseSnapshot): string[] {
	const issues: string[] = [];
	const vendoredVersion = parsePackageVersion(snapshot.vendoredScannerPackageJsonText);

	if (!vendoredVersion) {
		issues.push("web vendored scanner package.json is missing a parseable version");
		return issues;
	}

	const fallbackVersions = extractFallbackVersions(snapshot.configText);
	if (fallbackVersions.length === 0) {
		issues.push("web config is missing fallback scanner version literals");
	}
	for (const version of new Set(fallbackVersions)) {
		if (version !== vendoredVersion) {
			issues.push(`web fallback scanner version ${version} does not match vendored scanner ${vendoredVersion}`);
		}
	}

	const actionTagVersions = [
		...extractActionTagVersions(snapshot.docsText),
		...extractActionTagVersions(snapshot.partnerPagesText),
		...extractActionTagVersions(snapshot.vendoredReadmeText),
	];
	if (actionTagVersions.length === 0) {
		issues.push("web docs are missing scanner GitHub Action tag examples");
	}
	for (const version of new Set(actionTagVersions)) {
		if (version !== vendoredVersion) {
			issues.push(`web docs action tag ${version} does not match vendored scanner ${vendoredVersion}`);
		}
	}

	if (!snapshot.changelogText.includes(`Vendored scanner package updated to \`${vendoredVersion}\``)) {
		issues.push(`web CHANGELOG is missing vendored scanner ${vendoredVersion} release notes`);
	}
	if (!snapshot.changelogText.includes(`GitHub Action examples updated to \`v${vendoredVersion}\``)) {
		issues.push(`web CHANGELOG is missing GitHub Action v${vendoredVersion} release notes`);
	}
	if (!snapshot.changelogText.includes(`Scanner fallback version updated to \`${vendoredVersion}\``)) {
		issues.push(`web CHANGELOG is missing fallback version ${vendoredVersion} release notes`);
	}

	return issues;
}

export interface ReleasePreflightResult {
	readonly scannerIssues: readonly string[];
	readonly webIssues: readonly string[];
}

export function loadScannerReleaseSnapshot(rootDir: string): ScannerReleaseSnapshot {
	return {
		packageJsonText: readFileSync(resolve(rootDir, "package.json"), "utf8"),
		scannerTypesText: readFileSync(resolve(rootDir, "src/scanner/types.ts"), "utf8"),
		readmeText: readFileSync(resolve(rootDir, "README.md"), "utf8"),
		changelogText: readFileSync(resolve(rootDir, "CHANGELOG.md"), "utf8"),
		actionBundleText: readFileSync(resolve(rootDir, "actions/scan-skill/dist/index.cjs"), "utf8"),
		actionSourceText: readFileSync(resolve(rootDir, "actions/scan-skill/src/index.ts"), "utf8"),
	};
}

export function loadWebReleaseSnapshot(rootDir: string): WebReleaseSnapshot {
	return {
		vendoredScannerPackageJsonText: readFileSync(resolve(rootDir, "vendor/agentverus-scanner/package.json"), "utf8"),
		configText: readFileSync(resolve(rootDir, "src/lib/config.ts"), "utf8"),
		docsText: readFileSync(resolve(rootDir, "src/web/pages/docs.tsx"), "utf8"),
		partnerPagesText: readFileSync(resolve(rootDir, "src/web/pages/partner-pages.tsx"), "utf8"),
		vendoredReadmeText: readFileSync(resolve(rootDir, "vendor/agentverus-scanner/README.md"), "utf8"),
		changelogText: readFileSync(resolve(rootDir, "CHANGELOG.md"), "utf8"),
	};
}

export function runReleasePreflight(scannerRootDir: string, webRootDir: string): ReleasePreflightResult {
	const scannerIssues = findScannerReleaseIssues(loadScannerReleaseSnapshot(scannerRootDir));
	const webIssues = findWebReleaseIssues(loadWebReleaseSnapshot(webRootDir));
	return { scannerIssues, webIssues };
}
