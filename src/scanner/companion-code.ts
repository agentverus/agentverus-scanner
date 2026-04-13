import { readFile, readdir, stat } from "node:fs/promises";
import { extname, join, relative } from "node:path";

import { aggregateScores } from "./scoring.js";
import type { Finding, ParsedSkill, TrustReport } from "./types.js";

const DEFAULT_IGNORED_DIRS = new Set([
	".git",
	"node_modules",
	"dist",
	"build",
	"coverage",
	".next",
	".turbo",
]);

const TEXT_SOURCE_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".sh", ".bash"]);
const MAX_FILE_BYTES = 256 * 1024;
const MAX_SOURCE_FILES = 12;
const SENSITIVE_DISCLOSURE = /\b(?:credential|credentials|token|secret|api[_ -]?key|password|auth|oauth|cookie|session|login|webhook|environment variable|process\.env|\.env)\b/i;
const SECRET_SOURCE_PATTERNS = [
	/process\.env\.[A-Z0-9_]+/i,
	/process\.env\[['"][A-Z0-9_]+['"]\]/i,
	/os\.environ\[['"][A-Z0-9_]+['"]\]/i,
	/os\.getenv\(['"][A-Z0-9_]+['"]\)/i,
	/getenv\(['"][A-Z0-9_]+['"]\)/i,
	/~\/\.(?:aws\/credentials|ssh\/id_rsa|ssh\/id_ed25519)/i,
	/\.aws\/credentials/i,
	/\.ssh\/(?:id_rsa|id_ed25519|authorized_keys)/i,
	/\b(?:API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET|PASSWORD|AUTH[_-]?TOKEN|OPENAI_API_KEY)\b/i,
	/\b[A-Z0-9_]*(?:TOKEN|API[_-]?KEY|SECRET|PASSWORD|COOKIE)\b/i,
] as const;
const LOG_PATTERNS = [
	/\bconsole\.(?:log|error|warn)\s*\(/i,
	/\bprint\s*\(/i,
	/\bprocess\.(?:stdout|stderr)\.write\s*\(/i,
	/\bstdout\.write\s*\(/i,
	/\bstderr\.write\s*\(/i,
	/\bprintf\b[^\n]{0,160}(?:>&2|1>&2|2>|>>)/i,
	/\becho\s+["'$]/i,
	/\blogger\.(?:info|debug|warning)\s*\(/i,
] as const;
const NETWORK_PATTERNS = [
	/\bfetch\s*\(/i,
	/\baxios\.(?:post|get|request)\s*\(/i,
	/\brequests\.(?:post|get|request)\s*\(/i,
	/\bhttpx\.(?:post|get|request)\s*\(/i,
	/\burllib\.request\b/i,
	/\baiohttp\b/i,
	/\bwebhook\b/i,
	/\bcurl\b.{0,80}https?:\/\//i,
	/https?:\/\//i,
] as const;
const SECRET_TO_NETWORK_PATTERNS = [
	/(?:body|json)\s*[:=]\s*(?:JSON\.stringify\()?[^\n]{0,180}\b(?:api[_-]?key|token|secret|credentials?|cookie|auth)\b/i,
	/(?:fetch|axios\.(?:post|get|request)|requests\.(?:post|get|request)|httpx\.(?:post|get|request))\([^\n]{0,180}\b(?:webhook|exfil|collector|pastebin|requestbin|discord|slack|evil)\b/i,
] as const;
const SUSPICIOUS_ENDPOINT_PATTERNS = [
	/https?:\/\/[^\s"')]+(?:evil|exfil|webhook|collector|pastebin|requestbin|discord|slack)[^\s"')]*/i,
	/\b(?:webhook|exfiltrat(?:e|ion)|collector)\b/i,
] as const;
const CREDENTIAL_FILE_READ = [
	/open\([^\n]{0,120}(?:\.aws\/credentials|\.ssh\/(?:id_rsa|id_ed25519)|\.env)/i,
	/readFile(?:Sync)?\([^\n]{0,120}(?:\.aws\/credentials|\.ssh\/(?:id_rsa|id_ed25519)|\.env)/i,
	/cat\s+[^\n]{0,80}(?:\.aws\/credentials|\.ssh\/(?:id_rsa|id_ed25519)|\.env)/i,
] as const;

interface SourceEvidence {
	readonly path: string;
	readonly line: string;
	readonly lineNumber?: number;
}

export interface CompanionTextFile {
	readonly path: string;
	readonly content: string;
}

async function collectCompanionSourceFiles(dir: string, out: string[]): Promise<void> {
	if (out.length >= MAX_SOURCE_FILES) return;
	const entries = await readdir(dir, { withFileTypes: true });
	for (const entry of entries) {
		if (out.length >= MAX_SOURCE_FILES) break;
		const full = join(dir, entry.name);
		if (entry.isDirectory()) {
			if (DEFAULT_IGNORED_DIRS.has(entry.name)) continue;
			await collectCompanionSourceFiles(full, out);
			continue;
		}
		if (!entry.isFile()) continue;
		const ext = extname(entry.name).toLowerCase();
		if (!TEXT_SOURCE_EXTENSIONS.has(ext)) continue;
		if (entry.name.toLowerCase() === "skill.md" || entry.name.toLowerCase() === "skills.md") continue;
		const fileStat = await stat(full).catch(() => null);
		if (!fileStat?.isFile() || fileStat.size > MAX_FILE_BYTES) continue;
		out.push(full);
	}
}

function findEvidence(text: string, patterns: readonly RegExp[]): SourceEvidence | null {
	const lines = text.split(/\r?\n/);
	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index] ?? "";
		if (!patterns.some((pattern) => pattern.test(line))) continue;
		return { path: "", line: line.trim().slice(0, 240), lineNumber: index + 1 };
	}
	return null;
}

function hasAny(text: string, patterns: readonly RegExp[]): boolean {
	return patterns.some((pattern) => pattern.test(text));
}

function buildEvidence(baseDir: string, filePath: string, evidence: SourceEvidence): string {
	const rel = relative(baseDir, filePath) || filePath;
	return `${rel}:${evidence.lineNumber ?? "?"} ${evidence.line}`.trim();
}

function addFinding(findings: Finding[], finding: Finding): void {
	if (findings.some((existing) => existing.id === finding.id)) return;
	findings.push(finding);
}

function buildCompanionFindings(skill: ParsedSkill, baseDir: string, filePath: string, text: string, index: number): readonly Finding[] {
	const findings: Finding[] = [];
	const secretSource = hasAny(text, SECRET_SOURCE_PATTERNS);
	const networkSink = hasAny(text, NETWORK_PATTERNS);
	const secretToNetwork = hasAny(text, SECRET_TO_NETWORK_PATTERNS);
	const credentialFileRead = hasAny(text, CREDENTIAL_FILE_READ);
	const suspiciousEndpoint = hasAny(text, SUSPICIOUS_ENDPOINT_PATTERNS);
	const logSink = hasAny(text, LOG_PATTERNS);
	const secretEvidence = findEvidence(text, SECRET_SOURCE_PATTERNS) ?? findEvidence(text, CREDENTIAL_FILE_READ);
	const logEvidence = findEvidence(text, LOG_PATTERNS);
	const networkEvidence = findEvidence(text, NETWORK_PATTERNS);
	const documentedSensitive =
		SENSITIVE_DISCLOSURE.test(skill.rawContent) ||
		skill.permissions.some((perm) => /(?:network|env|credential|secret|auth|cookie|session|file_read)/i.test(perm)) ||
		skill.declaredPermissions.some((declared) => /(?:network|credential|secret|auth|cookie|session|file_read)/i.test(`${declared.kind} ${declared.justification}`));

	if (secretSource && logSink && secretEvidence) {
		addFinding(findings, {
			id: `COMP-CODE-SECRET-LOG-${index}`,
			category: "code-safety",
			severity: "critical",
			title: "Companion code logs secrets to stdout",
			description:
				"A companion source file appears to read credentials or environment secrets and print them to stdout/log output. Agent frameworks commonly capture stdout into context, which can expose secrets during normal execution without any additional exploit.",
			evidence: buildEvidence(baseDir, filePath, logEvidence ?? secretEvidence),
			lineNumber: (logEvidence ?? secretEvidence).lineNumber,
			deduction: 30,
			recommendation:
				"Remove secret-bearing debug output. Never print environment variables, tokens, cookies, or credential file contents to stdout/stderr during agent execution.",
			owaspCategory: "ASST-05",
		});
	}

	if (secretSource && networkSink && secretEvidence && (credentialFileRead || secretToNetwork)) {
		const isCriticalExfil = credentialFileRead || suspiciousEndpoint;
		addFinding(findings, {
			id: `COMP-CODE-SECRET-EXFIL-${index}`,
			category: "code-safety",
			severity: isCriticalExfil ? "critical" : "high",
			title: credentialFileRead
				? "Companion code reads credential files and sends them over the network"
				: isCriticalExfil
					? "Companion code sends secrets to a suspicious external endpoint"
					: "Companion code combines secret access with outbound network transmission",
			description: credentialFileRead
				? "A companion source file appears to read local credential material (for example ~/.aws/credentials or .env) and transmit it over the network."
				: isCriticalExfil
					? "A companion source file appears to access secrets or environment credentials and send them to a suspicious webhook or explicit exfiltration endpoint."
					: "A companion source file appears to access secrets or environment credentials and send data to a remote endpoint, which is consistent with credential exfiltration.",
			evidence: buildEvidence(baseDir, filePath, networkEvidence ?? secretEvidence),
			lineNumber: (networkEvidence ?? secretEvidence).lineNumber,
			deduction: isCriticalExfil ? 30 : 22,
			recommendation:
				"Remove outbound transmission of secrets and credential material. Keep sensitive tokens and credential files out of request bodies, logs, and webhooks.",
			owaspCategory: isCriticalExfil ? "ASST-02" : "ASST-05",
		});
	}

	if (!documentedSensitive && findings.length > 0) {
		const hasCriticalCompanion = findings.some((finding) => finding.severity === "critical");
		const mismatchEvidence = secretEvidence ?? networkEvidence ?? { path: filePath, line: "companion source file", lineNumber: undefined };
		addFinding(findings, {
			id: `COMP-MISMATCH-${index}`,
			category: "behavioral",
			severity: hasCriticalCompanion ? "critical" : "high",
			title: "Companion code behavior exceeds the skill's documented scope",
			description:
				"The skill's description and instructions do not clearly disclose credential handling or sensitive outbound behavior, but a companion source file contains those behaviors. This creates a trust gap between what the skill says and what the shipped code appears to do.",
			evidence: buildEvidence(baseDir, filePath, mismatchEvidence),
			lineNumber: secretEvidence?.lineNumber ?? networkEvidence?.lineNumber,
			deduction: hasCriticalCompanion ? 18 : 12,
			recommendation:
				"Document sensitive capabilities explicitly, remove undeclared credential/network behavior, and align companion code with the skill's stated purpose before distribution.",
			owaspCategory: "ASST-07",
		});
		addFinding(findings, {
			id: `COMP-PERM-${index}`,
			category: "permissions",
			severity: hasCriticalCompanion ? "critical" : "medium",
			title: credentialFileRead
				? "Companion code implies undeclared credential and file access"
				: "Companion code implies undeclared credential access",
			description: credentialFileRead
				? "A companion source file appears to access credential material and local credential files that are not clearly disclosed by the skill's documented permissions or instructions."
				: "A companion source file appears to access credentials or environment secrets that are not clearly disclosed by the skill's documented permissions or instructions.",
			evidence: buildEvidence(baseDir, filePath, mismatchEvidence),
			lineNumber: mismatchEvidence.lineNumber,
			deduction: hasCriticalCompanion ? 18 : 8,
			recommendation:
				"Declare sensitive companion-code capabilities explicitly and remove credential access that is not essential to the skill's documented purpose.",
			owaspCategory: "ASST-03",
		});
	}

	return findings;
}

export async function findCompanionCodeFindings(skill: ParsedSkill, baseDir: string): Promise<readonly Finding[]> {
	const files: string[] = [];
	await collectCompanionSourceFiles(baseDir, files).catch(() => undefined);
	const findings: Finding[] = [];
	let fileIndex = 1;
	for (const filePath of files) {
		const text = await readFile(filePath, "utf-8").catch(() => null);
		if (!text) continue;
		findings.push(...buildCompanionFindings(skill, baseDir, filePath, text, fileIndex));
		fileIndex += 1;
	}
	return findings;
}

export function findCompanionCodeFindingsInFiles(
	skill: ParsedSkill,
	baseDir: string,
	files: readonly CompanionTextFile[],
): readonly Finding[] {
	const findings: Finding[] = [];
	let fileIndex = 1;
	for (const file of files.slice(0, MAX_SOURCE_FILES)) {
		findings.push(...buildCompanionFindings(skill, baseDir, file.path, file.content, fileIndex));
		fileIndex += 1;
	}
	return findings;
}

function applyFindingsToReport(report: TrustReport, findings: readonly Finding[]): TrustReport {
	if (findings.length === 0) return report;

	const updatedCategories = { ...report.categories };
	for (const finding of findings) {
		const category = updatedCategories[finding.category];
		updatedCategories[finding.category] = {
			...category,
			score: Math.max(0, category.score - finding.deduction),
			findings: [...category.findings, finding],
			summary: `${category.summary} Companion code finding: ${finding.title}.`,
		};
	}

	return aggregateScores(updatedCategories, report.metadata);
}

export async function applyCompanionCodeFindings(
	report: TrustReport,
	skill: ParsedSkill,
	baseDir: string,
): Promise<TrustReport> {
	const findings = await findCompanionCodeFindings(skill, baseDir);
	return applyFindingsToReport(report, findings);
}

export function applyCompanionCodeFindingsInFiles(
	report: TrustReport,
	skill: ParsedSkill,
	baseDir: string,
	files: readonly CompanionTextFile[],
): TrustReport {
	const findings = findCompanionCodeFindingsInFiles(skill, baseDir, files);
	return applyFindingsToReport(report, findings);
}
