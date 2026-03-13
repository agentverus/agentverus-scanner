import type { Finding, ParsedSkill } from "../types.js";
import {
	buildContentContext,
	isInThreatListingContext,
	isInsideCodeBlock,
	isPrecededByNegation,
	isSecurityDefenseSkill,
} from "./context.js";

type CapabilityKind =
	| "credential_access"
	| "exec"
	| "system_modification"
	| "file_write"
	| "network";

const CAPABILITY_ORDER: readonly CapabilityKind[] = [
	"credential_access",
	"exec",
	"system_modification",
	"file_write",
	"network",
] as const;

const CAPABILITY_LABELS: Readonly<Record<CapabilityKind, string>> = {
	credential_access: "credential access",
	exec: "command execution",
	system_modification: "system modification",
	file_write: "file write",
	network: "network access",
};

const CAPABILITY_SEVERITY: Readonly<
	Record<CapabilityKind, { readonly severity: "high" | "medium"; readonly deduction: number }>
> = {
	credential_access: { severity: "high", deduction: 15 },
	exec: { severity: "high", deduction: 12 },
	system_modification: { severity: "high", deduction: 12 },
	file_write: { severity: "medium", deduction: 8 },
	network: { severity: "medium", deduction: 6 },
};

const CREDENTIAL_PATTERNS: readonly RegExp[] = [
	/(?:read|reads|access|get|cat|dump|exfiltrate|steal|harvest)\s+.{0,140}(?:\.env|\.ssh|id_rsa|id_ed25519|credentials?|secrets?|api[_-]?key|access[_-]?token|password)/i,
	/~\/\.ssh\/(?:id_rsa|id_ed25519|authorized_keys|config)\b/i,
	/(?:api[_-]?key|access[_-]?token|private[_-]?key|secret(?:s)?|password)\b.{0,80}\b(?:read|dump|exfiltrate|steal|harvest)/i,
	/(?:auth(?:entication)?\s+cookie|http-?only\s+cookie|session\s+tokens?\s+in\s+plaintext|cookies?\s+(?:export|import|get|set|clear)\b|state\s+(?:save|load)\s+\S*auth\.json|profile\s+sync\b|actual\s+Chrome\s+profile|real\s+Chrome\s+with\s+your\s+login\s+sessions|connect\s+to\s+the\s+user'?s\s+running\s+Chrome)/i,
	/(?:--auto-connect\b|--cdp\b|get\s+cdp-url|remote-debugging-port|browser\s+session\s+is\s+authenticated|cookies?\s+and\s+localStorage)/i,
] as const;

const EXEC_PATTERNS: readonly RegExp[] = [
	/\b(?:exec(?:ute)?|shell|spawn(?:ing)?|sub-?process|child_process|run\s+(?:bash|sh|zsh|cmd|powershell|python|node)|eval\s*\()/i,
	/\b(?:curl|wget)\b.{0,80}\|\s*(?:bash|sh|zsh|python)\b/i,
] as const;

const SYSTEM_MOD_PATTERNS: readonly RegExp[] = [
	/\b(?:sudo|systemctl|crontab|modprobe|insmod|rmmod|iptables|ufw|chown|chmod)\b/i,
	/\b(?:install\s+(?:packages?\s+)?globally|global\s+install|modify\s+system(?:\s+configuration)?|\/etc\/|\/usr\/|\/sys\/|\/proc\/)\b/i,
] as const;

const FILE_WRITE_PATTERNS: readonly RegExp[] = [
	/\b(?:file_write|write|writes|written|save|saves|store|stores|persist|append|create)\b.{0,80}\b(?:file|files|disk|workspace|directory|output)\b/i,
	/\b(?:write|save|store|persist)\b.{0,40}\b(?:database|cache|state)\b/i,
] as const;

const NETWORK_PATTERNS: readonly RegExp[] = [
	/https?:\/\/[^\s`"'<>()[\]{}]+/i,
	/\b(?:fetch|curl|wget|webhook|network_unrestricted|network_restricted|api\s+(?:endpoint|request)|post\s+to\s+https?:\/\/)\b/i,
] as const;

function tokenizeLower(input: string): string[] {
	return input
		.toLowerCase()
		.split(/[^a-z0-9]+/g)
		.map((t) => t.trim())
		.filter(Boolean);
}

function normalizeCapability(rawKind: string): CapabilityKind | null {
	const tokens = tokenizeLower(rawKind);
	if (tokens.length === 0) return null;

	const hasAny = (values: readonly string[]): boolean => values.some((v) => tokens.includes(v));

	if (hasAny(["credential", "credentials", "secret", "secrets", "token", "password", "env_access"])) {
		return "credential_access";
	}
	if (hasAny(["exec", "execute", "shell", "command", "spawn", "process"])) {
		return "exec";
	}
	if (hasAny(["system_modification", "system", "sudo", "admin", "root"])) {
		return "system_modification";
	}
	if (
		tokens.includes("file_write") ||
		(tokens.includes("file") &&
			hasAny(["write", "modify", "delete", "append", "create", "persist", "save", "store"]))
	) {
		return "file_write";
	}
	if (hasAny(["network", "http", "https", "fetch", "url", "webhook", "api"])) {
		return "network";
	}

	return null;
}

function firstPositiveMatch(
	content: string,
	patterns: readonly RegExp[],
	isDefenseSkill: boolean,
): string | null {
	const ctx = buildContentContext(content);

	for (const pattern of patterns) {
		const global = new RegExp(pattern.source, `${pattern.flags.replace("g", "")}g`);
		let match: RegExpExecArray | null;
		while ((match = global.exec(content)) !== null) {
			if (isPrecededByNegation(content, match.index)) continue;
			if (isInsideCodeBlock(match.index, ctx)) continue;
			if (isDefenseSkill && isInThreatListingContext(content, match.index)) continue;
			return (match[0] ?? "").trim().slice(0, 180);
		}
	}

	return null;
}

function collectDeclaredCapabilities(skill: ParsedSkill): {
	readonly declaredCapabilities: ReadonlySet<CapabilityKind>;
	readonly unknownDeclaredKinds: readonly string[];
	readonly explicitDeclared: ReadonlyMap<string, CapabilityKind>;
} {
	const declared = new Set<CapabilityKind>();
	const unknownKinds = new Set<string>();
	const explicitDeclared = new Map<string, CapabilityKind>();

	// Explicit declaration objects from frontmatter mapping:
	// permissions:
	//   - network: "justification"
	for (const p of skill.declaredPermissions) {
		const mapped = normalizeCapability(p.kind);
		if (!mapped) {
			unknownKinds.add(p.kind);
			continue;
		}
		declared.add(mapped);
		explicitDeclared.set(p.kind, mapped);
	}

	// Framework-style permission lists are also declaration signals.
	for (const perm of skill.permissions) {
		const mapped = normalizeCapability(perm);
		if (mapped) declared.add(mapped);
	}

	return {
		declaredCapabilities: declared,
		unknownDeclaredKinds: [...unknownKinds].sort((a, b) => a.localeCompare(b)),
		explicitDeclared,
	};
}

function inferCapabilities(skill: ParsedSkill): ReadonlyMap<CapabilityKind, string> {
	const inferred = new Map<CapabilityKind, string>();
	const isDefenseSkill = isSecurityDefenseSkill(skill);

	const add = (kind: CapabilityKind, evidence: string): void => {
		if (!inferred.has(kind)) inferred.set(kind, evidence);
	};

	for (const perm of skill.permissions) {
		const mapped = normalizeCapability(perm);
		if (mapped) add(mapped, `Permission: ${perm}`);
	}

	for (const tool of skill.tools) {
		const mapped = normalizeCapability(tool);
		if (mapped) add(mapped, `Tool: ${tool}`);
	}

	const credentialMatch = firstPositiveMatch(skill.rawContent, CREDENTIAL_PATTERNS, isDefenseSkill);
	if (credentialMatch) add("credential_access", `Content pattern: ${credentialMatch}`);

	const execMatch = firstPositiveMatch(skill.rawContent, EXEC_PATTERNS, isDefenseSkill);
	if (execMatch) add("exec", `Content pattern: ${execMatch}`);

	const systemMatch = firstPositiveMatch(skill.rawContent, SYSTEM_MOD_PATTERNS, isDefenseSkill);
	if (systemMatch) add("system_modification", `Content pattern: ${systemMatch}`);

	const fileWriteMatch = firstPositiveMatch(skill.rawContent, FILE_WRITE_PATTERNS, isDefenseSkill);
	if (fileWriteMatch) add("file_write", `Content pattern: ${fileWriteMatch}`);

	const networkMatch = firstPositiveMatch(skill.rawContent, NETWORK_PATTERNS, isDefenseSkill);
	if (networkMatch) add("network", `Content pattern: ${networkMatch}`);

	if (!inferred.has("network")) {
		const firstUrl = skill.urls[0];
		if (firstUrl) add("network", `URL reference: ${firstUrl}`);
	}

	return inferred;
}

export function analyzeCapabilityContract(skill: ParsedSkill): Finding[] {
	const findings: Finding[] = [];
	const { declaredCapabilities, unknownDeclaredKinds, explicitDeclared } =
		collectDeclaredCapabilities(skill);
	const inferred = inferCapabilities(skill);

	let missingIndex = 1;
	for (const capability of CAPABILITY_ORDER) {
		if (!inferred.has(capability)) continue;
		if (declaredCapabilities.has(capability)) continue;

		const sev = CAPABILITY_SEVERITY[capability];
		findings.push({
			id: `PERM-CONTRACT-MISSING-${missingIndex}`,
			category: "permissions",
			severity: sev.severity,
			title: `Capability contract mismatch: inferred ${CAPABILITY_LABELS[capability]} is not declared`,
			description:
				"The scanner inferred a risky capability from the skill content/metadata, but no matching declaration was found. Add a declaration with a clear justification, or remove the behavior.",
			evidence: inferred.get(capability) ?? CAPABILITY_LABELS[capability],
			deduction: sev.deduction,
			recommendation:
				"Declare this capability explicitly in frontmatter permissions with a specific justification, or remove the risky behavior.",
			owaspCategory:
				capability === "credential_access"
					? "ASST-05"
					: capability === "network"
						? "ASST-04"
						: "ASST-03",
		});
		missingIndex += 1;
	}

	for (let i = 0; i < unknownDeclaredKinds.length; i += 1) {
		const raw = unknownDeclaredKinds[i];
		findings.push({
			id: `PERM-CONTRACT-UNKNOWN-${i + 1}`,
			category: "permissions",
			severity: "info",
			title: `Unknown capability declaration kind: ${raw}`,
			description:
				"The declaration kind does not map to a known canonical capability. This may be framework-specific, but it weakens contract matching.",
			evidence: `Declaration kind: ${raw}`,
			deduction: 0,
			recommendation:
				"Use canonical capability names (credential_access, exec, system_modification, file_write, network) or add framework mapping support.",
			owaspCategory: "ASST-08",
		});
	}

	let unusedIndex = 1;
	for (const [rawKind, canonical] of explicitDeclared.entries()) {
		if (inferred.has(canonical)) continue;
		findings.push({
			id: `PERM-CONTRACT-UNUSED-${unusedIndex}`,
			category: "permissions",
			severity: "info",
			title: `Declared capability not inferred: ${CAPABILITY_LABELS[canonical]}`,
			description:
				"The skill declares this capability, but the scanner did not infer supporting behavior. Keep declarations tight to reduce reviewer confusion.",
			evidence: `Declaration kind: ${rawKind}`,
			deduction: 0,
			recommendation:
				"Remove stale declarations or add clear instructions showing where this capability is used.",
			owaspCategory: "ASST-08",
		});
		unusedIndex += 1;
	}

	return findings;
}
