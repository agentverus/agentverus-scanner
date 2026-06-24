import type { Finding, ParsedSkill } from "../types.js";
import {
	buildContentContext,
	isInThreatListingContext,
	isInsideCodeBlock,
	isInsideSafetySection,
	isPrecededByNegation,
	isSecurityDefenseSkill,
} from "./context.js";
import { hasSetupHeadingContext } from "../setup-context.js";
import { isKnownInstallerTarget } from "../url-risk.js";
import {
	type CapabilityKind,
	AUTH_STATE_MANAGEMENT_PATTERNS,
	AUTOMATION_EVASION_PATTERNS,
	BROWSER_AUTOMATION_PATTERNS,
	BROWSER_PROFILE_COPY_PATTERNS,
	BROWSER_SESSION_ATTACHMENT_PATTERNS,
	CAPABILITY_LABELS,
	CAPABILITY_ORDER,
	CAPABILITY_SEVERITY,
	CONFIGURATION_OVERRIDE_PATTERNS,
	CONTAINER_RUNTIME_CONTROL_PATTERNS,
	CONTENT_EXTRACTION_PATTERNS,
	COOKIE_URL_HANDOFF_PATTERNS,
	CREDENTIAL_FORM_AUTOMATION_PATTERNS,
	CREDENTIAL_HANDOFF_PATTERNS,
	CREDENTIAL_PATTERNS,
	CREDENTIAL_STORAGE_PATTERNS,
	CREDENTIAL_STORE_PERSISTENCE_PATTERNS,
	DOCUMENTATION_INGESTION_PATTERNS,
	ENVIRONMENT_CONFIGURATION_PATTERNS,
	EXEC_PATTERNS,
	EXTERNAL_TOOL_BRIDGE_PATTERNS,
	FILESYSTEM_DISCOVERY_PATTERNS,
	FILE_READ_PATTERNS,
	FILE_WRITE_PATTERNS,
	LOCAL_INPUT_CONTROL_PATTERNS,
	LOCAL_SERVICE_ACCESS_PATTERNS,
	NETWORK_PATTERNS,
	PACKAGE_BOOTSTRAP_PATTERNS,
	PAYMENT_PROCESSING_PATTERNS,
	PROCESS_ORCHESTRATION_PATTERNS,
	PROMPT_FILE_INGESTION_PATTERNS,
	REMOTE_DELEGATION_PATTERNS,
	REMOTE_TASK_MANAGEMENT_PATTERNS,
	SERVER_EXPOSURE_PATTERNS,
	SESSION_MANAGEMENT_PATTERNS,
	SYSTEM_MOD_PATTERNS,
	UI_STATE_ACCESS_PATTERNS,
	UNRESTRICTED_SCOPE_PATTERNS,
} from "./capability-contract-config.js";

function tokenizeLower(input: string): string[] {
	return input
		.toLowerCase()
		.split(/[^a-z0-9]{1,512}/g)
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
	if (hasAny(["credential_handoff", "cookie_bootstrap", "browser_cookie"])) {
		return "credential_handoff";
	}
	if (hasAny(["credential_storage", "vault", "auth_cookies"])) {
		return "credential_storage";
	}
	if (hasAny(["auth_state_management", "auth_state", "cookie_state"])) {
		return "auth_state_management";
	}
	if (hasAny(["configuration_override", "extend_md", "preferences_file"])) {
		return "configuration_override";
	}
	if (hasAny(["credential_form", "password_form", "login_form"])) {
		return "credential_form_automation";
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
	if (
		tokens.includes("file_read") ||
		tokens.includes("read") ||
		(tokens.includes("file") && hasAny(["read", "open", "load"]))
	) {
		return "file_read";
	}
	if (hasAny(["filesystem_discovery", "path_discovery", "basedir"])) {
		return "filesystem_discovery";
	}
	if (hasAny(["network", "http", "https", "fetch", "url", "webhook", "api"])) {
		return "network";
	}
	if (hasAny(["browser", "playwright", "cdp", "chromium", "chrome", "webapp", "snapshot"])) {
		return "browser_automation";
	}
	if (hasAny(["browser_session_attachment", "cdp_attach", "profile_sync"])) {
		return "browser_session_attachment";
	}
	if (hasAny(["remote_delegation", "remote_task", "cloud_browser", "streamable_http"])) {
		return "remote_delegation";
	}
	if (hasAny(["remote_task_management", "task_status", "async_runner"])) {
		return "remote_task_management";
	}
	if (hasAny(["server_exposure", "mcp_server", "mcp_endpoint"])) {
		return "server_exposure";
	}
	if (hasAny(["local_service_access", "localhost", "loopback", "port_probe"])) {
		return "local_service_access";
	}
	if (hasAny(["session", "session_name", "profile", "state", "cookie_store"])) {
		return "session_management";
	}
	if (hasAny(["extract", "scrape", "screenshot", "html", "text", "dom"])) {
		return "content_extraction";
	}
	if (hasAny(["documentation_ingestion", "webfetch", "remote_docs"])) {
		return "documentation_ingestion";
	}
	if (hasAny(["local_input_control", "clipboard", "paste_keystroke"])) {
		return "local_input_control";
	}
	if (hasAny(["external_tool_bridge", "tool_bridge", "mcp_integration"])) {
		return "external_tool_bridge";
	}
	if (hasAny(["package_bootstrap", "npx", "bunx", "pnpm_dlx"])) {
		return "package_bootstrap";
	}
	if (hasAny(["environment_configuration", "env_var", "encryption_key"])) {
		return "environment_configuration";
	}
	if (hasAny(["payment_processing", "payments", "premium_actions"])) {
		return "payment_processing";
	}
	if (hasAny(["unrestricted_scope", "no_restrictions", "proactive"])) {
		return "unrestricted_scope";
	}
	if (hasAny(["orchestration", "orchestrate", "server_lifecycle", "docker_control"])) {
		return "process_orchestration";
	}
	if (hasAny(["ui_state", "snapshot", "selector", "dom_snapshot"])) {
		return "ui_state_access";
	}

	return null;
}

function isInsideInlineCode(content: string, matchIndex: number): boolean {
	let lineStart = content.lastIndexOf("\n", matchIndex - 1) + 1;
	if (lineStart < 0) lineStart = 0;
	let lineEnd = content.indexOf("\n", matchIndex);
	if (lineEnd < 0) lineEnd = content.length;
	const line = content.slice(lineStart, lineEnd);
	const rel = matchIndex - lineStart;
	const open = line.lastIndexOf("`", rel);
	if (open < 0) return false;
	const close = line.indexOf("`", open + 1);
	return close >= rel;
}

/** Check if a match is a known-installer curl|sh in a setup/prerequisites section */
function isKnownInstallerInSetupSection(content: string, matchIndex: number, matchText: string): boolean {
	// Must be a curl|sh pattern with a known installer domain
	if (!/\b(?:curl|wget)\b/i.test(matchText)) return false;
	if (!isKnownInstallerTarget(matchText)) return false;

	// Must be under a setup/prerequisites heading
	return hasSetupHeadingContext(content, matchIndex);
}

function firstPositiveMatch(
	content: string,
	patterns: readonly RegExp[],
	_isDefenseSkill: boolean,
	allowCodeBlocks = false,
): string | null {
	const ctx = buildContentContext(content);

	for (const pattern of patterns) {
		const global = new RegExp(pattern.source, `${pattern.flags.replace("g", "")}g`);
		let match: RegExpExecArray | null;
		while ((match = global.exec(content)) !== null) {
			if (isPrecededByNegation(content, match.index)) continue;
			if (
				isInsideCodeBlock(match.index, ctx) &&
				!isInsideInlineCode(content, match.index) &&
				!allowCodeBlocks
			) {
				continue;
			}
			// Skip matches in threat-listing contexts for defense/educational skills —
			// these describe patterns being detected/blocked, not patterns the skill uses.
			if (_isDefenseSkill && isInThreatListingContext(content, match.index)) continue;
			// Skip matches inside safety boundary sections — these describe what the
			// skill must NOT do, not capabilities it has.
			if (isInsideSafetySection(match.index, ctx)) continue;
			// Skip known-installer curl|sh in setup/prerequisites sections — these
			// are legitimate installation instructions, not arbitrary exec.
			if (isInsideCodeBlock(match.index, ctx) && isKnownInstallerInSetupSection(content, match.index, match[0])) {
				continue;
			}
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

/**
 * Declarative table driving content-based capability inference. Order is
 * significant: `add` is first-wins, and `network` is also inferred from a bare
 * URL reference *after* this table runs (so a NETWORK_PATTERNS match here takes
 * precedence over the URL fallback). `allowCodeBlocks` mirrors the per-rule 4th
 * argument the previous hand-written calls passed to `firstPositiveMatch`.
 */
const CONTENT_INFERENCE_RULES: ReadonlyArray<{
	readonly capability: CapabilityKind;
	readonly patterns: readonly RegExp[];
	readonly allowCodeBlocks: boolean;
}> = [
	{ capability: "credential_access", patterns: CREDENTIAL_PATTERNS, allowCodeBlocks: false },
	{ capability: "credential_handoff", patterns: CREDENTIAL_HANDOFF_PATTERNS, allowCodeBlocks: true },
	{ capability: "credential_storage", patterns: CREDENTIAL_STORAGE_PATTERNS, allowCodeBlocks: false },
	{ capability: "auth_state_management", patterns: AUTH_STATE_MANAGEMENT_PATTERNS, allowCodeBlocks: true },
	{ capability: "exec", patterns: EXEC_PATTERNS, allowCodeBlocks: true },
	{ capability: "system_modification", patterns: SYSTEM_MOD_PATTERNS, allowCodeBlocks: false },
	{ capability: "file_write", patterns: FILE_WRITE_PATTERNS, allowCodeBlocks: true },
	{ capability: "file_read", patterns: FILE_READ_PATTERNS, allowCodeBlocks: false },
	{ capability: "filesystem_discovery", patterns: FILESYSTEM_DISCOVERY_PATTERNS, allowCodeBlocks: false },
	{ capability: "configuration_override", patterns: CONFIGURATION_OVERRIDE_PATTERNS, allowCodeBlocks: true },
	{ capability: "network", patterns: NETWORK_PATTERNS, allowCodeBlocks: true },
	{ capability: "browser_automation", patterns: BROWSER_AUTOMATION_PATTERNS, allowCodeBlocks: false },
	{ capability: "browser_session_attachment", patterns: BROWSER_SESSION_ATTACHMENT_PATTERNS, allowCodeBlocks: true },
	{ capability: "browser_profile_copy", patterns: BROWSER_PROFILE_COPY_PATTERNS, allowCodeBlocks: true },
	{ capability: "session_management", patterns: SESSION_MANAGEMENT_PATTERNS, allowCodeBlocks: false },
	{ capability: "content_extraction", patterns: CONTENT_EXTRACTION_PATTERNS, allowCodeBlocks: false },
	{ capability: "documentation_ingestion", patterns: DOCUMENTATION_INGESTION_PATTERNS, allowCodeBlocks: true },
	{ capability: "local_input_control", patterns: LOCAL_INPUT_CONTROL_PATTERNS, allowCodeBlocks: true },
	{ capability: "prompt_file_ingestion", patterns: PROMPT_FILE_INGESTION_PATTERNS, allowCodeBlocks: true },
	{ capability: "automation_evasion", patterns: AUTOMATION_EVASION_PATTERNS, allowCodeBlocks: true },
	{ capability: "external_tool_bridge", patterns: EXTERNAL_TOOL_BRIDGE_PATTERNS, allowCodeBlocks: true },
	{ capability: "package_bootstrap", patterns: PACKAGE_BOOTSTRAP_PATTERNS, allowCodeBlocks: true },
	{ capability: "cookie_url_handoff", patterns: COOKIE_URL_HANDOFF_PATTERNS, allowCodeBlocks: true },
	{ capability: "credential_store_persistence", patterns: CREDENTIAL_STORE_PERSISTENCE_PATTERNS, allowCodeBlocks: true },
	{ capability: "container_runtime_control", patterns: CONTAINER_RUNTIME_CONTROL_PATTERNS, allowCodeBlocks: true },
	{ capability: "environment_configuration", patterns: ENVIRONMENT_CONFIGURATION_PATTERNS, allowCodeBlocks: true },
	{ capability: "payment_processing", patterns: PAYMENT_PROCESSING_PATTERNS, allowCodeBlocks: false },
	{ capability: "unrestricted_scope", patterns: UNRESTRICTED_SCOPE_PATTERNS, allowCodeBlocks: false },
	{ capability: "credential_form_automation", patterns: CREDENTIAL_FORM_AUTOMATION_PATTERNS, allowCodeBlocks: false },
	{ capability: "remote_delegation", patterns: REMOTE_DELEGATION_PATTERNS, allowCodeBlocks: false },
	{ capability: "remote_task_management", patterns: REMOTE_TASK_MANAGEMENT_PATTERNS, allowCodeBlocks: true },
	{ capability: "server_exposure", patterns: SERVER_EXPOSURE_PATTERNS, allowCodeBlocks: true },
	{ capability: "local_service_access", patterns: LOCAL_SERVICE_ACCESS_PATTERNS, allowCodeBlocks: true },
	{ capability: "process_orchestration", patterns: PROCESS_ORCHESTRATION_PATTERNS, allowCodeBlocks: false },
	{ capability: "ui_state_access", patterns: UI_STATE_ACCESS_PATTERNS, allowCodeBlocks: false },
];

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

	for (const rule of CONTENT_INFERENCE_RULES) {
		const match = firstPositiveMatch(
			skill.rawContent,
			rule.patterns,
			isDefenseSkill,
			rule.allowCodeBlocks,
		);
		if (match) add(rule.capability, `Content pattern: ${match}`);
	}

	if (!inferred.has("network") && !isDefenseSkill) {
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
				capability === "credential_access" || capability === "credential_handoff" || capability === "credential_storage" || capability === "auth_state_management" || capability === "credential_form_automation"
					? "ASST-05"
					: capability === "network"
						? "ASST-04"
						: capability === "content_extraction" || capability === "remote_delegation" || capability === "remote_task_management"
							? "ASST-02"
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
				"Use canonical capability names (credential_access, credential_handoff, credential_storage, auth_state_management, credential_form_automation, exec, system_modification, container_runtime_control, file_write, file_read, filesystem_discovery, configuration_override, network, browser_automation, browser_session_attachment, session_management, content_extraction, documentation_ingestion, local_input_control, external_tool_bridge, package_bootstrap, environment_configuration, payment_processing, unrestricted_scope, remote_delegation, remote_task_management, server_exposure, local_service_access, process_orchestration, ui_state_access) or add framework mapping support.",
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
