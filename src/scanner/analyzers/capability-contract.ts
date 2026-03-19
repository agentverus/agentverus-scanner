import type { Finding, ParsedSkill } from "../types.js";
import {
	buildContentContext,
	isInThreatListingContext,
	isInsideCodeBlock,
	isInsideSafetySection,
	isPrecededByNegation,
	isSecurityDefenseSkill,
} from "./context.js";
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

/** Well-known installer domains where curl|sh is expected and lower risk */
const KNOWN_INSTALLER_DOMAINS =
	/(?:deno\.land|bun\.sh|rustup\.rs|get\.docker\.com|install\.python-poetry\.org|nvm-sh|golangci|foundry\.paradigm\.xyz|tailscale\.com|opencode\.ai|sh\.rustup\.rs|get\.pnpm\.io|volta\.sh)/i;

/** Check if a match is a known-installer curl|sh in a setup/prerequisites section */
function isKnownInstallerInSetupSection(content: string, matchIndex: number, matchText: string): boolean {
	// Must be a curl|sh pattern with a known installer domain
	if (!/\b(?:curl|wget)\b/i.test(matchText)) return false;
	if (!KNOWN_INSTALLER_DOMAINS.test(matchText)) return false;

	// Must be under a setup/prerequisites heading
	const preceding = content.slice(Math.max(0, matchIndex - 1000), matchIndex);
	const headings = preceding.match(/^#{1,4}\s+.+$/gm);
	if (!headings || headings.length === 0) return false;
	const lastHeading = headings[headings.length - 1]!.toLowerCase();
	return /\b(?:prerequisit(?:es?)?|install|setup|getting\s+started|requirements?|dependencies)\b/.test(lastHeading);
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

	const credentialHandoffMatch = firstPositiveMatch(
		skill.rawContent,
		CREDENTIAL_HANDOFF_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (credentialHandoffMatch) {
		add("credential_handoff", `Content pattern: ${credentialHandoffMatch}`);
	}

	const credentialStorageMatch = firstPositiveMatch(
		skill.rawContent,
		CREDENTIAL_STORAGE_PATTERNS,
		isDefenseSkill,
	);
	if (credentialStorageMatch) {
		add("credential_storage", `Content pattern: ${credentialStorageMatch}`);
	}

	const authStateManagementMatch = firstPositiveMatch(
		skill.rawContent,
		AUTH_STATE_MANAGEMENT_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (authStateManagementMatch) {
		add("auth_state_management", `Content pattern: ${authStateManagementMatch}`);
	}

	const execMatch = firstPositiveMatch(
		skill.rawContent,
		EXEC_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (execMatch) add("exec", `Content pattern: ${execMatch}`);

	const systemMatch = firstPositiveMatch(skill.rawContent, SYSTEM_MOD_PATTERNS, isDefenseSkill);
	if (systemMatch) add("system_modification", `Content pattern: ${systemMatch}`);

	const fileWriteMatch = firstPositiveMatch(
		skill.rawContent,
		FILE_WRITE_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (fileWriteMatch) add("file_write", `Content pattern: ${fileWriteMatch}`);

	const fileReadMatch = firstPositiveMatch(skill.rawContent, FILE_READ_PATTERNS, isDefenseSkill);
	if (fileReadMatch) add("file_read", `Content pattern: ${fileReadMatch}`);

	const filesystemDiscoveryMatch = firstPositiveMatch(
		skill.rawContent,
		FILESYSTEM_DISCOVERY_PATTERNS,
		isDefenseSkill,
	);
	if (filesystemDiscoveryMatch) {
		add("filesystem_discovery", `Content pattern: ${filesystemDiscoveryMatch}`);
	}

	const configurationOverrideMatch = firstPositiveMatch(
		skill.rawContent,
		CONFIGURATION_OVERRIDE_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (configurationOverrideMatch) {
		add("configuration_override", `Content pattern: ${configurationOverrideMatch}`);
	}

	const networkMatch = firstPositiveMatch(
		skill.rawContent,
		NETWORK_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (networkMatch) add("network", `Content pattern: ${networkMatch}`);

	const browserAutomationMatch = firstPositiveMatch(
		skill.rawContent,
		BROWSER_AUTOMATION_PATTERNS,
		isDefenseSkill,
	);
	if (browserAutomationMatch) {
		add("browser_automation", `Content pattern: ${browserAutomationMatch}`);
	}

	const browserSessionAttachmentMatch = firstPositiveMatch(
		skill.rawContent,
		BROWSER_SESSION_ATTACHMENT_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (browserSessionAttachmentMatch) {
		add("browser_session_attachment", `Content pattern: ${browserSessionAttachmentMatch}`);
	}

	const browserProfileCopyMatch = firstPositiveMatch(
		skill.rawContent,
		BROWSER_PROFILE_COPY_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (browserProfileCopyMatch) {
		add("browser_profile_copy", `Content pattern: ${browserProfileCopyMatch}`);
	}

	const sessionManagementMatch = firstPositiveMatch(
		skill.rawContent,
		SESSION_MANAGEMENT_PATTERNS,
		isDefenseSkill,
	);
	if (sessionManagementMatch) {
		add("session_management", `Content pattern: ${sessionManagementMatch}`);
	}

	const contentExtractionMatch = firstPositiveMatch(
		skill.rawContent,
		CONTENT_EXTRACTION_PATTERNS,
		isDefenseSkill,
	);
	if (contentExtractionMatch) {
		add("content_extraction", `Content pattern: ${contentExtractionMatch}`);
	}

	const documentationIngestionMatch = firstPositiveMatch(
		skill.rawContent,
		DOCUMENTATION_INGESTION_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (documentationIngestionMatch) {
		add("documentation_ingestion", `Content pattern: ${documentationIngestionMatch}`);
	}

	const localInputControlMatch = firstPositiveMatch(
		skill.rawContent,
		LOCAL_INPUT_CONTROL_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (localInputControlMatch) {
		add("local_input_control", `Content pattern: ${localInputControlMatch}`);
	}

	const promptFileIngestionMatch = firstPositiveMatch(
		skill.rawContent,
		PROMPT_FILE_INGESTION_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (promptFileIngestionMatch) {
		add("prompt_file_ingestion", `Content pattern: ${promptFileIngestionMatch}`);
	}

	const automationEvasionMatch = firstPositiveMatch(
		skill.rawContent,
		AUTOMATION_EVASION_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (automationEvasionMatch) {
		add("automation_evasion", `Content pattern: ${automationEvasionMatch}`);
	}

	const externalToolBridgeMatch = firstPositiveMatch(
		skill.rawContent,
		EXTERNAL_TOOL_BRIDGE_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (externalToolBridgeMatch) {
		add("external_tool_bridge", `Content pattern: ${externalToolBridgeMatch}`);
	}

	const packageBootstrapMatch = firstPositiveMatch(
		skill.rawContent,
		PACKAGE_BOOTSTRAP_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (packageBootstrapMatch) {
		add("package_bootstrap", `Content pattern: ${packageBootstrapMatch}`);
	}

	const cookieUrlHandoffMatch = firstPositiveMatch(
		skill.rawContent,
		COOKIE_URL_HANDOFF_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (cookieUrlHandoffMatch) {
		add("cookie_url_handoff", `Content pattern: ${cookieUrlHandoffMatch}`);
	}

	const credentialStorePersistenceMatch = firstPositiveMatch(
		skill.rawContent,
		CREDENTIAL_STORE_PERSISTENCE_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (credentialStorePersistenceMatch) {
		add("credential_store_persistence", `Content pattern: ${credentialStorePersistenceMatch}`);
	}

	const containerRuntimeControlMatch = firstPositiveMatch(
		skill.rawContent,
		CONTAINER_RUNTIME_CONTROL_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (containerRuntimeControlMatch) {
		add("container_runtime_control", `Content pattern: ${containerRuntimeControlMatch}`);
	}

	const environmentConfigurationMatch = firstPositiveMatch(
		skill.rawContent,
		ENVIRONMENT_CONFIGURATION_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (environmentConfigurationMatch) {
		add("environment_configuration", `Content pattern: ${environmentConfigurationMatch}`);
	}

	const paymentProcessingMatch = firstPositiveMatch(
		skill.rawContent,
		PAYMENT_PROCESSING_PATTERNS,
		isDefenseSkill,
	);
	if (paymentProcessingMatch) {
		add("payment_processing", `Content pattern: ${paymentProcessingMatch}`);
	}

	const unrestrictedScopeMatch = firstPositiveMatch(
		skill.rawContent,
		UNRESTRICTED_SCOPE_PATTERNS,
		isDefenseSkill,
	);
	if (unrestrictedScopeMatch) {
		add("unrestricted_scope", `Content pattern: ${unrestrictedScopeMatch}`);
	}

	const credentialFormAutomationMatch = firstPositiveMatch(
		skill.rawContent,
		CREDENTIAL_FORM_AUTOMATION_PATTERNS,
		isDefenseSkill,
	);
	if (credentialFormAutomationMatch) {
		add("credential_form_automation", `Content pattern: ${credentialFormAutomationMatch}`);
	}

	const remoteDelegationMatch = firstPositiveMatch(
		skill.rawContent,
		REMOTE_DELEGATION_PATTERNS,
		isDefenseSkill,
	);
	if (remoteDelegationMatch) {
		add("remote_delegation", `Content pattern: ${remoteDelegationMatch}`);
	}

	const remoteTaskManagementMatch = firstPositiveMatch(
		skill.rawContent,
		REMOTE_TASK_MANAGEMENT_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (remoteTaskManagementMatch) {
		add("remote_task_management", `Content pattern: ${remoteTaskManagementMatch}`);
	}

	const serverExposureMatch = firstPositiveMatch(
		skill.rawContent,
		SERVER_EXPOSURE_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (serverExposureMatch) {
		add("server_exposure", `Content pattern: ${serverExposureMatch}`);
	}

	const localServiceAccessMatch = firstPositiveMatch(
		skill.rawContent,
		LOCAL_SERVICE_ACCESS_PATTERNS,
		isDefenseSkill,
		true,
	);
	if (localServiceAccessMatch) {
		add("local_service_access", `Content pattern: ${localServiceAccessMatch}`);
	}

	const processOrchestrationMatch = firstPositiveMatch(
		skill.rawContent,
		PROCESS_ORCHESTRATION_PATTERNS,
		isDefenseSkill,
	);
	if (processOrchestrationMatch) {
		add("process_orchestration", `Content pattern: ${processOrchestrationMatch}`);
	}

	const uiStateAccessMatch = firstPositiveMatch(
		skill.rawContent,
		UI_STATE_ACCESS_PATTERNS,
		isDefenseSkill,
	);
	if (uiStateAccessMatch) {
		add("ui_state_access", `Content pattern: ${uiStateAccessMatch}`);
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
