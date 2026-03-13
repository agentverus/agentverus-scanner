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
	| "credential_handoff"
	| "credential_storage"
	| "exec"
	| "system_modification"
	| "file_write"
	| "file_read"
	| "filesystem_discovery"
	| "network"
	| "browser_automation"
	| "session_management"
	| "content_extraction"
	| "remote_delegation"
	| "remote_task_management"
	| "server_exposure"
	| "local_service_access"
	| "process_orchestration"
	| "ui_state_access"
	| "documentation_ingestion"
	| "local_input_control"
	| "credential_form_automation"
	| "package_bootstrap"
	| "environment_configuration"
	| "payment_processing";

const CAPABILITY_ORDER: readonly CapabilityKind[] = [
	"credential_access",
	"credential_handoff",
	"credential_storage",
	"credential_form_automation",
	"exec",
	"system_modification",
	"file_write",
	"file_read",
	"filesystem_discovery",
	"network",
	"browser_automation",
	"session_management",
	"content_extraction",
	"remote_delegation",
	"remote_task_management",
	"server_exposure",
	"local_service_access",
	"process_orchestration",
	"ui_state_access",
	"documentation_ingestion",
	"local_input_control",
	"package_bootstrap",
	"environment_configuration",
	"payment_processing",
] as const;

const CAPABILITY_LABELS: Readonly<Record<CapabilityKind, string>> = {
	credential_access: "credential access",
	credential_handoff: "credential handoff",
	credential_storage: "credential storage",
	credential_form_automation: "credential form automation",
	exec: "command execution",
	system_modification: "system modification",
	file_write: "file write",
	file_read: "file read",
	filesystem_discovery: "filesystem discovery",
	network: "network access",
	browser_automation: "browser automation",
	session_management: "session management",
	content_extraction: "content extraction",
	remote_delegation: "remote delegation",
	remote_task_management: "remote task management",
	server_exposure: "server exposure",
	local_service_access: "local service access",
	process_orchestration: "process orchestration",
	ui_state_access: "UI state access",
	documentation_ingestion: "documentation ingestion",
	local_input_control: "local input control",
	package_bootstrap: "package bootstrap",
	environment_configuration: "environment configuration",
	payment_processing: "payment processing",
};

const CAPABILITY_SEVERITY: Readonly<
	Record<CapabilityKind, { readonly severity: "high" | "medium"; readonly deduction: number }>
> = {
	credential_access: { severity: "high", deduction: 15 },
	credential_handoff: { severity: "high", deduction: 12 },
	credential_storage: { severity: "high", deduction: 12 },
	credential_form_automation: { severity: "medium", deduction: 8 },
	exec: { severity: "high", deduction: 12 },
	system_modification: { severity: "high", deduction: 12 },
	file_write: { severity: "medium", deduction: 8 },
	file_read: { severity: "medium", deduction: 6 },
	filesystem_discovery: { severity: "medium", deduction: 8 },
	network: { severity: "medium", deduction: 6 },
	browser_automation: { severity: "medium", deduction: 8 },
	session_management: { severity: "medium", deduction: 8 },
	content_extraction: { severity: "medium", deduction: 8 },
	remote_delegation: { severity: "medium", deduction: 8 },
	remote_task_management: { severity: "medium", deduction: 8 },
	server_exposure: { severity: "medium", deduction: 8 },
	local_service_access: { severity: "medium", deduction: 8 },
	process_orchestration: { severity: "medium", deduction: 8 },
	ui_state_access: { severity: "medium", deduction: 8 },
	documentation_ingestion: { severity: "medium", deduction: 8 },
	local_input_control: { severity: "medium", deduction: 8 },
	package_bootstrap: { severity: "medium", deduction: 8 },
	environment_configuration: { severity: "medium", deduction: 8 },
	payment_processing: { severity: "medium", deduction: 8 },
};

const CREDENTIAL_PATTERNS: readonly RegExp[] = [
	/(?:read|reads|access|get|cat|dump|exfiltrate|steal|harvest)\s+.{0,140}(?:\.env|\.ssh|id_rsa|id_ed25519|credentials?|secrets?|api[_-]?key|access[_-]?token|password)/i,
	/~\/\.ssh\/(?:id_rsa|id_ed25519|authorized_keys|config)\b/i,
	/(?:api[_-]?key|access[_-]?token|private[_-]?key|secret(?:s)?|password)\b.{0,80}\b(?:read|dump|exfiltrate|steal|harvest)/i,
	/(?:auth(?:entication)?\s+cookie|http-?only\s+cookie|session\s+tokens?\s+in\s+plaintext|cookies?\s+(?:export|import|get|set|clear)\b|state\s+(?:save|load)\s+\S*auth\.json|profile\s+sync\b|actual\s+Chrome\s+profile|real\s+Chrome\s+with\s+your\s+login\s+sessions|connect\s+to\s+the\s+user'?s\s+running\s+Chrome)/i,
	/(?:--auto-connect\b|--cdp\b|get\s+cdp-url|remote-debugging-port|browser\s+session\s+is\s+authenticated|cookies?\s+and\s+localStorage|session\s+saved|already\s+authenticated|default\s+Chrome\s+profile|full\s+profile\s+sync|sync\s+ALL\s+cookies|entire\s+browser\s+state|--secret\s+[^\s=]+=[^\s]+)/i,
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

const FILE_READ_PATTERNS: readonly RegExp[] = [
	/\bread\s+HTML\s+file\s+directly\b/i,
	/\bread\s+the\s+source\b/i,
	/\bReference\s+Files\b/i,
	/\breferences?\//i,
	/\bexamples\//i,
	/--promptfiles\b/i,
	/\bload\s+preferences\b/i,
	/\bEXTEND\.md\b/i,
	/\bSKILL\.md\s+file'?s\s+directory\b/i,
	/\bstatic_html_automation\.py\b/i,
	/\bfile:\/\//i,
] as const;

const FILESYSTEM_DISCOVERY_PATTERNS: readonly RegExp[] = [
	/\{baseDir\}/i,
	/\bcommon\s+installation\s+paths\b/i,
	/\bSKILL\.md\s+file'?s\s+directory\b/i,
	/\bproject\s+structure\s+analysis\b/i,
	/find\s+\.\s+-name\s+"Dockerfile\*"/i,
	/\.dockerignore/i,
	/\.claude\/plugins\/marketplaces\//i,
] as const;

const CREDENTIAL_HANDOFF_PATTERNS: readonly RegExp[] = [
	/\bget\s+authentication\s+cookie\b/i,
	/\bauth\s+cookie\s+via\s+the\s+ATXP\s+tool\b/i,
	/\bagents\s+get\s+an\s+auth\s+cookie\s+via\s+MCP\b/i,
	/\buse\s+that\s+auth\s+state\b/i,
	/\bstate\s+load\s+\.\/auth\.json\b/i,
	/\bconfigure\s+browser\s+cookie\b/i,
	/\bredirect\s+to\s+clean\s+the\s+URL\b/i,
] as const;

const CREDENTIAL_STORAGE_PATTERNS: readonly RegExp[] = [
	/\bauth_cookies\b/i,
	/\bAuth\s+Vault\b/i,
	/cookie-based\s+auth\s+pattern/i,
	/auth(?:entication)?\s+cookie/i,
	/session\s+tokens?\s+in\s+plaintext/i,
	/default\s+Chrome\s+profile/i,
	/persistent\s+profile/i,
	/persistent\s+but\s+empty\s+CLI\s+profile/i,
	/credentials\s+stored\s+encrypted/i,
] as const;

const NETWORK_PATTERNS: readonly RegExp[] = [
	/https?:\/\/[^\s`"'<>()[\]{}]+/i,
	/\b(?:fetch|curl|wget|webhook|network_unrestricted|network_restricted|api\s+(?:endpoint|request)|post\s+to\s+https?:\/\/)\b/i,
] as const;

const BROWSER_AUTOMATION_PATTERNS: readonly RegExp[] = [
	/\bbrowser\s+automation\b/i,
	/\bPlaywright\b/i,
	/\breal\s+Chrome\s+browser\b/i,
	/\bnavigate\s+websites?\b/i,
	/\bbrowse\s+(?:the\s+)?(?:directory|site|entries)\b/i,
	/\bbrowsing\s+agent-oriented\s+websites\b/i,
	/\bvisit\s+your\s+website\b/i,
	/\binteract\s+with\s+web\s+pages?\b/i,
	/\bfill\s+forms?\b/i,
	/\bclick\s+buttons\b/i,
	/\bclick\s+the\s+"?\+1"?\s+button\b/i,
	/\btake\s+screenshots?\b/i,
	/\btest(?:ing)?\s+web\s+apps?\b/i,
] as const;

const REMOTE_DELEGATION_PATTERNS: readonly RegExp[] = [
	/\bcloud-hosted\s+browser\b/i,
	/\bremote\s+task\b/i,
	/\bstreamable\s+HTTP\b/i,
	/\bexternal\s+services\s+through\s+well-?designed\s+tools\b/i,
	/\b(?:OpenAI|Replicate|DashScope|Gemini|Google)\b.{0,80}\b(?:providers?|API-based\s+image\s+generation)\b/i,
] as const;

const REMOTE_TASK_MANAGEMENT_PATTERNS: readonly RegExp[] = [
	/\bremote\s+task\b/i,
	/\btask\s+status\s+<id>\b/i,
	/\basync\s+by\s+default\b/i,
] as const;

const SERVER_EXPOSURE_PATTERNS: readonly RegExp[] = [
	/\bstreamable\s+HTTP\s+for\s+remote\s+servers\b/i,
	/\bMCP\s+Server\b/i,
	/\/mcp\b/i,
	/Call\s+MCP\s+tools\s+via/i,
	/Expose\s+tools\s+that\s+agents\s+can\s+call\s+programmatically/i,
] as const;

const LOCAL_SERVICE_ACCESS_PATTERNS: readonly RegExp[] = [
	/\bhttps?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?/i,
	/\bwith_server\.py\b/i,
	/\bdetectDevServers\s*\(/i,
] as const;

const SESSION_MANAGEMENT_PATTERNS: readonly RegExp[] = [
	/\bbrowser\s+sessions?\s+across\s+commands/i,
	/\bstate\s+(?:save|load)\s+\.\/auth\.json/i,
	/\b--session-name\b/i,
	/\bsession\s+saved\b/i,
	/\balready\s+authenticated\b/i,
	/\bsession\s+list\b/i,
	/\bclose\s+--all\b/i,
	/\bbackground\s+daemon\b/i,
] as const;

const CONTENT_EXTRACTION_PATTERNS: readonly RegExp[] = [
	/\bextract\s+information\s+from\s+web\s+pages?\b/i,
	/\bextract(?:ing)?\s+data\b/i,
	/\bdata\s+extraction\b/i,
	/\bscrape\s+data\s+from\s+a\s+page\b/i,
	/\bget\s+html\b/i,
	/\bget\s+text\b/i,
	/\bpage\.content\(\)/i,
	/\bscreenshot\b/i,
] as const;

const DOCUMENTATION_INGESTION_PATTERNS: readonly RegExp[] = [
	/Use\s+WebFetch\s+to\s+load/i,
	/web\s+search\s+and\s+WebFetch\s+as\s+needed/i,
	/fetch\s+specific\s+pages\s+with\s+`?\.md/i,
	/For\s+more\s+information,\s+see/i,
	/For\s+full\s+.+\s+details:/i,
	/For\s+deeper\s+.+\s+familiarity,\s+see/i,
	/Reference\s+implementation/i,
	/See\s+\[references?\//i,
	/\breferences?\//i,
	/\bReference\s+Files\b/i,
] as const;

const LOCAL_INPUT_CONTROL_PATTERNS: readonly RegExp[] = [
	/copy-to-clipboard/i,
	/paste-from-clipboard/i,
	/paste\s+keystroke/i,
	/keys\s+"Enter"/i,
	/press\s+Enter/i,
	/keyboard\s+type/i,
	/inserttext/i,
	/type\s+"text"/i,
	/type\s+into\s+focused\s+element/i,
	/send\s+keyboard\s+keys/i,
	/click\s+buttons/i,
	/click\s+the\s+"?\+1"?\s+button/i,
	/\bclick\s+@e\d+/i,
	/\bclick\s+<index>/i,
	/\bbrowser-use\s+click\b/i,
] as const;

const CREDENTIAL_FORM_AUTOMATION_PATTERNS: readonly RegExp[] = [
	/input\s+type="password"/i,
	/fill\s+@e\d+\s+"password123"/i,
	/form\s+filling/i,
	/fill\s+out\s+a\s+form/i,
	/fill\s+forms?\b/i,
	/login\s+to\s+a\s+site/i,
	/test\s+login/i,
	/login\s+flow/i,
] as const;

const PACKAGE_BOOTSTRAP_PATTERNS: readonly RegExp[] = [
	/\b(?:npx|pnpm\s+dlx|bunx)\b(?:\s+-y)?\s+[A-Za-z0-9@][^\s`"']+/i,
	/\bnpm\s+install\b(?!\s+(?:-g|--global)\b)/i,
] as const;

const ENVIRONMENT_CONFIGURATION_PATTERNS: readonly RegExp[] = [
	/\bAGENT_BROWSER_ENCRYPTION_KEY\b/i,
	/\bXDG_CONFIG_HOME\b/i,
	/\bX_BROWSER_CHROME_PATH\b/i,
	/\bAGENT_BROWSER_COLOR_SCHEME\b/i,
] as const;

const PAYMENT_PROCESSING_PATTERNS: readonly RegExp[] = [
	/\bCost:\s*\$\d/i,
	/\bCharge\s+for\s+premium\s+actions?\b/i,
	/\bPayments\b/i,
	/\$0\.\d+/i,
] as const;

const PROCESS_ORCHESTRATION_PATTERNS: readonly RegExp[] = [
	/\bwith_server\.py\b/i,
	/\bdocker\s+(?:build|run|exec|stop|info|ps|images|context)\b/i,
	/\bnode\s+run\.js\s+\/tmp\//i,
	/\bnpm\s+run\s+dev\b/i,
	/\bpython\s+your_automation\.py\b/i,
] as const;

const UI_STATE_ACCESS_PATTERNS: readonly RegExp[] = [
	/\bsnapshot\s+-i\b/i,
	/clickable\s+elements?\s+with\s+indices/i,
	/element\s+refs?\s+like\s+@e\d+/i,
	/page\.locator\('button'\)\.all\(\)/i,
	/discovering\s+buttons,\s+links,\s+and\s+inputs/i,
	/identify\s+selectors?\s+from\s+(?:rendered\s+state|inspection\s+results)/i,
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
	if (hasAny(["credential_handoff", "cookie_bootstrap", "browser_cookie"])) {
		return "credential_handoff";
	}
	if (hasAny(["credential_storage", "vault", "auth_cookies"])) {
		return "credential_storage";
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
	if (hasAny(["package_bootstrap", "npx", "bunx", "pnpm_dlx"])) {
		return "package_bootstrap";
	}
	if (hasAny(["environment_configuration", "env_var", "encryption_key"])) {
		return "environment_configuration";
	}
	if (hasAny(["payment_processing", "payments", "premium_actions"])) {
		return "payment_processing";
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

function firstPositiveMatch(
	content: string,
	patterns: readonly RegExp[],
	isDefenseSkill: boolean,
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

	const execMatch = firstPositiveMatch(skill.rawContent, EXEC_PATTERNS, isDefenseSkill);
	if (execMatch) add("exec", `Content pattern: ${execMatch}`);

	const systemMatch = firstPositiveMatch(skill.rawContent, SYSTEM_MOD_PATTERNS, isDefenseSkill);
	if (systemMatch) add("system_modification", `Content pattern: ${systemMatch}`);

	const fileWriteMatch = firstPositiveMatch(skill.rawContent, FILE_WRITE_PATTERNS, isDefenseSkill);
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

	const networkMatch = firstPositiveMatch(skill.rawContent, NETWORK_PATTERNS, isDefenseSkill);
	if (networkMatch) add("network", `Content pattern: ${networkMatch}`);

	const browserAutomationMatch = firstPositiveMatch(
		skill.rawContent,
		BROWSER_AUTOMATION_PATTERNS,
		isDefenseSkill,
	);
	if (browserAutomationMatch) {
		add("browser_automation", `Content pattern: ${browserAutomationMatch}`);
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

	const packageBootstrapMatch = firstPositiveMatch(
		skill.rawContent,
		PACKAGE_BOOTSTRAP_PATTERNS,
		isDefenseSkill,
	);
	if (packageBootstrapMatch) {
		add("package_bootstrap", `Content pattern: ${packageBootstrapMatch}`);
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
	);
	if (serverExposureMatch) {
		add("server_exposure", `Content pattern: ${serverExposureMatch}`);
	}

	const localServiceAccessMatch = firstPositiveMatch(
		skill.rawContent,
		LOCAL_SERVICE_ACCESS_PATTERNS,
		isDefenseSkill,
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
				capability === "credential_access" || capability === "credential_handoff" || capability === "credential_storage" || capability === "credential_form_automation"
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
				"Use canonical capability names (credential_access, credential_handoff, credential_storage, credential_form_automation, exec, system_modification, file_write, file_read, filesystem_discovery, network, browser_automation, session_management, content_extraction, documentation_ingestion, local_input_control, package_bootstrap, environment_configuration, payment_processing, remote_delegation, remote_task_management, server_exposure, local_service_access, process_orchestration, ui_state_access) or add framework mapping support.",
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
