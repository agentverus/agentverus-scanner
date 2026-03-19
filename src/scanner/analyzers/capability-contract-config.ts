export type CapabilityKind =
	| "credential_access"
	| "credential_handoff"
	| "credential_storage"
	| "auth_state_management"
	| "exec"
	| "system_modification"
	| "container_runtime_control"
	| "file_write"
	| "file_read"
	| "filesystem_discovery"
	| "configuration_override"
	| "network"
	| "browser_automation"
	| "browser_session_attachment"
	| "browser_profile_copy"
	| "browser_auth_state_handling"
	| "persistent_session_reuse"
	| "mcp_issued_browser_auth_cookie"
	| "skill_path_discovery"
	| "session_management"
	| "content_extraction"
	| "remote_delegation"
	| "remote_task_management"
	| "server_exposure"
	| "external_tool_bridge"
	| "local_service_access"
	| "process_orchestration"
	| "ui_state_access"
	| "documentation_ingestion"
	| "local_input_control"
	| "credential_form_automation"
	| "package_bootstrap"
	| "environment_configuration"
	| "payment_processing"
	| "unrestricted_scope"
	| "cookie_url_handoff"
	| "credential_store_persistence"
	| "external_instruction_override"
	| "prompt_file_ingestion"
	| "automation_evasion";

export const CAPABILITY_ORDER: readonly CapabilityKind[] = [
	"credential_access",
	"credential_handoff",
	"credential_storage",
	"auth_state_management",
	"credential_form_automation",
	"exec",
	"system_modification",
	"container_runtime_control",
	"file_write",
	"file_read",
	"filesystem_discovery",
	"configuration_override",
	"network",
	"browser_automation",
	"browser_session_attachment",
	"browser_profile_copy",
	"browser_auth_state_handling",
	"persistent_session_reuse",
	"mcp_issued_browser_auth_cookie",
	"skill_path_discovery",
	"session_management",
	"content_extraction",
	"remote_delegation",
	"remote_task_management",
	"server_exposure",
	"external_tool_bridge",
	"local_service_access",
	"process_orchestration",
	"ui_state_access",
	"documentation_ingestion",
	"local_input_control",
	"package_bootstrap",
	"environment_configuration",
	"payment_processing",
	"unrestricted_scope",
	"cookie_url_handoff",
	"credential_store_persistence",
	"external_instruction_override",
	"prompt_file_ingestion",
	"automation_evasion",
] as const;

export const CAPABILITY_LABELS: Readonly<Record<CapabilityKind, string>> = {
	credential_access: "credential access",
	credential_handoff: "credential handoff",
	credential_storage: "credential storage",
	auth_state_management: "auth state management",
	credential_form_automation: "credential form automation",
	exec: "command execution",
	system_modification: "system modification",
	container_runtime_control: "container runtime control",
	file_write: "file write",
	file_read: "file read",
	filesystem_discovery: "filesystem discovery",
	configuration_override: "configuration override",
	network: "network access",
	browser_automation: "browser automation",
	browser_session_attachment: "browser session attachment",
	browser_profile_copy: "browser profile copy",
	browser_auth_state_handling: "browser auth state handling",
	persistent_session_reuse: "persistent session reuse",
	mcp_issued_browser_auth_cookie: "MCP-issued browser auth cookie",
	skill_path_discovery: "skill path discovery",
	session_management: "session management",
	content_extraction: "content extraction",
	remote_delegation: "remote delegation",
	remote_task_management: "remote task management",
	server_exposure: "server exposure",
	external_tool_bridge: "external tool bridge",
	local_service_access: "local service access",
	process_orchestration: "process orchestration",
	ui_state_access: "UI state access",
	documentation_ingestion: "documentation ingestion",
	local_input_control: "local input control",
	package_bootstrap: "package bootstrap",
	environment_configuration: "environment configuration",
	payment_processing: "payment processing",
	unrestricted_scope: "unrestricted scope",
	cookie_url_handoff: "cookie URL handoff",
	credential_store_persistence: "credential store persistence",
	external_instruction_override: "external instruction override",
	prompt_file_ingestion: "prompt file ingestion",
	automation_evasion: "automation evasion",
};

export const CAPABILITY_SEVERITY: Readonly<
	Record<CapabilityKind, { readonly severity: "high" | "medium"; readonly deduction: number }>
> = {
	credential_access: { severity: "high", deduction: 15 },
	credential_handoff: { severity: "high", deduction: 12 },
	credential_storage: { severity: "high", deduction: 12 },
	auth_state_management: { severity: "high", deduction: 12 },
	credential_form_automation: { severity: "medium", deduction: 8 },
	exec: { severity: "high", deduction: 12 },
	system_modification: { severity: "high", deduction: 12 },
	container_runtime_control: { severity: "high", deduction: 10 },
	file_write: { severity: "medium", deduction: 8 },
	file_read: { severity: "medium", deduction: 6 },
	filesystem_discovery: { severity: "medium", deduction: 8 },
	configuration_override: { severity: "medium", deduction: 8 },
	network: { severity: "medium", deduction: 6 },
	browser_automation: { severity: "medium", deduction: 8 },
	browser_session_attachment: { severity: "high", deduction: 12 },
	browser_profile_copy: { severity: "high", deduction: 10 },
	browser_auth_state_handling: { severity: "high", deduction: 12 },
	persistent_session_reuse: { severity: "high", deduction: 10 },
	mcp_issued_browser_auth_cookie: { severity: "high", deduction: 12 },
	skill_path_discovery: { severity: "high", deduction: 10 },
	session_management: { severity: "medium", deduction: 8 },
	content_extraction: { severity: "medium", deduction: 8 },
	remote_delegation: { severity: "medium", deduction: 8 },
	remote_task_management: { severity: "medium", deduction: 8 },
	server_exposure: { severity: "medium", deduction: 8 },
	external_tool_bridge: { severity: "medium", deduction: 8 },
	local_service_access: { severity: "medium", deduction: 8 },
	process_orchestration: { severity: "medium", deduction: 8 },
	ui_state_access: { severity: "medium", deduction: 8 },
	documentation_ingestion: { severity: "medium", deduction: 8 },
	local_input_control: { severity: "medium", deduction: 8 },
	package_bootstrap: { severity: "medium", deduction: 8 },
	environment_configuration: { severity: "medium", deduction: 8 },
	payment_processing: { severity: "medium", deduction: 8 },
	unrestricted_scope: { severity: "high", deduction: 10 },
	cookie_url_handoff: { severity: "high", deduction: 10 },
	credential_store_persistence: { severity: "high", deduction: 10 },
	external_instruction_override: { severity: "high", deduction: 10 },
	prompt_file_ingestion: { severity: "medium", deduction: 8 },
	automation_evasion: { severity: "medium", deduction: 8 },
};

export const CREDENTIAL_PATTERNS: readonly RegExp[] = [
	/(?:read|reads|access|get|cat|dump|exfiltrate|steal|harvest)\s+.{0,140}(?:\.env|\.ssh|id_rsa|id_ed25519|credentials?|secrets?|api[_-]?key|access[_-]?token|password)/i,
	/~\/\.ssh\/(?:id_rsa|id_ed25519|authorized_keys|config)\b/i,
	/(?:api[_-]?key|access[_-]?token|private[_-]?key|secret(?:s)?|password)\b.{0,80}\b(?:read|dump|exfiltrate|steal|harvest)/i,
	/(?:auth(?:entication)?\s+cookie|http-?only\s+cookie|session\s+tokens?\s+in\s+plaintext|cookies?\s+(?:export|import|get|set|clear)\b|state\s+(?:save|load)\s+\S*auth\.json|profile\s+sync\b|actual\s+Chrome\s+profile|real\s+Chrome\s+with\s+your\s+login\s+sessions|connect\s+to\s+the\s+user'?s\s+running\s+Chrome)/i,
	/(?:--auto-connect\b|--cdp\b|get\s+cdp-url|remote-debugging-port|browser\s+session\s+is\s+authenticated|cookies?\s+and\s+localStorage|session\s+saved|already\s+authenticated|default\s+Chrome\s+profile|full\s+profile\s+sync|sync\s+ALL\s+cookies|entire\s+browser\s+state|--secret\s+[^\s=]+=[^\s]+)/i,
] as const;

export const EXEC_PATTERNS: readonly RegExp[] = [
	/\b(?:exec(?:ute)?|shell|spawn(?:ing)?|sub-?process|child_process|run\s+(?:bash|sh|zsh|cmd|powershell|python|node)|eval\s*\()/i,
	/\b(?:curl|wget)\b.{0,80}\|\s*(?:bash|sh|zsh|python)\b/i,
	/\b(?:npm|pnpm|yarn|bun)\s+(?:init|install|run|exec|create)\b|\b(?:npx|pnpm\s+dlx|bunx)\b/i,
] as const;

export const SYSTEM_MOD_PATTERNS: readonly RegExp[] = [
	/\b(?:sudo|systemctl|crontab|modprobe|insmod|rmmod|iptables|ufw|chown|chmod)\b/i,
	/\b(?:install\s+(?:packages?\s+)?globally|global\s+install|modify\s+system(?:\s+configuration)?|\/etc\/|\/usr\/|\/sys\/|\/proc\/)\b/i,
] as const;

export const FILE_WRITE_PATTERNS: readonly RegExp[] = [
	/\b(?:file_write|write|writes|written|save|saves|store|stores|persist|append|create)\b.{0,80}\b(?:file|files|disk|workspace|directory|output)\b/i,
	/\b(?:write|save|store|persist)\b.{0,40}\b(?:database|cache|state)\b/i,
	/\bset\s+up\s+project\s+structure\b/i,
	/\bproject\s+structure,\s*package\.json,\s*tsconfig\.json\b/i,
	/\bcreate\s+`[^`\n]+(?:\.[a-z0-9]+|\/[a-z0-9._-]+)`/i,
	/\bscreenshot\s+\S+\.(?:png|jpg|jpeg|webp|gif)\b/i,
	/\bpage\.screenshot\s*\(\s*path\s*=\s*['"][^'"]+\.(?:png|jpg|jpeg|webp|gif|pdf)['"]/i,
	/--image\s+\S+\.(?:png|jpg|jpeg|webp|gif)\b/i,
	/\bsaved\s+to\s+\/tmp\//i,
] as const;

export const FILE_READ_PATTERNS: readonly RegExp[] = [
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

export const FILESYSTEM_DISCOVERY_PATTERNS: readonly RegExp[] = [
	/\{baseDir\}/i,
	/\bcommon\s+installation\s+paths\b/i,
	/\bSKILL\.md\s+file'?s\s+directory\b/i,
	/\bproject\s+structure\s+analysis\b/i,
	/find\s+\.\s+-name\s+"Dockerfile\*"/i,
	/\.dockerignore/i,
	/\.claude\/plugins\/marketplaces\//i,
] as const;

export const CONFIGURATION_OVERRIDE_PATTERNS: readonly RegExp[] = [
	/\bEXTEND\.md\b/i,
	/\bload\s+preferences\b/i,
	/\.baoyu-skills\//i,
	/\bapply\s+settings\b/i,
] as const;

export const CREDENTIAL_HANDOFF_PATTERNS: readonly RegExp[] = [
	/\bget\s+authentication\s+cookie\b/i,
	/\bauth\s+cookie\s+via\s+the\s+ATXP\s+tool\b/i,
	/\bagents\s+get\s+an\s+auth\s+cookie\s+via\s+MCP\b/i,
	/\buse\s+that\s+auth\s+state\b/i,
	/\bstate\s+load\s+\.\/auth\.json\b/i,
	/\bconfigure\s+browser\s+cookie\b/i,
	/\bredirect\s+to\s+clean\s+the\s+URL\b/i,
] as const;

export const CREDENTIAL_STORAGE_PATTERNS: readonly RegExp[] = [
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

export const AUTH_STATE_MANAGEMENT_PATTERNS: readonly RegExp[] = [
	/state\s+(?:save|load)\s+\.\/auth\.json/i,
	/browser\s+session\s+is\s+authenticated/i,
	/use\s+that\s+auth\s+state/i,
	/cookies?\s+and\s+localStorage/i,
	/auth(?:entication)?\s+cookie/i,
	/actual\s+Chrome\s+profile\s*\(cookies,\s*logins,\s*extensions\)/i,
] as const;

export const NETWORK_PATTERNS: readonly RegExp[] = [
	/https?:\/\/[^\s`"'<>()[\]{}]+/i,
	/\b(?:fetch|curl|wget|webhook|network_unrestricted|network_restricted|api\s+(?:endpoint|request)|post\s+to\s+https?:\/\/|HEALTHCHECK|EXPOSE\s+\d{2,5})\b/i,
] as const;

export const BROWSER_AUTOMATION_PATTERNS: readonly RegExp[] = [
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

export const BROWSER_SESSION_ATTACHMENT_PATTERNS: readonly RegExp[] = [
	/--auto-connect\b/i,
	/--cdp\b/i,
	/get\s+cdp-url/i,
	/remote-debugging-port/i,
	/actual\s+Chrome\s+profile/i,
	/real\s+Chrome\s+with\s+your\s+login\s+sessions/i,
	/real\s+Chrome\s+with\s+CDP/i,
	/profile\s+sync\b/i,
] as const;

export const BROWSER_PROFILE_COPY_PATTERNS: readonly RegExp[] = [
	/actual\s+Chrome\s+profile/i,
	/login\s+sessions/i,
	/persistent\s+but\s+empty\s+CLI\s+profile/i,
	/full\s+profile\s+sync/i,
	/sync\s+ALL\s+cookies/i,
] as const;

export const REMOTE_DELEGATION_PATTERNS: readonly RegExp[] = [
	/\bcloud-hosted\s+browser\b/i,
	/\bremote\s+task\b/i,
	/\bstreamable\s+HTTP\b/i,
	/\bexternal\s+services\s+through\s+well-?designed\s+tools\b/i,
	/\b(?:OpenAI|Replicate|DashScope|Gemini|Google)\b.{0,80}\b(?:providers?|API-based\s+image\s+generation)\b/i,
] as const;

export const REMOTE_TASK_MANAGEMENT_PATTERNS: readonly RegExp[] = [
	/\bremote\s+task\b/i,
	/\btask\s+status\s+<id>\b/i,
	/\basync\s+by\s+default\b/i,
] as const;

export const SERVER_EXPOSURE_PATTERNS: readonly RegExp[] = [
	/\bstreamable\s+HTTP\s+for\s+remote\s+servers\b/i,
	/\bMCP\s+Server\b/i,
	/\/mcp\b/i,
	/\bEXPOSE\s+\d{2,5}\b/i,
	/\bcloud-hosted\s+browser\b/i,
	/Call\s+MCP\s+tools\s+via/i,
	/Expose\s+tools\s+that\s+agents\s+can\s+call\s+programmatically/i,
] as const;

export const UNRESTRICTED_SCOPE_PATTERNS: readonly RegExp[] = [
	/no\s+restrictions?\s+on\s+(?:navigation|actions|output)/i,
	/any\s+automation\s+task\s+you\s+request/i,
	/automating\s+any\s+browser\s+task/i,
	/general-purpose\s+browser\s+automation/i,
	/use\s+proactively/i,
] as const;

export const COOKIE_URL_HANDOFF_PATTERNS: readonly RegExp[] = [
	/query\s+string/i,
	/\?[A-Za-z0-9_-]*(?:cookie|token)=/i,
	/redirect\s+to\s+clean\s+the\s+URL/i,
] as const;

export const CREDENTIAL_STORE_PERSISTENCE_PATTERNS: readonly RegExp[] = [
	/auth_cookies/i,
	/cookie\s+auth/i,
	/Auth\s+Vault/i,
	/cookie-based\s+auth\s+pattern/i,
] as const;

export const EXTERNAL_TOOL_BRIDGE_PATTERNS: readonly RegExp[] = [
	/external\s+services\s+through\s+well-?designed\s+tools/i,
	/expose\s+tools\s+that\s+agents\s+can\s+call\s+programmatically/i,
	/interact\s+with\s+external\s+services/i,
	/MCP\s+integration/i,
] as const;

export const LOCAL_SERVICE_ACCESS_PATTERNS: readonly RegExp[] = [
	/\bhttps?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?/i,
	/\bwith_server\.py\b/i,
	/\bdetectDevServers\s*\(/i,
	/\bstdio\s+for\s+local\s+servers?\b/i,
	/\bPORT=\d{2,5}\b/i,
	/\bEXPOSE\s+\d{2,5}\b/i,
	/\btesting\s+web\s+apps?\b|\btest\s+this\s+web\s+app\b/i,
	/\bweb\s+server\b.{0,80}\bexpress\b|\bexpress\b.{0,80}\bweb\s+server\b/i,
	/\bMCP\s+endpoints?\s+directly\b/i,
] as const;

export const SESSION_MANAGEMENT_PATTERNS: readonly RegExp[] = [
	/\bbrowser\s+sessions?\s+across\s+commands/i,
	/\bstate\s+(?:save|load)\s+\.\/auth\.json/i,
	/\b--session-name\b/i,
	/\bsession\s+saved\b/i,
	/\balready\s+authenticated\b/i,
	/\bsession\s+list\b/i,
	/\bclose\s+--all\b/i,
	/\bbackground\s+daemon\b/i,
] as const;

export const CONTENT_EXTRACTION_PATTERNS: readonly RegExp[] = [
	/\bextract\s+information\s+from\s+web\s+pages?\b/i,
	/\bextract(?:ing)?\s+data\b/i,
	/\bdata\s+extraction\b/i,
	/\bscrape\s+data\s+from\s+a\s+page\b/i,
	/\bget\s+html\b/i,
	/\bget\s+text\b/i,
	/\bpage\.content\(\)/i,
	/\bscreenshot\b/i,
] as const;

export const DOCUMENTATION_INGESTION_PATTERNS: readonly RegExp[] = [
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

export const LOCAL_INPUT_CONTROL_PATTERNS: readonly RegExp[] = [
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
	/click\s+element/i,
	/descriptive\s+selectors/i,
	/execute\s+actions\s+using\s+discovered\s+selectors/i,
	/\bclick\s+@e\d+/i,
	/\bclick\s+<index>/i,
	/\bbrowser-use\s+click\b/i,
] as const;

export const PROMPT_FILE_INGESTION_PATTERNS: readonly RegExp[] = [
	/--promptfiles/i,
	/saved\s+prompt\s+files/i,
	/system\.md\s+content\.md/i,
	/reference\s+images/i,
] as const;

export const AUTOMATION_EVASION_PATTERNS: readonly RegExp[] = [
	/bypass(?:es|ing)?\s+anti-automation/i,
	/bypass(?:es|ing)?\s+anti-bot/i,
	/anti-bot\s+detection/i,
] as const;

export const CREDENTIAL_FORM_AUTOMATION_PATTERNS: readonly RegExp[] = [
	/input\s+type="password"/i,
	/fill\s+@e\d+\s+"password123"/i,
	/form\s+filling/i,
	/fill\s+out\s+a\s+form/i,
	/fill\s+forms?\b/i,
	/login\s+to\s+a\s+site/i,
	/test\s+login/i,
	/login\s+flow/i,
] as const;

export const PACKAGE_BOOTSTRAP_PATTERNS: readonly RegExp[] = [
	/\b(?:npx|pnpm\s+dlx|bunx)\b(?:\s+-y)?\s+[A-Za-z0-9@][^\s`"']+/i,
	/\bnpm\s+install\b(?!\s+(?:-g|--global)\b)/i,
	/\bpackage(?:\*|)\.json\b/i,
] as const;

export const CONTAINER_RUNTIME_CONTROL_PATTERNS: readonly RegExp[] = [
	/\bdocker\s+(?:build|run|exec|stop|info|ps|images|context)\b/i,
	/\bdocker-compose\s+config\b/i,
] as const;

export const ENVIRONMENT_CONFIGURATION_PATTERNS: readonly RegExp[] = [
	/\bAGENT_BROWSER_ENCRYPTION_KEY\b/i,
	/\bXDG_CONFIG_HOME\b/i,
	/\bX_BROWSER_CHROME_PATH\b/i,
	/\bAGENT_BROWSER_COLOR_SCHEME\b/i,
] as const;

export const PAYMENT_PROCESSING_PATTERNS: readonly RegExp[] = [
	/\bCost:\s*\$\d/i,
	/\bCharge\s+for\s+premium\s+actions?\b/i,
	/\bPayments\b/i,
	/\$0\.\d+/i,
] as const;

export const PROCESS_ORCHESTRATION_PATTERNS: readonly RegExp[] = [
	/\bwith_server\.py\b/i,
	/\bdocker\s+(?:build|run|exec|stop|info|ps|images|context)\b/i,
	/\bnode\s+run\.js\s+\/tmp\//i,
	/script\s+path\s*=\s*`?\{baseDir\}\/scripts\//i,
	/\$\{BUN_X\}\s+\{baseDir\}\/scripts\//i,
	/check-paste-permissions\.ts/i,
	/\bnpm\s+run\s+dev\b/i,
	/\bpython\s+your_automation\.py\b/i,
] as const;

export const UI_STATE_ACCESS_PATTERNS: readonly RegExp[] = [
	/\bsnapshot\s+-i\b/i,
	/clickable\s+elements?\s+with\s+indices/i,
	/element\s+refs?\s+like\s+@e\d+/i,
	/page\.locator\('button'\)\.all\(\)/i,
	/discovering\s+buttons,\s+links,\s+and\s+inputs/i,
	/identify\s+selectors?\s+from\s+(?:rendered\s+state|inspection\s+results)/i,
] as const;
