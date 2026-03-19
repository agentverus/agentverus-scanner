export interface BehavioralPattern {
	readonly name: string;
	readonly patterns: readonly RegExp[];
	readonly severity: "high" | "medium" | "low";
	readonly deduction: number;
	readonly owaspCategory: string;
	readonly recommendation: string;
}

export const BEHAVIORAL_PATTERNS: readonly BehavioralPattern[] = [
	{
		name: "Unrestricted scope",
		patterns: [
			/do\s+anything/i,
			/no\s+limitations/i,
			/complete\s+autonomy/i,
			/without\s+(?:any\s+)?restrictions/i,
			/unrestricted\s+(?:access|mode|operation)/i,
			/full\s+(?:system\s+)?access/i,
			/no\s+restrictions?\s+on\s+(?:navigation|actions|output)/i,
			/any\s+automation\s+task\s+you\s+request/i,
			/automating\s+any\s+browser\s+task/i,
			/any\s+task\s+requiring\s+programmatic\s+web\s+interaction/i,
			/general-purpose\s+browser\s+automation\s+skill/i,
		],
		severity: "high",
		deduction: 20,
		owaspCategory: "ASST-09",
		recommendation:
			"Define clear boundaries for what the skill can and cannot do. Unrestricted scope is a security risk.",
	},
	{
		name: "System modification",
		patterns: [
			/install\s+(?:packages?\s+)?globally/i,
			/(?:npm|pip|apt|brew)\s+install\s+(?:-g|--global)\b/i,
			/(?:sudo\s+)?(?:apt|yum|dnf|pacman)\s+install/i,
			/modify\s+(?:system|config(?:uration)?)\s+files?/i,
			/(?:write|edit|modify)\s+(?:\/etc|\/usr|\/sys|\/proc)/i,
			/chown\s+/i,
			/modify\s+(?:system\s+)?configuration/i,

			// Persistence & system manipulation (common malware tactics)
			/\bcrontab\s+(?:-e|-l|--edit|--list)\b/i,
			/\bsystemctl\s+(?:enable|disable|start|stop|restart|daemon-reload|edit)\b/i,
			/(?:\/etc\/systemd\/system|systemd\s+unit|\.service\b)/i,
			/\/etc\/hosts\b/i,
			/\b(?:iptables|ufw)\b/i,
			/\b(?:modprobe|insmod|rmmod)\b/i,
			/~\/\.(?:bashrc|zshrc|profile)\b/i,
			/(?:write|append|modify)\s+.*\.(?:bashrc|zshrc|profile)\b/i,
		],
		severity: "high",
		deduction: 20,
		owaspCategory: "ASST-03",
		recommendation:
			"Skills should not modify system configuration or install packages globally. Bundle required dependencies.",
	},
	{
		name: "Config tamper core",
		patterns: [
			/\b(?:write|edit|modify|append|overwrite|replace|patch|update|change|add\s+to)\b[^\n]*(?:AGENTS\.md|TOOLS\.md|CLAUDE\.md)\b/i,
		],
		severity: "high",
		deduction: 25,
		owaspCategory: "ASST-03",
		recommendation:
			"Do not instruct users to write, edit, or otherwise modify trust-boundary workspace files like AGENTS.md, TOOLS.md, or CLAUDE.md. Treat them as user-owned policy/configuration and keep the skill self-contained.",
	},
	{
		name: "Config tamper workspace",
		patterns: [
			/\b(?:write|edit|modify|append|overwrite|replace|patch|update|change|add\s+to)\b[^\n]*\.claude\//i,
		],
		severity: "high",
		deduction: 20,
		owaspCategory: "ASST-03",
		recommendation:
			"Do not instruct users to modify files under .claude/. This directory is part of the workspace trust boundary and should not be altered by untrusted instructions.",
	},
	{
		name: "Autonomous action without confirmation",
		patterns: [
			/without\s+(?:user\s+)?(?:confirmation|approval|consent|asking)/i,
			/automatically\s+(?:execute|run|perform|delete|modify)/i,
			/(?:silently|quietly)\s+(?:execute|run|perform)/i,
			/no\s+(?:user\s+)?(?:confirmation|approval)\s+(?:needed|required)/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-09",
		recommendation:
			"Require user confirmation before performing destructive or irreversible actions.",
	},
	{
		name: "Sub-agent spawning",
		patterns: [
			/spawn\s+(?:a\s+)?(?:sub-?agent|child\s+agent|new\s+agent)/i,
			/delegat(?:e|ing)\s+(?:to|tasks?\s+to)\s+(?:another|other)\s+agent/i,
			/(?:create|start|launch)\s+(?:a\s+)?(?:new\s+)?(?:sub-?)?process/i,
			/sub-?process(?:es)?\s+for\s+(?:parallel|concurrent)/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-03",
		recommendation:
			"Be explicit about sub-agent spawning and ensure delegated tasks are appropriately scoped.",
	},
	{
		name: "External instruction override file",
		patterns: [
			/\bEXTEND\.md\b/i,
			/(?:load|read|parse|apply)\s+(?:preferences|settings)\b/i,
			/\.baoyu-skills\//i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-11",
		recommendation:
			"Be explicit when external project/home files can override skill behavior. Treat sidecar config or instruction files as untrusted input and constrain what they are allowed to change.",
	},
	{
		name: "Opaque helper script execution",
		patterns: [
			/black-?box\s+scripts?/i,
			/do\s+not\s+read\s+the\s+source/i,
			/called?\s+directly\s+as\s+black-?box\s+scripts?/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-04",
		recommendation:
			"Avoid telling agents to execute bundled scripts as opaque black boxes. Encourage minimal inspection, provenance checks, or explicit trust boundaries before running helper code.",
	},
	{
		name: "OS input automation",
		patterns: [
			/copy-to-clipboard/i,
			/paste-from-clipboard/i,
			/paste\s+keystroke/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat clipboard and synthetic keystroke automation as privileged local input control. Require explicit user approval and avoid combining it with authenticated browser sessions unless necessary.",
	},
	{
		name: "Persistent session reuse",
		patterns: [
			/maintains?\s+browser\s+sessions?\s+across\s+commands/i,
			/browser\s+stays\s+open\s+between\s+commands/i,
			/persists?\s+state\s+via\s+a\s+background\s+daemon/i,
			/background\s+daemon/i,
			/state\s+auto-(?:saved|restored)/i,
			/session\s+saved/i,
			/all\s+future\s+runs:\s+already\s+authenticated/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Call out when browser or auth state persists across commands. Reused authenticated sessions should require explicit user consent and clear cleanup guidance.",
	},
	{
		name: "Session inventory and reuse",
		patterns: [
			/list\s+active\s+sessions/i,
			/reuse\s+session\s+ids?/i,
			/close\s+--all/i,
			/session\s+list\b/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat session inventory, reuse, and bulk cleanup commands as sensitive session-management capability. Be explicit about which sessions may be reused or enumerated, and avoid exposing shared authenticated state by default.",
	},
	{
		name: "Remote browser delegation",
		patterns: [
			/--browser\s+remote\b/i,
			/cloud-hosted\s+browser/i,
			/remote\s+browser\b/i,
			/proxy\s+support/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-02",
		recommendation:
			"Treat cloud or remote browser execution as external data egress. Be explicit about what page content, cookies, or secrets may leave the local machine, and require user approval before delegating authenticated sessions.",
	},
	{
		name: "Remote task delegation",
		patterns: [
			/remote\s+task/i,
			/task\s+status\s+<id>/i,
			/async\s+by\s+default/i,
			/cloud\s+task\s+progress/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-02",
		recommendation:
			"Treat delegated cloud tasks as remote execution and potential data egress. Be explicit about what browser state, prompts, or credentials are sent to the remote task runner, and require approval before offloading sensitive work.",
	},
	{
		name: "Compound browser action chaining",
		patterns: [
			/commands?\s+can\s+be\s+chained\s+with\s+`?&&`?/i,
			/\bopen\s+https?:\/\/\S+\s+&&\s+[^\n]+/i,
			/\bfill\s+@e\d+\s+"[^"]+"\s+&&\s+fill\s+@e\d+\s+"[^"]+"\s+&&/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat chained browser commands as compound automation that can hide risky multi-step actions. Prefer explicit step-by-step review for authenticated or destructive workflows.",
	},
	{
		name: "Auth import from user browser",
		patterns: [
			/import\s+auth\s+from\s+the\s+user'?s\s+browser/i,
			/use\s+that\s+auth\s+state/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat importing auth state from the user's browser as sensitive credential access. Require explicit user consent, minimize scope, and avoid persisting imported sessions longer than necessary.",
	},
	{
		name: "MCP-issued browser auth cookie",
		patterns: [
			/get\s+authentication\s+cookie/i,
			/auth\s+cookie\s+via\s+the\s+ATXP\s+tool/i,
			/agents\s+get\s+an\s+auth\s+cookie\s+via\s+MCP/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat MCP-delivered browser cookies as bearer credentials. Make the trust boundary explicit, minimize cookie lifetime/scope, and avoid mixing installation guidance with reusable browser-session tokens.",
	},
	{
		name: "Cookie bootstrap redirect",
		patterns: [
			/configure\s+browser\s+cookie/i,
			/server\s+will[:]?/i,
			/redirect\s+to\s+clean\s+the\s+URL/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat server-side cookie bootstrap redirects as credential handoff flows. Document URL leakage risks clearly and prefer safer cookie-setting mechanisms where possible.",
	},
	{
		name: "Browser session attachment",
		patterns: [
			/(?:--auto-connect\b|--cdp\b|get\s+cdp-url|remote-debugging-port|Chrome\s+DevTools|connect\s+to\s+the\s+user'?s\s+running\s+Chrome)/i,
			/(?:copy(?:ing)?\s+your\s+actual\s+Chrome\s+profile|real\s+Chrome\s+with\s+your\s+login\s+sessions|real\s+Chrome\s+with\s+CDP|profile\s+sync\b|local\s+Chrome\s+profile|cloud\s+profile|Chrome\s+with\s+CDP)/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat browser profile reuse, remote-debugging attachment, and live-session access as sensitive credential access. Require explicit user consent, minimize scope, and clean up persisted state.",
	},
	{
		name: "Profile-backed session persistence",
		patterns: [
			/persistent\s+profile/i,
			/--profile\s+[^\s]+\s+open/i,
			/--session-name\s+[^\s]+\s+open/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat reusable browser profiles and named session stores as persistent credential containers. Require user approval before binding automation to long-lived profiles or session names, and document cleanup/rotation guidance.",
	},
	{
		name: "Browser profile copy",
		patterns: [
			/actual\s+Chrome\s+profile/i,
			/login\s+sessions/i,
			/persistent\s+but\s+empty\s+CLI\s+profile/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat copying or reusing a local browser profile as sensitive credential access. Prefer isolated ephemeral profiles unless the user explicitly approves session reuse.",
	},
	{
		name: "Full browser profile sync",
		patterns: [
			/full\s+profile\s+sync/i,
			/sync\s+ALL\s+cookies/i,
			/entire\s+browser\s+state/i,
			/copies?\s+your\s+actual\s+Chrome\s+profile(?:\s*\(cookies,\s*logins,\s*extensions\))?/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Avoid syncing an entire browser profile or all cookies into agent-controlled workflows. Prefer the smallest domain-scoped auth state possible and require explicit user consent.",
	},
	{
		name: "Browser JavaScript evaluation",
		patterns: [
			/\bbrowser-use\s+eval\b/i,
			/\bagent-browser\s+eval\b/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat browser-side JavaScript evaluation as privileged execution. Constrain the origin, review the expression, and avoid combining it with authenticated sessions unless necessary.",
	},
	{
		name: "Credential form automation",
		patterns: [
			/input\s+type="password"/i,
			/fill\s+@e\d+\s+"password123"/i,
			/fill\s+out\s+a\s+form/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat automated interaction with login/password forms as sensitive credential handling. Require user approval before filling credentials or automating authenticated sign-in flows.",
	},
	{
		name: "State file replay",
		patterns: [
			/state\s+save\s+\.\/auth\.json/i,
			/state\s+load\s+\.\/auth\.json/i,
			/--state\s+\.\/auth\.json\s+open/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat saved auth-state files as credential containers. Minimize their lifetime, protect them at rest, and require explicit user approval before loading them into automated browser sessions.",
	},
	{
		name: "Browser auth state handling",
		patterns: [
			/(?:state\s+(?:save|load)\s+\S*auth\.json|state\s+files?\s+contain\s+session\s+tokens?\s+in\s+plaintext|auth(?:entication)?\s+cookie|http-?only\s+cookie|cookies?\s+(?:export|import|get|set|clear)\b|cookies?\s+and\s+localStorage)/i,
			/(?:session\s+tokens?\s+in\s+plaintext|browser\s+session\s+is\s+authenticated|auto-saved\s+to\s+~\/\.agent-browser\/sessions|session\s+saved|already\s+authenticated|default\s+Chrome\s+profile|actual\s+Chrome\s+profile\s*\(cookies,\s*logins,\s*extensions\))/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Avoid storing, exporting, or passing browser auth state unless the workflow clearly requires it. Prefer encrypted storage, short-lived state, and explicit user confirmation before reusing credentials.",
	},
	{
		name: "Data encoding for URL exfiltration",
		patterns: [
			/\b(?:encode|serialize|pack|compress)\b.{0,80}\b(?:URL|query|parameter|string)\b/i,
			/\b(?:URL|query)[- ]safe\s+(?:string|encoding|format)\b/i,
			/\b(?:encode|serialize|pack|compress)\b.{0,80}\b(?:transmit|send|post|upload|forward)\b.{0,60}https?:\/\//i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-02",
		recommendation:
			"Treat encoding sensitive data into URL parameters as potential data exfiltration. URLs leak into browser history, logs, analytics, and referrers.",
	},
	{
		name: "Environment secret piping",
		patterns: [
			/echo\s+"\$[A-Z0-9_]+"\s*\|/i,
			/(?:including|with|containing)\s+(?:all\s+)?environment\s+variables/i,
			/(?:for\s+each|every)\s+file\s+in\s+the\s+project.*POST\s+its\s+contents?\s+to/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat shell pipelines that pass secrets from environment variables as sensitive credential handling. Avoid exposing secret values to command histories or subprocess pipelines unless absolutely necessary.",
	},
	{
		name: "Secret parameter handling",
		patterns: [
			/--secret\s+[^\s=]+=[^\s]+/i,
			/secret\s+metadata/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat secret-bearing CLI parameters as credential handling. Avoid exposing secrets in command lines, logs, or reusable skill snippets; prefer secure secret stores or interactive injection.",
	},
	{
		name: "Credential vault enrollment",
		patterns: [
			/\bauth\s+save\b/i,
			/--password-stdin\b/i,
			/auth\s+vault/i,
			/\bauth\s+login\b/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat credential-vault setup and stored-login workflows as sensitive credential handling. Be explicit about what secrets enter the vault, where they are stored, and how they are protected or revoked.",
	},
	{
		name: "Federated auth flow",
		patterns: [
			/\bOAuth\b/i,
			/\b2FA\b/i,
			/token\s+refresh/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat OAuth, 2FA, and token-refresh guidance as authentication-sensitive workflows. Explain scope, storage, and refresh behavior clearly so agents do not handle more credential material than necessary.",
	},
	{
		name: "Credential in query string",
		patterns: [
			/(?:\b(?:cookie|token)\b.{0,120}\bquery\s+string\b|\bquery\s+string\b.{0,120}\b(?:cookie|token)\b)/i,
			/\?[A-Za-z0-9_-]*(?:cookie|token)=<[^>\s]+>/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Do not pass auth cookies or tokens in URLs. Query strings leak into browser history, logs, analytics, and referrers. Use secure headers or an explicit browser cookie API instead.",
	},
	{
		name: "Cookie header replay",
		patterns: [
			/-H\s+["']Cookie:\s*[^"']+(?:cookie|token)[^"']*["']/i,
			/\bCookie:\s*[A-Za-z0-9_-]+(?:cookie|token)=[^\s"']+/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat reusable Cookie headers as bearer credentials. Avoid embedding auth cookies in shell snippets or docs; prefer short-lived interactive auth or a dedicated secure credential handoff.",
	},
	{
		name: "Local service exposure",
		patterns: [
			/(?:browser-use\s+)?tunnel\s+\d+\b/i,
			/trycloudflare\.com/i,
			/session\s+share\b/i,
			/public\s+share\s+url/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-02",
		recommendation:
			"Do not expose local services, browser sessions, or internal tools publicly by default. Require explicit approval, constrain the shared surface, and shut down tunnels after use.",
	},
	{
		name: "Local service access",
		patterns: [
			/https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?/i,
			/\bEXPOSE\s+\d{2,5}\b/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat localhost and loopback services as privileged local attack surfaces. Require explicit approval, constrain reachable ports, and avoid combining local access with session reuse or tunneling.",
	},
	{
		name: "Package bootstrap execution",
		patterns: [
			/\b(?:npx|pnpm\s+dlx|bunx)\b(?:\s+-y)?\s+[A-Za-z0-9@][^\s`"']+/i,
			/\bnpm\s+install\b(?!\s+(?:-g|--global)\b)/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-04",
		recommendation:
			"Surface package bootstrap commands for review. Ephemeral package execution and install-time dependency pulls increase supply-chain risk, especially when versions are not pinned or provenance is unclear.",
	},
	{
		name: "Skill path discovery",
		patterns: [
			/determine\s+this\s+SKILL\.md\s+file'?s\s+directory\s+path/i,
			/common\s+installation\s+paths/i,
			/scripts?\s+are\s+located\s+in\s+the\s+`?scripts\/?`?\s+subdirectory/i,
			/script\s+path\s*=\s*`?\{baseDir\}\/scripts\//i,
			/\.claude\/plugins\/marketplaces\//i,
			/project-specific:\s*<project>\/\.claude\/skills/i,
			/\{baseDir\}/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat dynamic skill path resolution and installation-path discovery as local filesystem reconnaissance. Scope which paths may be read or executed from, and avoid broad path probing unless the user explicitly requested it.",
	},
	{
		name: "Dev server auto-detection",
		patterns: [
			/auto-?detect(?:s)?\s+(?:running\s+)?dev\s+servers?/i,
			/detectDevServers\s*\(/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat automatic localhost/dev-server discovery as local service enumeration. Require explicit approval before probing local ports or reusing discovered internal services.",
	},
	{
		name: "Temporary script execution",
		patterns: [
			/write\s+(?:custom\s+)?(?:Playwright\s+code|test\s+scripts?)\s+(?:in|to)\s+\/tmp/i,
			/\bnode\s+-e\b/i,
			/\bnode\s+run\.js\s+\/tmp\//i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat ad hoc script generation and immediate execution as privileged code execution. Review generated scripts before running them and avoid opaque wrapper commands where possible.",
	},
	{
		name: "Server lifecycle orchestration",
		patterns: [
			/with_server\.py/i,
			/manages?\s+server\s+lifecycle/i,
			/supports\s+multiple\s+servers/i,
			/--server\s+["'][^"']+["']/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat helper workflows that start or manage local servers as privileged local process control. Require explicit approval before launching services, and scope which commands/ports may be started.",
	},
	{
		name: "UI state enumeration",
		patterns: [
			/returns?\s+clickable\s+elements?\s+with\s+indices/i,
			/get\s+element\s+refs?\s+like\s+@e\d+/i,
			/snapshot\s+-i/i,
			/re-?snapshot/i,
			/get\s+fresh\s+refs/i,
			/parse\s+the\s+output\s+first/i,
			/check\s+result/i,
			/use\s+refs?\s+to\s+click,\s*fill,\s*select/i,
			/page\.locator\('button'\)\.all\(\)/i,
			/discovering\s+buttons,\s+links,\s+and\s+inputs/i,
			/identify\s+selectors?\s+from\s+rendered\s+state/i,
			/descriptive\s+selectors/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-02",
		recommendation:
			"Treat DOM/accessibility snapshots and clickable-element inventories as sensitive page-state extraction. Be explicit about when UI enumeration is allowed, especially on authenticated or local-only apps.",
	},
	{
		name: "Browser content extraction",
		patterns: [
			/extract\s+information\s+from\s+web\s+pages/i,
			/extract(?:ing)?\s+data/i,
			/data\s+extraction/i,
			/scrape\s+data\s+from\s+a\s+page/i,
			/tak(?:e|ing)\s+screenshots?/i,
			/captur(?:e|ing)\s+browser\s+screenshots/i,
			/view(?:ing)?\s+browser\s+logs/i,
			/inspect\s+rendered\s+DOM/i,
			/identify\s+selectors?\s+from\s+rendered\s+state/i,
			/\bget\s+html\b/i,
			/\bget\s+text\b/i,
			/page\.content\(\)/i,
			/page\.screenshot\s*\(/i,
			/screenshot\s+path\.png/i,
			/screenshot\s+saved\s+to/i,
			/screenshot\s+\(base64\)/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-02",
		recommendation:
			"Treat browser page capture and HTML/text extraction as potential data-access operations, especially when sessions may be authenticated. Make the data-access scope explicit and avoid collecting more page content than needed.",
	},
	{
		name: "Host environment reconnaissance",
		patterns: [
			/\bdocker\s+(?:info|context\s+ls|ps|images)\b/i,
			/find\s+\.\s+-name\s+["']Dockerfile\*/i,
			/find\s+\.\s+-name\s+["']\.dockerignore["']/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat environment discovery and host/container enumeration as privileged reconnaissance. Be explicit about what local state is probed and avoid broad scanning unless the user requested it.",
	},
	{
		name: "Prompt file ingestion",
		patterns: [
			/--promptfiles\b/i,
			/saved\s+prompt\s+files/i,
			/system\.md\s+content\.md/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-06",
		recommendation:
			"Treat prompt files and reference prompt bundles as untrusted instructions. Review them before loading and avoid mixing trusted agent policy with user- or repo-controlled prompt files.",
	},
	{
		name: "External AI provider delegation",
		patterns: [
			/API-based\s+image\s+generation/i,
			/reference\s+images/i,
			/--ref\s+\S+/i,
			/\b(?:OpenAI|Replicate|DashScope|Gemini|Google)\b.{0,80}\b(?:API|APIs|providers?)\b/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-02",
		recommendation:
			"Treat external AI-provider calls as data egress. Make it explicit what prompts, files, or images are sent to third-party providers and require approval before forwarding sensitive content.",
	},
	{
		name: "Remote documentation ingestion",
		patterns: [
			/Use\s+WebFetch\s+to\s+load/i,
			/web\s+search\s+and\s+WebFetch\s+as\s+needed/i,
			/fetch\s+specific\s+pages\s+with\s+`?\.md`?\s+suffix/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-06",
		recommendation:
			"Treat remote documentation fetches as untrusted content ingestion. Constrain which sources may be fetched, summarize rather than obey fetched content, and isolate downloaded guidance from trusted system instructions.",
	},
	{
		name: "External tool bridge",
		patterns: [
			/interact\s+with\s+external\s+services\s+through\s+well-?designed\s+tools/i,
			/interact\s+with\s+external\s+services/i,
			/external\s+services?.{0,60}(?:remote\s+)?APIs?|(?:remote\s+)?APIs?.{0,60}external\s+services?/i,
			/expose\s+tools\s+that\s+agents\s+can\s+call\s+programmatically/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat agent tool bridges to external services as privileged capability expansion. Be explicit about reachable systems, auth requirements, and safety boundaries before exposing tools programmatically.",
	},
	{
		name: "Remote transport exposure",
		patterns: [
			/streamable\s+HTTP\s+for\s+remote\s+servers/i,
			/remote\s+servers?,\s+using\s+stateless\s+JSON/i,
			/transport\s+mechanisms?\s*\(streamable\s+HTTP,\s*stdio\)/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-02",
		recommendation:
			"Treat remote tool transports as network-exposed attack surface. Be explicit about what data crosses the wire, who can connect, and which authentication or origin controls protect the remote server.",
	},
	{
		name: "Authentication integration surface",
		patterns: [
			/API\s+client\s+with\s+authentication/i,
			/authentication\s+requirements/i,
			/ATXP-based\s+authentication/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-05",
		recommendation:
			"When a skill builds or relies on authentication integrations, be explicit about what credentials are required, where they are stored, and how they are scoped or rotated.",
	},
	{
		name: "Credential store persistence",
		patterns: [
			/\bauth_cookies\b/i,
			/(?:cookie\s+auth|auth\s+cookie)/i,
			/SQLite\b.{0,120}\bauth_cookies\b|\bauth_cookies\b.{0,120}SQLite/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat persistent cookie stores and auth databases as sensitive credential material. Minimize retention, protect at rest, and avoid encouraging reusable bearer-cookie storage without clear security controls.",
	},
	{
		name: "Container runtime control",
		patterns: [
			/\bdocker\s+(?:info|context|ps|images|build(?:x)?|run|exec|stop|compose)\b/i,
			/\bdocker-compose\s+config\b/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat Docker or container-runtime control as privileged host access. Scope container operations tightly, avoid arbitrary daemon access, and require explicit approval before mutating local workloads.",
	},
	{
		name: "Local file access",
		patterns: [
			/--allow-file-access\b/i,
			/\bfile:\/\//i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat local file browsing as privileged access. Restrict it to explicit user-approved paths and avoid combining it with unrestricted browser/session reuse.",
	},
	{
		name: "Automation evasion",
		patterns: [
			/(?:bypass(?:es|ing)?|avoid(?:s|ing)?)\s+(?:anti-?bot|anti-automation|automation\s+detection|bot\s+detection)/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-07",
		recommendation:
			"Avoid instructions whose value proposition is evading platform defenses or automation detection. Document legitimate automation constraints instead.",
	},
	{
		name: "State persistence",
		patterns: [
			/(?:write|save|store)\s+(?:to\s+)?(?:file|disk|database|storage)/i,
			/persist(?:ent)?\s+(?:state|data|storage)/i,
			/(?:create|maintain)\s+(?:a\s+)?(?:log|cache|database)/i,
		],
		severity: "low",
		deduction: 5,
		owaspCategory: "ASST-09",
		recommendation:
			"If state persistence is needed, document what data is stored and where. Allow users to review stored data.",
	},
	{
		name: "Unbounded loops or retries",
		patterns: [
			/(?:retry|loop|repeat)\s+(?:indefinitely|forever|until\s+success)/i,
			/(?:infinite|unbounded)\s+(?:loop|retry|recursion)/i,
			/while\s*\(\s*true\s*\)/i,
			/no\s+(?:maximum|max|limit)\s+(?:on\s+)?(?:retries|attempts|iterations)/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-09",
		recommendation: "Set maximum retry counts and loop bounds to prevent resource exhaustion.",
	},
	{
		name: "Financial/payment actions",
		patterns: [
			/(?:process|make|initiate)\s+(?:a\s+)?payment/i,
			/(?:transfer|send)\s+(?:money|funds|crypto)/i,
			/(?:purchase|buy|order)\s+(?:on\s+behalf|for\s+the\s+user)/i,
			/(?:credit\s+card|bank\s+account|wallet)/i,
			/(?:cost|price)\s*:\s*\$\d/i,
			/charge\s+for\s+(?:premium|paid)\s+actions?/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-09",
		recommendation:
			"Financial actions should always require explicit user confirmation and should be clearly documented.",
	},
] as const;

export const KNOWN_INSTALLERS = /(?:deno\.land|bun\.sh|rustup\.rs|get\.docker\.com|install\.python-poetry\.org|nvm-sh|golangci|foundry\.paradigm\.xyz|tailscale\.com|opencode\.ai|sh\.rustup\.rs|get\.pnpm\.io|volta\.sh)/i;

export const PREREQUISITE_TRAP_PATTERNS = [
	/curl\s+.*\|\s*(?:sh|bash|zsh)/i,
	/curl\s+.*-[oO]\s+.*&&\s*(?:chmod|\.\/)/i,
] as const;