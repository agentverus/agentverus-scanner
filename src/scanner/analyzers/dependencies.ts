import type { CategoryScore, Finding, ParsedSkill } from "../types.js";
import { adjustForContext, buildContentContext, isInsideCodeBlock, isInThreatListingContext, isSecurityDefenseSkill } from "./context.js";
import { applyDeclaredPermissions } from "./declared-match.js";

/** Trusted domain patterns */
const TRUSTED_DOMAINS = [
	/^github\.com\/(?!.*\/raw\/)/,
	/^(?:www\.)?npmjs\.com/,
	/^registry\.npmjs\.org/,
	/^(?:www\.)?pypi\.org/,
	/^api\.npmjs\.com/,
	/^docs\.python\.org/,
	/^developer\.mozilla\.org/,
	/^learn\.microsoft\.com/,
	/^cloud\.google\.com/,
	/^stackoverflow\.com/,
	/^(?:www\.)?google\.com/,
	/^developers\.google\.com/,
	/^support\.google\.com/,
	/^(?:[\w-]+\.)?microsoft\.com/,
	/^(?:[\w-]+\.)?amazon\.com/,
	/^(?:[\w-]+\.)?aws\.amazon\.com/,
	/^(?:[\w-]+\.)?googleapis\.com/,
	/^(?:[\w-]+\.)?linkedin\.com/,
	/^(?:[\w-]+\.)?twitter\.com/,
	/^(?:[\w-]+\.)?x\.com/,
	/^(?:[\w-]+\.)?openai\.com/,
	/^(?:[\w-]+\.)?anthropic\.com/,
	/^(?:[\w-]+\.)?supabase\.co/,
	/^(?:[\w-]+\.)?heroku\.com/,
	/^(?:[\w-]+\.)?stripe\.com/,
	/^(?:[\w-]+\.)?slack\.com/,
	/^(?:[\w-]+\.)?discord\.com/,
	/^(?:[\w-]+\.)?notion\.so/,
	/^(?:[\w-]+\.)?gitlab\.com/,
	/^(?:[\w-]+\.)?bitbucket\.org/,
	/^(?:[\w-]+\.)?wikipedia\.org/,
	/^(?:[\w-]+\.)?w3\.org/,
	/^(?:[\w-]+\.)?json\.org/,
	/^(?:[\w-]+\.)?yaml\.org/,
	/^(?:[\w-]+\.)?mozilla\.org/,
	/^(?:[\w-]+\.)?apache\.org/,
	/^(?:[\w-]+\.)?readthedocs\.io/,
	/^(?:[\w-]+\.)?mintlify\.app/,
	/^(?:[\w-]+\.)?gitbook\.io/,
	/^(?:[\w-]+\.)?medium\.com/,
	/^(?:[\w-]+\.)?npm\.pkg\.github\.com/,
	/^(?:[\w-]+\.)?docker\.com/,
	/^(?:[\w-]+\.)?hub\.docker\.com/,
	/^crates\.io/,
	/^rubygems\.org/,
	/^pkg\.go\.dev/,
	/^example\.com/,
	/^example\.org/,
] as const;

/** Raw content domains — medium risk */
const RAW_CONTENT_DOMAINS = [
	/^raw\.githubusercontent\.com/,
	/^pastebin\.com/,
	/^gist\.github\.com/,
	/^gist\.githubusercontent\.com/,
	/^paste\./,
	/^hastebin\./,
	/^dpaste\./,
] as const;

/** IP address pattern */
const IP_ADDRESS_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}/;

/** Private/localhost IP patterns — not suspicious */
const PRIVATE_IP_REGEX = /^(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|localhost)/;

const LOCAL_SERVICE_HINT_PATTERNS = [
	{ regex: /\bEXPOSE\s+\d{2,5}\b/i, title: "Local service port exposure" },
	{ regex: /\bHEALTHCHECK\b/i, title: "Local service healthcheck reference" },
	{ regex: /\bstdio\s+for\s+local\s+servers?\b/i, title: "Local server transport reference" },
	{ regex: /\bMCP\s+endpoints?\s+directly\b/i, title: "Agent-callable endpoint reference" },
] as const;

const REMOTE_SERVICE_HINT_PATTERNS = [
	{
		regex: /\bcloud-hosted\s+browser\b|\bproxy\s+support\b/i,
		title: "Hosted browser service dependency",
		description:
			"The skill depends on a hosted or proxy-backed browser service, which introduces an external execution surface and additional dependency trust requirements.",
	},
	{
		regex: /\b(?:OpenAI|Google|DashScope|Replicate)\b.{0,80}\b(?:providers?|APIs?)\b|\bAPI-based\s+image\s+generation\b/i,
		title: "Third-party AI provider dependency",
		description:
			"The skill relies on third-party AI providers or APIs, expanding the remote dependency surface for prompts, inputs, or generated artifacts.",
	},
	{
		regex: /\bexternal\s+services\s+through\s+well-?designed\s+tools\b|\bintegrate\s+external\s+APIs?\s+or\s+services\b/i,
		title: "External service integration dependency",
		description:
			"The skill is explicitly designed to integrate remote services or APIs, which increases dependency trust and remote attack-surface considerations.",
	},
	{
		regex: /\bfor\s+more\s+information,\s+see\s+https?:\/\/\S+|\breference\s+implementation\b|\bUse\s+WebFetch\s+to\s+load\s+https?:\/\/\S+|\bsitemap\.xml\b|\bREADME\.md\b/i,
		title: "External documentation dependency",
		description:
			"The skill relies on external documentation, specs, or README content as part of its workflow, which introduces an additional remote dependency and trust boundary.",
	},
	{
		regex: /\bpackage(?:\*|)\.json\b|\btsconfig\.json\b|\bSet\s+Up\s+Project\s+Structure\b|\bproject\s+structure\b/i,
		title: "Package-managed project bootstrap dependency",
		description:
			"The skill bootstraps a package-managed project structure, which adds supply-chain exposure through manifest files, build configuration, and package-manager workflows.",
	},
	{
		regex: /\bquery\s+string\b.{0,120}\b(?:cookie|auth|token|session)\b|\b(?:cookie|auth|token|session)\b.{0,120}\bquery\s+string\b/i,
		title: "Credential query-parameter transport",
		description:
			"The skill describes moving cookies, auth state, or token material through URL query parameters, which turns bearer material into a dependency on URL handling, logging, and redirect hygiene.",
	},
	{
		regex: /\bAuth\s+Vault\b|\bauth_cookies\b|\bstate\s+save\s+\.\/auth\.json\b|\bpersistent\s+but\s+empty\s+CLI\s+profile\b|\b--session-name\b|\bsession\s+saved\b|\bstate\s+auto-saved\b/i,
		title: "Persistent credential-state store dependency",
		description:
			"The skill depends on persistent local credential or session state stores such as auth vaults, reusable browser profiles, saved auth-state files, or session databases.",
	},
] as const;

/** Download-and-execute patterns */
const DOWNLOAD_EXECUTE_PATTERNS = [
	/download\s+and\s+(?:execute|eval)\b/i,
	/(?:curl|wget)\s+.*?\|\s*(?:sh|bash|zsh|python)/i,
	/eval\s*\(\s*fetch/i,
	/import\s+.*?from\s+['"]https?:\/\//i,
	/require\s*\(\s*['"]https?:\/\//i,
] as const;

/** Well-known installer domains where curl|bash is a standard practice */
const KNOWN_INSTALLER_DOMAINS = [
	/deno\.land/i,
	/bun\.sh/i,
	/rustup\.rs/i,
	/get\.docker\.com/i,
	/install\.python-poetry\.org/i,
	/raw\.githubusercontent\.com\/nvm-sh/i,
	/raw\.githubusercontent\.com\/Homebrew/i,
	/raw\.githubusercontent\.com\/golangci/i,
	/foundry\.paradigm\.xyz/i,
	/tailscale\.com\/install/i,
	/opencode\.ai\/install/i,
	/sh\.rustup\.rs/i,
	/get\.pnpm\.io/i,
	/volta\.sh/i,
] as const;

/** Lifecycle scripts that run automatically during install/publish flows */
const LIFECYCLE_SCRIPTS = new Set([
	"preinstall",
	"install",
	"postinstall",
	"preuninstall",
	"uninstall",
	"postuninstall",
	"prepublish",
	"prepublishonly",
	"prepack",
	"postpack",
	"prepare",
]);

/** Dangerous script content that indicates command execution/network risk */
const DANGEROUS_SCRIPT_CONTENT =
	/\b(?:curl|wget|eval|exec|bash|sh\s+-c|node\s+-e|python\s+-c|base64|nc)\b|\/dev\/tcp|>\(|<\(|\$\(|`[^`]+`|\b\d{1,3}(?:\.\d{1,3}){3}\b|https?:\/\/\S+/i;

interface JsonCodeBlockCandidate {
	readonly content: string;
	readonly start: number;
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function extractJsonCodeBlockCandidates(content: string): JsonCodeBlockCandidate[] {
	const blocks: JsonCodeBlockCandidate[] = [];
	const codeBlockRegex = /```([^\n`]*)\r?\n([\s\S]*?)```/g;
	let match: RegExpExecArray | null;

	while ((match = codeBlockRegex.exec(content)) !== null) {
		const langRaw = (match[1] ?? "").trim().toLowerCase();
		const lang = (langRaw.split(/\s+/)[0] ?? "").trim();
		if (lang !== "" && lang !== "json" && lang !== "jsonc") {
			continue;
		}

		const blockContent = match[2] ?? "";
		blocks.push({
			content: blockContent,
			start: match.index,
		});
	}

	return blocks;
}

function extractScriptsFromJsonBlock(blockContent: string): Record<string, unknown> | null {
	// Strip JSONC-style comments while preserving content inside string literals.
	const stripJsonComments = (input: string): string => {
		let out = "";
		let inString = false;
		let escaping = false;
		let inLineComment = false;
		let inBlockComment = false;

		for (let i = 0; i < input.length; i += 1) {
			const ch = input[i] ?? "";
			const next = input[i + 1] ?? "";

			if (inLineComment) {
				if (ch === "\n") {
					inLineComment = false;
					out += ch;
				}
				continue;
			}

			if (inBlockComment) {
				if (ch === "*" && next === "/") {
					inBlockComment = false;
					i += 1;
				}
				continue;
			}

			if (inString) {
				out += ch;
				if (escaping) {
					escaping = false;
					continue;
				}
				if (ch === "\\") {
					escaping = true;
					continue;
				}
				if (ch === "\"") {
					inString = false;
				}
				continue;
			}

			if (ch === "\"") {
				inString = true;
				out += ch;
				continue;
			}

			if (ch === "/" && next === "/") {
				inLineComment = true;
				i += 1;
				continue;
			}

			if (ch === "/" && next === "*") {
				inBlockComment = true;
				i += 1;
				continue;
			}

			out += ch;
		}

		return out;
	};

	// Remove trailing commas before `}` or `]`, ignoring commas inside strings.
	const stripTrailingCommas = (input: string): string => {
		let out = "";
		let inString = false;
		let escaping = false;

		for (let i = 0; i < input.length; i += 1) {
			const ch = input[i] ?? "";

			if (inString) {
				out += ch;
				if (escaping) {
					escaping = false;
					continue;
				}
				if (ch === "\\") {
					escaping = true;
					continue;
				}
				if (ch === "\"") {
					inString = false;
				}
				continue;
			}

			if (ch === "\"") {
				inString = true;
				out += ch;
				continue;
			}

			if (ch === ",") {
				let j = i + 1;
				while (j < input.length && /\s/.test(input[j] ?? "")) j += 1;
				const nextNonWs = input[j] ?? "";
				if (nextNonWs === "}" || nextNonWs === "]") {
					continue;
				}
			}

			out += ch;
		}

		return out;
	};

	const parseLenientJson = (input: string): unknown | null => {
		try {
			return JSON.parse(input) as unknown;
		} catch {
			try {
				const noComments = stripJsonComments(input);
				const noTrailingCommas = stripTrailingCommas(noComments);
				return JSON.parse(noTrailingCommas) as unknown;
			} catch {
				return null;
			}
		}
	};

	try {
		const parsed = parseLenientJson(blockContent);
		if (!parsed) return null;
		if (!isObjectRecord(parsed)) return null;

		const scripts = parsed["scripts"];
		if (!isObjectRecord(scripts)) return null;

		return scripts;
	} catch {
		return null;
	}
}

function isExampleDocumentationContext(content: string, offset: number): boolean {
	const preceding = content.slice(Math.max(0, offset - 1500), offset);
	const headings = preceding.match(/^#{1,6}\s+.+$/gm);
	if (!headings || headings.length === 0) return false;

	const lastHeading = headings[headings.length - 1] ?? "";
	return /\b(?:examples?|demo|output|sample|tutorial|documentation|docs)\b/i.test(lastHeading);
}

/**
 * Check if a curl|bash pattern uses a well-known installer or is in a
 * prerequisites/setup section with a non-suspicious URL.
 */
function isLegitimateInstaller(content: string, matchIndex: number, matchText: string): boolean {
	// Check if URL is a known installer
	for (const domain of KNOWN_INSTALLER_DOMAINS) {
		if (domain.test(matchText)) return true;
	}

	// If the URL contains a raw IP address, it's never legitimate
	if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(matchText)) return false;

	// If URL is a known installer domain, it's always legitimate regardless of section
	// For unknown URLs, only downgrade if in a setup section AND the URL uses HTTPS
	// (raw IPs and HTTP are never legitimate even in setup sections)
	const usesHttps = /https:\/\//.test(matchText);
	const hasKnownTld = /\.(com|org|io|dev|sh|rs|land|cloud|app|ai|so|net|co)\//.test(matchText);

	if (!usesHttps || !hasKnownTld) return false;

	// Check if the match is inside a prerequisites/setup/installation section
	const preceding = content.slice(Math.max(0, matchIndex - 1000), matchIndex);
	const headings = preceding.match(/^#{1,4}\s+.+$/gm);
	if (headings && headings.length > 0) {
		const lastHeading = headings[headings.length - 1]!.toLowerCase();
		if (/\b(?:prerequisit|install|setup|getting\s+started|requirements?|dependencies)\b/.test(lastHeading)) {
			return true;
		}
	}

	// Check if inside YAML frontmatter metadata block (install:, command:, compatibility:)
	const nearbyLines = preceding.split("\n").slice(-10).join("\n").toLowerCase();
	if (/\b(?:install|command|compatibility|setup)\s*:/i.test(nearbyLines)) {
		return true;
	}

	return false;
}

/** Extract hostname from URL */
function getHostname(url: string): string {
	try {
		const parsed = new URL(url);
		return parsed.hostname;
	} catch {
		// Handle URLs without protocol
		const match = url.match(/^(?:https?:\/\/)?([^/:]+)/);
		return match?.[1] ?? url;
	}
}

/** Classify a URL by risk level */
function classifyUrl(url: string): {
	risk: "trusted" | "raw" | "ip" | "local" | "data" | "unknown";
	deduction: number;
} {
	if (url.startsWith("data:")) {
		return { risk: "data", deduction: 20 };
	}

	const hostname = getHostname(url);

	if (IP_ADDRESS_REGEX.test(hostname)) {
		if (PRIVATE_IP_REGEX.test(hostname)) {
			return { risk: "local", deduction: 8 };
		}
		return { risk: "ip", deduction: 20 };
	}
	if (PRIVATE_IP_REGEX.test(hostname)) {
		return { risk: "local", deduction: 8 };
	}

	const urlPath = url.replace(/^https?:\/\//, "");

	for (const pattern of TRUSTED_DOMAINS) {
		if (pattern.test(urlPath)) {
			return { risk: "trusted", deduction: 0 };
		}
	}

	for (const pattern of RAW_CONTENT_DOMAINS) {
		if (pattern.test(urlPath)) {
			return { risk: "raw", deduction: 10 };
		}
	}

	return { risk: "unknown", deduction: 5 };
}

function hasSensitiveUnknownUrlContext(content: string, url: string): boolean {
	const idx = content.indexOf(url);
	if (idx < 0) return false;

	const start = Math.max(0, idx - 220);
	const end = Math.min(content.length, idx + url.length + 220);
	const window = content.slice(start, end);
	return /\b(?:auth|authentication|cookie|token|login|dashboard|session|mcp|api|endpoint|provider|oauth|2fa|refresh|credential|secret)\b/i.test(
		window,
	);
}

function hasCredentialBearingUrlParam(url: string): boolean {
	return /[?&][^=#\s]*(?:cookie|token|auth|session)[^=#\s]*=|[?&][^=#\s]*=(?:<[^>]+>|\$\{?[A-Z0-9_]+\}?|\$[A-Z0-9_]+)/i.test(
		url,
	);
}

/**
 * Best-effort extraction of base domains that look like they belong to the skill's
 * own product/brand (self-references).
 *
 * SECURITY NOTE:
 * These are *candidates* only. Never use this to skip or automatically trust URLs.
 * It is trivial for malicious authors to pick a skill name that matches an attacker
 * domain. If you want to reduce false positives, use an explicit allowlist or an
 * opt-in semantic reputation check.
 */
export function extractSelfBaseDomains(skill: ParsedSkill): Set<string> {
	const selfBaseDomains = new Set<string>();

	const tokenSource = `${skill.name ?? ""} ${skill.description ?? ""}`.toLowerCase();
	const tokens = tokenSource
		.split(/[^a-z0-9]+/g)
		.map((t) => t.trim())
		.filter((t) => t.length >= 3);

	const getBaseDomain = (hostnameRaw: string): { baseDomain: string; baseToken: string } | null => {
		const hostname = hostnameRaw.toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
		if (!hostname || hostname === "localhost") return null;
		if (IP_ADDRESS_REGEX.test(hostname)) return null;

		const parts = hostname.split(".").filter(Boolean);
		if (parts.length < 2) return null;
		const tld = parts[parts.length - 1];
		const sld = parts[parts.length - 2];
		if (!tld || !sld) return null;
		return { baseDomain: `${sld}.${tld}`, baseToken: sld };
	};

	for (const url of skill.urls) {
		const hostname = getHostname(url);
		const base = getBaseDomain(hostname);
		if (!base) continue;
		if (tokens.includes(base.baseToken)) {
			selfBaseDomains.add(base.baseDomain);
		}
	}

	return selfBaseDomains;
}

/** Analyze dependencies and external URLs */
export async function analyzeDependencies(skill: ParsedSkill): Promise<CategoryScore> {
	const findings: Finding[] = [];
	let score = 100;
	const content = skill.rawContent;

	// Detect if this is a security/defense skill listing threat patterns educationally
	const isDefenseSkill = isSecurityDefenseSkill(skill);
	// Classify each URL, cap cumulative deduction for low-risk unknowns
	let unknownUrlDeductionTotal = 0;
	const UNKNOWN_URL_DEDUCTION_CAP = 15; // max total points lost from unknown (non-dangerous) URLs

	for (const url of skill.urls) {
		const classification = classifyUrl(url);

		if (classification.deduction > 0) {
			// For low-risk unknown URLs, cap total deduction to avoid penalizing
			// skills that document many legitimate API endpoints
			let effectiveDeduction = classification.deduction;
			if (classification.risk === "unknown") {
				if (unknownUrlDeductionTotal >= UNKNOWN_URL_DEDUCTION_CAP) {
					effectiveDeduction = 0;
				} else {
					effectiveDeduction = Math.min(
						classification.deduction,
						UNKNOWN_URL_DEDUCTION_CAP - unknownUrlDeductionTotal,
					);
				}
				unknownUrlDeductionTotal += classification.deduction;
			}

			let severity: "high" | "medium" | "low" =
				classification.risk === "ip" || classification.risk === "data"
					? "high"
					: classification.risk === "raw" || classification.risk === "local"
						? "medium"
						: "low";

			if (classification.risk === "unknown" && hasSensitiveUnknownUrlContext(content, url)) {
				severity = "medium";
				effectiveDeduction = Math.max(effectiveDeduction, 8);
			}

			let titleSuffix = "";

			// Security/defense skills listing threat IPs/URLs as examples: suppress finding
			if (isDefenseSkill && (classification.risk === "ip" || classification.risk === "unknown" || classification.risk === "raw")) {
				const urlIndex = content.indexOf(url);
				if (urlIndex >= 0 && isInThreatListingContext(content, urlIndex)) {
					effectiveDeduction = 0;
					severity = "low";
					titleSuffix = " (threat documentation)";
				}
			}

			score = Math.max(0, score - effectiveDeduction);

			findings.push({
				id: `DEP-URL-${findings.length + 1}`,
				category: "dependencies",
				severity,
				title: `${classification.risk === "ip" ? "Direct IP address" : classification.risk === "data" ? "Data URL" : classification.risk === "raw" ? "Raw content URL" : classification.risk === "local" ? "Local service URL" : "Unknown external"} reference${titleSuffix}`,
				description: `The skill references ${classification.risk === "ip" ? "a direct IP address" : classification.risk === "data" ? "a data: URL" : classification.risk === "raw" ? "a raw content hosting service" : classification.risk === "local" ? "a localhost or private-network service URL" : "an unknown external domain"} which is classified as ${severity} risk.`,
				evidence: url.slice(0, 200),
				deduction: effectiveDeduction,
				recommendation:
					classification.risk === "ip"
						? "Replace direct IP addresses with proper domain names. IP-based URLs bypass DNS-based security controls."
						: classification.risk === "raw"
							? "Use official package registries instead of raw content URLs. Raw URLs can be changed without notice."
							: classification.risk === "local"
								? "Review localhost/private-network service references carefully. Local service URLs can expose internal apps, admin panels, or developer tooling to agent-driven workflows."
								: "Verify that this external dependency is trustworthy and necessary.",
				owaspCategory: "ASST-04",
			});
		}

		if (hasCredentialBearingUrlParam(url)) {
			score = Math.max(0, score - 8);
			findings.push({
				id: `DEP-URL-CRED-${findings.length + 1}`,
				category: "dependencies",
				severity: "medium",
				title: "Credential-bearing URL parameter",
				description:
					"The skill includes a URL whose query parameters look like they carry cookies, auth state, or token material. URLs are commonly logged and replayed, so credential-bearing parameters expand the dependency risk surface even on first-party domains.",
				evidence: url.slice(0, 200),
				deduction: 8,
				recommendation:
					"Avoid query-string credential transport. Prefer secure headers, dedicated cookie APIs, or other mechanisms that do not expose bearer material in URLs.",
				owaspCategory: "ASST-04",
			});
		}
	}

	// Check for local service hints that appear before concrete localhost URLs.
	const ctx = buildContentContext(content);
	for (const hint of LOCAL_SERVICE_HINT_PATTERNS) {
		const globalHint = new RegExp(hint.regex.source, `${hint.regex.flags.replace("g", "")}g`);
		let match: RegExpExecArray | null;
		while ((match = globalHint.exec(content)) !== null) {
			const { severityMultiplier } = adjustForContext(match.index, content, ctx);
			if (severityMultiplier === 0) continue;

			const lineNumber = content.slice(0, match.index).split("\n").length;
			const deduction = 8;
			score = Math.max(0, score - deduction);
			findings.push({
				id: `DEP-LOCAL-HINT-${findings.length + 1}`,
				category: "dependencies",
				severity: "medium",
				title: hint.title,
				description:
					"The skill references a local-only service port or transport mode, which expands the reachable local attack surface even before explicit localhost URLs appear.",
				evidence: match[0].slice(0, 200),
				lineNumber,
				deduction,
				recommendation:
					"Review local service and exposed-port guidance carefully. Local transports and exposed ports can make internal tools or apps reachable by agent-driven workflows.",
				owaspCategory: "ASST-04",
			});
			break;
		}
	}

	for (const hint of REMOTE_SERVICE_HINT_PATTERNS) {
		const globalHint = new RegExp(hint.regex.source, `${hint.regex.flags.replace("g", "")}g`);
		let match: RegExpExecArray | null;
		while ((match = globalHint.exec(content)) !== null) {
			const { severityMultiplier } = adjustForContext(match.index, content, ctx);
			if (severityMultiplier === 0) continue;

			const lineNumber = content.slice(0, match.index).split("\n").length;
			const deduction = 8;
			score = Math.max(0, score - deduction);
			findings.push({
				id: `DEP-REMOTE-HINT-${findings.length + 1}`,
				category: "dependencies",
				severity: "medium",
				title: hint.title,
				description: hint.description,
				evidence: match[0].slice(0, 200),
				lineNumber,
				deduction,
				recommendation:
					"Review which external services or providers the skill depends on, what data crosses that boundary, and whether the dependency is necessary for the intended workflow.",
				owaspCategory: "ASST-04",
			});
			break;
		}
	}

	// Check for download-and-execute patterns (context-aware)
	for (const pattern of DOWNLOAD_EXECUTE_PATTERNS) {
		const globalPattern = new RegExp(pattern.source, `${pattern.flags.replace("g", "")}g`);
		let match: RegExpExecArray | null;
		while ((match = globalPattern.exec(content)) !== null) {
			const matchIndex = match.index;
			const lineNumber = content.slice(0, matchIndex).split("\n").length;

			// Skip truly negated mentions, but never break the scan: later matches may be real.
			const { severityMultiplier } = adjustForContext(matchIndex, content, ctx);
			if (severityMultiplier === 0) {
				continue;
			}

			// Reduce severity for known legitimate installers
			const isLegit = isLegitimateInstaller(content, matchIndex, match[0]);
			// Check if this is a description of threats to detect (security skill context)
			const inCodeBlock = isInsideCodeBlock(matchIndex, ctx);
			const isInThreatDesc = (() => {
				// Security/defense skills: use the broader threat-listing context detector
				if (isDefenseSkill && isInThreatListingContext(content, matchIndex)) return true;

				// Check the line itself — is it in a table row or list describing threats?
				let lineStart = content.lastIndexOf("\n", matchIndex - 1) + 1;
				if (lineStart < 0) lineStart = 0;
				let lineEnd = content.indexOf("\n", matchIndex);
				if (lineEnd < 0) lineEnd = content.length;
				const fullLine = content.slice(lineStart, lineEnd);

				// Table rows describing patterns/risks
				if (/^\s*\|.*\|/.test(fullLine) && /\b(?:critical|high|risk|dangerous|pattern|severity|pipe.to.shell)\b/i.test(fullLine)) return true;

				// Check preceding text for scan/detect/threat context
				const precText = content.slice(Math.max(0, matchIndex - 500), matchIndex);
				return /\b(?:scan\b.*\b(?:for|skill)|detect|flag|block|dangerous\s+(?:instruction|pattern|command)|malicious|malware|threat\s+pattern|what\s+(?:it|we)\s+detect|why\s+(?:it['']?s|this\s+(?:is|exists))\s+dangerous|findings?:|pattern.*risk|catch\s+them)\b/i.test(precText);
			})();

			if (isLegit || isInThreatDesc) {
				// Downgrade to informational — known installer or threat documentation
				findings.push({
					id: `DEP-DL-EXEC-${findings.length + 1}`,
					category: "dependencies",
					severity: "low",
					title: isLegit
						? "Download-and-execute pattern detected (known installer)"
						: "Download-and-execute pattern detected (in threat documentation)",
					description: isLegit
						? "The skill references a well-known installer script in its setup instructions."
						: "The skill describes a download-and-execute pattern as part of threat documentation.",
					evidence: match[0].slice(0, 200),
					lineNumber,
					deduction: 0,
					recommendation:
						"Consider documenting the exact version or hash of the installer for supply chain verification.",
					owaspCategory: "ASST-04",
				});
			} else if (inCodeBlock && /https:\/\//.test(match[0]) && !/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(match[0])) {
				// In a code block with HTTPS URL (no raw IP) — likely a setup example
				// Downgrade severity but still flag
				const deduction = 8;
				score = Math.max(0, score - deduction);
				findings.push({
					id: `DEP-DL-EXEC-${findings.length + 1}`,
					category: "dependencies",
					severity: "medium",
					title: "Download-and-execute pattern detected (inside code block)",
					description:
						"The skill contains a download-and-execute pattern inside a code block. Verify the URL is trustworthy.",
					evidence: match[0].slice(0, 200),
					lineNumber,
					deduction,
					recommendation:
						"Pin the installer to a specific version or hash. Consider bundling dependencies instead.",
					owaspCategory: "ASST-04",
				});
			} else {
				const deduction = 25;
				score = Math.max(0, score - deduction);

				findings.push({
					id: `DEP-DL-EXEC-${findings.length + 1}`,
					category: "dependencies",
					severity: "critical",
					title: "Download-and-execute pattern detected",
					description:
						"The skill contains instructions to download and execute external code, which is a severe supply chain risk.",
					evidence: match[0].slice(0, 200),
					lineNumber,
					deduction,
					recommendation:
						"Never download and execute external code. Bundle all required functionality within the skill.",
					owaspCategory: "ASST-04",
				});
			}
			break;
		}
	}

	// Check for npm lifecycle scripts inside embedded package.json code blocks
	let lifecycleFindingCount = 0;
	let lifecycleExecFindingCount = 0;
	let lifecycleDocFindingCount = 0;

	for (const block of extractJsonCodeBlockCandidates(content)) {
		const scripts = extractScriptsFromJsonBlock(block.content);
		if (!scripts) continue;

		const inDocContext = isExampleDocumentationContext(content, block.start);
		const lineNumber = content.slice(0, block.start).split("\n").length;

		for (const [scriptName, rawScriptValue] of Object.entries(scripts)) {
			if (!LIFECYCLE_SCRIPTS.has(scriptName.toLowerCase())) {
				continue;
			}
			if (typeof rawScriptValue !== "string") {
				continue;
			}

			const scriptValue = rawScriptValue.trim();
			let id: string;
			let severity: "critical" | "medium" | "low";
			let title: string;
			let description: string;
			let deduction: number;

			if (DANGEROUS_SCRIPT_CONTENT.test(scriptValue)) {
				lifecycleExecFindingCount += 1;
				id = `DEP-LIFECYCLE-EXEC-${lifecycleExecFindingCount}`;
				severity = "critical";
				title = `Dangerous npm lifecycle script detected (${scriptName})`;
				description =
					"The skill includes an npm lifecycle script with dangerous command content that may execute arbitrary code during install.";
				deduction = 20;
			} else if (inDocContext) {
				lifecycleDocFindingCount += 1;
				id = `DEP-LIFECYCLE-DOC-${lifecycleDocFindingCount}`;
				severity = "low";
				title = `Lifecycle script in documentation example (${scriptName})`;
				description =
					"An npm lifecycle script appears in an example/documentation section. Keep examples clearly marked as non-production.";
				deduction = 0;
			} else {
				lifecycleFindingCount += 1;
				id = `DEP-LIFECYCLE-${lifecycleFindingCount}`;
				severity = "medium";
				title = `Npm lifecycle script detected (${scriptName})`;
				description =
					"The skill includes an npm lifecycle script that runs automatically during install/publish and should be reviewed.";
				deduction = 8;
			}

			score = Math.max(0, score - deduction);

			findings.push({
				id,
				category: "dependencies",
				severity,
				title,
				description,
				evidence: `"${scriptName}": "${scriptValue}"`.slice(0, 200),
				lineNumber,
				deduction,
				recommendation:
					severity === "critical"
						? "Remove install-time lifecycle scripts or replace them with explicit, user-reviewed setup steps."
						: "Avoid install-time lifecycle hooks where possible, and document safer explicit setup commands.",
				owaspCategory: "ASST-04",
			});
		}
	}

	// Many external URLs can materially expand the attack surface, especially
	// when the skill also discusses auth, cookies, APIs, or payments.
	if (skill.urls.length > 3) {
		const hasSensitiveUrlContext = /\b(?:auth|authentication|cookie|token|login|payment|payments|mcp|credential|secret)\b/i.test(
			content,
		);
		const severity = hasSensitiveUrlContext ? "medium" : "info";
		const deduction = hasSensitiveUrlContext ? 8 : 0;
		score = Math.max(0, score - deduction);
		findings.push({
			id: "DEP-MANY-URLS",
			category: "dependencies",
			severity,
			title: `Many external URLs referenced (${skill.urls.length})`,
			description: hasSensitiveUrlContext
				? `The skill references ${skill.urls.length} external URLs and also discusses auth/API/payment workflows, which increases the chance that sensitive operations depend on many remote endpoints.`
				: `The skill references ${skill.urls.length} external URLs. While not inherently dangerous, many external dependencies increase the attack surface.`,
			evidence: `URLs: ${skill.urls.slice(0, 5).join(", ")}${skill.urls.length > 5 ? "..." : ""}`,
			deduction,
			recommendation: "Minimize external dependencies to reduce supply chain risk.",
			owaspCategory: "ASST-04",
		});
	}

	// Apply declared permissions — downgrade matching findings
	const adjustedFindings = applyDeclaredPermissions(findings, skill.declaredPermissions);

	// Recalculate score based on adjusted deductions
	let adjustedScore = 100;
	for (const f of adjustedFindings) {
		adjustedScore = Math.max(0, adjustedScore - f.deduction);
	}

	const summary =
		adjustedFindings.length === 0
			? "No dependency concerns detected."
			: `Found ${adjustedFindings.length} dependency-related findings. ${
					adjustedFindings.some((f) => f.severity === "critical")
						? "CRITICAL: Dependency execution patterns detected."
						: adjustedFindings.some((f) => f.severity === "high")
							? "High-risk external dependencies detected."
							: "Minor dependency concerns noted."
				}`;

	return {
		score: Math.max(0, Math.min(100, adjustedScore)),
		weight: 0.15,
		findings: adjustedFindings,
		summary,
	};
}
