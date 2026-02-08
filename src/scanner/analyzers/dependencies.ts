import type { CategoryScore, Finding, ParsedSkill } from "../types.js";
import { buildContentContext, isInsideCodeBlock, isInsideSafetySection } from "./context.js";
import { applyDeclaredPermissions } from "./declared-match.js";

/** Trusted domain patterns */
const TRUSTED_DOMAINS = [
	/^github\.com\/(?!.*\/raw\/)/,
	/^npmjs\.com/,
	/^registry\.npmjs\.org/,
	/^pypi\.org/,
	/^docs\./,
	/^developer\./,
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
	/^(?:[\w-]+\.)?vercel\.app/,
	/^(?:[\w-]+\.)?netlify\.app/,
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

	// Check if the match is inside a prerequisites/setup/installation section
	// by looking at nearby headings
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
	risk: "trusted" | "raw" | "ip" | "data" | "unknown";
	deduction: number;
} {
	if (url.startsWith("data:")) {
		return { risk: "data", deduction: 20 };
	}

	const hostname = getHostname(url);

	if (IP_ADDRESS_REGEX.test(hostname)) {
		// Localhost and private IPs are not suspicious — they're local services
		if (PRIVATE_IP_REGEX.test(hostname)) {
			return { risk: "trusted", deduction: 0 };
		}
		return { risk: "ip", deduction: 20 };
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

/** Analyze dependencies and external URLs */
export async function analyzeDependencies(skill: ParsedSkill): Promise<CategoryScore> {
	const findings: Finding[] = [];
	let score = 100;
	const content = skill.rawContent;

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

			score = Math.max(0, score - effectiveDeduction);

			const severity =
				classification.risk === "ip" || classification.risk === "data"
					? "high"
					: classification.risk === "raw"
						? "medium"
						: "low";

			findings.push({
				id: `DEP-URL-${findings.length + 1}`,
				category: "dependencies",
				severity,
				title: `${classification.risk === "ip" ? "Direct IP address" : classification.risk === "data" ? "Data URL" : classification.risk === "raw" ? "Raw content URL" : "Unknown external"} reference`,
				description: `The skill references ${classification.risk === "ip" ? "a direct IP address" : classification.risk === "data" ? "a data: URL" : classification.risk === "raw" ? "a raw content hosting service" : "an unknown external domain"} which is classified as ${severity} risk.`,
				evidence: url.slice(0, 200),
				deduction: effectiveDeduction,
				recommendation:
					classification.risk === "ip"
						? "Replace direct IP addresses with proper domain names. IP-based URLs bypass DNS-based security controls."
						: classification.risk === "raw"
							? "Use official package registries instead of raw content URLs. Raw URLs can be changed without notice."
							: "Verify that this external dependency is trustworthy and necessary.",
				owaspCategory: "ASST-04",
			});
		}
	}

	// Check for download-and-execute patterns (context-aware)
	const ctx = buildContentContext(content);
	for (const pattern of DOWNLOAD_EXECUTE_PATTERNS) {
		const globalPattern = new RegExp(pattern.source, `${pattern.flags.replace("g", "")}g`);
		let match: RegExpExecArray | null;
		while ((match = globalPattern.exec(content)) !== null) {
			const matchIndex = match.index;
			const lineNumber = content.slice(0, matchIndex).split("\n").length;

			// Skip matches inside safety sections
			if (isInsideSafetySection(matchIndex, ctx)) {
				break;
			}

			// Skip matches inside code blocks (educational examples)
			const inCodeBlock = isInsideCodeBlock(matchIndex, ctx);
			if (inCodeBlock && isInsideSafetySection(matchIndex, ctx)) {
				break;
			}

			// Reduce severity for known legitimate installers or prerequisite sections
			const isLegit = isLegitimateInstaller(content, matchIndex, match[0]);
			// Also reduce if inside a code block (likely a setup example)
			const isEducational = inCodeBlock;
			// Check if this is a description of threats to detect (security skill)
			const isInThreatDesc = (() => {
				const precText = content.slice(Math.max(0, matchIndex - 500), matchIndex);
				return /\b(?:scan|detect|flag|block|dangerous|malicious|threat|attack|what\s+it\s+detect|why\s+(?:it['']?s|this\s+(?:is|exists)))\b/i.test(precText);
			})();

			if (isLegit || isEducational || isInThreatDesc) {
				// Downgrade to informational — not a real threat
				findings.push({
					id: `DEP-DL-EXEC-${findings.length + 1}`,
					category: "dependencies",
					severity: "low",
					title: "Download-and-execute pattern detected (in setup/prerequisites)",
					description: isLegit
						? "The skill references a well-known installer script in its setup instructions."
						: "The skill contains a download-and-execute pattern inside a code block or setup section.",
					evidence: match[0].slice(0, 200),
					lineNumber,
					deduction: 0,
					recommendation:
						"Consider documenting the exact version or hash of the installer for supply chain verification.",
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

	// Informational: many external URLs
	if (skill.urls.length > 5) {
		findings.push({
			id: "DEP-MANY-URLS",
			category: "dependencies",
			severity: "info",
			title: `Many external URLs referenced (${skill.urls.length})`,
			description: `The skill references ${skill.urls.length} external URLs. While not inherently dangerous, many external dependencies increase the attack surface.`,
			evidence: `URLs: ${skill.urls.slice(0, 5).join(", ")}${skill.urls.length > 5 ? "..." : ""}`,
			deduction: 0,
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
						? "CRITICAL: Download-and-execute patterns detected."
						: adjustedFindings.some((f) => f.severity === "high")
							? "High-risk external dependencies detected."
							: "Minor dependency concerns noted."
				}`;

	return {
		score: Math.max(0, Math.min(100, adjustedScore)),
		weight: 0.2,
		findings: adjustedFindings,
		summary,
	};
}
