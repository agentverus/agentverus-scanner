import type { Category, Finding } from "./types.js";

const AUTH_PROFILE_RELATED = /(auth|cookie|profile|session|token|vault|login)/i;
const CATEGORY_PREFERENCE: Record<Category, number> = {
	behavioral: 0,
	injection: 1,
	dependencies: 2,
	permissions: 3,
	content: 4,
	"code-safety": 5,
};

export const TARGET_RENDERED_DUPLICATE_KEYS = new Set<string>([
	"behavioral::browser content extraction detected",
	"behavioral::ui state enumeration detected",
	"behavioral::skill path discovery detected",
	"behavioral::external instruction override file detected",
	"behavioral::server lifecycle orchestration detected",
	"behavioral::remote documentation ingestion detected",
	"behavioral::host environment reconnaissance detected",
	"behavioral::external tool bridge detected",
	"behavioral::remote transport exposure detected",
	"behavioral::unrestricted scope detected",
	"behavioral::remote browser delegation detected",
	"behavioral::remote task delegation detected",
	"behavioral::secret parameter handling detected",
	"behavioral::compound browser action chaining detected",
	"behavioral::credential form automation detected",
	"behavioral::opaque helper script execution detected",
	"behavioral::os input automation detected",
	"behavioral::external ai provider delegation detected",
	"behavioral::temporary script execution detected",
	"behavioral::dev server auto-detection detected",
	"behavioral::container runtime control detected",
	"behavioral::local service access detected",
	"behavioral::package bootstrap execution detected",
	"dependencies::unknown external reference",
	"dependencies::local service url reference",
	"dependencies::raw content url reference",
]);

export function isBrowserAuthOverlapCandidate(finding: Finding): boolean {
	if (finding.severity !== "high" && finding.severity !== "medium") return false;
	return AUTH_PROFILE_RELATED.test(`${finding.title}\n${finding.description}\n${finding.evidence}`);
}

export function normalizeEvidence(evidence: string): string {
	return evidence
		.toLowerCase()
		.replace(/https?:\/\/[^\s)\]]+/g, (url) =>
			url.replace(/([?&][^=]+=)[^&#\s)\]]+/g, "$1<value>"),
		)
		.replace(/"[^"]+"|'[^']+'/g, '"<value>"')
		.replace(/\b\d+\b/g, "#")
		.replace(/<[^>]+>/g, "<value>")
		.replace(/\s+/g, " ")
		.trim();
}

export function overlapPriority(
	finding: Finding,
	severityOrder: Readonly<Record<string, number>>,
): number {
	let penalty = 0;
	if (finding.title.startsWith("Capability contract mismatch")) penalty += 20;
	if (finding.title.startsWith("Many external URLs")) penalty += 12;
	if (finding.title.startsWith("Unknown external reference")) penalty += 10;
	if (finding.title.startsWith("External reference")) penalty += 10;
	return (
		(severityOrder[finding.severity] ?? 4) * 100 +
		(CATEGORY_PREFERENCE[finding.category] ?? 5) * 10 +
		penalty -
		Math.min(finding.deduction, 9)
	);
}

export function normalizeAuthTitle(title: string): string {
	return title
		.toLowerCase()
		.replace(/\s*\(inside code block\)/g, "")
		.replace(/\s*\(merged[^)]*\)/g, "")
		.trim();
}

export function cleanMergedTitle(title: string): string {
	return title
		.replace(/\s*\(inside code block\)/gi, "")
		.replace(/\s*\(merged[^)]*\)/gi, "")
		.trim();
}

export function authFamilyKey(finding: Finding): string | null {
	const hay = `${finding.title}\n${finding.description}\n${finding.evidence}`.toLowerCase();

	if (finding.category === "permissions" && finding.title.startsWith("Capability contract mismatch")) {
		if (/(profile|chrome|cdp|browser session|browser profile|auth state)/i.test(hay)) {
			return "permissions::browser-profile-auth";
		}
		if (/(auth cookie|cookie url|query string|credential handoff)/i.test(hay)) {
			return "permissions::cookie-handoff";
		}
		if (/(credential storage|credential store|auth vault|auth_cookies)/i.test(hay)) {
			return "permissions::credential-store";
		}
		if (/(persistent session|session management|session saved|state save|state load|session-name|background daemon)/i.test(hay)) {
			return "permissions::session-state";
		}
	}

	if (finding.category === "behavioral") {
		if (/(mcp-issued browser auth cookie|credential in query string|cookie bootstrap redirect|cookie header replay)/i.test(hay)) {
			return "behavioral::cookie-handoff-flow";
		}
		if (/(browser profile copy|full browser profile sync|browser session attachment|profile-backed session persistence|auth import from user browser|browser auth state handling)/i.test(hay)) {
			return "behavioral::browser-profile-flow";
		}
		if (/(persistent session reuse|session inventory and reuse|state file replay)/i.test(hay)) {
			return "behavioral::session-reuse-flow";
		}
		if (/(credential vault enrollment|federated auth flow|environment secret piping)/i.test(hay)) {
			return "behavioral::credential-store-flow";
		}
	}

	if (finding.category === "dependencies") {
		if (/(credential-bearing url parameter|credential query-parameter transport)/i.test(hay)) {
			return "dependencies::query-auth-transport";
		}
		if (/(persistent credential-state store|reusable authenticated browser container)/i.test(hay)) {
			return "dependencies::session-store";
		}
	}

	return null;
}

export function behavioralDependencyFamily(finding: Finding): string | null {
	const hay = `${cleanMergedTitle(finding.title)}\n${finding.description}\n${finding.evidence}`.toLowerCase();
	if (/(credential-bearing url parameter|credential query-parameter transport)/i.test(hay)) {
		return "cookie-handoff";
	}
	if (/reusable authenticated browser container/i.test(hay)) {
		return "browser-container";
	}
	if (/persistent credential-state store/i.test(hay)) {
		return "credential-store";
	}
	return null;
}

export function behavioralAuthFamily(finding: Finding): string | null {
	if (finding.category !== "behavioral") return null;
	const hay = `${cleanMergedTitle(finding.title)}\n${finding.description}\n${finding.evidence}`.toLowerCase();
	if (/(mcp-issued browser auth cookie|credential in query string|cookie bootstrap redirect|cookie header replay|browser auth state handling)/i.test(hay)) {
		return "cookie-handoff";
	}
	if (/(browser profile copy|full browser profile sync|browser session attachment|profile-backed session persistence|auth import from user browser|persistent session reuse|state file replay)/i.test(hay)) {
		return "browser-container";
	}
	if (/(credential vault enrollment|credential store persistence|federated auth flow|environment secret piping|browser auth state handling)/i.test(hay)) {
		return "credential-store";
	}
	return null;
}

export function broadBehavioralAuthFamily(finding: Finding): string | null {
	if (finding.category !== "behavioral") return null;
	const hay = `${cleanMergedTitle(finding.title)}\n${finding.description}\n${finding.evidence}`.toLowerCase();
	if (/(mcp-issued browser auth cookie|credential in query string|cookie bootstrap redirect|cookie header replay|browser auth state handling|authentication integration surface)/i.test(hay)) {
		return "behavioral::cookie-browser-auth";
	}
	if (/credential store persistence/i.test(hay) && /(auth_cookies|cookie)/i.test(hay)) {
		return "behavioral::cookie-browser-auth";
	}
	if (/(browser profile copy|browser session attachment|profile-backed session persistence|persistent session reuse|auth import from user browser|state file replay)/i.test(hay)) {
		return "behavioral::browser-container";
	}
	if (/(credential vault enrollment|credential store persistence|federated auth flow|environment secret piping)/i.test(hay)) {
		return "behavioral::credential-store";
	}
	return null;
}
