import { unzipSync } from "fflate";

import type { ScanOptions } from "./types.js";
import { SCANNER_VERSION } from "./types.js";

const DEFAULT_HEADERS: Readonly<Record<string, string>> = {
	Accept: "text/plain,text/markdown,text/html;q=0.9,application/zip;q=0.8,*/*;q=0.7",
	"User-Agent": `AgentVerusScanner/${SCANNER_VERSION}`,
};

const CLAWHUB_HOST = "clawhub.ai";
const CLAWHUB_DOWNLOAD_BASE = "https://auth.clawdhub.com/api/v1/download";

function normalizeGithubUrl(url: URL): string {
	if (url.hostname !== "github.com") return url.toString();

	// Convert GitHub "blob" URLs to raw content URLs.
	// https://github.com/<owner>/<repo>/blob/<branch>/<path>
	const parts = url.pathname.split("/").filter(Boolean);
	if (parts.length >= 5 && parts[2] === "blob") {
		const owner = parts[0] as string;
		const repo = parts[1] as string;
		const branch = parts[3] as string;
		const path = parts.slice(4).join("/");
		return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
	}

	return url.toString();
}

function normalizeClawHubUrl(url: URL): string {
	// Skill pages are at: https://clawhub.ai/<owner>/<slug>
	// Bulk scan should prefer downloading the bundle zip and extracting SKILL.md.
	if (url.hostname !== CLAWHUB_HOST) return url.toString();

	const parts = url.pathname.split("/").filter(Boolean);
	if (parts.length < 2) return url.toString();

	const [first, second] = parts;
	if (!first || !second) return url.toString();

	// Exclude known non-skill routes. This list is intentionally small.
	if (
		first === "admin" ||
		first === "assets" ||
		first === "cli" ||
		first === "dashboard" ||
		first === "import" ||
		first === "management" ||
		first === "og" ||
		first === "settings" ||
		first === "skills" ||
		first === "souls" ||
		first === "stars" ||
		first === "u" ||
		first === "upload"
	) {
		return url.toString();
	}

	const downloadUrl = new URL(CLAWHUB_DOWNLOAD_BASE);
	downloadUrl.searchParams.set("slug", second);
	return downloadUrl.toString();
}

export function normalizeSkillUrl(inputUrl: string): string {
	let url: URL;
	try {
		url = new URL(inputUrl);
	} catch {
		return inputUrl;
	}

	if (url.hostname === CLAWHUB_HOST) return normalizeClawHubUrl(url);
	if (url.hostname === "github.com") return normalizeGithubUrl(url);
	return url.toString();
}

function isZipResponse(contentType: string | null, url: string): boolean {
	if (contentType?.toLowerCase().includes("application/zip")) return true;
	try {
		const parsed = new URL(url);
		return parsed.hostname === "auth.clawdhub.com" && parsed.pathname === "/api/v1/download";
	} catch {
		return false;
	}
}

function isClawHubDownloadUrl(url: string): boolean {
	try {
		const parsed = new URL(url);
		return parsed.hostname === "auth.clawdhub.com" && parsed.pathname === "/api/v1/download";
	} catch {
		return false;
	}
}

function pickSkillMdPath(filePaths: readonly string[]): string | null {
	const candidates = filePaths.filter((p) => {
		const base = p.split("/").pop() ?? p;
		const lower = base.toLowerCase();
		return lower === "skill.md" || lower === "skills.md";
	});
	if (candidates.length === 0) return null;

	const rank = (p: string): number => {
		const base = p.split("/").pop() ?? p;
		const lowerBase = base.toLowerCase();
		const lower = p.toLowerCase();

		// Prefer the conventional "SKILL.md" file; fall back to "SKILLS.md" which
		// appears in some bundles. Prefer shallower paths.
		if (lowerBase === "skill.md" && lower === "skill.md") return 0;
		if (lowerBase === "skill.md") return 1;
		if (lowerBase === "skills.md" && lower === "skills.md") return 2;
		if (lowerBase === "skills.md") return 3;
		return 4;
	};

	return (
		[...candidates].sort((a, b) => rank(a) - rank(b) || a.length - b.length || a.localeCompare(b))[0] ??
		null
	);
}

function formatHttpErrorBodySnippet(text: string): string {
	const cleaned = text.replace(/\s+/g, " ").trim();
	if (!cleaned) return "";
	return cleaned.length > 200 ? `${cleaned.slice(0, 200)}...` : cleaned;
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableStatus(status: number): boolean {
	return status === 429 || (status >= 500 && status <= 599);
}

function parseRetryAfterMs(value: string | null): number | null {
	if (!value) return null;
	const seconds = Number.parseInt(value, 10);
	if (!Number.isNaN(seconds)) return Math.max(0, seconds * 1000);
	const dateMs = Date.parse(value);
	if (!Number.isNaN(dateMs)) return Math.max(0, dateMs - Date.now());
	return null;
}

function isRetryableError(error: unknown): boolean {
	if (!(error instanceof Error)) return false;

	if (error.name === "AbortError" || /aborted due to timeout/i.test(error.message)) return true;
	if (/fetch failed/i.test(error.message)) return true;
	if (/Zip did not contain/i.test(error.message)) return false;

	return false;
}

export async function fetchSkillContentFromUrl(
	inputUrl: string,
	options?: ScanOptions,
): Promise<{ readonly content: string; readonly sourceUrl: string }> {
	const sourceUrl = normalizeSkillUrl(inputUrl);

	const retries = Math.max(0, options?.retries ?? 2);
	const baseDelayMs = Math.max(0, options?.retryDelayMs ?? 750);
	const defaultTimeoutMs = isClawHubDownloadUrl(sourceUrl) ? 45_000 : 30_000;
	const timeoutMsRaw = options?.timeout;
	const timeoutMs = timeoutMsRaw === undefined ? defaultTimeoutMs : timeoutMsRaw;

	let lastError: unknown;

	for (let attempt = 0; attempt <= retries; attempt += 1) {
		try {
			const response = await fetch(sourceUrl, {
				headers: DEFAULT_HEADERS,
				signal: timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined,
			});

			if (!response.ok) {
				if (attempt < retries && isRetryableStatus(response.status)) {
					const retryAfter = parseRetryAfterMs(response.headers.get("retry-after"));
					const backoffMs =
						retryAfter ??
						Math.min(30_000, baseDelayMs * 2 ** attempt + Math.round(Math.random() * 250));
					await sleep(backoffMs);
					continue;
				}

				let snippet = "";
				try {
					snippet = formatHttpErrorBodySnippet(await response.text());
				} catch {
					// Ignore body read failures.
				}

				throw new Error(
					`Failed to fetch skill from ${sourceUrl}: ${response.status} ${response.statusText}${snippet ? ` — ${snippet}` : ""}`,
				);
			}

			const contentType = response.headers.get("content-type");
			if (isZipResponse(contentType, sourceUrl)) {
				const zipBytes = new Uint8Array(await response.arrayBuffer());
				const files = unzipSync(zipBytes);
				const paths = Object.keys(files);
				const skillMdPath = pickSkillMdPath(paths);
				if (!skillMdPath) {
					const preview = paths.sort().slice(0, 20).join(", ");
					throw new Error(
						`Zip did not contain SKILL.md (found ${paths.length} files). First files: ${preview}`,
					);
				}

				const decoder = new TextDecoder("utf-8");
				return { content: decoder.decode(files[skillMdPath]), sourceUrl };
			}

			return { content: await response.text(), sourceUrl };
		} catch (err) {
			lastError = err;
			if (attempt < retries && isRetryableError(err)) {
				const backoffMs = Math.min(30_000, baseDelayMs * 2 ** attempt + Math.round(Math.random() * 250));
				await sleep(backoffMs);
				continue;
			}
			throw err;
		}
	}

	throw lastError instanceof Error ? lastError : new Error("Failed to fetch skill content");
}
