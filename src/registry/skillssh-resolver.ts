/**
 * Resolves skills.sh sitemap URLs to raw GitHub content URLs.
 *
 * skills.sh indexes GitHub-hosted skills with URL pattern:
 *   https://skills.sh/{owner}/{repo}/{skill-slug}
 *
 * The SKILL.md file lives in the GitHub repo at one of several paths:
 *   - skills/{folder}/SKILL.md
 *   - {folder}/SKILL.md
 *   - SKILL.md (root, for single-skill repos)
 *
 * The folder name may differ from the skills.sh slug (e.g., slug "remotion-best-practices"
 * might be in folder "remotion"). We resolve by probing the repo structure.
 */

import { writeFile } from "node:fs/promises";
import { SCANNER_VERSION } from "../scanner/types.js";

export interface SkillsShEntry {
	readonly owner: string;
	readonly repo: string;
	readonly slug: string;
	readonly skillsShUrl: string;
}

export interface ResolvedSkill {
	readonly entry: SkillsShEntry;
	readonly rawUrl: string;
}

interface RepoInfo {
	readonly owner: string;
	readonly repo: string;
	readonly skills: SkillsShEntry[];
}

const RAW_BASE = "https://raw.githubusercontent.com";
const BRANCHES = ["main", "master"] as const;

// Path patterns to try, in order of likelihood
const PATH_PATTERNS = [
	(slug: string) => `skills/${slug}/SKILL.md`,
	(slug: string) => `${slug}/SKILL.md`,
	(slug: string) => `skills/${slug}/SKILL.md`.toLowerCase(),
	(_slug: string) => `SKILL.md`, // root (only for single-skill repos)
] as const;

/**
 * Parse a skills.sh sitemap XML into entries.
 */
export function parseSitemap(xml: string): SkillsShEntry[] {
	const entries: SkillsShEntry[] = [];
	// skills.sh serves skill URLs under both the apex and the www host
	// (the apex 308-redirects to www). Accept either. The three captured
	// segments are owner/repo/slug; child sitemap URLs (sitemap-skills-1.xml,
	// owner-only pages) have fewer segments and are correctly skipped.
	const urlPattern = /https:\/\/(?:www\.)?skills\.sh\/([^/\s<]+)\/([^/\s<]+)\/([^/\s<]+)/g;
	let match: RegExpExecArray | null;

	while ((match = urlPattern.exec(xml)) !== null) {
		const owner = match[1] as string;
		const repo = match[2] as string;
		const slug = match[3] as string;
		entries.push({
			owner,
			repo,
			slug,
			skillsShUrl: match[0],
		});
	}
	return entries;
}

/**
 * Group entries by repo.
 */
function groupByRepo(entries: SkillsShEntry[]): RepoInfo[] {
	const map = new Map<string, RepoInfo>();
	for (const entry of entries) {
		const key = `${entry.owner}/${entry.repo}`;
		const existing = map.get(key);
		if (existing) {
			existing.skills.push(entry);
		} else {
			map.set(key, { owner: entry.owner, repo: entry.repo, skills: [entry] });
		}
	}
	return [...map.values()];
}

/**
 * Probe a URL and return true if it returns 200.
 */
async function probeUrl(url: string, timeout: number): Promise<boolean> {
	try {
		const response = await fetch(url, {
			method: "HEAD",
			signal: AbortSignal.timeout(timeout),
			headers: { "User-Agent": `AgentVerusScanner/${SCANNER_VERSION}` },
		});
		return response.ok;
	} catch {
		return false;
	}
}

/**
 * Discover the branch and path pattern for a repo by probing with the first skill.
 */
async function discoverRepoPattern(
	repo: RepoInfo,
	timeout: number,
): Promise<{ branch: string; pathFn: (slug: string) => string } | null> {
	const firstSkill = repo.skills[0];
	if (!firstSkill) return null;

	for (const branch of BRANCHES) {
		for (const pathFn of PATH_PATTERNS) {
			const path = pathFn(firstSkill.slug);
			const url = `${RAW_BASE}/${repo.owner}/${repo.repo}/${branch}/${path}`;
			if (await probeUrl(url, timeout)) {
				return { branch, pathFn };
			}
		}
	}

	return null;
}

export interface ResolveOptions {
	/** Probe timeout in ms */
	readonly timeout?: number;
	/** Max concurrent repo probes */
	readonly concurrency?: number;
	/** Progress callback */
	readonly onProgress?: (resolved: number, total: number, repo: string) => void;
	/** Error callback */
	readonly onUnresolved?: (repo: string, slugs: string[]) => void;
}

export interface ResolveResult {
	readonly resolved: ResolvedSkill[];
	readonly unresolved: SkillsShEntry[];
	readonly repoCount: number;
	readonly resolvedRepoCount: number;
}

/**
 * Try to find the raw URL for a single skill using HEAD probes.
 * Tries common path patterns with slug variations.
 */
async function probeSkillUrl(
	owner: string,
	repo: string,
	slug: string,
	timeout: number,
): Promise<string | null> {
	// Generate slug variations: the skills.sh slug may not match the folder name exactly
	const slugVariations = new Set([slug]);
	// Try without common owner/repo prefix (e.g., "vercel-react-best-practices" → "react-best-practices")
	const ownerLower = owner.toLowerCase();
	if (slug.startsWith(`${ownerLower}-`)) {
		slugVariations.add(slug.slice(ownerLower.length + 1));
	}
	// Try just the last part after the last hyphen group that forms a meaningful name
	const repoLower = repo.toLowerCase().replace(/-/g, "");
	if (slug.replace(/-/g, "").startsWith(repoLower)) {
		const remainder = slug.slice(repo.length).replace(/^-+/, "");
		if (remainder) slugVariations.add(remainder);
	}

	for (const branch of BRANCHES) {
		for (const variation of slugVariations) {
			// Try: skills/{variation}/SKILL.md (most common for multi-skill repos)
			const url1 = `${RAW_BASE}/${owner}/${repo}/${branch}/skills/${variation}/SKILL.md`;
			if (await probeUrl(url1, timeout)) return url1;

			// Try: {variation}/SKILL.md (flat layout)
			const url2 = `${RAW_BASE}/${owner}/${repo}/${branch}/${variation}/SKILL.md`;
			if (await probeUrl(url2, timeout)) return url2;
		}

		// Try root SKILL.md (single-skill repos)
		const rootUrl = `${RAW_BASE}/${owner}/${repo}/${branch}/SKILL.md`;
		if (await probeUrl(rootUrl, timeout)) return rootUrl;
	}

	return null;
}

export interface ResolveSkillsShUrlOptions {
	/** Probe timeout in ms */
	readonly timeout?: number;
}

/**
 * Resolve a single skills.sh URL to a raw GitHub SKILL.md URL.
 *
 * Example:
 *   https://skills.sh/owner/repo/skill-slug
 */
export async function resolveSkillsShUrl(
	skillsShUrl: string,
	opts?: ResolveSkillsShUrlOptions,
): Promise<string> {
	let parsed: URL;
	try {
		parsed = new URL(skillsShUrl);
	} catch {
		throw new Error(`Invalid skills.sh URL: ${skillsShUrl}`);
	}

	if (parsed.hostname !== "skills.sh" && parsed.hostname !== "www.skills.sh") {
		throw new Error(`Not a skills.sh URL: ${skillsShUrl}`);
	}

	const parts = parsed.pathname.split("/").filter(Boolean);
	const owner = parts[0];
	const repo = parts[1];
	const slug = parts[2];

	if (!owner || !repo || !slug) {
		throw new Error(`Invalid skills.sh URL (expected /owner/repo/skill): ${skillsShUrl}`);
	}

	const timeout = opts?.timeout ?? 10_000;
	const rawUrl = await probeSkillUrl(owner, repo, slug, timeout);
	if (!rawUrl) {
		throw new Error(`Could not resolve skills.sh URL to raw SKILL.md: ${skillsShUrl}`);
	}
	return rawUrl;
}

/**
 * Resolve all skills.sh entries to raw GitHub URLs.
 *
 * Strategy:
 * 1. For each repo, try path probing with the first skill to discover the pattern
 * 2. Apply the discovered pattern to all skills in the same repo
 * 3. For repos where pattern discovery fails, probe each skill individually
 */
export async function resolveSkillsShUrls(
	entries: SkillsShEntry[],
	opts?: ResolveOptions,
): Promise<ResolveResult> {
	const timeout = opts?.timeout ?? 10_000;
	const concurrency = opts?.concurrency ?? 20;

	const repos = groupByRepo(entries);
	const resolved: ResolvedSkill[] = [];
	const unresolved: SkillsShEntry[] = [];
	let resolvedRepos = 0;
	let completedRepos = 0;

	const queue = [...repos];
	const workers: Promise<void>[] = [];

	for (let i = 0; i < concurrency; i++) {
		workers.push(
			(async () => {
				while (true) {
					const repo = queue.shift();
					if (!repo) break;

					// Strategy 1: Discover pattern from first skill
					const pattern = await discoverRepoPattern(repo, timeout);
					if (pattern) {
						resolvedRepos++;
						for (const skill of repo.skills) {
							const path = pattern.pathFn(skill.slug);
							const rawUrl = `${RAW_BASE}/${repo.owner}/${repo.repo}/${pattern.branch}/${path}`;
							resolved.push({ entry: skill, rawUrl });
						}
					} else {
						// Strategy 2: Probe each skill individually with slug variations
						let anyFound = false;
						for (const skill of repo.skills) {
							const url = await probeSkillUrl(repo.owner, repo.repo, skill.slug, timeout);
							if (url) {
								resolved.push({ entry: skill, rawUrl: url });
								anyFound = true;
							} else {
								unresolved.push(skill);
							}
						}
						if (anyFound) resolvedRepos++;
						else {
							opts?.onUnresolved?.(
								`${repo.owner}/${repo.repo}`,
								repo.skills.map((s) => s.slug),
							);
						}
					}

					completedRepos++;
					opts?.onProgress?.(completedRepos, repos.length, `${repo.owner}/${repo.repo}`);
				}
			})(),
		);
	}

	await Promise.all(workers);

	return {
		resolved,
		unresolved,
		repoCount: repos.length,
		resolvedRepoCount: resolvedRepos,
	};
}

const SKILLS_SH_SITEMAP_URL = "https://skills.sh/sitemap.xml";

async function fetchSitemapXml(url: string): Promise<string> {
	const response = await fetch(url, {
		headers: { "User-Agent": `AgentVerusScanner/${SCANNER_VERSION}` },
		signal: AbortSignal.timeout(30_000),
	});
	if (!response.ok) {
		throw new Error(`Failed to fetch sitemap ${url}: ${response.status}`);
	}
	return response.text();
}

/**
 * Extract child sitemap `<loc>` URLs from a `<sitemapindex>` document.
 */
export function parseSitemapIndex(xml: string): string[] {
	const locs: string[] = [];
	const locPattern = /<loc>\s*([^<\s]+)\s*<\/loc>/g;
	let match: RegExpExecArray | null;
	while ((match = locPattern.exec(xml)) !== null) {
		locs.push(match[1] as string);
	}
	return locs;
}

/**
 * Fetch the skills.sh sitemap and return parsed entries.
 *
 * skills.sh now serves a `<sitemapindex>` at /sitemap.xml that points at child
 * sitemaps (sitemap-skills-1.xml, ...) where the actual skill URLs live. Older
 * deployments served a flat sitemap of skill URLs directly. Handle both: if the
 * root is an index, fetch every child sitemap and parse skill URLs out of the
 * combined XML; otherwise parse the root directly.
 */
export async function fetchSkillsShSitemap(): Promise<SkillsShEntry[]> {
	const root = await fetchSitemapXml(SKILLS_SH_SITEMAP_URL);

	if (/<sitemapindex[\s>]/i.test(root)) {
		const childUrls = parseSitemapIndex(root);
		const childXmls = await Promise.all(
			childUrls.map(async (url) => {
				try {
					return await fetchSitemapXml(url);
				} catch {
					// A single unreachable child sitemap should not abort the whole
					// collection — skip it and parse whatever else resolved.
					return "";
				}
			}),
		);
		return parseSitemap(childXmls.join("\n"));
	}

	return parseSitemap(root);
}

/**
 * Write resolved URLs to a file compatible with our batch scanner.
 * Format: one raw GitHub URL per line.
 */
export async function writeResolvedUrls(
	skills: ResolvedSkill[],
	outPath: string,
): Promise<void> {
	const lines = skills.map((s) => s.rawUrl);
	await writeFile(outPath, lines.join("\n") + "\n", "utf-8");
}
