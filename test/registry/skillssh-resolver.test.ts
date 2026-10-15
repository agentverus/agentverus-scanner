import { afterEach, describe, expect, it, vi } from "vitest";
import {
	fetchSkillsShSitemap,
	parseSitemap,
	parseSitemapIndex,
	resolveSkillsShUrl,
} from "../../src/registry/skillssh-resolver.js";

const INDEX_XML = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://www.skills.sh/sitemap-misc.xml</loc></sitemap>
  <sitemap><loc>https://www.skills.sh/sitemap-owners.xml</loc></sitemap>
  <sitemap><loc>https://www.skills.sh/sitemap-skills-1.xml</loc></sitemap>
</sitemapindex>`;

const SKILLS_CHILD_XML = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://www.skills.sh/vercel-labs/skills/find-skills</loc></url>
  <url><loc>https://www.skills.sh/anthropics/skills/frontend-design</loc></url>
</urlset>`;

const OWNERS_CHILD_XML = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://www.skills.sh/vercel-labs</loc></url>
</urlset>`;

describe("parseSitemap", () => {
	it("matches skill URLs on both the apex and www host", () => {
		const xml = `
			<loc>https://skills.sh/acme/repo/alpha</loc>
			<loc>https://www.skills.sh/vercel-labs/skills/find-skills</loc>`;
		const entries = parseSitemap(xml);
		expect(entries).toHaveLength(2);
		expect(entries[0]).toMatchObject({ owner: "acme", repo: "repo", slug: "alpha" });
		expect(entries[1]).toMatchObject({
			owner: "vercel-labs",
			repo: "skills",
			slug: "find-skills",
			skillsShUrl: "https://www.skills.sh/vercel-labs/skills/find-skills",
		});
	});

	it("skips index and owner-only URLs (fewer than 3 path segments)", () => {
		const xml = `
			<loc>https://www.skills.sh/sitemap-skills-1.xml</loc>
			<loc>https://www.skills.sh/vercel-labs</loc>`;
		expect(parseSitemap(xml)).toHaveLength(0);
	});
});

describe("parseSitemapIndex", () => {
	it("extracts every child sitemap loc", () => {
		expect(parseSitemapIndex(INDEX_XML)).toEqual([
			"https://www.skills.sh/sitemap-misc.xml",
			"https://www.skills.sh/sitemap-owners.xml",
			"https://www.skills.sh/sitemap-skills-1.xml",
		]);
	});
});

describe("fetchSkillsShSitemap", () => {
	const savedFetch = globalThis.fetch;
	afterEach(() => {
		globalThis.fetch = savedFetch;
		vi.restoreAllMocks();
	});

	function mockFetch(routes: Record<string, string | null>) {
		const fetchMock = vi.fn(async (input: string | URL) => {
			const url = typeof input === "string" ? input : input.toString();
			const body = routes[url];
			if (body == null) return new Response("not found", { status: 404 });
			return new Response(body, { status: 200 });
		});
		// @ts-expect-error - override global fetch for tests
		globalThis.fetch = fetchMock;
		return fetchMock;
	}

	it("follows a sitemapindex into child sitemaps and parses skill URLs", async () => {
		mockFetch({
			"https://skills.sh/sitemap.xml": INDEX_XML,
			"https://www.skills.sh/sitemap-misc.xml": "<urlset></urlset>",
			"https://www.skills.sh/sitemap-owners.xml": OWNERS_CHILD_XML,
			"https://www.skills.sh/sitemap-skills-1.xml": SKILLS_CHILD_XML,
		});
		const entries = await fetchSkillsShSitemap();
		expect(entries.map((e) => e.slug).sort()).toEqual(["find-skills", "frontend-design"]);
	});

	it("tolerates an unreachable child sitemap (404) without aborting", async () => {
		mockFetch({
			"https://skills.sh/sitemap.xml": INDEX_XML,
			// misc + owners present, skills child is missing (404 via null)
			"https://www.skills.sh/sitemap-misc.xml": "<urlset></urlset>",
			"https://www.skills.sh/sitemap-owners.xml": OWNERS_CHILD_XML,
			"https://www.skills.sh/sitemap-skills-1.xml": null,
		});
		// Should resolve (not throw) and simply yield no skills from the dead child.
		await expect(fetchSkillsShSitemap()).resolves.toEqual([]);
	});

	it("still parses a legacy flat sitemap (no index)", async () => {
		mockFetch({
			"https://skills.sh/sitemap.xml": `<urlset>
				<loc>https://skills.sh/acme/repo/alpha</loc>
			</urlset>`,
		});
		const entries = await fetchSkillsShSitemap();
		expect(entries).toHaveLength(1);
		expect(entries[0]).toMatchObject({ owner: "acme", repo: "repo", slug: "alpha" });
	});
});

describe("resolveSkillsShUrl host guard", () => {
	const savedFetch = globalThis.fetch;
	afterEach(() => {
		globalThis.fetch = savedFetch;
	});

	it("rejects a non-skills.sh host", async () => {
		await expect(resolveSkillsShUrl("https://github.com/o/r/s")).rejects.toThrow(
			/Not a skills\.sh URL/,
		);
	});

	it("accepts the www host (passes the guard, fails later at resolution)", async () => {
		// Mock all probes as failures so resolution returns null; the point is that
		// a www host must NOT be rejected by the host guard.
		// @ts-expect-error - override global fetch for tests
		globalThis.fetch = vi.fn(async () => new Response("", { status: 404 }));
		await expect(
			resolveSkillsShUrl("https://www.skills.sh/acme/repo/alpha", { timeout: 50 }),
		).rejects.toThrow(/Could not resolve/);
	});
});
