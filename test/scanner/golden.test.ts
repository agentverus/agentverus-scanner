import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanSkill } from "../../src/scanner/index.js";
import type { BadgeTier } from "../../src/scanner/types.js";

const FIXTURES = join(__dirname, "../fixtures/skills");

function scan(name: string) {
	return scanSkill(readFileSync(join(FIXTURES, name), "utf-8"));
}

// Score bucket per tier, aligned to determineBadge's thresholds. A golden test
// deliberately locks in the end-to-end badge AND keeps the score inside its tier
// band, so a detector/calibration change that silently shifts a representative
// skill across a tier boundary fails loudly.
const BUCKET: Record<BadgeTier, [number, number]> = {
	certified: [90, 100],
	conditional: [75, 89],
	suspicious: [50, 74],
	rejected: [0, 49],
};

const GOLDEN: Array<{ file: string; badge: BadgeTier; note: string }> = [
	{ file: "safe-basic.md", badge: "certified", note: "minimal safe skill" },
	{ file: "openclaw-format.md", badge: "certified", note: "openclaw frontmatter format" },
	{ file: "declared-permissions.md", badge: "certified", note: "capabilities declared" },
	{ file: "suspicious-urls.md", badge: "conditional", note: "borderline URL references" },
	{ file: "browser-session-risk.md", badge: "suspicious", note: "dual-use browser/session risk" },
	{ file: "config-tampering.md", badge: "rejected", note: "agent-config tampering" },
	{ file: "obfuscated-skill.md", badge: "rejected", note: "obfuscation / evasion" },
	{ file: "malicious-injection.md", badge: "rejected", note: "prompt injection" },
	{ file: "malicious-exfiltration.md", badge: "rejected", note: "credential exfiltration" },
];

describe("golden fixtures — end-to-end badge + score bucket lock-in", () => {
	it.each(GOLDEN)("$file → $badge ($note)", async ({ file, badge }) => {
		const report = await scan(file);
		expect(report.badge).toBe(badge);

		if (badge === "rejected") {
			// `rejected` is forced by ANY critical finding *before* the score check, so a
			// critical-driven reject can legitimately score ≥ 50. Assert the real
			// invariant (score<50 OR a critical), not a fixed [0,49] band.
			const hasCritical = report.findings.some((f) => f.severity === "critical");
			expect(report.overall < 50 || hasCritical).toBe(true);
		} else {
			const [lo, hi] = BUCKET[badge];
			expect(report.overall).toBeGreaterThanOrEqual(lo);
			expect(report.overall).toBeLessThanOrEqual(hi);
		}
	});

	it("the scanned fixtures actually exercise all four badge tiers", async () => {
		const badges = new Set<string>();
		for (const g of GOLDEN) badges.add((await scan(g.file)).badge);
		expect([...badges].sort()).toEqual(["certified", "conditional", "rejected", "suspicious"]);
	});

	it("a fully-formed report carries all six category scores with numeric weight+score", async () => {
		const report = await scan("safe-basic.md");
		for (const cat of [
			"permissions",
			"injection",
			"dependencies",
			"behavioral",
			"content",
			"code-safety",
		] as const) {
			const c = report.categories[cat];
			expect(c, cat).toBeDefined();
			expect(typeof c.score).toBe("number");
			expect(typeof c.weight).toBe("number");
		}
	});
});
