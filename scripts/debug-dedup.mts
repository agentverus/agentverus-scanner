import { scanSkillFromUrl } from "../src/scanner/index.js";
import { readFileSync } from "fs";

const MEDIUM_PLUS = new Set(["medium", "high", "critical"]);

function normalizeTitle(title: string): string {
	return title
		.toLowerCase()
		.replace(/\s*\(inside code block\)/g, "")
		.replace(/\s*\(merged[^)]*\)/g, "")
		.replace(/\s*\(inside threat-listing context\)/g, "")
		.replace(/\s*\(inside safety boundary section\)/g, "")
		.replace(/\s*\(declared: [^)]*\)/g, "")
		.trim();
}

const urls = readFileSync("benchmarks/public-skill-corpus.txt", "utf-8").split("\n").filter(Boolean);

for (const url of urls) {
	const name = url.split("/").slice(-2).join("/").replace("/SKILL.md", "");
	const report = await scanSkillFromUrl(url);

	const counts = new Map<string, number>();
	for (const f of report.findings) {
		if (!MEDIUM_PLUS.has(f.severity)) continue;
		const key = `${f.category}::${normalizeTitle(f.title)}`;
		counts.set(key, (counts.get(key) ?? 0) + 1);
	}

	const dupes = [...counts.entries()].filter(([, count]) => count > 1);
	if (dupes.length > 0) {
		console.log(`\n${name}:`);
		for (const [key, count] of dupes) {
			console.log(`  ${key} × ${count}`);
		}
	}
}
