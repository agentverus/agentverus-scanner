import { scanSkillFromUrl } from "../src/scanner/index.js";

const urls = [
	"https://raw.githubusercontent.com/vercel-labs/agent-browser/main/skills/agent-browser/SKILL.md",
	"https://raw.githubusercontent.com/anthropics/skills/main/skills/mcp-builder/SKILL.md",
	"https://raw.githubusercontent.com/sickn33/antigravity-awesome-skills/main/skills/docker-expert/SKILL.md",
];

for (const url of urls) {
	const name = url.split("/").slice(-3, -1).join("/");
	const r = await scanSkillFromUrl(url);
	console.log(`\n=== ${name} === score=${r.overall} badge=${r.badge}`);
	for (const [c, s] of Object.entries(r.categories)) {
		console.log(`  ${c}: ${s.score} (${s.findings.length} findings)`);
	}
	const highs = r.findings.filter(f => f.severity === "high");
	console.log(`  High findings (${highs.length}):`);
	for (const f of highs) console.log(`    ${f.category}: ${f.title}`);
}
