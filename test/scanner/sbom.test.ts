import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanSkill } from "../../src/scanner/index.js";
import { buildSbomDocument } from "../../src/scanner/sbom.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string): string {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("buildSbomDocument", () => {
	it("should build a CycloneDX SBOM with skill + dependency components", async () => {
		const report = await scanSkill(loadFixture("suspicious-urls.md"));
		const sbom = buildSbomDocument([{ target: "./fixtures/suspicious-urls.md", report }], []);

		expect(sbom.bomFormat).toBe("CycloneDX");
		expect(sbom.specVersion).toBe("1.5");
		expect(sbom.metadata.tools[0]?.name).toBe("agentverus-scanner");
		expect(
			sbom.components.some(
				(component) =>
					component.type === "application" &&
					component.properties?.some((p) => p.name === "agentverus:target"),
			),
		).toBe(true);
		expect(
			sbom.components.some(
				(component) =>
					component.type === "data" &&
					(component.externalReferences?.[0]?.url ?? "").startsWith("http"),
			),
		).toBe(true);
		expect(sbom.dependencies[0]?.dependsOn.length).toBeGreaterThan(0);
	});

	it("should reuse dependency refs across scans with the same indicator", async () => {
		const report = await scanSkill(loadFixture("suspicious-urls.md"));
		const sbom = buildSbomDocument(
			[
				{ target: "./fixtures/suspicious-urls-a.md", report },
				{ target: "./fixtures/suspicious-urls-b.md", report },
			],
			[],
		);

		expect(sbom.dependencies.length).toBe(2);
		const first = sbom.dependencies[0]?.dependsOn ?? [];
		const second = sbom.dependencies[1]?.dependsOn ?? [];
		expect(first.some((ref) => second.includes(ref))).toBe(true);
	});
});
