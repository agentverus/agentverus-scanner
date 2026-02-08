import { describe, expect, it } from "vitest";
import { analyzeSemantic, isSemanticAvailable } from "../../src/scanner/analyzers/semantic.js";
import { parseSkill } from "../../src/scanner/parser.js";

describe("analyzeSemantic", () => {
	it("should return null when no API key is configured", async () => {
		// Ensure env var is not set for this test
		const savedKey = process.env.AGENTVERUS_LLM_API_KEY;
		delete process.env.AGENTVERUS_LLM_API_KEY;

		const skill = parseSkill("# Test Skill\nDo something safe.");
		const result = await analyzeSemantic(skill, { apiKey: undefined });

		expect(result).toBeNull();

		// Restore
		if (savedKey) process.env.AGENTVERUS_LLM_API_KEY = savedKey;
	});

	it("should report unavailable when no API key exists", () => {
		const savedKey = process.env.AGENTVERUS_LLM_API_KEY;
		delete process.env.AGENTVERUS_LLM_API_KEY;

		expect(isSemanticAvailable()).toBe(false);
		expect(isSemanticAvailable({ apiKey: "sk-test" })).toBe(true);

		if (savedKey) process.env.AGENTVERUS_LLM_API_KEY = savedKey;
	});

	it("should gracefully handle API errors", async () => {
		const skill = parseSkill("# Test Skill\nDo something safe.");
		// Point to a non-existent server
		const result = await analyzeSemantic(skill, {
			apiKey: "sk-fake",
			apiBase: "http://127.0.0.1:1/v1",
			timeout: 500,
		});

		expect(result).toBeNull();
	});
});
