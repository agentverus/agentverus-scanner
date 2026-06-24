import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { createServer } from "../src/server.js";

/**
 * In-process smoke test (T0.2): connects a real MCP Client to the server over an
 * in-memory transport pair. Exercises the bumped @modelcontextprotocol/sdk end to
 * end (tool registration, schema validation, request/response serialization) and
 * confirms scan_skill / normalize_skill_url return well-formed JSON.
 */
async function connectClient() {
	const server = createServer();
	const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
	const client = new Client({ name: "smoke-test-client", version: "0.0.0" });
	await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
	return client;
}

describe("agentverus-scanner-mcp server (smoke)", () => {
	it("exposes scan_skill and normalize_skill_url tools", async () => {
		const client = await connectClient();
		const { tools } = await client.listTools();
		const names = tools.map((t) => t.name);
		expect(names).toContain("scan_skill");
		expect(names).toContain("normalize_skill_url");
	});

	it("scan_skill returns a well-formed trust report for inline content", async () => {
		const client = await connectClient();
		const res = (await client.callTool({
			name: "scan_skill",
			arguments: { content: "---\nname: test-skill\ndescription: A simple safe skill.\n---\n# Test\nList files in the current directory." },
		})) as { content: Array<{ type: string; text: string }> };

		const payload = JSON.parse(res.content[0].text);
		expect(payload.target).toBe("content");
		expect(payload.report).toBeDefined();
		expect(typeof payload.report.overall).toBe("number");
		expect(["certified", "conditional", "suspicious", "rejected"]).toContain(payload.report.badge);
		expect(payload.report.categories).toBeDefined();
	});

	it("scan_skill rejects ambiguous input (more than one of content/path/url)", async () => {
		const client = await connectClient();
		const res = (await client.callTool({
			name: "scan_skill",
			arguments: { content: "x", url: "https://example.com/SKILL.md" },
		})) as { content: Array<{ type: string; text: string }> };

		const payload = JSON.parse(res.content[0].text);
		expect(payload.error).toMatch(/exactly one/i);
		expect(payload.provided).toEqual(expect.arrayContaining(["content", "url"]));
	});

	it("normalize_skill_url normalizes a GitHub blob URL to a scan-ready URL", async () => {
		const client = await connectClient();
		const res = (await client.callTool({
			name: "normalize_skill_url",
			arguments: { url: "https://github.com/owner/repo/blob/main/skills/x/SKILL.md" },
		})) as { content: Array<{ type: string; text: string }> };

		const payload = JSON.parse(res.content[0].text);
		expect(payload.url).toContain("github.com");
		expect(typeof payload.normalized).toBe("string");
		expect(payload.normalized.length).toBeGreaterThan(0);
	});
});
