#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { scanSkill, scanSkillFromUrl } from "agentverus-scanner";
import { normalizeSkillUrl } from "agentverus-scanner/source";
import { SCANNER_VERSION } from "agentverus-scanner/types";

function toJsonText(value: unknown): string {
	return JSON.stringify(value, null, 2);
}

/** Build the MCP server with all tools registered (no transport connected). Exported for tests. */
export function createServer(): McpServer {
	const server = new McpServer({
		name: "AgentVerus Scanner MCP",
		version: SCANNER_VERSION,
	});

	server.registerTool(
		"normalize_skill_url",
		{
			title: "Normalize skill URL",
			description:
				"Normalize skill URLs (GitHub blob/tree/repo URLs, ClawHub skill pages) into a direct downloadable/scan-ready URL.",
			inputSchema: {
				url: z.string().min(1),
			},
		},
		async ({ url }) => {
			const normalized = normalizeSkillUrl(url);
			return { content: [{ type: "text", text: toJsonText({ url, normalized }) }] };
		},
	);

	server.registerTool(
		"scan_skill",
		{
			title: "Scan a skill",
			description:
				"Scan a SKILL.md (or variant) and return an AgentVerus trust report. Provide exactly one of: content, path, or url.",
			inputSchema: {
				content: z.string().optional(),
				path: z.string().optional(),
				url: z.string().optional(),
				timeout: z.number().int().optional(),
				retries: z.number().int().nonnegative().optional(),
				retryDelayMs: z.number().int().nonnegative().optional(),
			},
		},
		async ({ content, path, url, timeout, retries, retryDelayMs }) => {
			const provided = [
				content ? "content" : null,
				path ? "path" : null,
				url ? "url" : null,
			].filter((v) => v !== null);
			if (provided.length !== 1) {
				return {
					content: [
						{
							type: "text",
							text: toJsonText({
								error:
									"Provide exactly one of: content, path, or url. For URLs, normalize_skill_url can help.",
								provided,
							}),
						},
					],
				};
			}

			const options = { timeout, retries, retryDelayMs };

			if (typeof content === "string") {
				const report = await scanSkill(content, options);
				return { content: [{ type: "text", text: toJsonText({ target: "content", report }) }] };
			}

			if (typeof path === "string") {
				const fileContent = await readFile(path, "utf-8");
				const report = await scanSkill(fileContent, options);
				return { content: [{ type: "text", text: toJsonText({ target: path, report }) }] };
			}

			if (typeof url === "string") {
				const report = await scanSkillFromUrl(url, options);
				return { content: [{ type: "text", text: toJsonText({ target: url, report }) }] };
			}

			return { content: [{ type: "text", text: toJsonText({ error: "Unexpected input state." }) }] };
		},
	);

	return server;
}

async function main(): Promise<void> {
	const server = createServer();
	const transport = new StdioServerTransport();
	await server.connect(transport);
}

// Only start the stdio server when executed directly (the bin entry), not when
// imported by a test or another module.
const isDirectRun = process.argv[1] === fileURLToPath(import.meta.url);
if (isDirectRun) {
	main().catch((err) => {
		const message = err instanceof Error ? err.message : String(err);
		console.error(message);
		process.exit(1);
	});
}

