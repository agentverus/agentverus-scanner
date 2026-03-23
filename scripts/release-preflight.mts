import { resolve } from "node:path";

import { runReleasePreflight } from "./release-guard.mts";

interface CliOptions {
	readonly mode: "all" | "scanner" | "web";
	readonly json: boolean;
	readonly scannerRoot: string;
	readonly webRoot: string;
}

function parseArgs(argv: readonly string[]): CliOptions {
	let mode: CliOptions["mode"] = "all";
	let json = false;
	let scannerRoot = process.cwd();
	let webRoot = resolve(process.cwd(), "../agentverus-web");

	for (let index = 0; index < argv.length; index += 1) {
		const arg = argv[index];
		if (arg === "--json") {
			json = true;
			continue;
		}
		if (arg === "--scanner-only") {
			mode = "scanner";
			continue;
		}
		if (arg === "--web-only") {
			mode = "web";
			continue;
		}
		if (arg === "--scanner-root") {
			scannerRoot = resolve(argv[index + 1] ?? scannerRoot);
			index += 1;
			continue;
		}
		if (arg === "--web-root") {
			webRoot = resolve(argv[index + 1] ?? webRoot);
			index += 1;
		}
	}

	return { mode, json, scannerRoot, webRoot };
}

function main(): void {
	const options = parseArgs(process.argv.slice(2));
	const result = runReleasePreflight(options.scannerRoot, options.webRoot);
	const scannerIssues = options.mode === "web" ? [] : result.scannerIssues;
	const webIssues = options.mode === "scanner" ? [] : result.webIssues;
	const failed = scannerIssues.length > 0 || webIssues.length > 0;

	if (options.json) {
		console.log(JSON.stringify({ scannerIssues, webIssues, ok: !failed }, null, 2));
	} else if (!failed) {
		console.log("release preflight passed");
	} else {
		if (scannerIssues.length > 0) {
			console.log("scanner release issues:");
			for (const issue of scannerIssues) console.log(`- ${issue}`);
		}
		if (webIssues.length > 0) {
			console.log("web release issues:");
			for (const issue of webIssues) console.log(`- ${issue}`);
		}
	}

	process.exit(failed ? 1 : 0);
}

main();
