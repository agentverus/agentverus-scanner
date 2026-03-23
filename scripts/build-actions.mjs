import { createHash } from "node:crypto";
import { readFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

import { build } from "esbuild";

const ENTRYPOINT = "actions/scan-skill/src/index.ts";
const OUTFILE = "actions/scan-skill/dist/index.cjs";

function computeHash(content) {
	return createHash("sha256").update(content).digest("hex").slice(0, 16);
}

const actionSource = await readFile(ENTRYPOINT, "utf8");
const actionSourceHash = computeHash(actionSource);

await mkdir(dirname(OUTFILE), { recursive: true });

await build({
	entryPoints: [ENTRYPOINT],
	outfile: OUTFILE,
	platform: "node",
	target: "node20",
	format: "cjs",
	bundle: true,
	minify: false,
	sourcemap: false,
	logLevel: "info",
	banner: {
		js: `/* ACTION_SOURCE_HASH:${actionSourceHash} */`,
	},
});

