import { rm } from "node:fs/promises";

const targets = process.argv.slice(2);
const dirs = targets.length > 0 ? targets : ["dist"];

for (const dir of dirs) {
	// Keep builds reproducible: remove stale output files that tsc will not delete.
	// Use `force` so clean works even when the directory doesn't exist.
	await rm(dir, { recursive: true, force: true });
}

