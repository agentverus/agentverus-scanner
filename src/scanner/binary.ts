import { open, readdir, stat } from "node:fs/promises";
import { extname, join } from "node:path";

const DEFAULT_IGNORED_DIRS = new Set([
	".git",
	"node_modules",
	"dist",
	"build",
	"coverage",
	".next",
	".turbo",
]);

const EXECUTABLE_EXTENSIONS = new Set([".exe", ".dll", ".so", ".dylib", ".bin"]);

const MACHO_MAGICS = new Set<number>([
	0xfeedface,
	0xfeedfacf,
	0xcefaedfe,
	0xcffaedfe,
	0xcafebabe,
	0xbebafeca,
]);

async function readMagicBytes(path: string): Promise<Buffer | null> {
	try {
		const s = await stat(path);
		if (!s.isFile()) return null;
		if (s.size < 4) return null;

		const fh = await open(path, "r");
		try {
			const buf = Buffer.alloc(4);
			await fh.read(buf, 0, 4, 0);
			return buf;
		} finally {
			await fh.close();
		}
	} catch {
		return null;
	}
}

async function isExecutableBinary(path: string): Promise<boolean> {
	const ext = extname(path).toLowerCase();
	const extSuspicious = EXECUTABLE_EXTENSIONS.has(ext);

	const magic = await readMagicBytes(path);
	if (!magic) return extSuspicious;

	// ELF: 0x7F 45 4C 46
	if (magic[0] === 0x7f && magic[1] === 0x45 && magic[2] === 0x4c && magic[3] === 0x46) return true;

	// Windows PE: starts with "MZ"
	if (magic[0] === 0x4d && magic[1] === 0x5a) return true;

	// Mach-O (big or little endian, fat binaries included)
	const be = magic.readUInt32BE(0);
	const le = magic.readUInt32LE(0);
	if (MACHO_MAGICS.has(be) || MACHO_MAGICS.has(le)) return true;

	return extSuspicious;
}

async function walkForExecutableBinaries(dir: string, out: string[], maxResults: number): Promise<void> {
	if (out.length >= maxResults) return;

	const entries = await readdir(dir, { withFileTypes: true });
	for (const entry of entries) {
		if (out.length >= maxResults) break;

		const full = join(dir, entry.name);
		if (entry.isDirectory()) {
			if (DEFAULT_IGNORED_DIRS.has(entry.name)) continue;
			await walkForExecutableBinaries(full, out, maxResults);
			continue;
		}

		if (!entry.isFile()) continue;
		if (await isExecutableBinary(full)) out.push(full);
	}
}

/**
 * Best-effort scan for executable binaries under a directory.
 *
 * Notes:
 * - This is only possible for local filesystem targets (CI/workspace scans).
 * - We intentionally only flag executable formats (ELF/PE/Mach-O) and common executable extensions.
 */
export async function findExecutableBinaries(rootDir: string, opts?: { readonly maxResults?: number }): Promise<readonly string[]> {
	const maxResults = opts?.maxResults ?? 5;
	const results: string[] = [];
	await walkForExecutableBinaries(rootDir, results, maxResults);
	return results;
}
