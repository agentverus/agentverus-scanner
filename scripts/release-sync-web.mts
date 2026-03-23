import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

interface CliOptions {
	readonly scannerRoot: string;
	readonly webRoot: string;
}

function parseArgs(argv: readonly string[]): CliOptions {
	let scannerRoot = process.cwd();
	let webRoot = resolve(process.cwd(), "../agentverus-web");

	for (let index = 0; index < argv.length; index += 1) {
		const arg = argv[index];
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

	return { scannerRoot, webRoot };
}

function replaceActionTags(text: string, version: string): string {
	return text.replaceAll(
		/agentverus\/agentverus-scanner\/actions\/scan-skill@v\d+\.\d+\.\d+/g,
		`agentverus/agentverus-scanner/actions/scan-skill@v${version}`,
	);
}

function replaceFallbackVersions(text: string, version: string): string {
	return text
		.replace(
			/(return\s+parsed\.version\?\.trim\(\)\s*\|\|\s*")\d+\.\d+\.\d+(";)/g,
			`$1${version}$2`,
		)
		.replace(/(return\s+")\d+\.\d+\.\d+(";)/g, `$1${version}$2`);
}

function replaceChangelogScannerVersion(text: string, version: string): string {
	return text
		.replace(/Vendored scanner package updated to `\d+\.\d+\.\d+`/g, `Vendored scanner package updated to \`${version}\``)
		.replace(/GitHub Action examples updated to `v\d+\.\d+\.\d+`/g, `GitHub Action examples updated to \`v${version}\``)
		.replace(/Scanner fallback version updated to `\d+\.\d+\.\d+`/g, `Scanner fallback version updated to \`${version}\``);
}

async function syncFile(sourcePath: string, targetPath: string): Promise<void> {
	await mkdir(dirname(targetPath), { recursive: true });
	await cp(sourcePath, targetPath, { force: true });
}

async function main(): Promise<void> {
	const options = parseArgs(process.argv.slice(2));
	const scannerPackagePath = resolve(options.scannerRoot, "package.json");
	const scannerReadmePath = resolve(options.scannerRoot, "README.md");
	const scannerDistPath = resolve(options.scannerRoot, "dist");
	const webVendorRoot = resolve(options.webRoot, "vendor/agentverus-scanner");
	const webConfigPath = resolve(options.webRoot, "src/lib/config.ts");
	const webDocsPath = resolve(options.webRoot, "src/web/pages/docs.tsx");
	const webPartnerPagesPath = resolve(options.webRoot, "src/web/pages/partner-pages.tsx");
	const webChangelogPath = resolve(options.webRoot, "CHANGELOG.md");

	const scannerPackage = JSON.parse(await readFile(scannerPackagePath, "utf8")) as { version?: string };
	if (!scannerPackage.version) {
		throw new Error("scanner package.json is missing version");
	}
	const scannerVersion = scannerPackage.version;

	await mkdir(webVendorRoot, { recursive: true });
	await syncFile(scannerPackagePath, resolve(webVendorRoot, "package.json"));
	await syncFile(scannerReadmePath, resolve(webVendorRoot, "README.md"));
	await cp(scannerDistPath, resolve(webVendorRoot, "dist"), { recursive: true, force: true });

	const [configText, docsText, partnerPagesText, changelogText] = await Promise.all([
		readFile(webConfigPath, "utf8"),
		readFile(webDocsPath, "utf8"),
		readFile(webPartnerPagesPath, "utf8"),
		readFile(webChangelogPath, "utf8"),
	]);

	await Promise.all([
		writeFile(webConfigPath, replaceFallbackVersions(configText, scannerVersion), "utf8"),
		writeFile(webDocsPath, replaceActionTags(docsText, scannerVersion), "utf8"),
		writeFile(webPartnerPagesPath, replaceActionTags(partnerPagesText, scannerVersion), "utf8"),
		writeFile(webChangelogPath, replaceChangelogScannerVersion(changelogText, scannerVersion), "utf8"),
	]);

	console.log(`Synced agentverus-web to scanner ${scannerVersion}`);
}

await main();
