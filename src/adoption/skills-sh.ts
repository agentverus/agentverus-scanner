interface SkillsShEntry {
	source: string;
	skillId: string;
	installs: number;
}

interface SkillsShIndex {
	readonly fetchedAt: Date;
	readonly skills: readonly SkillsShEntry[];
	readonly installsByKey: ReadonlyMap<string, number>;
	readonly installsByRepo: ReadonlyMap<string, number>;
}

let cachedIndex: SkillsShIndex | null = null;
let cachedIndexPromise: Promise<SkillsShIndex> | null = null;

function normalizeRepoKey(owner: string, repo: string): string {
	return `${owner}/${repo}`.toLowerCase();
}

function normalizeSkillKey(source: string, skillId: string): string {
	return `${source.toLowerCase()}/${skillId.toLowerCase()}`;
}

function extractBracketedArrayLiteral(
	input: string,
	marker: string,
): string | null {
	const markerIndex = input.indexOf(marker);
	if (markerIndex === -1) return null;

	const openIndex = input.indexOf("[", markerIndex);
	if (openIndex === -1) return null;

	let depth = 0;
	let inSingle = false;
	let inDouble = false;
	let inBacktick = false;
	let escape = false;

	for (let i = openIndex; i < input.length; i += 1) {
		const ch = input[i];
		if (!ch) continue;

		if (escape) {
			escape = false;
			continue;
		}

		if (inSingle) {
			if (ch === "\\\\") escape = true;
			else if (ch === "'") inSingle = false;
			continue;
		}

		if (inDouble) {
			if (ch === "\\\\") escape = true;
			else if (ch === "\"") inDouble = false;
			continue;
		}

		if (inBacktick) {
			if (ch === "\\\\") escape = true;
			else if (ch === "`") inBacktick = false;
			continue;
		}

		if (ch === "'") {
			inSingle = true;
			continue;
		}
		if (ch === "\"") {
			inDouble = true;
			continue;
		}
		if (ch === "`") {
			inBacktick = true;
			continue;
		}

		if (ch === "[") {
			depth += 1;
			continue;
		}
		if (ch === "]") {
			depth -= 1;
			if (depth === 0) {
				return input.slice(openIndex, i + 1);
			}
		}
	}

	return null;
}

function parseSkillsShHtml(html: string): readonly SkillsShEntry[] {
	const initialSkillsArray =
		extractBracketedArrayLiteral(html, "initialSkills") ?? "";

	const region = initialSkillsArray.length > 0 ? initialSkillsArray : html;
	const objects = region.match(/\{[^{}]*\}/g) ?? [];

	const skills: SkillsShEntry[] = [];
	for (const obj of objects) {
		const sourceMatch = /\bsource\s*:\s*['"]([^'"]+)['"]/.exec(obj);
		const skillIdMatch = /\bskillId\s*:\s*['"]([^'"]+)['"]/.exec(obj);
		const installsMatch = /\binstalls\s*:\s*(\d+)/.exec(obj);

		const source = sourceMatch?.[1];
		const skillId = skillIdMatch?.[1];
		const installsStr = installsMatch?.[1];

		if (!source || !skillId || !installsStr) continue;

		const installs = Number(installsStr);
		if (!Number.isFinite(installs)) continue;

		skills.push({ source, skillId, installs });
	}

	return skills;
}

async function buildIndex(): Promise<SkillsShIndex> {
	const res = await fetch("https://skills.sh");
	const html = await res.text();

	const skills = parseSkillsShHtml(html);

	const installsByKey = new Map<string, number>();
	const installsByRepo = new Map<string, number>();

	for (const entry of skills) {
		const repoKey = entry.source.toLowerCase();
		const skillKey = normalizeSkillKey(entry.source, entry.skillId);

		installsByKey.set(skillKey, entry.installs);
		installsByRepo.set(repoKey, (installsByRepo.get(repoKey) ?? 0) + entry.installs);
	}

	return {
		fetchedAt: new Date(),
		skills,
		installsByKey,
		installsByRepo,
	};
}

async function getIndex(): Promise<SkillsShIndex> {
	if (cachedIndex) return cachedIndex;
	if (cachedIndexPromise) return cachedIndexPromise;

	cachedIndexPromise = buildIndex()
		.then((index) => {
			cachedIndex = index;
			return index;
		})
		.catch(() => {
			const index: SkillsShIndex = {
				fetchedAt: new Date(),
				skills: [],
				installsByKey: new Map(),
				installsByRepo: new Map(),
			};
			cachedIndex = index;
			return index;
		});

	return cachedIndexPromise;
}

export async function fetchSkillsShData(): Promise<
	readonly { source: string; skillId: string; installs: number }[]
> {
	const index = await getIndex();
	return index.skills;
}

export async function lookupInstalls(
	owner: string,
	repo: string,
	skillId: string,
): Promise<number> {
	const index = await getIndex();
	const source = normalizeRepoKey(owner, repo);
	const key = normalizeSkillKey(source, skillId);
	return index.installsByKey.get(key) ?? 0;
}
