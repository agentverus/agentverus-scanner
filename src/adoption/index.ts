import { fetchRepoSignals } from "./github.js";
import { calculateAdoptionScore } from "./scoring.js";
import { fetchSkillsShData } from "./skills-sh.js";
import type { AdoptionScore, AdoptionSignals } from "./types.js";

interface ParsedSkillRef {
	readonly owner: string;
	readonly repo: string;
	readonly skillId: string | null;
}

function parseSkillRef(skillRef: string): ParsedSkillRef | null {
	const raw = skillRef.trim();
	if (!raw) return null;

	// Accept a GitHub URL as an input ref.
	if (raw.startsWith("https://") || raw.startsWith("http://")) {
		try {
			const url = new URL(raw);
			if (url.hostname !== "github.com") return null;

			const parts = url.pathname.split("/").filter(Boolean);
			const owner = parts[0];
			let repo = parts[1];

			if (!owner || !repo) return null;
			if (repo.endsWith(".git")) repo = repo.slice(0, -4);

			return { owner, repo, skillId: null };
		} catch {
			return null;
		}
	}

	const parts = raw.split("/").filter(Boolean);
	const owner = parts[0];
	let repo = parts[1];
	const skillId = parts[2] ?? null;

	if (!owner || !repo) return null;
	if (repo.endsWith(".git")) repo = repo.slice(0, -4);

	return { owner, repo, skillId };
}

async function resolveInstalls(
	owner: string,
	repo: string,
	skillId: string | null,
): Promise<number> {
	const skills = await fetchSkillsShData();
	const source = `${owner}/${repo}`.toLowerCase();

	let total = 0;
	for (const entry of skills) {
		if (entry.source.toLowerCase() !== source) continue;
		if (skillId) {
			if (entry.skillId.toLowerCase() === skillId.toLowerCase()) return entry.installs;
			continue;
		}
		total += entry.installs;
	}

	return total;
}

export async function resolveAdoption(skillRef: string): Promise<AdoptionScore> {
	const parsed = parseSkillRef(skillRef);
	if (!parsed) {
		const signals: AdoptionSignals = {
			installs: 0,
			stars: 0,
			forks: 0,
			lastUpdated: null,
			createdAt: null,
			source: "invalid_ref",
		};
		return calculateAdoptionScore(signals);
	}

	const [repoSignals, installs] = await Promise.all([
		fetchRepoSignals(parsed.owner, parsed.repo),
		resolveInstalls(parsed.owner, parsed.repo, parsed.skillId),
	]);

	const signals: AdoptionSignals = {
		installs,
		stars: repoSignals?.stars ?? 0,
		forks: repoSignals?.forks ?? 0,
		lastUpdated: repoSignals?.pushedAt ?? null,
		createdAt: repoSignals?.createdAt ?? null,
		source: repoSignals ? "skills.sh+github" : "skills.sh",
	};

	return calculateAdoptionScore(signals);
}

