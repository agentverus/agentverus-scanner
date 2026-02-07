function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

export interface RepoSignals {
	stars: number;
	forks: number;
	createdAt: Date;
	pushedAt: Date;
}

export async function fetchRepoSignals(
	owner: string,
	repo: string,
): Promise<RepoSignals | null> {
	const token = process.env.GITHUB_TOKEN;

	const headers: Record<string, string> = {
		accept: "application/vnd.github+json",
		"user-agent": "AgentVerus",
		"x-github-api-version": "2022-11-28",
	};

	if (token) {
		headers.authorization = `Bearer ${token}`;
	}

	try {
		const res = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
			headers,
		});

		if (res.status === 403) return null;
		if (!res.ok) return null;

		const json: unknown = await res.json();
		if (!isRecord(json)) return null;

		const stars = json.stargazers_count;
		const forks = json.forks_count;
		const createdAt = json.created_at;
		const pushedAt = json.pushed_at;

		if (
			typeof stars !== "number" ||
			typeof forks !== "number" ||
			typeof createdAt !== "string" ||
			typeof pushedAt !== "string"
		) {
			return null;
		}

		const createdDate = new Date(createdAt);
		const pushedDate = new Date(pushedAt);

		if (Number.isNaN(createdDate.getTime()) || Number.isNaN(pushedDate.getTime())) {
			return null;
		}

		return {
			stars,
			forks,
			createdAt: createdDate,
			pushedAt: pushedDate,
		};
	} catch {
		return null;
	}
}

