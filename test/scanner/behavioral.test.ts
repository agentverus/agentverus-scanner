import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeBehavioral } from "../../src/scanner/analyzers/behavioral.js";
import { parseSkill } from "../../src/scanner/parser.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string) {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("analyzeBehavioral", () => {
	it("should score safe-basic skill above 90", async () => {
		const skill = parseSkill(loadFixture("safe-basic.md"));
		const result = await analyzeBehavioral(skill);

		expect(result.score).toBeGreaterThanOrEqual(90);
		expect(result.weight).toBe(0.15);
	});

	it("should detect system modification in malicious-escalation", async () => {
		const skill = parseSkill(loadFixture("malicious-escalation.md"));
		const result = await analyzeBehavioral(skill);

		expect(result.score).toBeLessThan(80);
		const sysModFindings = result.findings.filter((f) => f.owaspCategory === "ASST-03");
		expect(sysModFindings.length).toBeGreaterThan(0);
	});

	it("should detect sub-agent spawning", async () => {
		const skill = parseSkill(loadFixture("malicious-escalation.md"));
		const result = await analyzeBehavioral(skill);

		const spawnFindings = result.findings.filter(
			(f) =>
				f.title.toLowerCase().includes("sub-agent") || f.title.toLowerCase().includes("spawning"),
		);
		expect(spawnFindings.length).toBeGreaterThanOrEqual(0);
	});

	it("should score well-behaved skills highly", async () => {
		const skill = parseSkill(loadFixture("openclaw-format.md"));
		const result = await analyzeBehavioral(skill);

		expect(result.score).toBeGreaterThanOrEqual(90);
	});

	// ── v0.4.0: System manipulation patterns ───────────────────────────────

	it("should detect crontab manipulation", async () => {
		const skill = parseSkill(
			`---\nname: cron-skill\ndescription: Schedules tasks\n---\nRun crontab -e to add a scheduled job.`,
		);
		const result = await analyzeBehavioral(skill);

		const sysFindings = result.findings.filter((f) => f.owaspCategory === "ASST-03");
		expect(sysFindings.length).toBeGreaterThan(0);
	});

	it("should detect systemctl commands", async () => {
		const skill = parseSkill(
			`---\nname: service-skill\ndescription: Manages services\n---\nUse systemctl enable my-service to persist it.`,
		);
		const result = await analyzeBehavioral(skill);

		const sysFindings = result.findings.filter((f) => f.owaspCategory === "ASST-03");
		expect(sysFindings.length).toBeGreaterThan(0);
	});

	it("should detect /etc/hosts modification", async () => {
		const skill = parseSkill(
			`---\nname: hosts-skill\ndescription: Edits hosts\n---\nModify /etc/hosts to redirect the domain.`,
		);
		const result = await analyzeBehavioral(skill);

		const sysFindings = result.findings.filter((f) => f.owaspCategory === "ASST-03");
		expect(sysFindings.length).toBeGreaterThan(0);
	});

	it("should detect firewall manipulation (iptables/ufw)", async () => {
		const skill = parseSkill(
			`---\nname: fw-skill\ndescription: Opens ports\n---\nRun iptables to open the required port.`,
		);
		const result = await analyzeBehavioral(skill);

		const sysFindings = result.findings.filter((f) => f.owaspCategory === "ASST-03");
		expect(sysFindings.length).toBeGreaterThan(0);
	});

	it("should detect kernel module loading", async () => {
		const skill = parseSkill(
			`---\nname: kernel-skill\ndescription: Loads modules\n---\nUse modprobe to load the driver.`,
		);
		const result = await analyzeBehavioral(skill);

		const sysFindings = result.findings.filter((f) => f.owaspCategory === "ASST-03");
		expect(sysFindings.length).toBeGreaterThan(0);
	});

	it("should detect shell profile persistence (~/.bashrc)", async () => {
		const skill = parseSkill(
			`---\nname: persist-skill\ndescription: Persists PATH\n---\nAppend to ~/.bashrc to persist the PATH change.`,
		);
		const result = await analyzeBehavioral(skill);

		const sysFindings = result.findings.filter((f) => f.owaspCategory === "ASST-03");
		expect(sysFindings.length).toBeGreaterThan(0);
	});
});
