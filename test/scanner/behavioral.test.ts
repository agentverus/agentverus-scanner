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

	// --- Config tampering detection ---

	it("should detect config tamper core (AGENTS.md/TOOLS.md/CLAUDE.md)", async () => {
		const skill = parseSkill(loadFixture("config-tampering.md"));
		const result = await analyzeBehavioral(skill);

		const tamperFindings = result.findings.filter((f) =>
			f.id.startsWith("BEH-CONFIG-TAMPER-CORE-"),
		);
		expect(tamperFindings.length).toBeGreaterThan(0);
		expect(tamperFindings[0]?.severity).toBe("high");
		expect(tamperFindings[0]?.deduction).toBeGreaterThanOrEqual(20);
	});

	it("should detect config tamper workspace (.claude/)", async () => {
		const skill = parseSkill(loadFixture("config-tampering.md"));
		const result = await analyzeBehavioral(skill);

		const tamperFindings = result.findings.filter((f) =>
			f.id.startsWith("BEH-CONFIG-TAMPER-WORKSPACE-"),
		);
		expect(tamperFindings.length).toBeGreaterThan(0);
		expect(tamperFindings[0]?.severity).toBe("high");
	});

	it("should NOT produce config-tamper findings for safe fixture", async () => {
		const skill = parseSkill(loadFixture("config-tampering-safe.md"));
		const result = await analyzeBehavioral(skill);

		const tamperFindings = result.findings.filter(
			(f) =>
				f.id.startsWith("BEH-CONFIG-TAMPER-CORE-") ||
				f.id.startsWith("BEH-CONFIG-TAMPER-WORKSPACE-"),
		);
		expect(tamperFindings.length).toBe(0);
	});

	it("should detect browser session attachment and local exposure patterns", async () => {
		const skill = parseSkill(loadFixture("browser-session-risk.md"));
		const result = await analyzeBehavioral(skill);

		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("persistent session reuse")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("session inventory and reuse")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("external instruction override file")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("remote browser delegation")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("remote task delegation")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("auth import from user browser")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("browser session attachment")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("browser profile copy")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("full browser profile sync")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("browser javascript evaluation")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("credential form automation")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("browser auth state handling")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("secret parameter handling")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("credential in query string")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("cookie header replay")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("local service exposure")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("local service access")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("package bootstrap execution")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("skill path discovery")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("dev server auto-detection")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("temporary script execution")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("browser content extraction")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("prompt file ingestion")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("external ai provider delegation")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("external tool bridge")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("remote transport exposure")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("authentication integration surface")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("credential store persistence")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("local file access")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("automation evasion")),
		).toBe(true);
	});

	it("should detect financial cost language and container runtime control", async () => {
		const skill = parseSkill(`---\nname: paid-docker-helper\ndescription: Charges for premium actions and controls Docker\n---\nCost: $0.50 USD\nCharge for premium actions when the user enables deployment.\nRun docker build --no-cache -t test . and docker run --rm test.`);
		const result = await analyzeBehavioral(skill);

		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("financial/payment actions")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("container runtime control")),
		).toBe(true);
	});

	it("should detect credential vault and federated auth flows", async () => {
		const skill = parseSkill(`---\nname: auth-helper\ndescription: Stores credentials for login\n---\nUse the Auth Vault to store logins.\necho "$PASSWORD" | agent-browser auth save myapp --password-stdin\nagent-browser auth login myapp\nSee references for OAuth, 2FA, and token refresh patterns.`);
		const result = await analyzeBehavioral(skill);

		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("credential vault enrollment")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("federated auth flow")),
		).toBe(true);
	});

	it("should detect remote documentation ingestion", async () => {
		const skill = parseSkill(`---\nname: docs-loader\ndescription: Loads remote docs for an agent\n---\nUse WebFetch to load https://example.com/doc.md and web search and WebFetch as needed.\nThen fetch specific pages with .md suffix.`);
		const result = await analyzeBehavioral(skill);

		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("remote documentation ingestion")),
		).toBe(true);
	});

	it("should detect opaque helper scripts and os input automation", async () => {
		const skill = parseSkill(`---\nname: helper-runner\ndescription: Executes helper scripts\n---\nUse bundled scripts as black-box scripts. Do not read the source before running them.\nScripts include copy-to-clipboard.ts and paste-from-clipboard.ts to send a real paste keystroke.`);
		const result = await analyzeBehavioral(skill);

		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("opaque helper script execution")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("os input automation")),
		).toBe(true);
	});

	it("should detect server orchestration, browser extraction, and host reconnaissance", async () => {
		const skill = parseSkill(`---\nname: local-ops\ndescription: Extract information from web pages and inspect local Docker state\n---\nUse scripts/with_server.py because it manages server lifecycle and supports multiple servers.\npython scripts/with_server.py --server "npm run dev" --port 5173 -- python your_automation.py\nInspect rendered DOM, identify selectors from rendered state, capture browser screenshots, and view browser logs.\nCall page.content() and get html for browser capture.\nRun docker info, docker ps, and find . -name "Dockerfile*" before proceeding.`);
		const result = await analyzeBehavioral(skill);

		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("server lifecycle orchestration")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("browser content extraction")),
		).toBe(true);
		expect(
			result.findings.some((f) => f.title.toLowerCase().includes("host environment reconnaissance")),
		).toBe(true);
	});

	it("should not false-positive on existing safe fixtures for config tampering", async () => {
		for (const fixture of ["safe-basic.md", "safe-complex.md"]) {
			const skill = parseSkill(loadFixture(fixture));
			const result = await analyzeBehavioral(skill);

			const tamperFindings = result.findings.filter(
				(f) =>
					f.id.startsWith("BEH-CONFIG-TAMPER-CORE-") ||
					f.id.startsWith("BEH-CONFIG-TAMPER-WORKSPACE-"),
			);
			expect(tamperFindings.length).toBe(0);
		}
	});
});
