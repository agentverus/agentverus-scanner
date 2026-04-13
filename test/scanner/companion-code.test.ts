import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { scanTarget } from "../../src/scanner/runner.js";

const PACKAGES_DIR = join(import.meta.dirname, "../fixtures/packages");

function targetPath(name: string): string {
	return join(PACKAGES_DIR, name, "SKILL.md");
}

describe("companion code correlation", () => {
	it("should ignore benign companion code", async () => {
		const result = await scanTarget(targetPath("companion-safe"));
		const companionFindings = result.report.findings.filter((finding) =>
			finding.id.startsWith("COMP-"),
		);

		expect(companionFindings.length).toBe(0);
	});

	it("should ignore documented companion auth usage", async () => {
		const result = await scanTarget(targetPath("companion-auth-safe"));
		const companionFindings = result.report.findings.filter((finding) =>
			finding.id.startsWith("COMP-"),
		);

		expect(companionFindings.length).toBe(0);
	});

	it("should flag companion code that logs secrets to stdout", async () => {
		const result = await scanTarget(targetPath("companion-secret-logging"));
		const finding = result.report.findings.find((entry) =>
			entry.id.startsWith("COMP-CODE-SECRET-LOG-"),
		);
		const mismatch = result.report.findings.find((entry) => entry.id.startsWith("COMP-MISMATCH-"));

		expect(finding).toBeDefined();
		expect(["high", "critical"]).toContain(finding?.severity);
		expect(finding?.evidence).toContain("weather.ts");
		expect(["high", "critical"]).toContain(mismatch?.severity);
	});

	it("should flag companion code that exfiltrates secrets over the network", async () => {
		const result = await scanTarget(targetPath("companion-exfiltration"));
		const exfil = result.report.findings.find((entry) =>
			entry.id.startsWith("COMP-CODE-SECRET-EXFIL-"),
		);
		const mismatch = result.report.findings.find((entry) => entry.id.startsWith("COMP-MISMATCH-"));

		expect(exfil).toBeDefined();
		expect(["high", "critical"]).toContain(exfil?.severity);
		expect(["ASST-05", "ASST-02"]).toContain(exfil?.owaspCategory);
		expect(mismatch).toBeDefined();
	});

	it("should flag stdout.write and stderr.write secret leaks", async () => {
		const stdoutResult = await scanTarget(targetPath("companion-stdout-write"));
		const stderrResult = await scanTarget(targetPath("companion-stderr-write"));

		const stdoutFinding = stdoutResult.report.findings.find((entry) =>
			entry.id.startsWith("COMP-CODE-SECRET-LOG-"),
		);
		const stderrFinding = stderrResult.report.findings.find((entry) =>
			entry.id.startsWith("COMP-CODE-SECRET-LOG-"),
		);

		expect(stdoutFinding).toBeDefined();
		expect(stderrFinding).toBeDefined();
		expect(stdoutFinding?.evidence).toContain("process.stdout.write");
		expect(stderrFinding?.evidence).toContain("process.stderr.write");
	});

	it("should flag shell printf redirection leaks", async () => {
		const result = await scanTarget(targetPath("companion-printf-stderr"));
		const finding = result.report.findings.find((entry) =>
			entry.id.startsWith("COMP-CODE-SECRET-LOG-"),
		);

		expect(finding).toBeDefined();
		expect(finding?.evidence).toContain("printf 'WEATHER_TOKEN=%s");
	});

	it("should flag console.error secret leaks", async () => {
		const result = await scanTarget(targetPath("companion-console-error"));
		const finding = result.report.findings.find((entry) =>
			entry.id.startsWith("COMP-CODE-SECRET-LOG-"),
		);

		expect(finding).toBeDefined();
		expect(finding?.evidence).toContain("console.error");
	});

	it("should treat credential-file reads plus network send as critical companion-code risk", async () => {
		const result = await scanTarget(targetPath("companion-mismatch"));
		const exfil = result.report.findings.find((entry) =>
			entry.id.startsWith("COMP-CODE-SECRET-EXFIL-"),
		);
		const mismatch = result.report.findings.find((entry) => entry.id.startsWith("COMP-MISMATCH-"));

		expect(exfil).toBeDefined();
		expect(exfil?.severity).toBe("critical");
		expect(exfil?.owaspCategory).toBe("ASST-02");
		expect(exfil?.evidence).toContain("worker.py");
		expect(mismatch).toBeDefined();
	});
});
