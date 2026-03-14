import { describe, expect, it } from "vitest";
import { aggregateScores } from "../../src/scanner/scoring.js";
import type { Category, CategoryScore, ScanMetadata } from "../../src/scanner/types.js";

function makeCategoryScore(
	score: number,
	weight: number,
	overrides?: Partial<CategoryScore>,
): CategoryScore {
	return {
		score,
		weight,
		findings: overrides?.findings ?? [],
		summary: overrides?.summary ?? "Test summary",
	};
}

const metadata: ScanMetadata = {
	scannedAt: new Date("2026-02-06T00:00:00Z"),
	scannerVersion: "0.1.0",
	durationMs: 100,
	skillFormat: "openclaw",
};

describe("aggregateScores", () => {
	it("should calculate weighted overall score", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(100, 0.25),
			injection: makeCategoryScore(100, 0.3),
			dependencies: makeCategoryScore(100, 0.2),
			behavioral: makeCategoryScore(100, 0.15),
			content: makeCategoryScore(100, 0.1),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.overall).toBe(100);
		expect(report.badge).toBe("certified");
	});

	it("should return CERTIFIED for score 90+ with no critical/high", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.25),
			injection: makeCategoryScore(90, 0.3),
			dependencies: makeCategoryScore(95, 0.2),
			behavioral: makeCategoryScore(90, 0.15),
			content: makeCategoryScore(85, 0.1),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.overall).toBeGreaterThanOrEqual(90);
		expect(report.badge).toBe("certified");
	});

	it("should return REJECTED for any critical finding regardless of score", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.25),
			injection: makeCategoryScore(95, 0.3, {
				findings: [
					{
						id: "TEST-CRIT",
						category: "injection",
						severity: "critical",
						title: "Critical test",
						description: "Test",
						evidence: "test",
						deduction: 5,
						recommendation: "fix",
						owaspCategory: "ASST-01",
					},
				],
			}),
			dependencies: makeCategoryScore(95, 0.2),
			behavioral: makeCategoryScore(95, 0.15),
			content: makeCategoryScore(95, 0.1),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.badge).toBe("rejected");
	});

	it("should return REJECTED for score below 50", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(10, 0.25),
			injection: makeCategoryScore(20, 0.3),
			dependencies: makeCategoryScore(30, 0.2),
			behavioral: makeCategoryScore(40, 0.15),
			content: makeCategoryScore(50, 0.1),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.overall).toBeLessThan(50);
		expect(report.badge).toBe("rejected");
	});

	it("should return CONDITIONAL for score 75-89 with ≤2 high findings", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(80, 0.25, {
				findings: [
					{
						id: "TEST-HIGH",
						category: "permissions",
						severity: "high",
						title: "High test",
						description: "Test",
						evidence: "test",
						deduction: 15,
						recommendation: "fix",
						owaspCategory: "ASST-08",
					},
				],
			}),
			injection: makeCategoryScore(85, 0.3),
			dependencies: makeCategoryScore(80, 0.2),
			behavioral: makeCategoryScore(80, 0.15),
			content: makeCategoryScore(75, 0.1),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.overall).toBeGreaterThanOrEqual(75);
		expect(report.overall).toBeLessThan(90);
		expect(report.badge).toBe("conditional");
	});

	it("should sort findings by severity (critical first)", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(80, 0.25, {
				findings: [
					{
						id: "LOW-1",
						category: "permissions",
						severity: "low",
						title: "Low",
						description: "t",
						evidence: "e",
						deduction: 3,
						recommendation: "r",
						owaspCategory: "ASST-08",
					},
				],
			}),
			injection: makeCategoryScore(50, 0.3, {
				findings: [
					{
						id: "CRIT-1",
						category: "injection",
						severity: "critical",
						title: "Critical",
						description: "t",
						evidence: "e",
						deduction: 40,
						recommendation: "r",
						owaspCategory: "ASST-01",
					},
				],
			}),
			dependencies: makeCategoryScore(90, 0.2),
			behavioral: makeCategoryScore(90, 0.15, {
				findings: [
					{
						id: "MED-1",
						category: "behavioral",
						severity: "medium",
						title: "Medium",
						description: "t",
						evidence: "e",
						deduction: 10,
						recommendation: "r",
						owaspCategory: "ASST-09",
					},
				],
			}),
			content: makeCategoryScore(80, 0.1),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.findings[0]?.severity).toBe("critical");
		expect(report.findings[1]?.severity).toBe("medium");
		expect(report.findings[2]?.severity).toBe("low");
	});

	it("should merge overlapping browser auth findings in report output without relaxing badge calculation", () => {
		const sharedEvidence = 'actual Chrome profile with your login sessions';
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.20, {
				findings: [
					{
						id: 'PERM-1',
						category: 'permissions',
						severity: 'high',
						title: 'Capability contract mismatch: inferred credential access is not declared',
						description: 't',
						evidence: sharedEvidence,
						deduction: 12,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
				],
			}),
			injection: makeCategoryScore(95, 0.25),
			dependencies: makeCategoryScore(95, 0.15, {
				findings: [
					{
						id: 'DEP-1',
						category: 'dependencies',
						severity: 'medium',
						title: 'Persistent credential-state store dependency',
						description: 't',
						evidence: sharedEvidence,
						deduction: 8,
						recommendation: 'r',
						owaspCategory: 'ASST-04',
					},
				],
			}),
			behavioral: makeCategoryScore(95, 0.15, {
				findings: [
					{
						id: 'BEH-1',
						category: 'behavioral',
						severity: 'high',
						title: 'Browser profile copy detected',
						description: 't',
						evidence: sharedEvidence,
						deduction: 15,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
					{
						id: 'BEH-2',
						category: 'behavioral',
						severity: 'high',
						title: 'Full browser profile sync detected',
						description: 't',
						evidence: sharedEvidence,
						deduction: 15,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
				],
			}),
			content: makeCategoryScore(95, 0.10),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.badge).toBe('suspicious');
		expect(report.findings.length).toBe(1);
		expect(report.findings[0]?.title).toBe('Browser profile copy detected');
		expect(report.findings[0]?.description).toContain('Full browser profile sync detected');
	});

	it('should merge repeated auth finding families even when evidence differs', () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.20),
			injection: makeCategoryScore(95, 0.25),
			dependencies: makeCategoryScore(95, 0.15),
			behavioral: makeCategoryScore(95, 0.15, {
				findings: [
					{
						id: 'BEH-1',
						category: 'behavioral',
						severity: 'high',
						title: 'Persistent session reuse detected',
						description: 't',
						evidence: 'browser stays open between commands',
						deduction: 15,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
					{
						id: 'BEH-2',
						category: 'behavioral',
						severity: 'high',
						title: 'Persistent session reuse detected (inside code block)',
						description: 't',
						evidence: 'state auto-saved',
						deduction: 15,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
				],
			}),
			content: makeCategoryScore(95, 0.10),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.findings.length).toBe(1);
		expect(report.findings[0]?.title).toContain('Persistent session reuse detected');
		expect(report.findings[0]?.description).toContain('repeated finding family');
	});

	it('should merge generic dependency auth context into a stronger specific dependency finding', () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.20),
			injection: makeCategoryScore(95, 0.25),
			dependencies: makeCategoryScore(95, 0.15, {
				findings: [
					{
						id: 'DEP-1',
						category: 'dependencies',
						severity: 'medium',
						title: 'Many external URLs referenced (8)',
						description: 't',
						evidence: 'URLs: https://site.com/login, https://site.com/dashboard',
						deduction: 8,
						recommendation: 'r',
						owaspCategory: 'ASST-04',
					},
					{
						id: 'DEP-2',
						category: 'dependencies',
						severity: 'medium',
						title: 'Credential-bearing URL parameter',
						description: 't',
						evidence: 'https://site.com?session_token=<secret>',
						deduction: 8,
						recommendation: 'r',
						owaspCategory: 'ASST-04',
					},
				],
			}),
			behavioral: makeCategoryScore(95, 0.15),
			content: makeCategoryScore(95, 0.10),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.findings.length).toBe(1);
		expect(report.findings[0]?.title).toBe('Credential-bearing URL parameter');
		expect(report.findings[0]?.description).toContain('Many external URLs referenced');
	});

	it('should merge specific auth dependencies into a stronger behavioral auth finding', () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.20),
			injection: makeCategoryScore(95, 0.25),
			dependencies: makeCategoryScore(95, 0.15, {
				findings: [
					{
						id: 'DEP-1',
						category: 'dependencies',
						severity: 'medium',
						title: 'Reusable authenticated browser container dependency',
						description: 't',
						evidence: 'persistent but empty CLI profile',
						deduction: 8,
						recommendation: 'r',
						owaspCategory: 'ASST-04',
					},
				],
			}),
			behavioral: makeCategoryScore(95, 0.15, {
				findings: [
					{
						id: 'BEH-1',
						category: 'behavioral',
						severity: 'high',
						title: 'Browser profile copy detected',
						description: 't',
						evidence: 'actual Chrome profile',
						deduction: 15,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
				],
			}),
			content: makeCategoryScore(95, 0.10),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.findings.length).toBe(1);
		expect(report.findings[0]?.title).toBe('Browser profile copy detected');
		expect(report.findings[0]?.description).toContain('Reusable authenticated browser container dependency');
	});

	it('should merge broader behavioral auth families after earlier report shaping', () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.20),
			injection: makeCategoryScore(95, 0.25),
			dependencies: makeCategoryScore(95, 0.15),
			behavioral: makeCategoryScore(95, 0.15, {
				findings: [
					{
						id: 'BEH-1',
						category: 'behavioral',
						severity: 'high',
						title: 'Persistent session reuse detected',
						description: 't',
						evidence: 'session saved',
						deduction: 15,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
					{
						id: 'BEH-2',
						category: 'behavioral',
						severity: 'high',
						title: 'Browser session attachment detected',
						description: 't',
						evidence: 'real Chrome with CDP',
						deduction: 15,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
				],
			}),
			content: makeCategoryScore(95, 0.10),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.findings.length).toBe(1);
		expect(report.findings[0]?.description).toContain('Merged auth/profile context:');
		expect((report.findings[0]?.description.match(/\n\nMerged /g) ?? []).length).toBe(1);
	});

	it('should fold auth_cookies persistence into cookie-browser-auth family', () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.20),
			injection: makeCategoryScore(95, 0.25),
			dependencies: makeCategoryScore(95, 0.15),
			behavioral: makeCategoryScore(95, 0.15, {
				findings: [
					{
						id: 'BEH-1',
						category: 'behavioral',
						severity: 'high',
						title: 'MCP-issued browser auth cookie detected',
						description: 't',
						evidence: 'agents get an auth cookie via MCP',
						deduction: 15,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
					{
						id: 'BEH-2',
						category: 'behavioral',
						severity: 'medium',
						title: 'Credential store persistence detected',
						description: 't',
						evidence: 'auth_cookies',
						deduction: 10,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
				],
			}),
			content: makeCategoryScore(95, 0.10),
			"code-safety": makeCategoryScore(100, 0.15),
		};
		const report = aggregateScores(categories, metadata);
		expect(report.findings.length).toBe(1);
		expect(report.findings[0]?.description).toContain('Merged auth/profile context:');
	});

	it('should merge multiple high behavioral auth findings into one summary', () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.20),
			injection: makeCategoryScore(95, 0.25),
			dependencies: makeCategoryScore(95, 0.15),
			behavioral: makeCategoryScore(95, 0.15, {
				findings: [
					{
						id: 'BEH-1',
						category: 'behavioral',
						severity: 'high',
						title: 'Persistent session reuse detected',
						description: 't',
						evidence: 'session saved',
						deduction: 15,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
					{
						id: 'BEH-2',
						category: 'behavioral',
						severity: 'high',
						title: 'Credential vault enrollment detected',
						description: 't',
						evidence: 'Auth vault',
						deduction: 15,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
				],
			}),
			content: makeCategoryScore(95, 0.10),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.findings.length).toBe(1);
		expect(report.findings[0]?.title).toBe('Persistent session reuse detected');
		expect(report.findings[0]?.description).toContain('Credential vault enrollment detected');
	});

	it('should merge auth-related permission contract mismatches into one behavioral summary when present', () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.20, {
				findings: [
					{
						id: 'PERM-1',
						category: 'permissions',
						severity: 'high',
						title: 'Capability contract mismatch: inferred credential access is not declared',
						description: 't',
						evidence: 'actual Chrome profile',
						deduction: 12,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
					{
						id: 'PERM-2',
						category: 'permissions',
						severity: 'high',
						title: 'Capability contract mismatch: inferred credential handoff is not declared',
						description: 't',
						evidence: 'use that auth state',
						deduction: 12,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
				],
			}),
			injection: makeCategoryScore(95, 0.25),
			dependencies: makeCategoryScore(95, 0.15),
			behavioral: makeCategoryScore(95, 0.15, {
				findings: [
					{
						id: 'BEH-1',
						category: 'behavioral',
						severity: 'high',
						title: 'Browser profile copy detected',
						description: 't',
						evidence: 'actual Chrome profile',
						deduction: 15,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
				],
			}),
			content: makeCategoryScore(95, 0.10),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.findings.length).toBe(1);
		expect(report.findings[0]?.title).toBe('Browser profile copy detected');
		expect(report.findings[0]?.description).toContain('Merged auth/profile context:');
		expect(report.findings[0]?.description).toContain('credential access is not declared');
	});

	it('should merge auth findings that map to the same broader risk family', () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(95, 0.20, {
				findings: [
					{
						id: 'PERM-1',
						category: 'permissions',
						severity: 'high',
						title: 'Capability contract mismatch: inferred credential access is not declared',
						description: 't',
						evidence: 'actual Chrome profile',
						deduction: 12,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
					{
						id: 'PERM-2',
						category: 'permissions',
						severity: 'high',
						title: 'Capability contract mismatch: inferred auth state management is not declared',
						description: 't',
						evidence: 'actual Chrome profile (cookies, logins, extensions)',
						deduction: 12,
						recommendation: 'r',
						owaspCategory: 'ASST-05',
					},
				],
			}),
			injection: makeCategoryScore(95, 0.25),
			dependencies: makeCategoryScore(95, 0.15),
			behavioral: makeCategoryScore(95, 0.15),
			content: makeCategoryScore(95, 0.10),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		expect(report.findings.length).toBe(1);
		expect(report.findings[0]?.description).toContain('same auth risk family');
	});

	// --- Config tampering badge cap ---

	it("should cap badge to SUSPICIOUS for high config-tamper finding (BEH-CONFIG-TAMPER-*)", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(100, 0.20),
			injection: makeCategoryScore(100, 0.25),
			dependencies: makeCategoryScore(100, 0.15),
			behavioral: makeCategoryScore(80, 0.15, {
				findings: [
					{
						id: "BEH-CONFIG-TAMPER-CORE-1",
						category: "behavioral",
						severity: "high",
						title: "Config tamper core detected",
						description: "Modify AGENTS.md",
						evidence: "Modify AGENTS.md",
						deduction: 25,
						recommendation: "Do not modify",
						owaspCategory: "ASST-03",
					},
				],
			}),
			content: makeCategoryScore(100, 0.10),
			"code-safety": makeCategoryScore(100, 0.15),
		};

		const report = aggregateScores(categories, metadata);
		// Score would be ~96 (only behavioral docked) — normally certified/conditional
		expect(report.overall).toBeGreaterThanOrEqual(90);
		// But config-tamper cap forces suspicious
		expect(report.badge).toBe("suspicious");
	});

	it("should cap badge to REJECTED for critical config-tamper finding (CS-CONFIG-TAMPER-*)", () => {
		const categories: Record<Category, CategoryScore> = {
			permissions: makeCategoryScore(100, 0.20),
			injection: makeCategoryScore(100, 0.25),
			dependencies: makeCategoryScore(100, 0.15),
			behavioral: makeCategoryScore(100, 0.15),
			content: makeCategoryScore(100, 0.10),
			"code-safety": makeCategoryScore(70, 0.15, {
				findings: [
					{
						id: "CS-CONFIG-TAMPER-CORE-1",
						category: "code-safety",
						severity: "critical",
						title: "Write to AGENTS.md in code block",
						description: "appendFileSync AGENTS.md",
						evidence: "appendFileSync AGENTS.md",
						deduction: 30,
						recommendation: "Do not write",
						owaspCategory: "ASST-03",
					},
				],
			}),
		};

		const report = aggregateScores(categories, metadata);
		// Critical → rejected (existing rule, but config-tamper makes it explicit)
		expect(report.badge).toBe("rejected");
	});
});
