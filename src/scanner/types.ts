/** Detected skill file format */
export type SkillFormat = "openclaw" | "claude" | "generic";

/** Finding severity level */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Analysis category */
export type Category = "permissions" | "injection" | "dependencies" | "behavioral" | "content";

/** Badge tier based on score and findings */
export type BadgeTier = "certified" | "conditional" | "suspicious" | "rejected";

/** A permission explicitly declared by the skill author */
export interface DeclaredPermission {
	readonly kind: string;
	readonly justification: string;
}

/** Parsed skill file content */
export interface ParsedSkill {
	readonly name: string;
	readonly description: string;
	readonly instructions: string;
	readonly tools: readonly string[];
	readonly permissions: readonly string[];
	readonly declaredPermissions: readonly DeclaredPermission[];
	readonly dependencies: readonly string[];
	readonly urls: readonly string[];
	readonly rawSections: Readonly<Record<string, string>>;
	readonly rawContent: string;
	readonly format: SkillFormat;
	readonly warnings: readonly string[];
}

/** A single security finding */
export interface Finding {
	readonly id: string;
	readonly category: Category;
	readonly severity: Severity;
	readonly title: string;
	readonly description: string;
	readonly evidence: string;
	readonly lineNumber?: number;
	readonly deduction: number;
	readonly recommendation: string;
	readonly owaspCategory: string;
}

/** Score result for a single analysis category */
export interface CategoryScore {
	readonly score: number;
	readonly weight: number;
	readonly findings: readonly Finding[];
	readonly summary: string;
}

/** Metadata about a scan run */
export interface ScanMetadata {
	readonly scannedAt: Date;
	readonly scannerVersion: string;
	readonly durationMs: number;
	readonly skillFormat: SkillFormat;
}

/** Complete trust report */
export interface TrustReport {
	readonly overall: number;
	readonly badge: BadgeTier;
	readonly categories: Readonly<Record<Category, CategoryScore>>;
	readonly findings: readonly Finding[];
	readonly metadata: ScanMetadata;
}

/** Options for running a scan */
export interface ScanOptions {
	readonly timeout?: number;
	readonly retries?: number;
	readonly retryDelayMs?: number;
}

/** ASST Taxonomy categories */
export const ASST_CATEGORIES = {
	"ASST-01": "Instruction Injection",
	"ASST-02": "Data Exfiltration",
	"ASST-03": "Privilege Escalation",
	"ASST-04": "Dependency Hijacking",
	"ASST-05": "Credential Harvesting",
	"ASST-06": "Prompt Injection Relay",
	"ASST-07": "Deceptive Functionality",
	"ASST-08": "Excessive Permissions",
	"ASST-09": "Missing Safety Boundaries",
	"ASST-10": "Obfuscation",
} as const;

/** Scanner version */
export const SCANNER_VERSION = "0.1.0";
