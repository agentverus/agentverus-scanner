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
	readonly skillName: string;
	readonly skillDescription: string;
}

/** Complete trust report */
export interface TrustReport {
	readonly overall: number;
	readonly badge: BadgeTier;
	readonly categories: Readonly<Record<Category, CategoryScore>>;
	readonly findings: readonly Finding[];
	readonly metadata: ScanMetadata;
}

/** Options for the LLM-assisted semantic analyzer */
export interface SemanticAnalyzerOptions {
	/** OpenAI-compatible API base URL (default: https://api.openai.com/v1) */
	readonly apiBase?: string;
	/** API key (default: AGENTVERUS_LLM_API_KEY env var) */
	readonly apiKey?: string;
	/** Model to use (default: gpt-4o-mini) */
	readonly model?: string;
	/** Timeout in ms for the LLM call (default: 30000) */
	readonly timeout?: number;
}

/** Options for running a scan */
export interface ScanOptions {
	readonly timeout?: number;
	readonly retries?: number;
	readonly retryDelayMs?: number;
	/** Enable LLM-assisted semantic analysis. Pass true to use env defaults, or an options object. */
	readonly semantic?: boolean | SemanticAnalyzerOptions;
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
export const SCANNER_VERSION = "0.3.0";
