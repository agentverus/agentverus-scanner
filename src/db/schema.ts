import {
	pgTable,
	uuid,
	text,
	integer,
	timestamp,
	pgEnum,
	jsonb,
	date,
	index,
	uniqueIndex,
	check,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

// Enums
export const skillFormatEnum = pgEnum("skill_format", ["openclaw", "claude", "generic"]);

export const severityEnum = pgEnum("severity", [
	"critical",
	"high",
	"medium",
	"low",
	"info",
]);

export const certificationTierEnum = pgEnum("certification_tier", [
	"free",
	"basic",
	"enterprise",
]);

export const certificationStatusEnum = pgEnum("certification_status", [
	"pending",
	"processing",
	"active",
	"expired",
	"revoked",
	"failed",
]);

export const apiKeyTierEnum = pgEnum("api_key_tier", [
	"free",
	"pro",
	"enterprise",
	"admin",
]);

export const badgeTierEnum = pgEnum("badge_tier", [
	"certified",
	"conditional",
	"suspicious",
	"rejected",
]);

// Tables
export const skills = pgTable(
	"skills",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		url: text("url"),
		name: text("name").notNull(),
		description: text("description"),
		format: skillFormatEnum("format").notNull(),
		contentHash: text("content_hash").notNull(),
		publisherUrl: text("publisher_url"),
		createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
		updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
	},
	(table) => [
		uniqueIndex("idx_skills_url").on(table.url),
		index("idx_skills_content_hash").on(table.contentHash),
		index("idx_skills_name").on(table.name),
	],
);

export const scanResults = pgTable(
	"scan_results",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		skillId: uuid("skill_id")
			.notNull()
			.references(() => skills.id, { onDelete: "cascade" }),
		overallScore: integer("overall_score").notNull(),
		badge: badgeTierEnum("badge").notNull(),
		permissionsScore: integer("permissions_score").notNull(),
		injectionScore: integer("injection_score").notNull(),
		dependenciesScore: integer("dependencies_score").notNull(),
		behavioralScore: integer("behavioral_score").notNull(),
		contentScore: integer("content_score").notNull(),
		report: jsonb("report").notNull(),
		scannerVersion: text("scanner_version").notNull(),
		scannedAt: timestamp("scanned_at", { withTimezone: true }).notNull().defaultNow(),
		durationMs: integer("duration_ms").notNull(),
	},
	(table) => [
		index("idx_scan_results_skill_id").on(table.skillId),
		index("idx_scan_results_scanned_at").on(table.scannedAt),
		check("score_range", sql`${table.overallScore} >= 0 AND ${table.overallScore} <= 100`),
	],
);

export const findings = pgTable(
	"findings",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		scanResultId: uuid("scan_result_id")
			.notNull()
			.references(() => scanResults.id, { onDelete: "cascade" }),
		findingId: text("finding_id").notNull(),
		category: text("category").notNull(),
		severity: severityEnum("severity").notNull(),
		title: text("title").notNull(),
		description: text("description").notNull(),
		evidence: text("evidence"),
		lineNumber: integer("line_number"),
		deduction: integer("deduction").notNull(),
		recommendation: text("recommendation"),
		owaspCategory: text("owasp_category"),
	},
	(table) => [
		index("idx_findings_scan_result_id").on(table.scanResultId),
		index("idx_findings_severity").on(table.severity),
	],
);

export const certifications = pgTable(
	"certifications",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		skillId: uuid("skill_id")
			.notNull()
			.references(() => skills.id, { onDelete: "cascade" }),
		scanResultId: uuid("scan_result_id").references(() => scanResults.id),
		tier: certificationTierEnum("tier").notNull().default("free"),
		status: certificationStatusEnum("status").notNull().default("pending"),
		stripePaymentId: text("stripe_payment_id"),
		stripeCheckoutSessionId: text("stripe_checkout_session_id"),
		badgeUrl: text("badge_url"),
		attestation: text("attestation"),
		publisherEmail: text("publisher_email").notNull(),
		issuedAt: timestamp("issued_at", { withTimezone: true }),
		expiresAt: timestamp("expires_at", { withTimezone: true }),
		createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
	},
	(table) => [
		index("idx_certifications_skill_id").on(table.skillId),
		index("idx_certifications_status").on(table.status),
	],
);

export const apiKeys = pgTable(
	"api_keys",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		keyHash: text("key_hash").notNull(),
		name: text("name").notNull(),
		tier: apiKeyTierEnum("tier").notNull().default("free"),
		ownerEmail: text("owner_email").notNull(),
		requestsToday: integer("requests_today").notNull().default(0),
		requestsMonth: integer("requests_month").notNull().default(0),
		lastResetDate: date("last_reset_date").notNull().defaultNow(),
		createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
		lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
		revokedAt: timestamp("revoked_at", { withTimezone: true }),
	},
	(table) => [
		uniqueIndex("idx_api_keys_key_hash").on(table.keyHash),
		index("idx_api_keys_owner_email").on(table.ownerEmail),
	],
);
