import { createHash } from "node:crypto";

/** Compute SHA-256 hash of content */
export function sha256(content: string): string {
	return createHash("sha256").update(content).digest("hex");
}

/** Truncate a string to a maximum length */
export function truncate(str: string, maxLength: number): string {
	if (str.length <= maxLength) return str;
	return `${str.slice(0, maxLength - 3)}...`;
}

/** Format a duration in milliseconds to human-readable */
export function formatDuration(ms: number): string {
	if (ms < 1000) return `${ms}ms`;
	const seconds = Math.round(ms / 100) / 10;
	return `${seconds}s`;
}

/** Generate a UUID v4 */
export function generateId(): string {
	return crypto.randomUUID();
}
