/** Shared URL/domain risk helpers used across scanner analyzers. */

export const KNOWN_INSTALLER_DOMAIN_PATTERNS = [
	/deno\.land/i,
	/bun\.sh/i,
	/rustup\.rs/i,
	/get\.docker\.com/i,
	/install\.python-poetry\.org/i,
	/raw\.githubusercontent\.com\/nvm-sh/i,
	/raw\.githubusercontent\.com\/Homebrew/i,
	/raw\.githubusercontent\.com\/golangci/i,
	/foundry\.paradigm\.xyz/i,
	/tailscale\.com(?:\/install)?/i,
	/opencode\.ai(?:\/install)?/i,
	/sh\.rustup\.rs/i,
	/get\.pnpm\.io/i,
	/volta\.sh/i,
] as const;

export function isKnownInstallerTarget(text: string): boolean {
	return KNOWN_INSTALLER_DOMAIN_PATTERNS.some((pattern) => pattern.test(text));
}

/** High-abuse TLDs commonly used for phishing/malware delivery. */
export const HIGH_ABUSE_TLD_PATTERN = "(?:xyz|top|buzz|click|loan|gq|ml|cf|tk|pw|cc|icu|cam|sbs)";

export const HIGH_ABUSE_TLD_HOST_REGEX = new RegExp(`\\.${HIGH_ABUSE_TLD_PATTERN}$`, "i");
export const HIGH_ABUSE_TLD_IN_TEXT_REGEX = new RegExp(`\\.${HIGH_ABUSE_TLD_PATTERN}(?:\\/|\\b)`, "i");

export function hasHighAbuseTldHost(hostname: string): boolean {
	return HIGH_ABUSE_TLD_HOST_REGEX.test(hostname);
}

export function hasHighAbuseTldInText(text: string): boolean {
	return HIGH_ABUSE_TLD_IN_TEXT_REGEX.test(text);
}
