import { lookup } from "node:dns/promises";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fetchSkillContentFromUrl } from "../../src/scanner/source.js";

// Mock DNS so the "public hostname resolves to a private IP" case is deterministic
// and offline. Only the hostname test below calls lookup; literal-IP tests short-
// circuit before DNS, so the default mock never affects them.
vi.mock("node:dns/promises", () => ({ lookup: vi.fn() }));

describe("fetchSkillContentFromUrl SSRF IPv6 blocking", () => {
	const savedFetch = globalThis.fetch;

	beforeEach(() => {
		// Default mock: return a tiny valid markdown body.
		const fetchMock = vi.fn(async () => {
			return new Response("# OK\n", {
				status: 200,
				headers: { "content-type": "text/markdown" },
			});
		});
		// @ts-expect-error - override global fetch for tests
		globalThis.fetch = fetchMock;
	});

	afterEach(() => {
		globalThis.fetch = savedFetch;
		vi.restoreAllMocks();
	});

	it("blocks deprecated site-local fec0::/10", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://[fec0::1]/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/Blocked IP address/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("blocks IPv4-mapped IPv6 that maps to loopback", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://[::ffff:127.0.0.1]/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/Blocked IP address/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("blocks IPv4-compatible IPv6 that maps to loopback", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://[::127.0.0.1]/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/Blocked IP address/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("blocks Teredo 2001:0000::/32", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://[2001:0::1]/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/Blocked IP address/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("blocks 6to4 when embedded IPv4 is private", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://[2002:0a00:0001::]/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/Blocked IP address/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("allows global IPv6 literals", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		const { content } = await fetchSkillContentFromUrl("https://[2001:4860:4860::8888]/SKILL.md", {
			retries: 0,
			timeout: 0,
		});
		expect(content).toContain("# OK");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("allows 6to4 when embedded IPv4 is public", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		const { content } = await fetchSkillContentFromUrl("https://[2002:0808:0808::]/SKILL.md", {
			retries: 0,
			timeout: 0,
		});
		expect(content).toContain("# OK");
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});
});

describe("fetchSkillContentFromUrl SSRF IPv4 + hostname blocking", () => {
	const savedFetch = globalThis.fetch;

	beforeEach(() => {
		const fetchMock = vi.fn(async () => new Response("# OK\n", { status: 200 }));
		// @ts-expect-error - override global fetch for tests
		globalThis.fetch = fetchMock;
		vi.mocked(lookup).mockReset();
	});

	afterEach(() => {
		globalThis.fetch = savedFetch;
		vi.restoreAllMocks();
	});

	it.each([
		["https://127.0.0.1/SKILL.md", "loopback"],
		["https://0.0.0.0/SKILL.md", "unspecified / this-host"],
		["https://169.254.169.254/latest/meta-data/", "cloud metadata (link-local)"],
		["https://10.0.0.5/SKILL.md", "private A"],
		["https://192.168.1.10/SKILL.md", "private C"],
		["https://172.16.5.5/SKILL.md", "private B lower bound"],
		["https://172.31.255.255/SKILL.md", "private B upper bound"],
		["https://100.64.0.1/SKILL.md", "CGNAT"],
	])("blocks literal IPv4 %s (%s) before any fetch", async (url) => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(fetchSkillContentFromUrl(url, { retries: 0, timeout: 0 })).rejects.toThrow(
			/Blocked IP address/i,
		);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it.each([
		"https://localhost/SKILL.md",
		"https://foo.localhost/SKILL.md",
		"https://service.local/SKILL.md",
		"https://metadata.google.internal/SKILL.md",
	])("blocks SSRF-target hostname %s before any fetch", async (url) => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(fetchSkillContentFromUrl(url, { retries: 0, timeout: 0 })).rejects.toThrow(
			/Blocked hostname/i,
		);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("blocks a public hostname that resolves to a private IP (mocked DNS)", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		vi.mocked(lookup).mockResolvedValue([{ address: "10.0.0.5", family: 4 }] as never);
		await expect(
			fetchSkillContentFromUrl("https://evil.example/SKILL.md", { retries: 0, timeout: 0 }),
			// match the DNS-derived message so this can only pass via the lookup path
		).rejects.toThrow(/resolves to 10\.0\.0\.5/);
		expect(vi.mocked(lookup)).toHaveBeenCalledWith("evil.example", expect.anything());
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("fails closed when DNS resolution itself fails", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		vi.mocked(lookup).mockRejectedValue(new Error("ENOTFOUND"));
		await expect(
			fetchSkillContentFromUrl("https://unresolvable.example/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/Unable to resolve hostname/);
		expect(vi.mocked(lookup)).toHaveBeenCalledWith("unresolvable.example", expect.anything());
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

describe("fetchSkillContentFromUrl URL-shape hardening", () => {
	const savedFetch = globalThis.fetch;

	beforeEach(() => {
		// Mock fetch so a "rejects" can only come from the scanner's own guard,
		// not from a native fetch failure that happens to match the regex.
		const fetchMock = vi.fn(async () => new Response("# OK\n", { status: 200 }));
		// @ts-expect-error - override global fetch for tests
		globalThis.fetch = fetchMock;
	});

	afterEach(() => {
		globalThis.fetch = savedFetch;
	});

	it("rejects embedded credentials before any fetch", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://user:pass@example.com/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/credentials/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects non-standard ports before any fetch", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("https://example.com:8080/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/ports/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects non-https protocols before any fetch", async () => {
		const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
		await expect(
			fetchSkillContentFromUrl("http://example.com/SKILL.md", { retries: 0, timeout: 0 }),
		).rejects.toThrow(/https/i);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

