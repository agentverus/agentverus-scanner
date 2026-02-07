import { Hono } from "hono";
import { BaseLayout } from "../layouts/base.js";

const submitApp = new Hono();

submitApp.get("/submit", (c) => {
	return c.html(
		<BaseLayout
			title="Submit Skill"
			description="Submit an AI agent skill for trust scanning and certification."
		>
			<section class="py-12 px-4">
				<div class="max-w-3xl mx-auto">
					<div class="inline-block border border-white/30 px-3 py-1 text-xs uppercase tracking-widest text-white/60 mb-6">
						Skill Scanner
					</div>
					<h1 class="text-2xl font-extrabold mb-3 uppercase tracking-wider">Submit a Skill for Scanning</h1>
					<div class="w-full h-px bg-white/20 mb-6" />
					<p class="text-white/50 text-sm mb-8 uppercase tracking-wide">
						Paste your SKILL.md content or provide a URL. We'll analyze it for security threats and
						generate a trust report. <span class="text-certified font-bold">Free.</span>
					</p>

					<form id="scan-form" class="space-y-6">
						<div>
							<label class="block text-xs font-bold uppercase tracking-widest mb-2 text-white/70">Skill URL</label>
							<input
								type="url"
								name="url"
								placeholder="https://github.com/user/repo/blob/main/SKILL.md"
								class="w-full bg-black border border-white/20 px-4 py-3 text-white text-sm placeholder-white/30 focus:outline-none focus:border-white"
							/>
							<p class="text-white/30 text-xs mt-1 uppercase tracking-wide">
								Direct URL to a SKILL.md file (raw content URL works best)
							</p>
						</div>

						<div class="flex items-center gap-4">
							<div class="flex-1 h-px bg-white/20" />
							<span class="text-white/30 text-xs uppercase tracking-widest">Or</span>
							<div class="flex-1 h-px bg-white/20" />
						</div>

						<div>
							<label class="block text-xs font-bold uppercase tracking-widest mb-2 text-white/70">Paste SKILL.md Content</label>
							<textarea
								name="content"
								rows={12}
								placeholder="---
name: My Skill
description: A helpful skill
tools:
  - read
permissions:
  - read
---

# My Skill

## Instructions
..."
								class="w-full bg-black border border-white/20 px-4 py-3 text-white text-sm placeholder-white/30 font-mono focus:outline-none focus:border-white"
							/>
						</div>

						<div>
							<label class="block text-xs font-bold uppercase tracking-widest mb-2 text-white/70">Your Email (for notification)</label>
							<input
								type="email"
								name="email"
								placeholder="you@example.com"
								class="w-full bg-black border border-white/20 px-4 py-3 text-white text-sm placeholder-white/30 focus:outline-none focus:border-white"
							/>
						</div>

						<button
							type="submit"
							class="w-full border-2 border-white bg-white text-black py-3 font-bold text-sm uppercase tracking-widest hover:bg-transparent hover:text-white transition"
						>
							Scan Skill — Free
						</button>
					</form>

					<div id="results" class="mt-8" />

					<script
						dangerouslySetInnerHTML={{
							__html: `
document.getElementById('scan-form').addEventListener('submit', async (e) => {
	e.preventDefault();
	const form = e.target;
	const url = form.url.value;
	const content = form.content.value;
	const email = form.email.value || 'anonymous@scan.local';

	if (!url && !content) {
		alert('Please provide a URL or paste content');
		return;
	}

	const btn = form.querySelector('button[type="submit"]');
	btn.textContent = 'SCANNING...';
	btn.disabled = true;

	try {
		const res = await fetch('/api/v1/certify', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ url: url || undefined, content: content || undefined, email }),
		});
		const data = await res.json();

		if (!res.ok) {
			document.getElementById('results').innerHTML = '<div class="border border-rejected p-4 text-rejected text-sm">' + (data.error?.message || 'Scan failed') + '</div>';
			return;
		}

		const report = data.report;
		const badgeColors = { certified: 'text-certified', conditional: 'text-conditional', suspicious: 'text-suspicious', rejected: 'text-rejected' };
		const color = badgeColors[report.badge] || 'text-white/40';

		let html = '<div class="border border-white/20 p-6">';
		html += '<h2 class="text-lg font-bold uppercase tracking-wider mb-4">Scan Results</h2>';
		html += '<div class="w-full h-px bg-white/20 mb-6"></div>';
		html += '<div class="flex items-center gap-4 mb-6">';
		html += '<span class="text-5xl font-extrabold ' + color + '">' + report.overall + '</span>';
		html += '<div>';
		html += '<span class="text-sm font-bold ' + color + ' uppercase tracking-widest">' + report.badge + '</span>';
		html += '<p class="text-white/40 text-xs uppercase tracking-wider">Trust Score</p>';
		html += '</div></div>';

		// Badge embed
		html += '<div class="mb-6 p-4 border border-white/10">';
		html += '<p class="text-xs text-white/40 mb-2 uppercase tracking-wider">Embed this badge:</p>';
		html += '<code class="text-xs text-certified break-all">![AgentVerus](' + window.location.origin + data.badgeUrl + ')</code>';
		html += '</div>';

		// Findings
		if (report.findings && report.findings.length > 0) {
			html += '<h3 class="text-sm font-bold uppercase tracking-wider mb-3">Findings (' + report.findings.length + ')</h3>';
			report.findings.forEach(function(f) {
				const sevColors = { critical: 'text-rejected', high: 'text-suspicious', medium: 'text-conditional', low: 'text-certified', info: 'text-white/40' };
				html += '<div class="mb-2 p-3 border border-white/10">';
				html += '<span class="text-xs font-bold uppercase tracking-wider ' + (sevColors[f.severity] || 'text-white/40') + ' mr-2">[' + f.severity.toUpperCase() + ']</span>';
				html += '<span class="text-sm font-bold">' + f.title + '</span>';
				if (f.evidence) html += '<p class="text-xs text-white/40 mt-1">' + f.evidence.substring(0, 150) + '</p>';
				html += '</div>';
			});
		}

		html += '</div>';
		document.getElementById('results').innerHTML = html;
	} catch (err) {
		document.getElementById('results').innerHTML = '<div class="border border-rejected p-4 text-rejected text-sm">Error: ' + err.message + '</div>';
	} finally {
		btn.textContent = 'SCAN SKILL — FREE';
		btn.disabled = false;
	}
});`,
						}}
					/>
				</div>
			</section>
		</BaseLayout>,
	);
});

export { submitApp };
