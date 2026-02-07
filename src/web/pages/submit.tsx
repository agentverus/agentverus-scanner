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
					<h1 class="text-3xl font-bold mb-3">Submit a Skill for Scanning</h1>
					<p class="text-gray-400 mb-8">
						Paste your SKILL.md content or provide a URL. We'll analyze it for security threats and
						generate a trust report. <strong class="text-certified">Free.</strong>
					</p>

					<form id="scan-form" class="space-y-6">
						<div>
							<label class="block text-sm font-medium mb-2">Skill URL</label>
							<input
								type="url"
								name="url"
								placeholder="https://github.com/user/repo/blob/main/SKILL.md"
								class="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-certified"
							/>
							<p class="text-gray-500 text-sm mt-1">
								Direct URL to a SKILL.md file (raw content URL works best)
							</p>
						</div>

						<div class="flex items-center gap-4">
							<div class="flex-1 h-px bg-gray-700" />
							<span class="text-gray-500 text-sm">OR</span>
							<div class="flex-1 h-px bg-gray-700" />
						</div>

						<div>
							<label class="block text-sm font-medium mb-2">Paste SKILL.md Content</label>
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
								class="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-certified"
							/>
						</div>

						<div>
							<label class="block text-sm font-medium mb-2">Your Email (for notification)</label>
							<input
								type="email"
								name="email"
								placeholder="you@example.com"
								class="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-certified"
							/>
						</div>

						<button
							type="submit"
							class="w-full bg-certified hover:bg-blue-700 text-white py-3 rounded-lg font-semibold text-lg transition font-display"
						>
							🔍 Scan Skill — Free
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
	btn.textContent = '⏳ Scanning...';
	btn.disabled = true;

	try {
		const res = await fetch('/api/v1/certify', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ url: url || undefined, content: content || undefined, email }),
		});
		const data = await res.json();

		if (!res.ok) {
			document.getElementById('results').innerHTML = '<div class="bg-red-900/50 border border-red-700 rounded-lg p-4 text-red-300">' + (data.error?.message || 'Scan failed') + '</div>';
			return;
		}

		const report = data.report;
		const badgeColors = { certified: 'text-certified', conditional: 'text-conditional', suspicious: 'text-suspicious', rejected: 'text-rejected' };
		const color = badgeColors[report.badge] || 'text-gray-400';

		let html = '<div class="bg-gray-900 border border-gray-800 rounded-xl p-6">';
		html += '<h2 class="text-2xl font-bold mb-4">Scan Results</h2>';
		html += '<div class="flex items-center gap-4 mb-6">';
		html += '<span class="text-5xl font-bold ' + color + '">' + report.overall + '</span>';
		html += '<div>';
		html += '<span class="text-lg font-semibold ' + color + ' uppercase">' + report.badge + '</span>';
		html += '<p class="text-gray-400 text-sm">Trust Score</p>';
		html += '</div></div>';

		// Badge embed
		html += '<div class="mb-6 p-4 bg-gray-800 rounded-lg">';
		html += '<p class="text-sm text-gray-400 mb-2">Embed this badge:</p>';
		html += '<code class="text-xs text-blue-400 break-all">![AgentVerus](' + window.location.origin + data.badgeUrl + ')</code>';
		html += '</div>';

		// Findings
		if (report.findings && report.findings.length > 0) {
			html += '<h3 class="text-lg font-semibold mb-3">Findings (' + report.findings.length + ')</h3>';
			report.findings.forEach(function(f) {
				const sevColors = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-blue-500', info: 'bg-gray-500' };
				html += '<div class="mb-2 p-3 bg-gray-800 rounded-lg">';
				html += '<span class="inline-block px-2 py-0.5 rounded text-xs font-medium text-white ' + (sevColors[f.severity] || 'bg-gray-500') + ' mr-2">' + f.severity.toUpperCase() + '</span>';
				html += '<span class="font-medium">' + f.title + '</span>';
				if (f.evidence) html += '<p class="text-sm text-gray-400 mt-1">' + f.evidence.substring(0, 150) + '</p>';
				html += '</div>';
			});
		}

		html += '</div>';
		document.getElementById('results').innerHTML = html;
	} catch (err) {
		document.getElementById('results').innerHTML = '<div class="bg-red-900/50 border border-red-700 rounded-lg p-4 text-red-300">Error: ' + err.message + '</div>';
	} finally {
		btn.textContent = '🔍 Scan Skill — Free';
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
