import { Hono } from "hono";
import { BaseLayout } from "../layouts/base.js";

const docsApp = new Hono();

docsApp.get("/docs", (c) => {
	return c.html(
		<BaseLayout title="API Documentation" description="REST API documentation for AgentVerus.">
			<section class="py-12 px-4">
				<div class="max-w-4xl mx-auto">
					<div class="inline-block border border-white/30 px-3 py-1 text-xs uppercase tracking-widest text-white/60 mb-6">
						API Reference
					</div>
					<h1 class="text-2xl font-extrabold mb-3 uppercase tracking-wider">API Documentation</h1>
					<div class="w-full h-px bg-white/20 mb-6" />
					<p class="text-white/50 text-sm mb-8">
						Base URL:{" "}
						<code class="border border-white/20 px-2 py-1 text-certified text-xs">
							{c.req.url.split("/docs")[0]}/api/v1
						</code>
					</p>

					{/* Authentication */}
					<div class="mb-12">
						<h2 class="text-lg font-bold uppercase tracking-wider mb-4">Authentication</h2>
						<div class="w-full h-px bg-white/10 mb-4" />
						<p class="text-white/50 text-sm mb-3">Some endpoints require an API key. Pass it via header:</p>
						<pre class="border border-white/20 p-4 text-xs overflow-x-auto mb-4">
							<code class="text-certified">Authorization: Bearer at_your_api_key_here</code>
						</pre>
						<p class="text-white/50 text-sm">
							Public endpoints (GET) don't require authentication. POST endpoints require a valid
							API key.
						</p>
					</div>

					{/* Endpoints */}
					{[
						{
							method: "POST",
							path: "/api/v1/skill/scan",
							desc: "Submit a skill for scanning. Returns a complete trust report.",
							auth: "Optional",
							body: `{
  "content": "---\\nname: My Skill\\n---\\n# Instructions...",
  // OR
  "url": "https://raw.githubusercontent.com/.../SKILL.md"
}`,
							response: `{
  "skillId": "uuid",
  "scanResultId": "uuid",
  "contentHash": "sha256...",
  "report": {
    "overall": 95,
    "badge": "certified",
    "categories": { ... },
    "findings": [ ... ],
    "metadata": { ... }
  }
}`,
							curl: `curl -X POST ${c.req.url.split("/docs")[0]}/api/v1/skill/scan \\
  -H "Content-Type: application/json" \\
  -d '{"content": "---\\nname: Test\\n---\\n# My Skill"}'`,
						},
						{
							method: "GET",
							path: "/api/v1/skill/:id/trust",
							desc: "Get the latest trust report for a skill.",
							auth: "None",
							body: null,
							response: `{
  "skill": { "id": "uuid", "name": "...", "url": "..." },
  "report": { "overall": 95, "badge": "certified", ... }
}`,
							curl: `curl ${c.req.url.split("/docs")[0]}/api/v1/skill/SKILL_ID/trust`,
						},
						{
							method: "GET",
							path: "/api/v1/skill/:id/badge",
							desc: "Get an SVG trust badge for embedding. Query params: style (flat|flat-square), label.",
							auth: "None",
							body: null,
							response: "SVG image (Content-Type: image/svg+xml)",
							curl: `# Embed in markdown:
![AgentVerus](${c.req.url.split("/docs")[0]}/api/v1/skill/SKILL_ID/badge)`,
						},
						{
							method: "GET",
							path: "/api/v1/skills",
							desc: "Search and list skills. Query params: q, badge, sort, order, page, limit.",
							auth: "None",
							body: null,
							response: `{
  "skills": [ ... ],
  "pagination": { "page": 1, "limit": 20, "total": 0, "totalPages": 0 }
}`,
							curl: `curl "${c.req.url.split("/docs")[0]}/api/v1/skills?q=weather&badge=certified"`,
						},
						{
							method: "POST",
							path: "/api/v1/certify",
							desc: "Submit a skill for free certification. Runs scan and issues badge.",
							auth: "Optional",
							body: `{
  "content": "...",  // or "url": "..."
  "email": "publisher@example.com"
}`,
							response: `{
  "certificationId": "uuid",
  "skillId": "uuid",
  "status": "active",
  "badgeUrl": "/api/v1/skill/uuid/badge",
  "report": { ... }
}`,
							curl: `curl -X POST ${c.req.url.split("/docs")[0]}/api/v1/certify \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://...", "email": "me@example.com"}'`,
						},
					].map((endpoint) => (
						<div class="mb-8 border border-white/20 p-6">
							<div class="flex items-center gap-3 mb-3">
								<span
									class={`px-3 py-1 text-xs font-bold uppercase tracking-widest ${
										endpoint.method === "GET"
											? "border border-certified text-certified"
											: "border border-conditional text-conditional"
									}`}
								>
									{endpoint.method}
								</span>
								<code class="text-sm">{endpoint.path}</code>
								<span class="text-white/30 text-xs ml-auto uppercase tracking-wider">Auth: {endpoint.auth}</span>
							</div>
							<p class="text-white/50 text-sm mb-4">{endpoint.desc}</p>

							{endpoint.body && (
								<div class="mb-4">
									<p class="text-xs font-bold uppercase tracking-wider mb-1 text-white/60">Request Body:</p>
									<pre class="border border-white/10 p-3 text-xs overflow-x-auto">
										<code class="text-conditional">{endpoint.body}</code>
									</pre>
								</div>
							)}

							<div class="mb-4">
								<p class="text-xs font-bold uppercase tracking-wider mb-1 text-white/60">Response:</p>
								<pre class="border border-white/10 p-3 text-xs overflow-x-auto">
									<code class="text-certified">{endpoint.response}</code>
								</pre>
							</div>

							<div>
								<p class="text-xs font-bold uppercase tracking-wider mb-1 text-white/60">Example:</p>
								<pre class="border border-white/10 p-3 text-xs overflow-x-auto">
									<code class="text-white/70">{endpoint.curl}</code>
								</pre>
							</div>
						</div>
					))}

					{/* Rate Limits */}
					<div class="mt-12">
						<h2 class="text-lg font-bold uppercase tracking-wider mb-4">Rate Limits</h2>
						<div class="w-full h-px bg-white/10 mb-4" />
						<div class="border border-white/20 p-6">
							<table class="w-full text-xs">
								<thead>
									<tr class="border-b border-white/20">
										<th class="text-left py-2 uppercase tracking-wider text-white/60">Tier</th>
										<th class="text-left py-2 uppercase tracking-wider text-white/60">Limit</th>
										<th class="text-left py-2 uppercase tracking-wider text-white/60">Price</th>
									</tr>
								</thead>
								<tbody class="text-white/50">
									<tr class="border-b border-white/10">
										<td class="py-2">Unauthenticated</td>
										<td>60 requests/minute</td>
										<td>Free</td>
									</tr>
									<tr class="border-b border-white/10">
										<td class="py-2">Free API Key</td>
										<td>100 requests/day</td>
										<td>Free</td>
									</tr>
									<tr class="border-b border-white/10">
										<td class="py-2">Pro</td>
										<td>10,000 requests/day</td>
										<td>Coming soon</td>
									</tr>
									<tr>
										<td class="py-2">Enterprise</td>
										<td>Unlimited</td>
										<td>Contact us</td>
									</tr>
								</tbody>
							</table>
						</div>
					</div>

					{/* Error Codes */}
					<div class="mt-12 mb-12">
						<h2 class="text-lg font-bold uppercase tracking-wider mb-4">Error Codes</h2>
						<div class="w-full h-px bg-white/10 mb-4" />
						<div class="border border-white/20 p-6">
							<table class="w-full text-xs">
								<thead>
									<tr class="border-b border-white/20">
										<th class="text-left py-2 uppercase tracking-wider text-white/60">Code</th>
										<th class="text-left py-2 uppercase tracking-wider text-white/60">Status</th>
										<th class="text-left py-2 uppercase tracking-wider text-white/60">Description</th>
									</tr>
								</thead>
								<tbody class="text-white/50">
									<tr class="border-b border-white/10">
										<td class="py-2">VALIDATION_ERROR</td>
										<td>400</td>
										<td>Invalid request body or parameters</td>
									</tr>
									<tr class="border-b border-white/10">
										<td class="py-2">UNAUTHORIZED</td>
										<td>401</td>
										<td>Missing or invalid API key</td>
									</tr>
									<tr class="border-b border-white/10">
										<td class="py-2">FORBIDDEN</td>
										<td>403</td>
										<td>Insufficient permissions</td>
									</tr>
									<tr class="border-b border-white/10">
										<td class="py-2">NOT_FOUND</td>
										<td>404</td>
										<td>Resource not found</td>
									</tr>
									<tr class="border-b border-white/10">
										<td class="py-2">RATE_LIMIT_EXCEEDED</td>
										<td>429</td>
										<td>Too many requests</td>
									</tr>
									<tr>
										<td class="py-2">INTERNAL_ERROR</td>
										<td>500</td>
										<td>Server error</td>
									</tr>
								</tbody>
							</table>
						</div>
					</div>
				</div>
			</section>
		</BaseLayout>,
	);
});

export { docsApp };
