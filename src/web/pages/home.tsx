import { Hono } from "hono";
import { BaseLayout } from "../layouts/base.js";

const homeApp = new Hono();

homeApp.get("/", (c) => {
	return c.html(
		<BaseLayout
			title="Trust, but verify"
			description="The trust certification service for AI agent skills."
		>
			{/* Hero */}
			<section class="border-b-2 border-white/20">
				<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
					<div>
						<div class="inline-block border border-white/30 px-3 py-1 text-xs uppercase tracking-widest text-white/60 mb-6">
							Trust Certification Engine
						</div>
						<h1 class="text-5xl md:text-7xl font-extrabold text-white mb-6 uppercase leading-none tracking-tight">
							Trust,<br />but verify.
						</h1>
						<p class="text-sm text-white/50 mb-10 max-w-lg leading-relaxed uppercase tracking-wide">
							The trust certification service for AI agent skills. Scan, audit, and certify skills
							before they access your data.
						</p>
						<div class="flex gap-4">
							<a
								href="/submit"
								class="border-2 border-white bg-white text-black px-8 py-3 font-bold text-sm uppercase tracking-widest hover:bg-transparent hover:text-white transition"
							>
								Scan a Skill
							</a>
							<a
								href="/registry"
								class="border-2 border-white/40 text-white px-8 py-3 font-bold text-sm uppercase tracking-widest hover:border-white transition"
							>
								Registry
							</a>
						</div>
					</div>
					<div class="border border-white/20 bg-black p-0 font-mono text-xs">
						<div class="border-b border-white/20 px-4 py-2 flex justify-between text-white/50 uppercase text-[10px] tracking-widest">
							<span>Exec: AgentVerus Scan</span>
							<span>Status: <span class="text-certified">Running</span></span>
						</div>
						<div class="p-4 text-white/70 leading-relaxed">
							<div class="text-white/30 mb-2">─────────────────────────────────────────────────</div>
							<div>{">"} Parsing SKILL.md...</div>
							<div>{">"} Running 5 analyzers...</div>
							<div class="text-white/30 my-2">{">"} ─────────────────────────────────</div>
							<div>{">"} Score: <span class="text-certified font-bold">94/100</span> | Badge: <span class="text-certified font-bold">CERTIFIED</span></div>
							<div>{">"} Findings: 2 (0 critical, 1 high, 1 medium)</div>
							<div class="text-white/30 my-2">{">"} ─────────────────────────────────</div>
							<div>{">"} Badge generated: certified-94.svg</div>
							<div class="mt-2 text-white/40">{">"} Waiting for next scan<span class="animate-pulse">_</span></div>
						</div>
					</div>
				</div>
			</section>

			{/* Stats */}
			<section class="border-b-2 border-white/20">
				<div class="max-w-7xl mx-auto px-4 grid grid-cols-1 md:grid-cols-3 divide-x divide-white/10">
					<div class="py-12 text-center">
						<p class="text-5xl font-extrabold text-white tracking-tight" id="stat-total">
							—
						</p>
						<p class="text-white/40 mt-2 text-xs uppercase tracking-widest">Skills Scanned</p>
					</div>
					<div class="py-12 text-center">
						<p class="text-5xl font-extrabold text-rejected tracking-tight">15%</p>
						<p class="text-white/40 mt-2 text-xs uppercase tracking-widest">Found Dangerous</p>
					</div>
					<div class="py-12 text-center">
						<p class="text-5xl font-extrabold text-certified tracking-tight">Free</p>
						<p class="text-white/40 mt-2 text-xs uppercase tracking-widest">For All Scans</p>
					</div>
				</div>
			</section>

			{/* The Process */}
			<section class="border-b-2 border-white/20 py-20 px-4">
				<div class="max-w-7xl mx-auto">
					<div class="mb-12">
						<h2 class="text-2xl font-extrabold uppercase tracking-widest mb-4">The Process</h2>
						<div class="w-full h-px bg-white/20" />
					</div>
					<div class="grid grid-cols-1 md:grid-cols-3 gap-0">
						{[
							{
								step: "01",
								title: "Submit",
								desc: "Paste your SKILL.md content or provide a URL. Our scanner supports OpenClaw, Claude Code, and generic markdown formats.",
							},
							{
								step: "02",
								title: "Scan",
								desc: "Our engine runs 5 parallel analyzers: permissions, injection detection, dependency analysis, behavioral risk, and content safety.",
							},
							{
								step: "03",
								title: "Certify",
								desc: "Get a trust score (0-100), embeddable SVG badge, and detailed findings report. Listed in the public registry.",
							},
						].map((item, i) => (
							<div class={`border border-white/20 p-8 ${i > 0 ? "md:border-l-0" : ""}`}>
								<div class="text-white/30 text-xs uppercase tracking-widest mb-4">{item.step}</div>
								<h3 class="text-lg font-bold uppercase tracking-wider mb-3">{item.title}</h3>
								<p class="text-white/50 text-sm leading-relaxed">{item.desc}</p>
							</div>
						))}
					</div>
				</div>
			</section>

			{/* Detection Capabilities */}
			<section class="border-b-2 border-white/20 py-20 px-4">
				<div class="max-w-7xl mx-auto">
					<div class="mb-12">
						<h2 class="text-2xl font-extrabold uppercase tracking-widest mb-4">Detection Capabilities</h2>
						<div class="w-full h-px bg-white/20" />
					</div>
					<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-0">
						{[
							{
								icon: "/icons/permission.png",
								title: "Permission Analysis",
								desc: "Flags excessive or mismatched permissions for the skill's stated purpose.",
							},
							{
								icon: "/icons/injection.png",
								title: "Injection Detection",
								desc: "Catches prompt injection, instruction override, and social engineering attacks.",
							},
							{
								icon: "/icons/dependency.png",
								title: "Dependency Scanning",
								desc: "Identifies suspicious URLs, IP addresses, and download-and-execute patterns.",
							},
							{
								icon: "/icons/behavioral.png",
								title: "Behavioral Risk",
								desc: "Detects unrestricted scope, system modification, and autonomous action risks.",
							},
							{
								icon: "/icons/content.png",
								title: "Content Safety",
								desc: "Checks for safety boundaries, harmful content, and documentation quality.",
							},
							{
								icon: "/icons/badge.png",
								title: "Trust Badges",
								desc: "Embeddable SVG badges showing trust score. CERTIFIED, CONDITIONAL, SUSPICIOUS, or REJECTED.",
							},
						].map((feature) => (
							<div class="border border-white/20 p-6 -mt-px -ml-px">
								<img
									src={feature.icon}
									alt={feature.title}
									class="w-8 h-8 mb-4 opacity-60"
								/>
								<h3 class="text-sm font-bold uppercase tracking-wider mb-2">{feature.title}</h3>
								<p class="text-white/50 text-xs leading-relaxed">{feature.desc}</p>
							</div>
						))}
					</div>
				</div>
			</section>

			{/* Social proof */}
			<section class="border-b-2 border-white/20 py-20 px-4">
				<div class="max-w-3xl mx-auto">
					<div class="border border-white/20 p-8 font-mono text-sm">
						<div class="text-white/30 text-xs uppercase tracking-widest mb-4">// Intelligence Report</div>
						<div class="text-white/70 leading-relaxed">
							<p class="mb-3">{">"} "Gen Digital found 15% of OpenClaw skills contain malicious instructions."</p>
							<p class="text-white/40">
								{">"} Our scanner catches what they catch — and more. We use the{" "}
								<span class="text-white font-bold">ASST</span> (Agent Skill Security Threats) taxonomy,
								our OWASP-style categorization of 10 threat categories specific to AI agent skills.
							</p>
						</div>
					</div>
				</div>
			</section>

			{/* CTA */}
			<section class="py-20 px-4">
				<div class="max-w-3xl mx-auto text-center">
					<h2 class="text-3xl font-extrabold mb-4 uppercase tracking-wider">Scan Your First Skill</h2>
					<div class="w-24 h-px bg-white/20 mx-auto mb-6" />
					<p class="text-white/50 mb-8 text-sm uppercase tracking-wide">
						No account required. No payment. Paste your SKILL.md and get a trust report in seconds.
					</p>
					<a
						href="/submit"
						class="inline-block border-2 border-white bg-white text-black px-10 py-3 font-bold text-sm uppercase tracking-widest hover:bg-transparent hover:text-white transition"
					>
						Start Scanning →
					</a>
				</div>
			</section>
		</BaseLayout>,
	);
});

export { homeApp };
