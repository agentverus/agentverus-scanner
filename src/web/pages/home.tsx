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
			<section class="py-20 px-4">
				<div class="max-w-4xl mx-auto text-center">
					<h1 class="text-5xl md:text-7xl font-bold text-white mb-6 font-display">
						Trust, but <span class="text-certified">verify</span>.
					</h1>
					<p class="text-xl text-gray-400 mb-10 max-w-2xl mx-auto">
						The trust certification service for AI agent skills. Scan, audit, and certify skills
						before they access your data.
					</p>
					<div class="flex gap-4 justify-center">
						<a
							href="/submit"
							class="bg-certified hover:bg-blue-700 text-white px-8 py-3 rounded-lg font-semibold text-lg transition font-display"
						>
							Scan a Skill Free
						</a>
						<a
							href="/registry"
							class="border border-gray-600 hover:border-gray-400 text-white px-8 py-3 rounded-lg font-semibold text-lg transition font-display"
						>
							Browse Registry
						</a>
					</div>
				</div>
			</section>

			{/* Stats */}
			<section class="py-12 border-y border-gray-800 bg-gray-900/30">
				<div class="max-w-7xl mx-auto px-4 grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
					<div>
						<p class="text-4xl font-bold text-white font-display" id="stat-total">
							—
						</p>
						<p class="text-gray-400 mt-1">Skills Scanned</p>
					</div>
					<div>
						<p class="text-4xl font-bold text-rejected font-display">15%</p>
						<p class="text-gray-400 mt-1">Found Dangerous</p>
					</div>
					<div>
						<p class="text-4xl font-bold text-certified font-display">Free</p>
						<p class="text-gray-400 mt-1">For All Scans</p>
					</div>
				</div>
			</section>

			{/* How it works */}
			<section class="py-20 px-4">
				<div class="max-w-7xl mx-auto">
					<h2 class="text-3xl font-bold text-center mb-12 font-display">How It Works</h2>
					<div class="grid grid-cols-1 md:grid-cols-3 gap-8">
						{[
							{
								step: "1",
								title: "Submit",
								desc: "Paste your SKILL.md content or provide a URL. Our scanner supports OpenClaw, Claude Code, and generic markdown formats.",
							},
							{
								step: "2",
								title: "Scan",
								desc: "Our engine runs 5 parallel analyzers: permissions, injection detection, dependency analysis, behavioral risk, and content safety.",
							},
							{
								step: "3",
								title: "Certify",
								desc: "Get a trust score (0-100), embeddable SVG badge, and detailed findings report. Listed in the public registry.",
							},
						].map((item) => (
							<div class="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center">
								<div class="w-12 h-12 bg-certified/20 text-certified rounded-full flex items-center justify-center text-xl font-bold mx-auto mb-4 font-display">
									{item.step}
								</div>
								<h3 class="text-xl font-semibold mb-3 font-display">{item.title}</h3>
								<p class="text-gray-400">{item.desc}</p>
							</div>
						))}
					</div>
				</div>
			</section>

			{/* Features */}
			<section class="py-20 px-4 bg-gray-900/30">
				<div class="max-w-7xl mx-auto">
					<h2 class="text-3xl font-bold text-center mb-12 font-display">What We Detect</h2>
					<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
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
							<div class="bg-gray-900 border border-gray-800 rounded-xl p-6">
								<img
									src={feature.icon}
									alt={feature.title}
									class="w-10 h-10 mb-3 rounded"
								/>
								<h3 class="text-lg font-semibold mb-2 font-display">{feature.title}</h3>
								<p class="text-gray-400 text-sm">{feature.desc}</p>
							</div>
						))}
					</div>
				</div>
			</section>

			{/* Social proof */}
			<section class="py-20 px-4">
				<div class="max-w-3xl mx-auto text-center">
					<blockquote class="text-2xl font-medium text-gray-300 italic mb-4">
						"Gen Digital found 15% of OpenClaw skills contain malicious instructions."
					</blockquote>
					<p class="text-gray-500">
						Our scanner catches what they catch — and more. We use the{" "}
						<strong class="text-gray-300">ASST</strong> (Agent Skill Security Threats) taxonomy, our
						OWASP-style categorization of 10 threat categories specific to AI agent skills.
					</p>
				</div>
			</section>

			{/* CTA */}
			<section class="py-16 px-4 bg-gray-900/30 border-t border-gray-800">
				<div class="max-w-3xl mx-auto text-center">
					<h2 class="text-3xl font-bold mb-4 font-display">Scan your first skill free</h2>
					<p class="text-gray-400 mb-8">
						No account required. No payment. Just paste your SKILL.md and get a trust report in
						seconds.
					</p>
					<a
						href="/submit"
						class="bg-certified hover:bg-blue-700 text-white px-8 py-3 rounded-lg font-semibold text-lg transition inline-block font-display"
					>
						Start Scanning →
					</a>
				</div>
			</section>
		</BaseLayout>,
	);
});

export { homeApp };
