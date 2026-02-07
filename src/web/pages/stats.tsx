import { Hono } from "hono";
import { BaseLayout } from "../layouts/base.js";

const statsApp = new Hono();

statsApp.get("/stats", (c) => {
	return c.html(
		<BaseLayout title="Live Stats" description="Real-time statistics from AgentVerus scanning.">
			<section class="py-12 px-4">
				<div class="max-w-7xl mx-auto">
					<div class="inline-block border border-white/30 px-3 py-1 text-xs uppercase tracking-widest text-white/60 mb-6">
						System Telemetry
					</div>
					<h1 class="text-2xl font-extrabold mb-3 uppercase tracking-wider">Live Scanning Statistics</h1>
					<div class="w-full h-px bg-white/20 mb-3" />
					<p class="text-white/50 text-sm mb-8 uppercase tracking-wide">
						Real-time transparency into the state of AI agent skill security.
					</p>

					{/* Overview Stats */}
					<div class="grid grid-cols-2 md:grid-cols-4 gap-0 mb-12">
						{[
							{ label: "Total Scanned", value: "—", color: "text-white" },
							{ label: "Avg Trust Score", value: "—", color: "text-conditional" },
							{ label: "Critical Findings", value: "—", color: "text-rejected" },
							{ label: "Certified Skills", value: "—", color: "text-certified" },
						].map((stat) => (
							<div class="border border-white/20 -ml-px -mt-px p-6 text-center">
								<p class={`text-4xl font-extrabold ${stat.color} tracking-tight`}>{stat.value}</p>
								<p class="text-white/40 text-xs mt-2 uppercase tracking-widest">{stat.label}</p>
							</div>
						))}
					</div>

					{/* Badge Distribution */}
					<div class="border border-white/20 p-6 mb-8">
						<h2 class="text-sm font-bold uppercase tracking-wider mb-4">Badge Distribution</h2>
						<div class="w-full h-px bg-white/10 mb-4" />
						<div class="space-y-3">
							{[
								{ label: "CERTIFIED", color: "bg-certified", pct: 0 },
								{ label: "CONDITIONAL", color: "bg-conditional", pct: 0 },
								{ label: "SUSPICIOUS", color: "bg-suspicious", pct: 0 },
								{ label: "REJECTED", color: "bg-rejected", pct: 0 },
							].map((item) => (
								<div class="flex items-center gap-3">
									<span class="w-32 text-xs text-white/50 uppercase tracking-wider">{item.label}</span>
									<div class="flex-1 bg-white/5 h-3 overflow-hidden">
										<div
											class={`h-full ${item.color} transition-all duration-500`}
											style={`width: ${item.pct}%`}
										/>
									</div>
									<span class="w-12 text-right text-xs text-white/40">{item.pct}%</span>
								</div>
							))}
						</div>
						<p class="text-white/30 text-xs mt-4 uppercase tracking-wide">
							Statistics will populate as skills are scanned. Submit your first skill to get
							started.
						</p>
					</div>

					{/* ASST Category Distribution */}
					<div class="border border-white/20 p-6 mb-8">
						<h2 class="text-sm font-bold uppercase tracking-wider mb-4">Top Findings by ASST Category</h2>
						<div class="w-full h-px bg-white/10 mb-4" />
						<div class="text-white/30 text-center py-8">
							<p class="text-xs uppercase tracking-widest">// Awaiting data</p>
							<p class="text-xs mt-2">Data will appear after bulk scanning is complete.</p>
						</div>
					</div>

					{/* CTA */}
					<div class="text-center py-8">
						<a
							href="/submit"
							class="inline-block border-2 border-white bg-white text-black px-8 py-3 font-bold text-xs uppercase tracking-widest hover:bg-transparent hover:text-white transition"
						>
							Contribute — Scan a Skill
						</a>
					</div>
				</div>
			</section>
		</BaseLayout>,
	);
});

export { statsApp };
