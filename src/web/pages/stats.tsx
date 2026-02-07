import { Hono } from "hono";
import { BaseLayout } from "../layouts/base.js";

const statsApp = new Hono();

statsApp.get("/stats", (c) => {
	return c.html(
		<BaseLayout title="Live Stats" description="Real-time statistics from AgentVerus scanning.">
			<section class="py-12 px-4">
				<div class="max-w-7xl mx-auto">
					<h1 class="text-3xl font-bold mb-3">Live Scanning Statistics</h1>
					<p class="text-gray-400 mb-8">
						Real-time transparency into the state of AI agent skill security.
					</p>

					{/* Overview Stats */}
					<div class="grid grid-cols-2 md:grid-cols-4 gap-6 mb-12">
						{[
							{ label: "Total Skills Scanned", value: "—", color: "text-white" },
							{ label: "Average Trust Score", value: "—", color: "text-conditional" },
							{ label: "Critical Findings", value: "—", color: "text-rejected" },
							{ label: "Certified Skills", value: "—", color: "text-certified" },
						].map((stat) => (
							<div class="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center">
								<p class={`text-4xl font-bold ${stat.color}`}>{stat.value}</p>
								<p class="text-gray-400 text-sm mt-1">{stat.label}</p>
							</div>
						))}
					</div>

					{/* Badge Distribution */}
					<div class="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
						<h2 class="text-xl font-semibold mb-4">Badge Distribution</h2>
						<div class="space-y-3">
							{[
								{ label: "CERTIFIED", color: "bg-certified", pct: 0 },
								{ label: "CONDITIONAL", color: "bg-conditional", pct: 0 },
								{ label: "SUSPICIOUS", color: "bg-suspicious", pct: 0 },
								{ label: "REJECTED", color: "bg-rejected", pct: 0 },
							].map((item) => (
								<div class="flex items-center gap-3">
									<span class="w-32 text-sm text-gray-400">{item.label}</span>
									<div class="flex-1 bg-gray-800 rounded-full h-4 overflow-hidden">
										<div
											class={`h-full ${item.color} rounded-full transition-all duration-500`}
											style={`width: ${item.pct}%`}
										/>
									</div>
									<span class="w-12 text-right text-sm text-gray-400">{item.pct}%</span>
								</div>
							))}
						</div>
						<p class="text-gray-500 text-sm mt-4">
							Statistics will populate as skills are scanned. Submit your first skill to get
							started.
						</p>
					</div>

					{/* ASST Category Distribution */}
					<div class="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
						<h2 class="text-xl font-semibold mb-4">Top Findings by ASST Category</h2>
						<div class="text-gray-500 text-center py-8">
							<p class="text-2xl mb-2">📊</p>
							<p>Data will appear after bulk scanning is complete.</p>
						</div>
					</div>

					{/* CTA */}
					<div class="text-center py-8">
						<a
							href="/submit"
							class="bg-certified hover:bg-blue-700 text-white px-8 py-3 rounded-lg font-semibold text-lg transition font-display"
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
