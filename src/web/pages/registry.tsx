import { Hono } from "hono";
import { BaseLayout } from "../layouts/base.js";

const registryApp = new Hono();

registryApp.get("/registry", (c) => {
	const q = c.req.query("q") ?? "";
	const badge = c.req.query("badge") ?? "";

	return c.html(
		<BaseLayout title="Skill Registry" description="Browse and search certified AI agent skills.">
			<section class="py-12 px-4">
				<div class="max-w-7xl mx-auto">
					<h1 class="text-3xl font-bold mb-8">Skill Trust Registry</h1>

					{/* Search */}
					<form method="get" action="/registry" class="mb-8">
						<div class="flex gap-3">
							<input
								type="text"
								name="q"
								value={q}
								placeholder="Search skills by name, description, or URL..."
								class="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-certified"
								hx-get="/registry"
								hx-trigger="input changed delay:300ms"
								hx-target="#results"
								hx-include="[name='badge']"
							/>
							<button
								type="submit"
								class="bg-gray-800 hover:bg-gray-700 text-white px-6 py-3 rounded-lg font-medium transition font-display"
							>
								Search
							</button>
						</div>
					</form>

					{/* Badge filters */}
					<div class="flex gap-3 mb-8 flex-wrap">
						{[
							{ value: "", label: "All", color: "bg-gray-700" },
							{ value: "certified", label: "Certified", color: "bg-certified" },
							{ value: "conditional", label: "Conditional", color: "bg-conditional" },
							{ value: "suspicious", label: "Suspicious", color: "bg-suspicious" },
							{ value: "rejected", label: "Rejected", color: "bg-rejected" },
						].map((filter) => (
							<a
								href={`/registry?badge=${filter.value}${q ? `&q=${q}` : ""}`}
								class={`px-4 py-2 rounded-full text-sm font-medium text-white transition ${
									badge === filter.value
										? `${filter.color} ring-2 ring-white`
										: `${filter.color}/20 hover:${filter.color}/40`
								}`}
							>
								{filter.label}
							</a>
						))}
					</div>

					{/* Results */}
					<div id="results">
						<div class="text-center py-16 text-gray-500">
							<p class="text-5xl mb-4">📭</p>
							<p class="text-xl mb-2">No skills found yet.</p>
							<p class="mb-6">Be the first to submit a skill for scanning.</p>
							<a
								href="/submit"
								class="bg-certified hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-medium transition font-display"
							>
								Submit a Skill
							</a>
						</div>
					</div>
				</div>
			</section>
		</BaseLayout>,
	);
});

export { registryApp };
