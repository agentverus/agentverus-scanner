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
					<div class="inline-block border border-white/30 px-3 py-1 text-xs uppercase tracking-widest text-white/60 mb-6">
						Public Registry
					</div>
					<h1 class="text-2xl font-extrabold mb-3 uppercase tracking-wider">Skill Trust Registry</h1>
					<div class="w-full h-px bg-white/20 mb-8" />

					{/* Search */}
					<form method="get" action="/registry" class="mb-8">
						<div class="flex gap-0">
							<input
								type="text"
								name="q"
								value={q}
								placeholder="Search skills by name, description, or URL..."
								class="flex-1 bg-black border border-white/20 px-4 py-3 text-white text-sm placeholder-white/30 focus:outline-none focus:border-white"
								hx-get="/registry"
								hx-trigger="input changed delay:300ms"
								hx-target="#results"
								hx-include="[name='badge']"
							/>
							<button
								type="submit"
								class="border border-white/20 border-l-0 bg-white/5 hover:bg-white/10 text-white px-6 py-3 font-bold text-xs uppercase tracking-widest transition"
							>
								Search
							</button>
						</div>
					</form>

					{/* Badge filters */}
					<div class="flex gap-2 mb-8 flex-wrap">
						{[
							{ value: "", label: "All", color: "" },
							{ value: "certified", label: "Certified", color: "text-certified border-certified" },
							{ value: "conditional", label: "Conditional", color: "text-conditional border-conditional" },
							{ value: "suspicious", label: "Suspicious", color: "text-suspicious border-suspicious" },
							{ value: "rejected", label: "Rejected", color: "text-rejected border-rejected" },
						].map((filter) => (
							<a
								href={`/registry?badge=${filter.value}${q ? `&q=${q}` : ""}`}
								class={`px-4 py-1.5 text-xs font-bold uppercase tracking-widest border transition ${
									badge === filter.value
										? `${filter.color || "text-white border-white"} bg-white/10`
										: `${filter.color || "text-white/40 border-white/20"} hover:bg-white/5`
								}`}
							>
								{filter.label}
							</a>
						))}
					</div>

					{/* Results */}
					<div id="results">
						<div class="border border-white/20 py-16 text-center">
							<p class="text-3xl mb-4 text-white/20">∅</p>
							<p class="text-sm font-bold uppercase tracking-wider mb-2">No skills found yet.</p>
							<p class="text-white/40 text-xs uppercase tracking-wide mb-6">Be the first to submit a skill for scanning.</p>
							<a
								href="/submit"
								class="inline-block border-2 border-white bg-white text-black px-6 py-2 font-bold text-xs uppercase tracking-widest hover:bg-transparent hover:text-white transition"
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
