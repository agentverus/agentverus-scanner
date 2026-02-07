import { Hono } from "hono";

const fontTestApp = new Hono();

fontTestApp.get("/font-test", (c) => {
	return c.html(
		<html lang="en" class="dark">
			<head>
				<meta charset="UTF-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1.0" />
				<title>AgentVerus — Font Comparison</title>
				<link rel="preconnect" href="https://fonts.googleapis.com" />
				<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="" />
				<link
					href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Big+Shoulders+Display:wght@400;500;600;700;800&family=Jost:wght@400;500;600;700&family=Outfit:wght@400;500;600;700;800&family=Inter:wght@400;500;600&family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
					rel="stylesheet"
				/>
				<script src="https://cdn.tailwindcss.com" />
				<script
					dangerouslySetInnerHTML={{
						__html: `tailwind.config = {
							darkMode: 'class',
							theme: {
								extend: {
									colors: {
										certified: '#3B82F6',
										rejected: '#EF4444',
									}
								}
							}
						}`,
					}}
				/>
			</head>
			<body class="bg-gray-950 text-gray-100 min-h-screen p-6 md:p-12">
				<h1
					class="text-sm font-mono text-blue-400 uppercase tracking-widest mb-12"
					style={{ fontFamily: "'JetBrains Mono', monospace" }}
				>
					AgentVerus — Font Comparison (pick your favorite)
				</h1>

				{/* OPTION A */}
				<div class="border border-gray-800 rounded-2xl p-8 md:p-12 mb-8 bg-gray-900/50">
					<div
						class="text-xs font-mono text-blue-400 uppercase tracking-widest mb-6"
						style={{ fontFamily: "'JetBrains Mono', monospace" }}
					>
						A — Bebas Neue + Outfit + Inter
					</div>
					<div style={{ fontFamily: "'Bebas Neue', sans-serif" }}>
						<div class="text-6xl md:text-8xl text-white mb-2 tracking-wide">
							Trust, but <span class="text-certified">verify</span>.
						</div>
					</div>
					<div style={{ fontFamily: "'Inter', sans-serif" }}>
						<div class="text-lg text-gray-400 mb-8 max-w-xl">
							The trust certification service for AI agent skills. Scan, audit, and certify
							skills before they access your data.
						</div>
					</div>
					<div class="flex gap-4 mb-10">
						<span
							class="bg-certified text-white px-6 py-2.5 rounded-lg font-semibold"
							style={{ fontFamily: "'Outfit', sans-serif" }}
						>
							Scan a Skill Free
						</span>
						<span
							class="border border-gray-600 text-white px-6 py-2.5 rounded-lg font-semibold"
							style={{ fontFamily: "'Outfit', sans-serif" }}
						>
							Browse Registry
						</span>
					</div>
					<div class="grid grid-cols-3 gap-6 mb-10">
						<div>
							<div
								class="text-5xl font-bold text-white"
								style={{ fontFamily: "'Bebas Neue', sans-serif", letterSpacing: "0.05em" }}
							>
								932
							</div>
							<div class="text-gray-500 text-sm" style={{ fontFamily: "'Inter', sans-serif" }}>
								Skills Scanned
							</div>
						</div>
						<div>
							<div
								class="text-5xl font-bold text-rejected"
								style={{ fontFamily: "'Bebas Neue', sans-serif", letterSpacing: "0.05em" }}
							>
								15%
							</div>
							<div class="text-gray-500 text-sm" style={{ fontFamily: "'Inter', sans-serif" }}>
								Found Dangerous
							</div>
						</div>
						<div>
							<div
								class="text-5xl font-bold text-certified"
								style={{ fontFamily: "'Bebas Neue', sans-serif", letterSpacing: "0.05em" }}
							>
								Free
							</div>
							<div class="text-gray-500 text-sm" style={{ fontFamily: "'Inter', sans-serif" }}>
								For All Scans
							</div>
						</div>
					</div>
					<div style={{ fontFamily: "'Outfit', sans-serif" }}>
						<div class="text-2xl font-bold text-white mb-3">What We Detect</div>
						<div class="text-lg font-semibold text-white">Permission Analysis</div>
					</div>
					<div class="text-gray-400 text-sm mt-1" style={{ fontFamily: "'Inter', sans-serif" }}>
						Flags excessive or mismatched permissions for the skill's stated purpose.
					</div>
				</div>

				{/* OPTION B */}
				<div class="border border-gray-800 rounded-2xl p-8 md:p-12 mb-8 bg-gray-900/50">
					<div
						class="text-xs font-mono text-blue-400 uppercase tracking-widest mb-6"
						style={{ fontFamily: "'JetBrains Mono', monospace" }}
					>
						B — Big Shoulders Display + DM Sans
					</div>
					<div style={{ fontFamily: "'Big Shoulders Display', sans-serif" }}>
						<div class="text-6xl md:text-8xl font-extrabold text-white mb-2 uppercase tracking-wide">
							Trust, but <span class="text-certified">verify</span>.
						</div>
					</div>
					<div style={{ fontFamily: "'DM Sans', sans-serif" }}>
						<div class="text-lg text-gray-400 mb-8 max-w-xl">
							The trust certification service for AI agent skills. Scan, audit, and certify
							skills before they access your data.
						</div>
					</div>
					<div class="flex gap-4 mb-10">
						<span
							class="bg-certified text-white px-6 py-2.5 rounded-lg font-semibold"
							style={{ fontFamily: "'DM Sans', sans-serif" }}
						>
							Scan a Skill Free
						</span>
						<span
							class="border border-gray-600 text-white px-6 py-2.5 rounded-lg font-semibold"
							style={{ fontFamily: "'DM Sans', sans-serif" }}
						>
							Browse Registry
						</span>
					</div>
					<div class="grid grid-cols-3 gap-6 mb-10">
						<div>
							<div
								class="text-5xl font-extrabold text-white"
								style={{ fontFamily: "'Big Shoulders Display', sans-serif" }}
							>
								932
							</div>
							<div class="text-gray-500 text-sm" style={{ fontFamily: "'DM Sans', sans-serif" }}>
								Skills Scanned
							</div>
						</div>
						<div>
							<div
								class="text-5xl font-extrabold text-rejected"
								style={{ fontFamily: "'Big Shoulders Display', sans-serif" }}
							>
								15%
							</div>
							<div class="text-gray-500 text-sm" style={{ fontFamily: "'DM Sans', sans-serif" }}>
								Found Dangerous
							</div>
						</div>
						<div>
							<div
								class="text-5xl font-extrabold text-certified"
								style={{ fontFamily: "'Big Shoulders Display', sans-serif" }}
							>
								FREE
							</div>
							<div class="text-gray-500 text-sm" style={{ fontFamily: "'DM Sans', sans-serif" }}>
								For All Scans
							</div>
						</div>
					</div>
					<div style={{ fontFamily: "'Big Shoulders Display', sans-serif" }}>
						<div class="text-2xl font-bold text-white mb-3 uppercase tracking-wide">
							What We Detect
						</div>
					</div>
					<div style={{ fontFamily: "'DM Sans', sans-serif" }}>
						<div class="text-lg font-semibold text-white">Permission Analysis</div>
						<div class="text-gray-400 text-sm mt-1">
							Flags excessive or mismatched permissions for the skill's stated purpose.
						</div>
					</div>
				</div>

				{/* OPTION C */}
				<div class="border border-gray-800 rounded-2xl p-8 md:p-12 mb-8 bg-gray-900/50">
					<div
						class="text-xs font-mono text-blue-400 uppercase tracking-widest mb-6"
						style={{ fontFamily: "'JetBrains Mono', monospace" }}
					>
						C — Jost + Inter (Futura-inspired — closest to IWC Portugieser)
					</div>
					<div style={{ fontFamily: "'Jost', sans-serif" }}>
						<div class="text-6xl md:text-8xl font-bold text-white mb-2">
							Trust, but <span class="text-certified">verify</span>.
						</div>
					</div>
					<div style={{ fontFamily: "'Inter', sans-serif" }}>
						<div class="text-lg text-gray-400 mb-8 max-w-xl">
							The trust certification service for AI agent skills. Scan, audit, and certify
							skills before they access your data.
						</div>
					</div>
					<div class="flex gap-4 mb-10">
						<span
							class="bg-certified text-white px-6 py-2.5 rounded-lg font-semibold"
							style={{ fontFamily: "'Jost', sans-serif" }}
						>
							Scan a Skill Free
						</span>
						<span
							class="border border-gray-600 text-white px-6 py-2.5 rounded-lg font-semibold"
							style={{ fontFamily: "'Jost', sans-serif" }}
						>
							Browse Registry
						</span>
					</div>
					<div class="grid grid-cols-3 gap-6 mb-10">
						<div>
							<div
								class="text-5xl font-bold text-white"
								style={{ fontFamily: "'Jost', sans-serif" }}
							>
								932
							</div>
							<div class="text-gray-500 text-sm" style={{ fontFamily: "'Inter', sans-serif" }}>
								Skills Scanned
							</div>
						</div>
						<div>
							<div
								class="text-5xl font-bold text-rejected"
								style={{ fontFamily: "'Jost', sans-serif" }}
							>
								15%
							</div>
							<div class="text-gray-500 text-sm" style={{ fontFamily: "'Inter', sans-serif" }}>
								Found Dangerous
							</div>
						</div>
						<div>
							<div
								class="text-5xl font-bold text-certified"
								style={{ fontFamily: "'Jost', sans-serif" }}
							>
								Free
							</div>
							<div class="text-gray-500 text-sm" style={{ fontFamily: "'Inter', sans-serif" }}>
								For All Scans
							</div>
						</div>
					</div>
					<div style={{ fontFamily: "'Jost', sans-serif" }}>
						<div class="text-2xl font-bold text-white mb-3">What We Detect</div>
						<div class="text-lg font-semibold text-white">Permission Analysis</div>
					</div>
					<div class="text-gray-400 text-sm mt-1" style={{ fontFamily: "'Inter', sans-serif" }}>
						Flags excessive or mismatched permissions for the skill's stated purpose.
					</div>
				</div>

				<div
					class="text-center text-gray-600 text-sm mt-8"
					style={{ fontFamily: "'JetBrains Mono', monospace" }}
				>
					A = dramatic/military • B = industrial/bold • C = geometric/precision (IWC)
				</div>
			</body>
		</html>,
	);
});

export { fontTestApp };
