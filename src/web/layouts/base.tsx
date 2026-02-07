import type { FC } from "hono/jsx";

interface BaseLayoutProps {
	title: string;
	description?: string;
	children: unknown;
}

export const BaseLayout: FC<BaseLayoutProps> = ({ title, description, children }) => {
	return (
		<html lang="en" class="dark">
			<head>
				<meta charset="UTF-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1.0" />
				<title>{title} | AGENTVERUS</title>
				{description && <meta name="description" content={description} />}
				<link rel="preconnect" href="https://fonts.googleapis.com" />
				<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="" />
				<link
					href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&display=swap"
					rel="stylesheet"
				/>
				<script src="https://cdn.tailwindcss.com" />
				<script src="https://unpkg.com/htmx.org@2.0.4" />
				<script
					dangerouslySetInnerHTML={{
						__html: `tailwind.config = {
							darkMode: 'class',
							theme: {
								extend: {
									fontFamily: {
										mono: ['"JetBrains Mono"', '"IBM Plex Mono"', '"Fira Code"', 'monospace'],
									},
									colors: {
										certified: '#3B82F6',
										conditional: '#F59E0B',
										suspicious: '#F97316',
										rejected: '#EF4444',
									}
								}
							}
						}`,
					}}
				/>
				<style
					dangerouslySetInnerHTML={{
						__html: `
							* { font-family: "JetBrains Mono", "IBM Plex Mono", "Fira Code", monospace; }
							::selection { background: #fff; color: #000; }
						`,
					}}
				/>
			</head>
			<body class="bg-black text-white min-h-screen flex flex-col font-mono">
				<header class="border-b-2 border-white/20 sticky top-0 z-50 bg-black">
					<nav class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
						<a href="/" class="text-lg font-bold text-white tracking-wider">
							AGENTVERUS_
						</a>
						<div class="flex items-center gap-6 text-sm uppercase tracking-wide">
							<a href="/registry" class="text-white/60 hover:text-white transition">
								Registry
							</a>
							<a href="/submit" class="text-white/60 hover:text-white transition">
								Submit
							</a>
							<a href="/docs" class="text-white/60 hover:text-white transition">
								Docs
							</a>
							<a href="/stats" class="text-white/60 hover:text-white transition">
								Stats
							</a>
							<a
								href="/submit"
								class="border border-white text-white px-4 py-1.5 hover:bg-white hover:text-black transition uppercase text-xs font-bold tracking-widest"
							>
								Scan Free
							</a>
							<span class="text-white/30 text-xs">v0.1.0</span>
						</div>
					</nav>
				</header>

				<main class="flex-1">{children}</main>

				<footer class="border-t-2 border-white/20 py-4 bg-black">
					<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row justify-between items-center gap-3">
						<p class="text-white/40 text-xs uppercase tracking-widest">
							Scanner Status: <span class="text-certified">Online</span> • © 2026 AGENTVERUS
						</p>
						<div class="flex gap-6">
							<a href="/docs" class="text-white/40 hover:text-white text-xs uppercase tracking-wider transition">
								API
							</a>
							<a
								href="https://github.com/jdrhyne/agentverus"
								class="text-white/40 hover:text-white text-xs uppercase tracking-wider transition"
							>
								GitHub
							</a>
						</div>
					</div>
				</footer>
			</body>
		</html>
	);
};
