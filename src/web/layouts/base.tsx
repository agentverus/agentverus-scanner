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
				<title>{title} | AgentVerus</title>
				{description && <meta name="description" content={description} />}
				<script src="https://cdn.tailwindcss.com" />
				<script src="https://unpkg.com/htmx.org@2.0.4" />
				<script
					dangerouslySetInnerHTML={{
						__html: `tailwind.config = {
							darkMode: 'class',
							theme: {
								extend: {
									colors: {
										certified: '#2ECC40',
										conditional: '#DFB317',
										suspicious: '#FE7D37',
										rejected: '#E05D44',
									}
								}
							}
						}`,
					}}
				/>
			</head>
			<body class="bg-gray-950 text-gray-100 min-h-screen flex flex-col">
				<header class="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm sticky top-0 z-50">
					<nav class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
						<a href="/" class="text-xl font-bold text-white flex items-center gap-2">
							<span class="text-2xl">🛡️</span> AgentVerus
						</a>
						<div class="flex items-center gap-6">
							<a href="/registry" class="text-gray-300 hover:text-white transition">
								Registry
							</a>
							<a href="/submit" class="text-gray-300 hover:text-white transition">
								Submit Skill
							</a>
							<a href="/docs" class="text-gray-300 hover:text-white transition">
								API Docs
							</a>
							<a
								href="/submit"
								class="bg-certified hover:bg-green-600 text-white px-4 py-2 rounded-lg font-medium transition"
							>
								Scan Free
							</a>
						</div>
					</nav>
				</header>

				<main class="flex-1">{children}</main>

				<footer class="border-t border-gray-800 bg-gray-900/30 py-8">
					<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row justify-between items-center gap-4">
						<p class="text-gray-500 text-sm">© 2026 AgentVerus. Trust, but verify.</p>
						<div class="flex gap-6">
							<a href="/docs" class="text-gray-500 hover:text-gray-300 text-sm transition">
								API
							</a>
							<a
								href="https://github.com/jdrhyne/agentverus"
								class="text-gray-500 hover:text-gray-300 text-sm transition"
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
