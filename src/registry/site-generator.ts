/**
 * Static site generator for the registry scan results.
 * Produces a single-page HTML dashboard with search, filtering, and drill-down.
 */

import { readFile, writeFile, mkdir, copyFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import type { RegistryScanResult, RegistryScanSummary } from "./types.js";

export interface SiteOptions {
	/** Directory containing scan output */
	readonly dataDir: string;
	/** Output directory for the site */
	readonly outDir: string;
	/** Site title override */
	readonly title?: string;
}

function generateHtml(
	summary: RegistryScanSummary,
	results: RegistryScanResult[],
	title: string,
): string {
	const b = summary.badges;
	const total = summary.scanned;

	// Pre-compute stats
	const certifiedPct = total > 0 ? ((b["certified"] ?? 0) / total * 100).toFixed(1) : "0";
	const rejectedPct = total > 0 ? ((b["rejected"] ?? 0) / total * 100).toFixed(1) : "0";

	// Build JSON for client-side search (compact)
	const compactResults = results.map((r) => ({
		s: r.slug,
		n: r.name,
		sc: r.score,
		b: r.badge,
		f: r.format,
		fc: r.findings.length,
		fs: r.findings.slice(0, 3).map((f) => ({ t: f.title, sv: f.severity, c: f.owaspCategory })),
		cats: {
			p: r.categories["permissions"]?.score ?? 0,
			i: r.categories["injection"]?.score ?? 0,
			d: r.categories["dependencies"]?.score ?? 0,
			bh: r.categories["behavioral"]?.score ?? 0,
			c: r.categories["content"]?.score ?? 0,
		},
	}));

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title}</title>
<meta name="description" content="Security analysis of ${total.toLocaleString()} AI agent skills from the ClawHub registry using AgentVerus Scanner.">
<meta property="og:title" content="${title}">
<meta property="og:description" content="We scanned ${total.toLocaleString()} AI agent skills. ${b["rejected"] ?? 0} were rejected. See the full results.">
<meta property="og:type" content="website">
<style>
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --border: #30363d;
  --text: #e6edf3;
  --text-muted: #8b949e;
  --accent: #58a6ff;
  --green: #3fb950;
  --yellow: #d29922;
  --orange: #db6d28;
  --red: #f85149;
  --radius: 8px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.container { max-width: 1200px; margin: 0 auto; padding: 24px 16px; }
header { text-align: center; padding: 48px 0 32px; }
header h1 { font-size: 2rem; margin-bottom: 8px; }
header p { color: var(--text-muted); font-size: 1.1rem; }

/* Stats cards */
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 32px 0; }
.stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; text-align: center; }
.stat-card .value { font-size: 2rem; font-weight: 700; }
.stat-card .label { color: var(--text-muted); font-size: 0.85rem; margin-top: 4px; }
.stat-card.green .value { color: var(--green); }
.stat-card.yellow .value { color: var(--yellow); }
.stat-card.orange .value { color: var(--orange); }
.stat-card.red .value { color: var(--red); }

/* Badge bar */
.badge-bar { display: flex; height: 24px; border-radius: 12px; overflow: hidden; margin: 24px 0; }
.badge-bar .segment { transition: width 0.3s; }
.badge-bar .certified { background: var(--green); }
.badge-bar .conditional { background: var(--yellow); }
.badge-bar .suspicious { background: var(--orange); }
.badge-bar .rejected { background: var(--red); }

/* Filter & search */
.controls { display: flex; gap: 12px; flex-wrap: wrap; margin: 24px 0; align-items: center; }
.controls input[type="search"] {
  flex: 1; min-width: 200px; padding: 10px 16px; background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); color: var(--text); font-size: 0.95rem; outline: none;
}
.controls input[type="search"]:focus { border-color: var(--accent); }
.controls select {
  padding: 10px 16px; background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); color: var(--text); font-size: 0.95rem;
}
.result-count { color: var(--text-muted); font-size: 0.85rem; }

/* Results table */
.results-table { width: 100%; border-collapse: collapse; margin-top: 16px; }
.results-table th, .results-table td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
.results-table th { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; cursor: pointer; user-select: none; white-space: nowrap; }
.results-table th:hover { color: var(--text); }
.results-table th .sort-arrow { margin-left: 4px; opacity: 0.5; }
.results-table th.active .sort-arrow { opacity: 1; }
.results-table tr:hover td { background: rgba(88,166,255,0.04); }
.results-table .slug { font-family: monospace; font-size: 0.9rem; }
.results-table .score-cell { font-weight: 600; font-variant-numeric: tabular-nums; }
.results-table .badge-cell { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
.badge-certified { color: var(--green); }
.badge-conditional { color: var(--yellow); }
.badge-suspicious { color: var(--orange); }
.badge-rejected { color: var(--red); }

.score-bar { display: inline-block; height: 6px; border-radius: 3px; vertical-align: middle; margin-right: 8px; }

/* Finding pills */
.finding-pill { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; margin: 1px 2px; }
.finding-pill.critical { background: rgba(248,81,73,0.15); color: var(--red); }
.finding-pill.high { background: rgba(219,109,40,0.15); color: var(--orange); }
.finding-pill.medium { background: rgba(210,153,34,0.15); color: var(--yellow); }
.finding-pill.low { background: rgba(88,166,255,0.1); color: var(--accent); }

/* Pagination */
.pagination { display: flex; justify-content: center; gap: 8px; margin: 24px 0; }
.pagination button { padding: 8px 16px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); color: var(--text); cursor: pointer; }
.pagination button:hover { border-color: var(--accent); }
.pagination button:disabled { opacity: 0.4; cursor: default; }
.pagination button.active { background: var(--accent); color: var(--bg); border-color: var(--accent); }

/* Footer */
footer { text-align: center; padding: 48px 0 24px; color: var(--text-muted); font-size: 0.85rem; border-top: 1px solid var(--border); margin-top: 48px; }

/* Responsive */
@media (max-width: 768px) {
  header h1 { font-size: 1.4rem; }
  .stats { grid-template-columns: repeat(2, 1fr); }
  .results-table { font-size: 0.85rem; }
  .results-table th, .results-table td { padding: 8px 6px; }
}
</style>
</head>
<body>
<div class="container">

<header>
  <h1>🛡️ ${title}</h1>
  <p>Security analysis of ${total.toLocaleString()} AI agent skills from the ClawHub registry</p>
  <p style="margin-top: 8px; font-size: 0.9rem;">Scanned ${new Date(summary.scannedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })} · AgentVerus Scanner v${summary.scannerVersion}</p>
</header>

<div class="stats">
  <div class="stat-card">
    <div class="value">${total.toLocaleString()}</div>
    <div class="label">Skills Scanned</div>
  </div>
  <div class="stat-card green">
    <div class="value">${(b["certified"] ?? 0).toLocaleString()}</div>
    <div class="label">🟢 Certified (${certifiedPct}%)</div>
  </div>
  <div class="stat-card yellow">
    <div class="value">${(b["conditional"] ?? 0).toLocaleString()}</div>
    <div class="label">🟡 Conditional</div>
  </div>
  <div class="stat-card orange">
    <div class="value">${(b["suspicious"] ?? 0).toLocaleString()}</div>
    <div class="label">🟠 Suspicious</div>
  </div>
  <div class="stat-card red">
    <div class="value">${(b["rejected"] ?? 0).toLocaleString()}</div>
    <div class="label">🔴 Rejected (${rejectedPct}%)</div>
  </div>
  <div class="stat-card">
    <div class="value">${summary.averageScore}</div>
    <div class="label">Average Score</div>
  </div>
</div>

<div class="badge-bar" title="Badge distribution">
  <div class="segment certified" style="width:${total > 0 ? (b["certified"] ?? 0) / total * 100 : 0}%"></div>
  <div class="segment conditional" style="width:${total > 0 ? (b["conditional"] ?? 0) / total * 100 : 0}%"></div>
  <div class="segment suspicious" style="width:${total > 0 ? (b["suspicious"] ?? 0) / total * 100 : 0}%"></div>
  <div class="segment rejected" style="width:${total > 0 ? (b["rejected"] ?? 0) / total * 100 : 0}%"></div>
</div>

<div class="controls">
  <input type="search" id="search" placeholder="Search skills by name or slug..." autocomplete="off">
  <select id="badge-filter">
    <option value="all">All Badges</option>
    <option value="certified">🟢 Certified</option>
    <option value="conditional">🟡 Conditional</option>
    <option value="suspicious">🟠 Suspicious</option>
    <option value="rejected">🔴 Rejected</option>
  </select>
  <span class="result-count" id="result-count"></span>
</div>

<table class="results-table">
  <thead>
    <tr>
      <th data-sort="s">Slug <span class="sort-arrow">↕</span></th>
      <th data-sort="sc" class="active">Score <span class="sort-arrow">↑</span></th>
      <th data-sort="b">Badge <span class="sort-arrow">↕</span></th>
      <th>Categories</th>
      <th>Findings</th>
    </tr>
  </thead>
  <tbody id="results-body"></tbody>
</table>

<div class="pagination" id="pagination"></div>

<footer>
  <p>Generated by <a href="https://github.com/agentverus/agentverus-scanner">AgentVerus Scanner</a> · <a href="./data/results.json">Download JSON</a> · <a href="./data/results.csv">Download CSV</a> · <a href="./REPORT.md">Full Report</a></p>
</footer>

</div>

<script>
const DATA = ${JSON.stringify(compactResults)};
const PAGE_SIZE = 50;

let filtered = [...DATA];
let sortKey = 'sc';
let sortAsc = true;
let page = 0;

const badgeOrder = { rejected: 0, suspicious: 1, conditional: 2, certified: 3 };
const badgeEmoji = { certified: '🟢', conditional: '🟡', suspicious: '🟠', rejected: '🔴' };
const badgeClass = { certified: 'badge-certified', conditional: 'badge-conditional', suspicious: 'badge-suspicious', rejected: 'badge-rejected' };

function scoreColor(score) {
  if (score >= 90) return 'var(--green)';
  if (score >= 75) return 'var(--yellow)';
  if (score >= 50) return 'var(--orange)';
  return 'var(--red)';
}

function catBar(label, score) {
  return '<span style="display:inline-block;width:40px;font-size:0.75rem;color:var(--text-muted)" title="' + label + '">' + label.slice(0,3).toUpperCase() + '</span>' +
    '<span class="score-bar" style="width:' + score + '%;max-width:60px;background:' + scoreColor(score) + '"></span>' +
    '<span style="font-size:0.75rem;color:var(--text-muted)">' + score + '</span><br>';
}

function renderRow(r) {
  const cats = catBar('Permissions', r.cats.p) + catBar('Injection', r.cats.i) + catBar('Dependencies', r.cats.d) + catBar('Behavioral', r.cats.bh) + catBar('Content', r.cats.c);
  const findings = r.fs.map(f => '<span class="finding-pill ' + f.sv + '" title="' + f.c + '">' + f.t.slice(0, 50) + '</span>').join('');
  return '<tr>' +
    '<td class="slug"><a href="https://clawhub.ai/skills/' + r.s + '" target="_blank" rel="noopener">' + r.s + '</a></td>' +
    '<td class="score-cell" style="color:' + scoreColor(r.sc) + '">' + r.sc + '</td>' +
    '<td class="badge-cell ' + (badgeClass[r.b]||'') + '">' + (badgeEmoji[r.b]||'') + ' ' + r.b.toUpperCase() + '</td>' +
    '<td>' + cats + '</td>' +
    '<td>' + (findings || '<span style="color:var(--text-muted)">None</span>') + '</td>' +
    '</tr>';
}

function render() {
  const start = page * PAGE_SIZE;
  const pageData = filtered.slice(start, start + PAGE_SIZE);
  document.getElementById('results-body').innerHTML = pageData.map(renderRow).join('');
  document.getElementById('result-count').textContent = filtered.length + ' of ' + DATA.length + ' skills';

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  let pagHtml = '';
  if (totalPages > 1) {
    pagHtml += '<button ' + (page === 0 ? 'disabled' : '') + ' onclick="goPage(' + (page-1) + ')">&laquo; Prev</button>';
    const startP = Math.max(0, page - 3);
    const endP = Math.min(totalPages, startP + 7);
    for (let i = startP; i < endP; i++) {
      pagHtml += '<button class="' + (i === page ? 'active' : '') + '" onclick="goPage(' + i + ')">' + (i+1) + '</button>';
    }
    pagHtml += '<button ' + (page >= totalPages-1 ? 'disabled' : '') + ' onclick="goPage(' + (page+1) + ')">Next &raquo;</button>';
  }
  document.getElementById('pagination').innerHTML = pagHtml;
}

function applyFilters() {
  const q = document.getElementById('search').value.toLowerCase();
  const badge = document.getElementById('badge-filter').value;
  filtered = DATA.filter(r => {
    if (badge !== 'all' && r.b !== badge) return false;
    if (q && !r.s.includes(q) && !r.n.toLowerCase().includes(q)) return false;
    return true;
  });
  doSort();
  page = 0;
  render();
}

function doSort() {
  filtered.sort((a, b) => {
    let va, vb;
    if (sortKey === 's') { va = a.s; vb = b.s; }
    else if (sortKey === 'sc') { va = a.sc; vb = b.sc; }
    else if (sortKey === 'b') { va = badgeOrder[a.b] ?? 5; vb = badgeOrder[b.b] ?? 5; }
    else { va = a.sc; vb = b.sc; }
    if (typeof va === 'string') return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    return sortAsc ? va - vb : vb - va;
  });
}

window.goPage = function(p) { page = Math.max(0, p); render(); window.scrollTo(0, document.querySelector('.results-table').offsetTop - 80); };

document.getElementById('search').addEventListener('input', applyFilters);
document.getElementById('badge-filter').addEventListener('change', applyFilters);

document.querySelectorAll('.results-table th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.sort;
    if (sortKey === key) { sortAsc = !sortAsc; }
    else { sortKey = key; sortAsc = true; }
    document.querySelectorAll('.results-table th').forEach(t => t.classList.remove('active'));
    th.classList.add('active');
    th.querySelector('.sort-arrow').textContent = sortAsc ? '↑' : '↓';
    doSort();
    page = 0;
    render();
  });
});

// Initial render
render();
</script>
</body>
</html>`;
}

export async function generateSite(opts: SiteOptions): Promise<void> {
	const [resultsRaw, summaryRaw] = await Promise.all([
		readFile(`${opts.dataDir}/results.json`, "utf-8"),
		readFile(`${opts.dataDir}/summary.json`, "utf-8"),
	]);

	const results: RegistryScanResult[] = JSON.parse(resultsRaw);
	const summary: RegistryScanSummary = JSON.parse(summaryRaw);
	const title = opts.title ?? "AgentVerus Registry Report";

	const html = generateHtml(summary, results, title);

	await mkdir(opts.outDir, { recursive: true });
	await mkdir(`${opts.outDir}/data`, { recursive: true });
	await writeFile(`${opts.outDir}/index.html`, html, "utf-8");

	// Copy data files
	for (const file of ["results.json", "results.csv", "summary.json", "errors.json"]) {
		const src = `${opts.dataDir}/${file}`;
		if (existsSync(src)) {
			await copyFile(src, `${opts.outDir}/data/${file}`);
		}
	}

	// Copy report if it exists
	const reportSrc = `${opts.dataDir}/../report/REPORT.md`;
	if (existsSync(reportSrc)) {
		await copyFile(reportSrc, `${opts.outDir}/REPORT.md`);
	}
}
