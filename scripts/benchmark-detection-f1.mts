/**
 * Detection-F1 benchmark harness (autoresearch run: detection-f1).
 *
 * Primary metric: file-level F1 on malicious-vs-benign classification, where a
 * file is PREDICTED malicious iff its badge is in {rejected, suspicious}.
 * Also reports precision, recall, specificity, a 3-way ALLOW/REVIEW/BLOCK
 * breakdown, and per-category recall (agentverus's own 6 categories).
 *
 * Emits `METRIC name=value` lines for the arl runtime. f1 is primary.
 */
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanSkill } from "../src/scanner/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, "..");
const FIXTURES = join(REPO, "test/fixtures/skills");
const LABELS = join(REPO, "runs/detection-f1/corpus/labels.json");

type Label = {
  file: string;
  label: "malicious" | "benign";
  expected_categories: string[];
  source: string;
};

const PRED_MAL = new Set(["rejected", "suspicious"]);

function bin(value: number): string {
  return value.toFixed(4);
}

async function main() {
  const labels: { samples: Label[] } = JSON.parse(readFileSync(LABELS, "utf-8"));
  const samples = labels.samples;

  let tp = 0,
    fp = 0,
    fn = 0,
    tn = 0;
  let allow = 0,
    review = 0,
    block = 0;
  let catHit = 0,
    catTotal = 0;
  const misses: string[] = [];

  for (const s of samples) {
    const content = readFileSync(join(FIXTURES, s.file), "utf-8");
    const report: any = await scanSkill(content);
    const badge: string = String(report.badge).toLowerCase();
    const predMalicious = PRED_MAL.has(badge);
    const actualMalicious = s.label === "malicious";

    if (badge === "rejected") block++;
    else if (badge === "suspicious" || badge === "conditional") review++;
    else allow++;

    if (actualMalicious && predMalicious) tp++;
    else if (actualMalicious && !predMalicious) {
      fn++;
      misses.push(`FN ${s.file} (badge=${badge})`);
    } else if (!actualMalicious && predMalicious) {
      fp++;
      misses.push(`FP ${s.file} (badge=${badge})`);
    } else tn++;

    // category recall (reported only): did the expected category fire >=1 finding?
    if (actualMalicious && s.expected_categories.length > 0) {
      const firedCats = new Set<string>(
        (report.findings ?? []).map((f: any) => String(f.category)),
      );
      for (const c of s.expected_categories) {
        catTotal++;
        if (firedCats.has(c)) catHit++;
      }
    }
  }

  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  const specificity = tn + fp === 0 ? 0 : tn / (tn + fp);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  const catRecall = catTotal === 0 ? 0 : catHit / catTotal;

  // Diagnostics to stderr (not parsed by arl).
  console.error(`samples=${samples.length} tp=${tp} fp=${fp} fn=${fn} tn=${tn}`);
  console.error(`ALLOW=${allow} REVIEW=${review} BLOCK=${block}`);
  for (const m of misses) console.error("  " + m);

  // METRIC lines (arl parses these from stdout). f1 = primary.
  console.log(`METRIC f1=${bin(f1)}`);
  console.log(`METRIC precision=${bin(precision)}`);
  console.log(`METRIC recall=${bin(recall)}`);
  console.log(`METRIC specificity=${bin(specificity)}`);
  console.log(`METRIC category_recall=${bin(catRecall)}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
