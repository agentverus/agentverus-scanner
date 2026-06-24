/**
 * Detection-F1 benchmark harness (autoresearch run: detection-f1).
 *
 * Full corpus = seed fixtures + fetched benign + injected malicious + external holdout.
 * A file is PREDICTED malicious iff its badge is in {rejected, suspicious}.
 *
 * Split: deterministic by filename hash -> 70% train / 30% holdout. The `external`
 * bucket (agentshield-derived) is ALWAYS holdout-realism, never trained against.
 *
 * Primary METRIC = f1 (overall, full corpus). Also emits holdout_f1 (anti-overfit
 * gate), external_recall (realism), precision (guardrail >=0.90), recall,
 * specificity, category_recall. arl parses `METRIC name=value` from stdout.
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanSkill } from "../src/scanner/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, "..");
const FIXTURES = join(REPO, "test/fixtures/skills");
const CORPUS = join(REPO, "runs/detection-f1/corpus");

type Sample = {
  path: string;
  label: "malicious" | "benign";
  expected_categories: string[];
  bucket: "seed" | "benign" | "malicious" | "external";
};

const PRED_MAL = new Set(["rejected", "suspicious"]);

function isHoldout(name: string): boolean {
  // deterministic 30% holdout by filename hash
  const h = createHash("sha256").update(name).digest()[0];
  return h % 10 < 3;
}

function loadSamples(): Sample[] {
  const out: Sample[] = [];

  // 1. seed fixtures
  const seed = JSON.parse(readFileSync(join(CORPUS, "labels.json"), "utf8"));
  for (const s of seed.samples) {
    out.push({ path: join(FIXTURES, s.file), label: s.label, expected_categories: s.expected_categories, bucket: "seed" });
  }

  // 2. fetched benign
  const benignDir = join(CORPUS, "benign");
  if (existsSync(benignDir)) {
    for (const f of readdirSync(benignDir).filter((x) => x.endsWith(".md"))) {
      out.push({ path: join(benignDir, f), label: "benign", expected_categories: [], bucket: "benign" });
    }
  }

  // 3. generated malicious + external
  if (existsSync(join(CORPUS, "generated-labels.json"))) {
    const gen = JSON.parse(readFileSync(join(CORPUS, "generated-labels.json"), "utf8"));
    for (const s of gen.samples) {
      const bucket = s.file.startsWith("external/") ? "external" : "malicious";
      out.push({ path: join(CORPUS, s.file), label: s.label, expected_categories: s.expected_categories, bucket });
    }
  }
  return out;
}

type Counts = { tp: number; fp: number; fn: number; tn: number };
function f1Of(c: Counts): number {
  const p = c.tp + c.fp === 0 ? 0 : c.tp / (c.tp + c.fp);
  const r = c.tp + c.fn === 0 ? 0 : c.tp / (c.tp + c.fn);
  return p + r === 0 ? 0 : (2 * p * r) / (p + r);
}

async function main() {
  const samples = loadSamples();
  const all: Counts = { tp: 0, fp: 0, fn: 0, tn: 0 };
  const hold: Counts = { tp: 0, fp: 0, fn: 0, tn: 0 };
  let extTotal = 0, extCaught = 0;
  let catHit = 0, catTotal = 0;
  const benignFP: string[] = [];

  for (const s of samples) {
    const report: any = await scanSkill(readFileSync(s.path, "utf8"));
    const badge = String(report.badge).toLowerCase();
    const predMal = PRED_MAL.has(badge);
    const actualMal = s.label === "malicious";
    const holdout = s.bucket === "external" || isHoldout(s.path.split("/").pop()!);

    const tally = (c: Counts) => {
      if (actualMal && predMal) c.tp++;
      else if (actualMal && !predMal) c.fn++;
      else if (!actualMal && predMal) c.fp++;
      else c.tn++;
    };
    tally(all);
    if (holdout) tally(hold);

    if (!actualMal && predMal) benignFP.push(`${s.bucket}/${s.path.split("/").pop()} (badge=${badge})`);

    if (s.bucket === "external") {
      extTotal++;
      if (predMal) extCaught++;
    }
    if (actualMal && s.expected_categories.length > 0) {
      const fired = new Set<string>((report.findings ?? []).map((f: any) => String(f.category)));
      for (const c of s.expected_categories) { catTotal++; if (fired.has(c)) catHit++; }
    }
  }

  const precision = all.tp + all.fp === 0 ? 0 : all.tp / (all.tp + all.fp);
  const recall = all.tp + all.fn === 0 ? 0 : all.tp / (all.tp + all.fn);
  const specificity = all.tn + all.fp === 0 ? 0 : all.tn / (all.tn + all.fp);
  const catRecall = catTotal === 0 ? 0 : catHit / catTotal;
  const extRecall = extTotal === 0 ? 0 : extCaught / extTotal;
  const f = (n: number) => n.toFixed(4);

  console.error(`n=${samples.length} all=${JSON.stringify(all)} holdout=${JSON.stringify(hold)}`);
  console.error(`benign false-positives (${benignFP.length}):`);
  for (const m of benignFP) console.error("  FP " + m);

  console.log(`METRIC f1=${f(f1Of(all))}`);
  console.log(`METRIC holdout_f1=${f(f1Of(hold))}`);
  console.log(`METRIC external_recall=${f(extRecall)}`);
  console.log(`METRIC precision=${f(precision)}`);
  console.log(`METRIC recall=${f(recall)}`);
  console.log(`METRIC specificity=${f(specificity)}`);
  console.log(`METRIC category_recall=${f(catRecall)}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
