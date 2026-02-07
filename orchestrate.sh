#!/bin/bash
# AgentVerus Overnight Build Orchestrator
# Runs Codex GPT-5.3-codex xhigh agents in tmux sessions
# Each sprint runs sequentially, tasks within sprints run in parallel where possible

set -euo pipefail

PROJECT_DIR="/Users/nuthome/Projects/agent-trust"
SOCKET="/tmp/agentverus-build.sock"
MODEL="gpt-5.3-codex"
REASONING="xhigh"
SANDBOX="workspace-write"
LOG_DIR="$PROJECT_DIR/.build-logs"

mkdir -p "$LOG_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[$(date '+%H:%M:%S')] ✓${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] ⚠${NC} $1"; }
error() { echo -e "${RED}[$(date '+%H:%M:%S')] ✗${NC} $1"; }

# Initialize tmux
tmux -S "$SOCKET" kill-server 2>/dev/null || true
log "Orchestrator starting — Model: $MODEL | Reasoning: $REASONING"

run_codex_task() {
    local session_name="$1"
    local task_prompt="$2"
    
    # Create tmux session
    tmux -S "$SOCKET" new-session -d -s "$session_name" -n build
    
    # Build the codex command
    local cmd="codex exec -m $MODEL -C $PROJECT_DIR --config model_reasoning_effort=\"$REASONING\" --sandbox $SANDBOX --full-auto --skip-git-repo-check \"$task_prompt\" 2>/dev/null"
    
    # Send command to tmux
    tmux -S "$SOCKET" send-keys -t "$session_name":0.0 -l -- "$cmd"
    sleep 0.2
    tmux -S "$SOCKET" send-keys -t "$session_name":0.0 Enter
    
    log "  Launched: $session_name"
}

wait_for_sessions() {
    local sessions=("$@")
    local timeout=1800  # 30 min per sprint max
    local start=$(date +%s)
    
    while true; do
        local all_done=true
        local elapsed=$(( $(date +%s) - start ))
        
        if [ $elapsed -gt $timeout ]; then
            warn "Sprint timeout reached (${timeout}s). Moving on."
            break
        fi
        
        for sess in "${sessions[@]}"; do
            if tmux -S "$SOCKET" has-session -t "$sess" 2>/dev/null; then
                # Check if codex has finished (look for shell prompt)
                local output=$(tmux -S "$SOCKET" capture-pane -p -t "$sess":0.0 -S -5 2>/dev/null || echo "")
                if echo "$output" | grep -qE '^\$|^❯|Process exited|^nuthome@'; then
                    success "  Completed: $sess"
                    # Save output
                    tmux -S "$SOCKET" capture-pane -p -J -t "$sess":0.0 -S -500 > "$LOG_DIR/$sess.log" 2>/dev/null
                    tmux -S "$SOCKET" kill-session -t "$sess" 2>/dev/null || true
                else
                    all_done=false
                fi
            fi
        done
        
        if $all_done; then
            break
        fi
        
        sleep 15
    done
}

# ═══════════════════════════════════════════════════════════
# SPRINT 0: Project Scaffolding
# ═══════════════════════════════════════════════════════════
log "═══ SPRINT 0: Project Scaffolding ═══"

run_codex_task "s0-scaffold" "You are building AgentVerus — an agent skill trust certification service.

Read PLAN.md and AGENTS.md for full context.

Complete ALL Sprint 0 tasks (0.1 through 0.9):
- Initialize the TypeScript project with pnpm
- Configure TypeScript 5.7+ strict mode, ESM
- Set up Biome for linting/formatting
- Set up Vitest for testing
- Install and configure Drizzle ORM with Neon PostgreSQL driver
- Create environment config (src/config/env.ts) with Zod validation
- Set up GitHub Actions CI
- Create Hono app skeleton (src/app.ts, src/index.ts)
- Create database schema (src/db/schema.ts) with all 5 tables per PLAN.md Section 3

Use these skills if helpful: planner, parallel-task

Important: The badge system uses 4 tiers: CERTIFIED (90-100, zero Critical/High), CONDITIONAL (75-89, zero Critical, ≤2 High), SUSPICIOUS (50-74, zero Critical), REJECTED (<50 or any Critical).

Commit after each major task. Make sure pnpm install works and pnpm check passes."

wait_for_sessions "s0-scaffold"
success "Sprint 0 complete"

# ═══════════════════════════════════════════════════════════
# SPRINT 1: Skill Scanner Engine (THE CORE)
# ═══════════════════════════════════════════════════════════
log "═══ SPRINT 1: Skill Scanner Engine ═══"

# 1A: Parser + test fixtures (independent)
run_codex_task "s1-parser" "You are building AgentVerus. Read PLAN.md and AGENTS.md.

Complete Tasks 1.1 and 1.2 from Sprint 1:

Task 1.1 — Multi-Format Skill Parser (src/scanner/parser.ts):
Parse SKILL.md files into a structured ParsedSkill object. Handle 3 formats:
- OpenClaw (YAML frontmatter with --- delimiters + markdown body)
- Claude Code (similar YAML + markdown)
- Generic markdown (no frontmatter)
Extract: metadata (name, description, homepage, requires), full instruction text, code blocks, URLs, file paths, tool references, permission declarations.

Task 1.2 — Test Fixture Skills:
Create 8 test fixtures in test/fixtures/:
- safe-weather.md (clean, simple weather skill — should score 95+)
- safe-formatter.md (clean code formatter)
- malicious-exfil.md (data exfiltration instructions — should be REJECTED)
- malicious-injection.md (prompt injection — should be REJECTED)
- suspicious-permissions.md (over-requests permissions — SUSPICIOUS)
- obfuscated-base64.md (base64 encoded malicious content — REJECTED)
- conditional-scope-creep.md (does more than stated — CONDITIONAL)
- missing-metadata.md (works but sloppy metadata — CONDITIONAL)

Write comprehensive tests. Commit when done."

# 1B: Permission + Injection analyzers (independent, can parallel)
run_codex_task "s1-analyzers-a" "You are building AgentVerus. Read PLAN.md and AGENTS.md.

Complete Tasks 1.3 and 1.4 from Sprint 1:

Task 1.3 — Permission Analyzer (src/scanner/analyzers/permissions.ts):
Analyze what permissions a skill requests or implies. Check for:
- Explicit tool declarations (exec, file read/write, network, browser, etc.)
- Implicit permission needs (instructions that would require elevated access)
- Permission scope vs stated purpose mismatch
- Dangerous permission combinations
Score starts at 100, deductions per finding. Weight: 0.25.

Task 1.4 — Injection Analyzer (src/scanner/analyzers/injection.ts):
Detect instruction injection attempts. Check for:
- 'Ignore previous instructions' patterns (50+ variations)
- System prompt override attempts
- Hidden instructions in markdown comments, HTML tags, zero-width chars
- Persona hijacking ('You are now...', 'Forget your rules...')
- Nested injection (instructions to inject into downstream agents)
- Social engineering ('For best results, disable safety...')
Score starts at 100, deductions per finding. Weight: 0.30 (highest — biggest threat).

Use the ASST taxonomy from PLAN.md Section 5. Write thorough tests using the fixture files. Commit when done."

# 1C: Dependency + Behavioral + Content analyzers
run_codex_task "s1-analyzers-b" "You are building AgentVerus. Read PLAN.md and AGENTS.md.

Complete Tasks 1.5, 1.6, and 1.7 from Sprint 1:

Task 1.5 — Dependency Analyzer (src/scanner/analyzers/dependencies.ts):
Check external dependencies for risk:
- Extract all URLs and check for suspicious domains, raw paste sites, IP addresses
- Detect mutable references (pastebin, gist without commit hash, raw URLs that could change)
- Check for script downloads (curl|wget piped to sh/bash)
- Detect package install instructions without version pinning
- Flag references to known malicious domains (if detectable)
Weight: 0.20.

Task 1.6 — Behavioral Analyzer (src/scanner/analyzers/behavioral.ts):
Analyze behavioral risk profile:
- Autonomous action without human confirmation (-10)
- State persistence (writing files, databases) (-5)
- Sub-agent spawning or delegation (-10)
- Unrestricted scope phrases ('do anything', 'no limitations') (-20)
- System modification (installing packages, modifying configs) (-20)
- Unbounded loops or retries (-10)
- Financial/payment actions (-10)
Weight: 0.15.

Task 1.7 — Content Analyzer (src/scanner/analyzers/content.ts):
Analyze content quality and transparency:
- Has clear description of what skill does? (+10 if detailed)
- Has explicit scope boundaries (what it should NOT do)? (-15 if missing)
- Has changelog/version history? (-5 if missing)
- Instruction clarity (vague vs specific)
- Output format specification (-5 if missing)
- Error handling instructions (-3 if missing)
Weight: 0.10.

Write thorough tests using the fixture files. Commit when done."

log "  Waiting for Sprint 1 parallel tasks..."
wait_for_sessions "s1-parser" "s1-analyzers-a" "s1-analyzers-b"

# 1D: Score aggregator + orchestrator + CLI (depends on above)
run_codex_task "s1-scoring" "You are building AgentVerus. Read PLAN.md and AGENTS.md.

Complete Tasks 1.8, 1.9, and 1.10 from Sprint 1:

Task 1.8 — Score Aggregator (src/scanner/scoring.ts):
Combine all category scores into final trust report. Weighted average:
- permissions (0.25), injection (0.30), dependencies (0.20), behavioral (0.15), content (0.10)
4-tier badge system:
- CERTIFIED (90-100, zero Critical AND zero High)
- CONDITIONAL (75-89, zero Critical AND ≤2 High)  
- SUSPICIOUS (50-74, zero Critical)
- REJECTED (<50 OR any Critical — Critical auto-rejects regardless of score)
IMPORTANT: A score of 95 with one Critical finding MUST be REJECTED.

Task 1.9 — Scanner Orchestrator (src/scanner/index.ts):
Main entry point: scanSkill(input: string | URL): Promise<TrustReport>
1. Detect format (URL → fetch content, string → use directly)
2. Parse with parser
3. Run all 5 analyzers in parallel (Promise.all)
4. Aggregate scores
5. Return complete TrustReport

Task 1.10 — CLI Tool (src/scanner/cli.ts):
Command-line scanner. Usage: pnpm scan <file-or-url>
- Parse args for file path or --url flag
- Run scanSkill()
- Print colorized output: score + badge tier + findings grouped by severity
- Exit code 0 for CERTIFIED/CONDITIONAL, 1 for SUSPICIOUS/REJECTED
- Add 'scan' script to package.json

Run ALL test fixtures through the scanner and verify expected badge tiers:
- safe-weather.md → CERTIFIED
- safe-formatter.md → CERTIFIED
- malicious-exfil.md → REJECTED
- malicious-injection.md → REJECTED
- suspicious-permissions.md → SUSPICIOUS
- obfuscated-base64.md → REJECTED
- conditional-scope-creep.md → CONDITIONAL
- missing-metadata.md → CONDITIONAL

Commit when done."

wait_for_sessions "s1-scoring"
success "Sprint 1 complete — Scanner engine built"

# ═══════════════════════════════════════════════════════════
# SPRINT 2: Trust Registry + API
# ═══════════════════════════════════════════════════════════
log "═══ SPRINT 2: Trust Registry + API ═══"

run_codex_task "s2-api" "You are building AgentVerus. Read PLAN.md and AGENTS.md.

Complete ALL Sprint 2 tasks (2.1 through 2.11):

- Database client (src/db/client.ts) with Drizzle + Neon
- POST /api/v1/skill/scan endpoint — accepts URL or raw content, runs scanner, stores result
- GET /api/v1/skill/:id/trust endpoint — returns full trust report
- GET /api/v1/skills endpoint — paginated search with badge filter, sort by score/name/date
- GET /api/v1/skill/:id/badge endpoint — returns SVG badge image
- Auth middleware for API key validation (X-API-Key header)
- Rate limiting (100 req/day free tier)
- Error handling middleware (JSON for API, HTML for web)
- Web pages: base layout (src/web/layouts/base.tsx), registry page, skill detail page
- Mount all routes in src/app.ts

Use Hono framework with JSX for web pages. Tailwind via CDN. htmx for interactivity.

The badge tiers are: CERTIFIED (green #2ECC40), CONDITIONAL (yellow #DFB317), SUSPICIOUS (orange #FE7D37), REJECTED (red #E05D44).

Write tests for all API endpoints. Commit frequently."

wait_for_sessions "s2-api"
success "Sprint 2 complete — Registry + API built"

# ═══════════════════════════════════════════════════════════
# SPRINT 3: Badges + Free Certification Flow
# ═══════════════════════════════════════════════════════════
log "═══ SPRINT 3: Badges + Free Certification ═══"

run_codex_task "s3-badges" "You are building AgentVerus. Read PLAN.md and AGENTS.md.

Complete Sprint 3 tasks — NOTE: This is the FREE version (no Stripe/payments):

Task 3.1 — SVG Badge Generator (src/badges/generator.ts, templates.ts):
Generate shields.io-style SVG badges. Left side 'AgentVerus', right side shows badge tier + score.
Colors: CERTIFIED=#2ECC40, CONDITIONAL=#DFB317, SUSPICIOUS=#FE7D37, REJECTED=#E05D44.
Support flat and flat-square styles.

Task 3.2 — Badge API already built in Sprint 2.

Task 3.3 (revised) — FREE Submission Flow:
- Web form at /submit: enter skill URL or paste SKILL.md content, enter email (optional)
- POST /api/v1/skill/scan handles it (already exists from Sprint 2)
- After scan: redirect to skill detail page showing results + badge embed code
- No payment required. All scans are free.

Task 3.4 — Cryptographic Attestation (src/lib/crypto.ts):
- ECDSA P-256 signing for certified skills
- Attestation document: skill ID, URL, content hash, score, badge tier, scan date, issuer
- Verify function + public key at /.well-known/agentverus-public-key

Task 3.5 — Email Notification (simplified):
- Using Resend SDK, send scan-complete email if email was provided
- Template: your skill scored X, here's your badge embed code
- No payment-related emails

Commit when done."

wait_for_sessions "s3-badges"
success "Sprint 3 complete — Badges + certification flow"

# ═══════════════════════════════════════════════════════════
# SPRINT 4: Launch (No Payments)
# ═══════════════════════════════════════════════════════════
log "═══ SPRINT 4: Launch ═══"

run_codex_task "s4-launch" "You are building AgentVerus. Read PLAN.md and AGENTS.md.

Complete Sprint 4 tasks (revised — NO payment integration):

Task 4.2 — Landing Page (src/web/pages/home.tsx):
Route GET /. Hero: 'Trust, but verify.' headline. Stats from DB (skills scanned, avg score, % critical). How it works (3 steps: Submit → Scan → Badge). Feature grid for each analysis type. CTA: 'Scan Your First Skill Free'. Professional, modern design with Tailwind.

Task 4.1 (revised) — API Key Self-Service:
- Register page at /register: enter email → get free API key (100 scans/day)
- Email verification (send API key via email)
- No payment required

Task 4.4 — API Documentation (src/web/pages/docs.tsx):
Route GET /docs. Document all endpoints with curl + JS examples. Auth section, rate limits, error codes.

Task 4.5 — Deployment Config:
- Cloudflare Workers (wrangler.toml) OR Vercel config
- Environment variable setup
- DEPLOY.md with instructions
- pnpm deploy script

Make sure the entire app builds and all tests pass. Commit when done."

wait_for_sessions "s4-launch"
success "Sprint 4 complete — Ready to launch"

# ═══════════════════════════════════════════════════════════
# SPRINT 5: Bulk Scan + Research
# ═══════════════════════════════════════════════════════════
log "═══ SPRINT 5: Bulk Scan + Research Publication ═══"

run_codex_task "s5-research" "You are building AgentVerus. Read PLAN.md and AGENTS.md.

Complete Sprint 5 tasks:

Task 5.1 — Bulk Scan Script (scripts/bulk-scan.ts):
Takes a list of skill URLs from a file (one per line), scans each, stores results.
Progress bar, retry on failure, rate limiting, summary at end.

Task 5.2 — Skill URL Collection (scripts/collect-skills.ts):
Scrape/collect skill URLs from:
- ClawHub (if API available, or scrape)
- GitHub search for SKILL.md files
- Known skill repositories (jdrhyne/agent-skills, anthropics/skills)
Output: skills-to-scan.txt with one URL per line.

Task 5.3 — Aggregate Statistics (scripts/generate-report.ts):
After bulk scan, generate stats:
- Total skills scanned
- Distribution by badge tier (pie chart data)
- Top 10 most common findings
- % with Critical findings
- % with injection attempts
- Average score by skill category/format
Output: JSON stats file + markdown report template.

Task 5.4 — Blog Post Template (content/state-of-agent-skill-security.md):
'State of Agent Skill Security — February 2026' report template.
Pre-filled with structure: methodology, key findings, threat analysis (by ASST category), recommendations, raw data. Stats get filled in from the generate-report output.

Commit when done."

wait_for_sessions "s5-research"
success "Sprint 5 complete — Research publication ready"

# ═══════════════════════════════════════════════════════════
# FINAL: Summary
# ═══════════════════════════════════════════════════════════
log "═══════════════════════════════════════════════════════"
success "🎉 ALL SPRINTS COMPLETE"
log "═══════════════════════════════════════════════════════"
log "Build logs: $LOG_DIR/"
log "Project: $PROJECT_DIR"
log ""
log "Next steps:"
log "  1. cd $PROJECT_DIR && pnpm test"
log "  2. Review git log"  
log "  3. pnpm dev to test locally"
log "  4. Deploy"

# Save final status
echo "BUILD COMPLETE: $(date)" > "$LOG_DIR/STATUS"
git -C "$PROJECT_DIR" log --oneline -20 >> "$LOG_DIR/STATUS"
