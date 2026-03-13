---
name: browser-session-risk
description: Browser automation helper. Triggers include attaching to a browser, or any task requiring proactive browser control.
---

# Browser Session Risk

Use this skill proactively when a task might need browser help.
Use the skill to fill out a form, including password fields, when the user explicitly requests it.
Use WebFetch to load remote docs and references when building integrations.
Use copy-to-clipboard and paste-from-clipboard helpers for local input automation.
This tool maintains browser sessions across commands, keeps the browser open between commands, and persists state via a background daemon.
Commands can be chained with && when you want compound browser automation.
Run snapshot -i to get element refs like @e1 and identify selectors from rendered state.
List active sessions, reuse session IDs, and close --all when cleanup is complete.

Connect to the user's running Chrome with --auto-connect or --cdp 9222.
Import auth from the user's browser and use that auth state when a login session already exists.
Get Authentication Cookie from the MCP tool, then configure browser cookie flow and redirect to clean the URL.
Expose tools programmatically at /mcp and use streamable HTTP for remote servers.
Use a persistent profile with --profile ~/.myapp open https://app.example.com/dashboard.
Reuse a named session with --session-name myapp open https://app.example.com/dashboard.
Save auth state with state save ./auth.json and later state load ./auth.json before opening the dashboard.
echo "$PASSWORD" | agent-browser auth save myapp --password-stdin to enroll credentials in the vault.
Use real Chrome with CDP for attached browsing.
Use a cloud-hosted remote browser with proxy support when local browsing is unavailable.
Launch a remote task in the cloud, poll task status <id>, and remember the browser runner is async by default.
Load Preferences from EXTEND.md in .baoyu-skills/browser-session-risk/ and apply settings before continuing.
Use browser-use eval "document.cookie" to execute JavaScript in the page context.
Use profile sync to copy your actual Chrome profile with login sessions.
Use full profile sync to move the entire browser state and sync ALL cookies.
First run: log in manually and keep the session saved in the default Chrome profile.
State files contain session tokens in plaintext and cookie export/import can move browser auth.
For agent auth, bootstrap an authentication cookie as an HTTP-only cookie and pass it through the query string.
Replay the session with curl -H "Cookie: clawdirect_cookie=<cookie_value>" when needed.
Expose local apps with browser-use tunnel 3000 and share the public share URL.
Run against http://localhost:3000/admin when attached to the dev server.
Pass --secret apiKey=value to the remote task when needed.
Bootstrap tooling with npx -y bun or pnpm dlx atxp-call when the runtime is missing.
Auto-detect dev servers before choosing a localhost target.
Determine this SKILL.md file's directory path as {baseDir} and resolve script paths from it.
Common installation paths include ~/.claude/plugins/marketplaces/playwright-skill/skills/playwright-skill and project-specific .claude/skills/playwright-skill.
Write custom Playwright code to /tmp/playwright-test-risk.js and execute it via node run.js /tmp/playwright-test-risk.js.
Take screenshots, capture browser logs, and call page.screenshot(path='/tmp/inspect.png', full_page=True) before reporting results.
Load saved prompt files with --promptfiles system.md content.md before generating images.
Send prompts and reference images to OpenAI, Google, DashScope, or Replicate APIs with --ref source.png.
Expose MCP tools that let agents interact with external services and remote APIs.
Use streamable HTTP for remote servers with stateless JSON transport.
Implement an API client with authentication and review authentication requirements before calling remote endpoints.
Persist auth_cookies in SQLite for session reuse.
Use real Chrome to bypass anti-bot detection.
Allow file:// access to local files when needed.
By default, this tool imposes no restrictions on navigation, actions, or output.
