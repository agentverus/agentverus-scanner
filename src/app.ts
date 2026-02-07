import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { errorHandler } from "./api/middleware/errors.js";
// Middleware
import { rateLimit } from "./api/middleware/rateLimit.js";
import { badgeApp } from "./api/v1/badge.js";
import { certifyApp } from "./api/v1/certify.js";
// API routes
import { scanApp } from "./api/v1/scan.js";
import { skillsApp } from "./api/v1/skills.js";
import { trustApp } from "./api/v1/trust.js";
// Crypto
import { getPublicKeyPem } from "./lib/crypto.js";
import { docsApp } from "./web/pages/docs.js";
// Web pages
import { homeApp } from "./web/pages/home.js";
import { registryApp } from "./web/pages/registry.js";
import { statsApp } from "./web/pages/stats.js";
import { submitApp } from "./web/pages/submit.js";
// import { fontTestApp } from "./web/pages/font-test.js";

const app = new Hono();

// Global middleware
app.use("*", cors());
app.use("*", logger());
app.use("/api/*", rateLimit({ windowMs: 60_000, max: 60 }));

// Health checks
app.get("/health", (c) => c.json({ status: "ok", version: "0.1.0" }));
app.get("/api/v1/health", (c) => c.json({ status: "ok", version: "0.1.0" }));

// API v1 routes
app.route("/api/v1", scanApp);
app.route("/api/v1", trustApp);
app.route("/api/v1", skillsApp);
app.route("/api/v1", badgeApp);
app.route("/api/v1", certifyApp);

// Well-known endpoints
app.get("/.well-known/agentverus-public-key", (c) => {
	const publicKey = getPublicKeyPem();
	c.header("Content-Type", "application/x-pem-file");
	return c.text(publicKey);
});

// Web routes
app.route("", homeApp);
app.route("", registryApp);
app.route("", submitApp);
app.route("", docsApp);
app.route("", statsApp);
// app.route("", fontTestApp);

// Global error handler
app.onError(errorHandler);

// 404 handlers
app.notFound((c) => {
	if (c.req.path.startsWith("/api/")) {
		return c.json({ error: { code: "NOT_FOUND", message: "Endpoint not found" } }, 404);
	}
	return c.text("Not Found", 404);
});

export { app };
