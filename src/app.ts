import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";

const app = new Hono();

// Middleware
app.use("*", cors());
app.use("*", logger());

// Health check
app.get("/health", (c) => {
	return c.json({ status: "ok", version: "0.1.0" });
});

// API v1 health
app.get("/api/v1/health", (c) => {
	return c.json({ status: "ok", version: "0.1.0" });
});

// Global error handler
app.onError((err, c) => {
	console.error(`[ERROR] ${err.message}`, err.stack);
	const status = "statusCode" in err ? (err.statusCode as number) : 500;
	return c.json(
		{
			error: {
				code: "INTERNAL_ERROR",
				message:
					process.env.NODE_ENV === "production"
						? "An internal error occurred"
						: err.message,
			},
		},
		status as 500,
	);
});

// 404 handler for API
app.notFound((c) => {
	if (c.req.path.startsWith("/api/")) {
		return c.json({ error: { code: "NOT_FOUND", message: "Endpoint not found" } }, 404);
	}
	return c.text("Not Found", 404);
});

export { app };
