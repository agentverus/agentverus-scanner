import { z } from "zod/v4";

const envSchema = z.object({
	DATABASE_URL: z.string().optional().default(""),
	RESEND_API_KEY: z.string().optional().default(""),
	API_SIGNING_KEY: z.string().optional().default(""),
	NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
	PORT: z.coerce.number().int().positive().default(3000),
	BASE_URL: z.string().url().default("http://localhost:3000"),
	GITHUB_TOKEN: z.string().optional().default(""),
	ADMIN_API_KEY: z.string().optional().default(""),
});

export type Config = z.infer<typeof envSchema>;

function loadConfig(): Config {
	const result = envSchema.safeParse(process.env);
	if (!result.success) {
		const formatted = z.prettifyError(result.error);
		console.error("❌ Invalid environment variables:\n", formatted);
		throw new Error("Invalid environment configuration");
	}
	return result.data;
}

/** Application configuration validated from environment variables */
export const config: Config = loadConfig();
