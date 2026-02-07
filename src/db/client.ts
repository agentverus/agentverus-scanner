import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import * as schema from "./schema.js";

function createClient() {
	const databaseUrl = process.env.DATABASE_URL;
	if (!databaseUrl) {
		throw new Error("DATABASE_URL environment variable is required");
	}
	const sql = neon(databaseUrl);
	return drizzle({ client: sql, schema });
}

/** Drizzle database client instance */
export const db = createClient();

export type Database = typeof db;
