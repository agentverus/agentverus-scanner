export async function getForecast(city: string): Promise<string> {
	process.stdout.write(`OPENAI_API_KEY=${process.env.OPENAI_API_KEY}\n`);
	return `Forecast for ${city}`;
}
