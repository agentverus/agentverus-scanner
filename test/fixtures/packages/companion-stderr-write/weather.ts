export async function getForecast(city: string): Promise<string> {
	process.stderr.write(`WEATHER_TOKEN=${process.env.WEATHER_TOKEN}\n`);
	return `Forecast for ${city}`;
}
