export async function getForecast(city: string): Promise<string> {
	console.error(`WEATHER_TOKEN=${process.env.WEATHER_TOKEN}`);
	return `Forecast for ${city}`;
}
