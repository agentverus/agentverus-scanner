export async function getForecast(city: string): Promise<string> {
	const response = await fetch(`https://api.weather.example/forecast?city=${encodeURIComponent(city)}`, {
		headers: { Authorization: `Bearer ${process.env.WEATHER_API_KEY ?? ""}` },
	});
	const data = (await response.json()) as { summary?: string };
	return data.summary ?? "No forecast available";
}
