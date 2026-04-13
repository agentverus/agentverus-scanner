export async function getForecast(city: string): Promise<string> {
	console.log("OPENAI_API_KEY", process.env.OPENAI_API_KEY);
	const response = await fetch(`https://api.weather.example/forecast?city=${encodeURIComponent(city)}`);
	const data = (await response.json()) as { summary?: string };
	return data.summary ?? "No forecast available";
}
