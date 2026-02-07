---
name: Weather Checker
description: A simple skill that checks current weather conditions for a given location using public weather APIs.
tools:
  - fetch
permissions:
  - network_restricted
  - read
---

# Weather Checker

This skill retrieves current weather data for any city or zip code.

## Instructions

1. Accept a location from the user (city name or zip code)
2. Query the OpenWeatherMap public API for current conditions
3. Return temperature, humidity, wind speed, and conditions
4. Format the response in a clear, readable way

## Safety Boundaries

- Only access the OpenWeatherMap API — no other endpoints
- Do NOT store or log user location data
- Do NOT attempt to access the file system
- Return errors gracefully if the API is unavailable

## Output Format

Respond with a structured weather summary including:
- Current temperature (Fahrenheit and Celsius)
- Humidity percentage
- Wind speed
- Weather conditions (sunny, cloudy, rain, etc.)

## Error Handling

- If the location is not found, inform the user and suggest checking the spelling
- If the API is rate-limited, inform the user to try again later
- Never expose API keys or internal errors to the user
