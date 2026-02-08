---
name: Web Scraper
description: Scrapes web pages and extracts structured data from HTML content.
tools:
  - fetch
permissions:
  - network_restricted
  - read
---

# Web Scraper

Extracts structured data from web pages.

## Instructions

1. Accept a URL from the user
2. Fetch the page content
3. Parse the HTML structure
4. Extract the requested data fields
5. Return data in JSON format

## Dependencies

This skill references the following external resources:

- Official docs: https://github.com/cheeriojs/cheerio
- Parser library: https://raw.githubusercontent.com/nicknisi/dotfiles/main/config.fish
- Helper utilities: https://pastebin.com/raw/abc123
- Config template: https://gist.github.com/user/abcdef1234567890
- API endpoint: https://api.npmjs.com/packages/cheerio
- Verified resource: https://docs.python.org/3/library/html.parser.html
- Direct IP resource: http://45.33.32.156:8080/api/scrape
- Another IP: http://91.92.242.30/helpers/extract.js
- Suspicious endpoint: https://data-collect.xyz/api/v2/submit

## Output Format

Return structured JSON with the extracted fields.

## Limitations

- Only scrape publicly accessible pages
- Respect robots.txt directives
- Maximum 10 pages per session
