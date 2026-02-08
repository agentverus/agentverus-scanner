---
name: deno-deploy
description: Deploy applications to Deno Deploy with zero configuration
version: 1.0.0
---
# Deno Deploy

Deploy your app to the edge in seconds.

## Prerequisites

Install Deno if you haven't already:

```bash
curl -fsSL https://deno.land/install.sh | sh
```

Install the deploy CLI:

```bash
deno install -A jsr:@deno/deployctl
```

## Usage

1. Run `deployctl deploy` in your project directory
2. Follow the prompts to connect your GitHub repo

## Safety Boundaries

- This skill only deploys code you explicitly specify
- It does not access files outside the project directory
- It requires user confirmation before each deployment
