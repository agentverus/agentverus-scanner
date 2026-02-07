import type { AdoptionTier } from "../adoption/types.js";

interface AdoptionBadgeOptions {
	readonly score: number;
	readonly tier: AdoptionTier;
	readonly style?: "flat" | "flat-square" | "plastic";
	readonly label?: string;
}

const ADOPTION_COLORS: Record<AdoptionTier, string> = {
	widely_used: "#FFD700",
	gaining_adoption: "#4A90D9",
	early: "#7BC96F",
	not_adopted: "#9E9E9E",
};

const ADOPTION_LABELS: Record<AdoptionTier, string> = {
	widely_used: "WIDELY USED",
	gaining_adoption: "GAINING ADOPTION",
	early: "EARLY",
	not_adopted: "NOT ADOPTED",
};

export function generateAdoptionBadge(options: AdoptionBadgeOptions): string {
	const { score, tier, style = "flat", label = "Adoption" } = options;

	const rightColor = ADOPTION_COLORS[tier];
	const rightText = `${ADOPTION_LABELS[tier]} ${score}`;

	const leftWidth = label.length * 6.5 + 12;
	const rightWidth = rightText.length * 6.5 + 12;
	const totalWidth = leftWidth + rightWidth;

	const radius = style === "flat-square" ? 0 : 3;
	const leftColor = "#555";

	const gradient =
		style === "plastic"
			? `<linearGradient id="s" x2="0" y2="100%">
				<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
				<stop offset="1" stop-opacity=".1"/>
			</linearGradient>`
			: "";

	const gradientRef = style === "plastic" ? ' fill="url(#s)"' : "";

	return `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${rightText}">
	<title>${label}: ${rightText}</title>
	${gradient}
	<clipPath id="r">
		<rect width="${totalWidth}" height="20" rx="${radius}" fill="#fff"/>
	</clipPath>
	<g clip-path="url(#r)">
		<rect width="${leftWidth}" height="20" fill="${leftColor}"/>
		<rect x="${leftWidth}" width="${rightWidth}" height="20" fill="${rightColor}"/>
		<rect width="${totalWidth}" height="20"${gradientRef}/>
	</g>
	<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
		<text aria-hidden="true" x="${leftWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${escapeXml(label)}</text>
		<text x="${leftWidth / 2}" y="14">${escapeXml(label)}</text>
		<text aria-hidden="true" x="${leftWidth + rightWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${escapeXml(rightText)}</text>
		<text x="${leftWidth + rightWidth / 2}" y="14">${escapeXml(rightText)}</text>
	</g>
</svg>`;
}

function escapeXml(str: string): string {
	return str
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&apos;");
}

