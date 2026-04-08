#!/usr/bin/env node
// Hound — Icon Generator
// Converts the SVG source icon to PNG at all required sizes.
// Usage: node scripts/generate-icons.js

'use strict';

const path = require('path');
const fs = require('fs');

let sharp;
try {
  sharp = require('sharp');
} catch {
  console.error('Error: sharp not found. Run: npm install');
  process.exit(1);
}

const SIZES = [16, 32, 48, 128];
const ICONS_DIR = path.join(__dirname, '..', 'icons');

// Ensure icons directory exists
fs.mkdirSync(ICONS_DIR, { recursive: true });

// Shield SVG — matches Hound brand identity
// Shield fills 80% of canvas with 10% padding on each side
const SVG_TEMPLATE = (size) => {
  const s = size;
  // Scale the internal paths proportionally from a 128×128 viewBox
  // Shield spans x=13..115 (80% fill, 10% padding each side)
  return `<svg width="${s}" height="${s}" viewBox="0 0 128 128" fill="none" xmlns="http://www.w3.org/2000/svg">
  <!-- Background fill for visibility at small sizes -->
  <rect width="128" height="128" rx="${Math.round(s * 0.18)}" fill="#0f1117"/>

  <!-- Shield body (80% fill: x=13..115, y=10..118) -->
  <path d="M64 10L13 29v37c0 27 17.5 50 51 59 33.5-9 51-32 51-59V29L64 10z"
        fill="#10b981" opacity="0.18"/>
  <path d="M64 10L13 29v37c0 27 17.5 50 51 59 33.5-9 51-32 51-59V29L64 10z"
        stroke="#10b981" stroke-width="${Math.max(3, Math.round(s * 0.05))}" stroke-linejoin="round"/>

  <!-- Check mark -->
  <path d="M38 65l17 17 35-35"
        stroke="#10b981" stroke-width="${Math.max(4, Math.round(s * 0.07))}"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
};

async function generateIcons() {
  console.log('Generating Hound extension icons...\n');

  for (const size of SIZES) {
    const svgBuffer = Buffer.from(SVG_TEMPLATE(size));
    const outPath = path.join(ICONS_DIR, `icon-${size}.png`);

    await sharp(svgBuffer)
      .resize(size, size)
      .png({ compressionLevel: 9, adaptiveFiltering: true })
      .toFile(outPath);

    const stat = fs.statSync(outPath);
    console.log(`  ✓  icon-${size}.png  (${stat.size} bytes)`);
  }

  console.log('\nAll icons generated in apps/browser-extension/icons/');
}

generateIcons().catch((err) => {
  console.error('Icon generation failed:', err.message);
  process.exit(1);
});
