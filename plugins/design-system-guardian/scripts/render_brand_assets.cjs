const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
function loadSharp() {
  try {
    return require('sharp');
  } catch (error) {
    if (error?.code !== 'MODULE_NOT_FOUND' || !String(error.message).includes('detect-libc')) {
      throw error;
    }

    const packageRoot = path.dirname(require.resolve('sharp/package.json'));
    const expectedVersion = JSON.parse(
      fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'),
    ).version;
    const virtualStore = path.join(path.dirname(packageRoot), '.pnpm');
    let entries;
    try {
      entries = fs.readdirSync(virtualStore).sort();
    } catch {
      throw error;
    }

    for (const entry of entries) {
      const candidate = path.join(virtualStore, entry, 'node_modules', 'sharp');
      const manifest = path.join(candidate, 'package.json');
      if (!fs.existsSync(manifest)) continue;
      const metadata = JSON.parse(fs.readFileSync(manifest, 'utf8'));
      if (metadata.name === 'sharp' && metadata.version === expectedVersion) {
        return require(candidate);
      }
    }
    throw error;
  }
}

const sharp = loadSharp();

const root = path.resolve(__dirname, '..');
const brand = path.join(root, 'assets', 'brand');
const markPath = path.join(brand, 'guardian-mark.svg');
const light = fs.readFileSync(markPath, 'utf8').replace(/\r\n/g, '\n').trimEnd() + '\n';

function dataUri(svg) {
  return `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
}

function seal(name, bytes) {
  fs.writeFileSync(path.join(brand, name), bytes);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

async function main() {
  fs.mkdirSync(brand, { recursive: true });
  fs.writeFileSync(markPath, light, 'utf8');

  const dark = light
    .replace('fill="#FFFFFF" stroke="#D8E0EF"', 'fill="#10131A" stroke="#374151"')
    .replace('</svg>', '  <rect x="8" y="8" width="224" height="224" rx="52" fill="none" stroke="#FFFFFF" stroke-opacity="0.08"/>\n</svg>');

  const lockup = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 240" role="img" aria-label="Design System Guardian">\n  <image href="${dataUri(light)}" x="0" y="0" width="240" height="240"/>\n  <text x="272" y="112" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="42" font-weight="750" fill="#111827">Design System</text>\n  <text x="272" y="164" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="42" font-weight="750" fill="#3157D8">Guardian</text>\n</svg>\n`;

  const social = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 640">\n  <rect width="1280" height="640" fill="#0B1020"/>\n  <circle cx="1110" cy="90" r="250" fill="#3157D8" opacity="0.16"/>\n  <circle cx="1190" cy="570" r="310" fill="#6D28D9" opacity="0.14"/>\n  <image href="${dataUri(dark)}" x="96" y="120" width="400" height="400"/>\n  <text x="548" y="244" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="62" font-weight="760" fill="#FFFFFF">Design System</text>\n  <text x="548" y="320" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="62" font-weight="760" fill="#8EA6FF">Guardian</text>\n  <text x="552" y="382" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="28" fill="#C7D2FE">Exact approved identities. Fail-closed auditing.</text>\n  <rect x="552" y="422" width="354" height="48" rx="24" fill="#FF4D67"/>\n  <text x="729" y="454" text-anchor="middle" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="20" font-weight="700" fill="#FFFFFF">Missing means conspicuous</text>\n</svg>`;

  const hashes = {};
  hashes['guardian-mark.svg'] = crypto.createHash('sha256').update(Buffer.from(light)).digest('hex');
  hashes['guardian-mark-dark.svg'] = seal('guardian-mark-dark.svg', Buffer.from(dark));
  hashes['guardian-lockup.svg'] = seal('guardian-lockup.svg', Buffer.from(lockup));
  hashes['guardian-avatar.png'] = seal(
    'guardian-avatar.png',
    await sharp(Buffer.from(light)).resize(512, 512).png({ compressionLevel: 9 }).toBuffer(),
  );
  hashes['guardian-social-preview.png'] = seal(
    'guardian-social-preview.png',
    await sharp(Buffer.from(social)).png({ compressionLevel: 9 }).toBuffer(),
  );
  const manifest = `${JSON.stringify({ schemaVersion: 1, assets: hashes }, null, 2)}\n`;
  fs.writeFileSync(path.join(brand, 'manifest.json'), manifest, 'utf8');
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});