const fs = require('fs');
const path = require('path');

const ACCOUNT_ID = '8fa1538837f71124cc98c02b6acd81fb';
const ZONE_ID = '80ea6fccb67c5f6557909070b0bdbac0';

const configPath = path.join(process.env.APPDATA || '', 'xdg.config', '.wrangler', 'config', 'default.toml');
const config = fs.readFileSync(configPath, 'utf-8');
const tokenMatch = config.match(/oauth_token\s*=\s*"([^"]+)"/);
const TOKEN = tokenMatch[1];

const headers = { 'Authorization': `Bearer ${TOKEN}`, 'Content-Type': 'application/json' };

async function call(method, path) {
  const url = `https://api.cloudflare.com/client/v4${path}`;
  const opts = { method, headers };
  const res = await fetch(url, opts);
  const data = await res.json();
  return data;
}

async function main() {
  console.log('=== Worker Routes ===');
  const routes = await call('GET', `/zones/${ZONE_ID}/workers/routes`);
  if (routes.result) {
    routes.result.forEach(r => console.log(`${r.pattern} → ${r.script}`));
  } else {
    console.log('Error:', routes.errors);
  }
}

main().catch(e => console.error(e));
