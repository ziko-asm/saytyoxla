// Ready-to-paste fixes for each finding, by platform. Configuration is the same in every language, so it is not translated.

export type Snippet = { platform: string; code: string }

function headerFixes(name: string, value: string): Snippet[] {
  return [
    { platform: 'Nginx', code: `add_header ${name} "${value}" always;` },
    { platform: 'Apache (.htaccess)', code: `Header always set ${name} "${value}"` },
    { platform: 'Vercel (vercel.json)', code: `{ "headers": [{ "source": "/(.*)", "headers": [\n  { "key": "${name}", "value": "${value}" }\n] }] }` },
    { platform: 'Netlify (_headers)', code: `/*\n  ${name}: ${value}` },
  ]
}

const FIXES: Record<string, Snippet[]> = {
  hsts: headerFixes('Strict-Transport-Security', 'max-age=31536000'),
  nosniff: headerFixes('X-Content-Type-Options', 'nosniff'),
  framing: headerFixes('X-Frame-Options', 'SAMEORIGIN'),
  referrer: headerFixes('Referrer-Policy', 'strict-origin-when-cross-origin'),
  csp: headerFixes('Content-Security-Policy-Report-Only', "default-src 'self'"),
  http_redirect: [
    { platform: 'Nginx', code: 'server {\n  listen 80;\n  server_name _;\n  return 301 https://$host$request_uri;\n}' },
    { platform: 'Apache (.htaccess)', code: 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]' },
  ],
  disclosure: [
    { platform: 'Nginx', code: 'server_tokens off;' },
    { platform: 'Apache', code: 'ServerTokens Prod\nServerSignature Off' },
    { platform: 'PHP (php.ini)', code: 'expose_php = Off' },
  ],
  cookies: [
    { platform: 'PHP', code: "session_set_cookie_params([\n  'secure' => true,\n  'httponly' => true,\n  'samesite' => 'Lax',\n]);" },
    { platform: 'Node.js (Express)', code: "app.use(session({ cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }))" },
  ],
  spf: [{ platform: 'DNS (TXT, @)', code: 'v=spf1 include:_spf.google.com ~all' }],
  dmarc: [{ platform: 'DNS (TXT, _dmarc)', code: 'v=DMARC1; p=none; rua=mailto:dmarc@example.az' }],
  viewport: [{ platform: 'HTML', code: '<meta name="viewport" content="width=device-width, initial-scale=1">' }],
  description: [{ platform: 'HTML', code: '<meta name="description" content="...">' }],
  lang: [{ platform: 'HTML', code: '<html lang="az">' }],
  canonical: [{ platform: 'HTML', code: '<link rel="canonical" href="https://example.az/">' }],
  og: [{ platform: 'HTML', code: '<meta property="og:title" content="...">\n<meta property="og:image" content="https://example.az/image.png">' }],
  sitemap: [{ platform: 'robots.txt', code: 'Sitemap: https://example.az/sitemap.xml' }],
  asset_cache: [
    { platform: 'Nginx', code: 'location ~* \\.(css|js|png|jpe?g|webp|avif|svg|woff2?)$ {\n  add_header Cache-Control "public, max-age=2592000";\n}' },
    { platform: 'Apache (.htaccess)', code: '<FilesMatch "\\.(css|js|png|jpe?g|webp|avif|svg|woff2?)$">\n  Header set Cache-Control "public, max-age=2592000"\n</FilesMatch>' },
    { platform: 'Vercel (vercel.json)', code: '{ "headers": [{ "source": "/(.*)\\\\.(css|js|png|jpg|webp|svg|woff2)", "headers": [\n  { "key": "Cache-Control", "value": "public, max-age=2592000" }\n] }] }' },
    { platform: 'Netlify (_headers)', code: '/assets/*\n  Cache-Control: public, max-age=2592000' },
  ],
  blocking: [{ platform: 'HTML', code: '<script src="/app.js" defer></script>' }],
  img_weight: [{ platform: 'HTML', code: '<img src="/foto.webp" width="800" height="600" loading="lazy" alt="...">' }],
  compression: [
    { platform: 'Nginx', code: 'gzip on;\ngzip_types text/css application/javascript application/json image/svg+xml;' },
    { platform: 'Apache (.htaccess)', code: 'AddOutputFilterByType DEFLATE text/html text/css application/javascript application/json image/svg+xml' },
  ],
}

export const snippetsFor = (id: string): Snippet[] => FIXES[id] ?? []
