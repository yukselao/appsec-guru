/* Intentionally vulnerable web apps for DAST testing. Shared by Deploy Test Apps
   and the Create Scan wizard. Run them on an isolated lab host only. */
window.WT_TESTAPPS = [
  {id: 'juice-shop', name: 'OWASP Juice Shop', port: 3000, path: '/', tags: ['Angular SPA', 'Node.js', 'REST', 'SQLi', 'XSS', 'auth'],
    about: 'Modern single-page shop with 100+ challenges. Good for crawler, DOM and API coverage.',
    compose: `services:
  juice-shop:
    image: bkimminich/juice-shop:latest
    container_name: juice-shop
    ports:
      - "3000:3000"
    restart: unless-stopped`},
  {id: 'dvwa', name: 'DVWA', port: 8081, path: '/login.php', tags: ['PHP', 'MySQL', 'SQLi', 'command injection', 'file upload'],
    about: 'Classic PHP app with selectable security levels. Log in with admin / password, then press "Create / Reset Database".',
    compose: `services:
  dvwa:
    image: vulnerables/web-dvwa:latest
    container_name: dvwa
    ports:
      - "8081:80"
    restart: unless-stopped`},
  {id: 'webgoat', name: 'OWASP WebGoat', port: 8082, path: '/WebGoat', tags: ['Java', 'Spring', 'lessons', 'XXE', 'deserialization'],
    about: 'Lesson-based Java app. Register a user on first visit. WebWolf runs on port 9090.',
    compose: `services:
  webgoat:
    image: webgoat/webgoat:latest
    container_name: webgoat
    environment:
      - TZ=Europe/Istanbul
    ports:
      - "8082:8080"
      - "9090:9090"
    restart: unless-stopped`},
  {id: 'mutillidae', name: 'OWASP Mutillidae II', port: 8083, path: '/', tags: ['PHP', 'OWASP Top 10', 'many vulns'],
    about: 'Large PHP app covering the OWASP Top 10. Click "setup/reset the DB" on first visit.',
    compose: `services:
  mutillidae:
    image: citizenstig/nowasp:latest
    container_name: mutillidae
    ports:
      - "8083:80"
    restart: unless-stopped`},
  {id: 'bwapp', name: 'bWAPP', port: 8084, path: '/install.php', tags: ['PHP', '100+ bugs'],
    about: 'Buggy web application. Open /install.php once, then log in as bee / bug.',
    compose: `services:
  bwapp:
    image: raesene/bwapp:latest
    container_name: bwapp
    ports:
      - "8084:80"
    restart: unless-stopped`},
  {id: 'vampi', name: 'VAmPI', port: 5002, path: '/', tags: ['REST API', 'OpenAPI', 'BOLA', 'mass assignment'],
    about: 'Vulnerable REST API with an OpenAPI spec at /openapi.json. Call /createdb first.',
    compose: `services:
  vampi:
    image: erev0s/vampi:latest
    container_name: vampi
    environment:
      - vulnerable=1
      - tokentimetolive=600
    ports:
      - "5002:5000"
    restart: unless-stopped`},
  {id: 'dvga', name: 'DVGA (GraphQL)', port: 5013, path: '/', tags: ['GraphQL', 'injection', 'DoS'],
    about: 'Damn Vulnerable GraphQL Application. Endpoint /graphql, GraphiQL UI at /graphiql.',
    compose: `services:
  dvga:
    image: dolevf/dvga:latest
    container_name: dvga
    environment:
      - WEB_HOST=0.0.0.0
    ports:
      - "5013:5013"
    restart: unless-stopped`},
];
