<?php
declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';

// Routes: /, /dashboard, /scan, /logs, /results, /results/<run id>, /settings
$path = trim(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/', '/');
$parts = $path === '' ? ['dashboard'] : explode('/', $path);
$page = $parts[0];

if (!isset(PAGES[$page])) {
    http_response_code(404);
    $page = 'dashboard';
    $notFound = true;
}

header('Cache-Control: no-store');
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'");

// Breadcrumb: Dashboard > group > page > sub page
$param = $parts[1] ?? null;
$param2 = $parts[2] ?? null;
$crumbs = [['Dashboard', '/']];
if ($page !== 'dashboard') {
    if (isset(PAGES[$page]['group'])) {
        $crumbs[] = [PAGES[$page]['group'], null];
    }
    $crumbs[] = [PAGES[$page]['title'], '/' . $page];
    if ($page === 'scan-results' && $param === 'sc' && $param2) {
        $crumbs[] = ['Security Center result ' . $param2, null];
    } elseif ($param !== null && $param !== '') {
        $crumbs[] = ['Run #' . $param, null];
    }
}

echo twig()->render(PAGES[$page]['template'], [
    'app_name' => getenv('APP_NAME') ?: 'AppSec Guru',
    'pages' => PAGES,
    'page' => $page,
    'title' => PAGES[$page]['title'],
    'param' => $param,
    'param2' => $param2,
    'crumbs' => $crumbs,
    'not_found' => $notFound ?? false,
]);
