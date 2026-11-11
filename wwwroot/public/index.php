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
$template = PAGES[$page]['template'];
$finding = null;
$crumbs = [['Dashboard', '/']];
if ($page !== 'dashboard') {
    if (isset(PAGES[$page]['group'])) {
        $crumbs[] = [PAGES[$page]['group'], null];
    }
    $crumbs[] = [PAGES[$page]['title'], '/' . $page];
    if ($page === 'scan-results') {
        // /scan-results/<run>[/finding/<plugin>[/<n>]]  or  /scan-results/sc/<result>[/finding/<plugin>[/<n>]]
        $isSc = $param === 'sc' && $param2;
        $rest = array_slice($parts, $isSc ? 3 : 2);
        $base = $isSc ? '/scan-results/sc/' . rawurlencode($param2) : '/scan-results/' . rawurlencode((string) $param);
        $hasFinding = ($rest[0] ?? '') === 'finding' && preg_match('/^\d+$/', $rest[1] ?? '');
        if ($isSc) {
            $crumbs[] = ['Security Center result ' . $param2, $hasFinding ? $base : null];
        } elseif ($param !== null && $param !== '') {
            $crumbs[] = ['Run #' . $param, $hasFinding ? $base : null];
        }
        if ($hasFinding && ($isSc || preg_match('/^\d+$/', (string) $param))) {
            $n = isset($rest[2]) && preg_match('/^\d+$/', $rest[2]) ? (int) $rest[2] : null;
            $finding = ['src' => $isSc ? 'sc' : 'run', 'ref' => $isSc ? $param2 : $param, 'plugin' => $rest[1], 'n' => $n, 'base' => $base];
            $crumbs[] = ['Plugin ' . $rest[1], $n ? $base . '/finding/' . $rest[1] : null];
            if ($n) {
                $crumbs[] = ['Instance ' . $n, null];
            }
            $template = 'pages/finding.html.twig';
        }
    } elseif ($param !== null && $param !== '') {
        $crumbs[] = ['Run #' . $param, null];
    }
}

echo twig()->render($template, [
    'app_name' => getenv('APP_NAME') ?: 'AppSec Guru',
    'pages' => PAGES,
    'page' => $page,
    'title' => PAGES[$page]['title'],
    'param' => $param,
    'param2' => $param2,
    'finding' => $finding,
    'crumbs' => $crumbs,
    'not_found' => $notFound ?? false,
]);
