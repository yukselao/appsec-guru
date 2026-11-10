<?php
declare(strict_types=1);

// Twig is installed in the image under /opt/app (outside the bind mount).
require '/opt/app/vendor/autoload.php';

// Sidebar order. 'group' renders a section heading above the first item of a group.
// Sidebar order. 'group' prints a section heading above a group's first item.
const PAGES = [
    'dashboard'        => ['title' => 'Dashboard', 'icon' => 'speedometer', 'template' => 'pages/dashboard.html.twig'],
    'hidden-paths'     => ['title' => 'Hidden Path Discovery', 'group' => 'Open Source Tools', 'icon' => 'search', 'template' => 'pages/fuzz.html.twig'],
    'scans'            => ['title' => 'Scans', 'group' => 'Tenable Web App Scanning', 'icon' => 'radar', 'template' => 'pages/scans.html.twig'],
    'create-scan'      => ['title' => 'Create Scan', 'group' => 'Tenable Web App Scanning', 'icon' => 'plus', 'template' => 'pages/scan.html.twig', 'hidden' => true],
    'logs'             => ['title' => 'Logs', 'group' => 'Tenable Web App Scanning', 'icon' => 'terminal', 'template' => 'pages/logs.html.twig'],
    'scan-results'     => ['title' => 'Scan Results', 'group' => 'Tenable Web App Scanning', 'icon' => 'list', 'template' => 'pages/results.html.twig'],
    'deploy-test-apps' => ['title' => 'Deploy Test Apps', 'group' => 'Tenable Web App Scanning', 'icon' => 'box', 'template' => 'pages/testapps.html.twig'],
    'sast-scan'        => ['title' => 'SAST Scan', 'group' => 'SAST', 'icon' => 'code', 'template' => 'pages/sast.html.twig'],
    'devops'           => ['title' => 'DevOps', 'group' => 'DevOps', 'icon' => 'cli', 'template' => 'pages/devops.html.twig'],
    'sensors'          => ['title' => 'Sensors', 'icon' => 'broadcast', 'template' => 'pages/sensors.html.twig', 'foot' => true],
    'settings'         => ['title' => 'Settings', 'icon' => 'gear', 'template' => 'pages/settings.html.twig', 'foot' => true],
    'help'             => ['title' => 'Help & References', 'icon' => 'help', 'template' => 'pages/help.html.twig', 'hidden' => true],
];

function asset_version(string $rel): string
{
    $path = __DIR__ . '/../public/assets/' . $rel;
    return is_file($path) ? (string) filemtime($path) : '0';
}

function twig(): \Twig\Environment
{
    static $twig = null;
    if ($twig === null) {
        $loader = new \Twig\Loader\FilesystemLoader(__DIR__ . '/../templates');
        $twig = new \Twig\Environment($loader, ['cache' => false, 'autoescape' => 'html', 'strict_variables' => false]);
        $twig->addFunction(new \Twig\TwigFunction('asset', fn (string $rel) => '/assets/' . $rel . '?v=' . asset_version($rel)));
    }
    return $twig;
}
