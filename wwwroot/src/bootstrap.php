<?php
declare(strict_types=1);

// Twig is installed in the image under /opt/app (outside the bind mount).
require '/opt/app/vendor/autoload.php';

// Sidebar order. 'group' renders a section heading above the first item of a group.
// Sidebar order. 'group' prints a section heading above a group's first item.
const PAGES = [
    'dashboard'        => ['title' => 'Dashboard', 'icon' => 'speedometer', 'template' => 'pages/dashboard.html.twig'],
    'subdomains'       => ['title' => 'Subdomain Discovery', 'group' => 'Open Source Tools', 'icon' => 'sitemap', 'template' => 'pages/subdomains.html.twig'],
    'hidden-paths'     => ['title' => 'Hidden Path Discovery', 'group' => 'Open Source Tools', 'icon' => 'search', 'template' => 'pages/fuzz.html.twig'],
    'port-scan'        => ['title' => 'Port Scan', 'group' => 'Open Source Tools', 'icon' => 'ports', 'template' => 'pages/portscan.html.twig'],
    'nuclei'           => ['title' => 'Nuclei', 'group' => 'Open Source Tools', 'icon' => 'bug', 'template' => 'pages/nuclei.html.twig'],
    'katana'           => ['title' => 'Katana Crawler', 'group' => 'Open Source Tools', 'icon' => 'spider', 'template' => 'pages/katana.html.twig'],
    'sqlmap'           => ['title' => 'SQLMap', 'group' => 'Open Source Tools', 'icon' => 'database', 'template' => 'pages/sqlmap.html.twig'],
    'commix'           => ['title' => 'Commix', 'group' => 'Open Source Tools', 'icon' => 'inject', 'template' => 'pages/commix.html.twig'],
    'container-overview' => ['title' => 'Overview', 'group' => 'Container Security', 'icon' => 'container', 'template' => 'pages/container-overview.html.twig'],
    'trivy-scan'       => ['title' => 'Trivy Scan', 'group' => 'Container Security', 'icon' => 'vuln', 'template' => 'pages/trivy.html.twig'],
    'image-inventory'  => ['title' => 'Image Inventory', 'group' => 'Container Security', 'icon' => 'layers', 'template' => 'pages/image-inventory.html.twig'],
    'image-vulns'      => ['title' => 'Image Vulnerabilities', 'group' => 'Container Security', 'icon' => 'bug', 'template' => 'pages/image-vulns.html.twig'],
    'iac-scan'         => ['title' => 'IaC / Dockerfile', 'group' => 'Container Security', 'icon' => 'filecode', 'template' => 'pages/iac.html.twig'],
    'registries'       => ['title' => 'Registries', 'group' => 'Container Security', 'icon' => 'registry', 'template' => 'pages/registries.html.twig'],
    'clusters'         => ['title' => 'Live Cluster', 'group' => 'Kubernetes Security', 'icon' => 'cluster', 'template' => 'pages/clusters.html.twig'],
    'k8s-posture'      => ['title' => 'K8s Posture', 'group' => 'Kubernetes Security', 'icon' => 'helm', 'template' => 'pages/k8s-posture.html.twig'],
    'kubescape'        => ['title' => 'Manifest Scan', 'group' => 'Kubernetes Security', 'icon' => 'shieldcheck', 'template' => 'pages/kubescape.html.twig'],
    'kubebench'        => ['title' => 'CIS Benchmark', 'group' => 'Kubernetes Security', 'icon' => 'checklist', 'template' => 'pages/kubebench.html.twig'],
    'findings'         => ['title' => 'All Findings', 'group' => 'Security Findings', 'icon' => 'list', 'template' => 'pages/findings.html.twig'],
    'trends'           => ['title' => 'Trends & Compare', 'group' => 'Security Findings', 'icon' => 'trend', 'template' => 'pages/trends.html.twig'],
    'scans'            => ['title' => 'Scans', 'group' => 'Tenable Web App Scanning', 'icon' => 'radar', 'template' => 'pages/scans.html.twig'],
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
