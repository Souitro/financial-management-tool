<?php
// ============================================================
// reports.php — Financial Reports (Manager / CEO only)
// ============================================================
date_default_timezone_set('Africa/Johannesburg');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ── Auth guard ──────────────────────────────────────────────
if (!isset($_SESSION['user_id'], $_SESSION['company_id'])) {
    header('Location: login.php');
    exit;
}

$current_user_id    = (int)$_SESSION['user_id'];
$current_company_id = (int)$_SESSION['company_id'];
$current_user_role  = $_SESSION['user_role'] ?? 'Employee';

// ── Role gate: Employees cannot access reports ──────────────
if ($current_user_role === 'Employee') {
    header('Location: dashboard.php?err=access_denied');
    exit;
}

// ── PDO Connection ──────────────────────────────────────────
$host    = '127.0.0.1';
$db      = 'souitro_db';
$dbuser  = 'root';
$dbpass  = '';
$charset = 'utf8mb4';

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$db;charset=$charset",
        $dbuser, $dbpass,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]
    );
    $pdo->exec("SET time_zone = '+02:00'");
} catch (\PDOException $e) {
    die('Database unavailable. Please contact support.');
}

// ── Fetch user + company ────────────────────────────────────
try {
    $stmt = $pdo->prepare("
        SELECT u.name, u.role,
               c.company_name, c.primary_color, c.secondary_color, c.accent_color
        FROM users u
        JOIN companies c ON c.id = u.company_id
        WHERE u.id = ? AND u.company_id = ? AND u.is_active = 1
        LIMIT 1
    ");
    $stmt->execute([$current_user_id, $current_company_id]);
    $row = $stmt->fetch();

    if (!$row) {
        session_unset(); session_destroy();
        header('Location: login.php?err=inactive');
        exit;
    }

    $user = [
        'name'         => $row['name'],
        'role'         => $row['role'],
        'company_name' => $row['company_name'],
        'brand'        => [
            'primary'   => $row['primary_color'],
            'secondary' => $row['secondary_color'],
            'accent'    => $row['accent_color'],
        ],
    ];
    $isCEO = ($user['role'] === 'CEO');

    // ── Current month summary ───────────────────────────────
    $stmt = $pdo->prepare("
        SELECT
            IFNULL(SUM(CASE WHEN status = 'paid'   THEN total_amount END), 0) AS revenue_paid,
            IFNULL(SUM(CASE WHEN status IN ('sent','overdue') THEN total_amount END), 0) AS revenue_outstanding,
            COUNT(*)                                                            AS total_invoices,
            IFNULL(SUM(total_amount), 0)                                        AS total_invoiced
        FROM invoices
        WHERE company_id = ?
          AND MONTH(issue_date) = MONTH(CURDATE())
          AND YEAR(issue_date)  = YEAR(CURDATE())
    ");
    $stmt->execute([$current_company_id]);
    $monthSummary = $stmt->fetch();

    // ── Invoice status counts (all time) ────────────────────
    $stmt = $pdo->prepare("
        SELECT status,
               COUNT(*)           AS invoice_count,
               IFNULL(SUM(total_amount), 0) AS total_amount
        FROM invoices
        WHERE company_id = ?
        GROUP BY status
    ");
    $stmt->execute([$current_company_id]);
    $statusBreakdown = [];
    foreach ($stmt->fetchAll() as $s) {
        $statusBreakdown[$s['status']] = $s;
    }

    // ── Top 6 clients by total invoiced ────────────────────
    $stmt = $pdo->prepare("
        SELECT
            cl.name                                             AS client_name,
            IFNULL(SUM(inv.total_amount), 0)                   AS total_invoiced,
            IFNULL(SUM(CASE WHEN inv.status = 'paid' THEN inv.total_amount END), 0) AS total_paid,
            MAX(inv.status)                                     AS latest_status
        FROM invoices inv
        JOIN clients cl ON cl.id = inv.client_id
        WHERE inv.company_id = ?
        GROUP BY cl.id, cl.name
        ORDER BY total_invoiced DESC
        LIMIT 6
    ");
    $stmt->execute([$current_company_id]);
    $topClients = $stmt->fetchAll();

    // ── Monthly revenue for bar chart (last 6 months) ───────
    $stmt = $pdo->prepare("
        SELECT
            DATE_FORMAT(issue_date, '%b') AS month_label,
            DATE_FORMAT(issue_date, '%Y-%m') AS month_key,
            IFNULL(SUM(CASE WHEN status = 'paid' THEN total_amount END), 0) AS paid_revenue
        FROM invoices
        WHERE company_id = ?
          AND issue_date >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
        GROUP BY month_key, month_label
        ORDER BY month_key ASC
        LIMIT 6
    ");
    $stmt->execute([$current_company_id]);
    $monthlyChart = $stmt->fetchAll();

    // ── CEO ONLY: team members for payroll display ──────────
    $payroll = [];
    if ($isCEO) {
        $stmt = $pdo->prepare("
            SELECT name, role
            FROM users
            WHERE company_id = ? AND is_active = 1
            ORDER BY FIELD(role, 'CEO', 'Manager', 'Employee'), name
        ");
        $stmt->execute([$current_company_id]);
        $payroll = $stmt->fetchAll();
    }

} catch (\PDOException $e) {
    $user         = ['name' => 'User', 'role' => $current_user_role, 'company_name' => '', 'brand' => ['primary' => '#0e6fcb', 'secondary' => '#00c8c8', 'accent' => '#ff5e3a']];
    $isCEO        = false;
    $monthSummary = ['revenue_paid' => 0, 'revenue_outstanding' => 0, 'total_invoices' => 0, 'total_invoiced' => 0];
    $statusBreakdown = [];
    $topClients   = [];
    $monthlyChart = [];
    $payroll      = [];
}
// ── HTML starts below ────────────────────────────────────────
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Financial Reports | <?= htmlspecialchars($user['company_name']) ?></title>
<link rel="icon" type="image/png" href="img/logo.png"/>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=DM+Sans:opsz,wght@9..40,400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
:root{--p:#0e6fcb;--s:#00c8c8;--a:#ff5e3a;--ink:#030c17;
  --glass:rgba(255,255,255,.055);--border:rgba(255,255,255,.09);--border2:rgba(255,255,255,.16);
  --text:rgba(255,255,255,.92);--text2:rgba(255,255,255,.52);--text3:rgba(255,255,255,.25);
  --green:#1adc8e;--yellow:#f0b429;--purple:#a855f7}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'DM Sans',sans-serif;background:var(--ink);color:var(--text);min-height:100vh;font-size:14px}
body::before{content:'';position:fixed;inset:0;pointer-events:none;
  background:radial-gradient(ellipse 70% 50% at 20% 5%,rgba(14,111,203,.18) 0%,transparent 55%),
             radial-gradient(ellipse 50% 40% at 80% 90%,rgba(0,200,200,.12) 0%,transparent 50%)}
.topbar{background:rgba(3,12,23,.82);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);
  height:56px;display:flex;align-items:center;padding:0 28px;gap:14px;position:sticky;top:0;z-index:100}
.topbar-title{font-family:'Instrument Serif',serif;font-size:18px;flex:1}
.wrap{max-width:1200px;margin:0 auto;padding:28px 22px 60px;position:relative;z-index:1}
/* Period selector */
.period-bar{display:flex;align-items:center;gap:10px;margin-bottom:24px;flex-wrap:wrap}
.period-btn{padding:7px 16px;border-radius:20px;border:1px solid var(--border);background:var(--glass);
  color:var(--text2);font-size:12.5px;font-weight:600;cursor:pointer;transition:all .18s;font-family:'DM Sans',sans-serif}
.period-btn:hover,.period-btn.active{background:rgba(14,111,203,.2);border-color:rgba(14,111,203,.35);color:#fff}
/* Cards */
.gc{background:var(--glass);backdrop-filter:blur(22px);border:1px solid var(--border);border-radius:18px;padding:20px 22px;position:relative;overflow:hidden}
.gc::before{content:'';position:absolute;inset:0;border-radius:inherit;background:linear-gradient(135deg,rgba(255,255,255,.06) 0%,transparent 55%);pointer-events:none}
.gc[data-c]::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:18px 18px 0 0;background:var(--cc,var(--p))}
.gc-t{font-size:10.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text3);margin-bottom:14px;display:flex;align-items:center;gap:8px}
.gc-t .dot{width:6px;height:6px;border-radius:50%;background:var(--cc,var(--p));flex-shrink:0;box-shadow:0 0 7px var(--cc,var(--p))}
.g4{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:13px;margin-bottom:18px}
.g2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin-bottom:18px}
.g3{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:18px}
.sv{font-family:'DM Mono',monospace;font-size:25px;font-weight:500;line-height:1;margin-bottom:4px;letter-spacing:-.02em}
.sl{font-size:11.5px;color:var(--text2);margin-bottom:6px}
.sd{font-size:11.5px;font-weight:600}
.up{color:var(--green)}.dn{color:var(--a)}.wn{color:var(--yellow)}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text3);padding:8px 12px;border-bottom:1px solid var(--border)}
.tbl td{padding:11px 12px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:rgba(255,255,255,.025)}
.mono{font-family:'DM Mono',monospace}
.prog{height:5px;background:rgba(255,255,255,.07);border-radius:20px;overflow:hidden}
.prog-f{height:100%;border-radius:20px;transition:width .9s cubic-bezier(.16,1,.3,1)}
.tag{display:inline-flex;align-items:center;padding:3px 9px;border-radius:20px;font-size:11.5px;font-weight:600}
.tg{background:rgba(26,220,142,.1);color:var(--green)}
.ty{background:rgba(240,180,41,.1);color:var(--yellow)}
.tr{background:rgba(255,94,58,.1);color:var(--a)}
.tb{background:rgba(14,111,203,.14);color:#5aabee}
.btn{display:inline-flex;align-items:center;gap:7px;padding:8px 15px;border-radius:9px;font-family:'DM Sans',sans-serif;font-size:13px;font-weight:600;cursor:pointer;border:none;transition:all .18s;white-space:nowrap}
.btn-p{background:linear-gradient(135deg,var(--p),color-mix(in srgb,var(--p) 60%,var(--s)));color:#fff;box-shadow:0 6px 18px rgba(14,111,203,.28)}
.btn-p:hover{transform:translateY(-1px)}
.btn-g{background:rgba(255,255,255,.08);border:1px solid var(--border);color:var(--text2)}
.btn-g:hover{color:var(--text)}
.btn-sm{padding:6px 12px;font-size:12px;border-radius:8px}
/* Big chart bar */
.chart-bars{display:flex;align-items:flex-end;gap:7px;height:100px;padding:0 4px}
.chart-bar-wrap{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px}
.chart-bar{width:100%;border-radius:5px 5px 0 0;min-height:4px;transition:height .8s cubic-bezier(.16,1,.3,1)}
.chart-bar-lbl{font-size:10px;color:var(--text3);font-family:'DM Mono',monospace}
.chart-bar-val{font-size:10px;color:var(--text2);font-family:'DM Mono',monospace;margin-bottom:4px}
@media(max-width:800px){.g4,.g3,.g2{grid-template-columns:1fr}}
@media print{body::before{display:none}.topbar,.period-bar .btn-g{display:none}.gc{break-inside:avoid}}
</style>
</head>
<body>
<div class="topbar">
  <a href="dashboard.php" style="color:var(--text2);font-size:13px;text-decoration:none;display:flex;align-items:center;gap:6px">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
    Dashboard
  </a>
  <div class="topbar-title">Financial Reports</div>
  <?php if($isCEO): ?><span style="background:rgba(240,180,41,.15);color:var(--yellow);font-size:10px;font-weight:700;padding:3px 10px;border-radius:20px">CEO Full Access</span><?php endif;?>
  <button class="btn btn-g btn-sm" onclick="window.print()">🖨 Print</button>
  <button class="btn btn-p btn-sm">Export PDF</button>
</div>

<div class="wrap">

  <!-- Period selector -->
  <div class="period-bar">
    <span style="font-size:13px;color:var(--text2);font-weight:500">Period:</span>
    <button class="period-btn" onclick="setPeriod(this,'Jan 2025')">Jan</button>
    <button class="period-btn" onclick="setPeriod(this,'Feb 2025')">Feb</button>
    <button class="period-btn" onclick="setPeriod(this,'Mar 2025')">Mar</button>
    <button class="period-btn" onclick="setPeriod(this,'Apr 2025')">Apr</button>
    <button class="period-btn" onclick="setPeriod(this,'May 2025')">May</button>
    <button class="period-btn active" onclick="setPeriod(this,'Jun 2025')">Jun</button>
    <button class="period-btn" onclick="setPeriod(this,'Q2 2025')">Q2 2025</button>
    <button class="period-btn" onclick="setPeriod(this,'YTD 2025')">YTD 2025</button>
    <button class="btn btn-g btn-sm" style="margin-left:auto">Export CSV</button>
  </div>

  <!-- KPI strip -->
  <div class="g4">
    <div class="gc" data-c style="--cc:#0e6fcb"><div class="gc-t"><span class="dot"></span>Gross Revenue</div><div class="sv" id="r-gross">R 84,320</div><div class="sl" id="r-period">June 2025</div><div class="sd up" id="r-delta">↑ 12% vs May</div></div>
    <div class="gc" data-c style="--cc:var(--a)"><div class="gc-t"><span class="dot"></span>Total Expenses</div><div class="sv" id="r-exp">R 56,400</div><div class="sl">67% of revenue</div></div>
    <div class="gc" data-c style="--cc:var(--green)"><div class="gc-t"><span class="dot"></span>Net Profit</div><div class="sv" id="r-profit">R 27,920</div><div class="sd up">33.1% margin</div></div>
    <div class="gc" data-c style="--cc:var(--yellow)"><div class="gc-t"><span class="dot"></span>Collection Rate</div><div class="sv">82%</div><div class="sd up">↑ 4% vs May</div></div>
    <div class="gc" data-c style="--cc:var(--s)"><div class="gc-t"><span class="dot"></span>Invoices Issued</div><div class="sv">47</div><div class="sl">This period</div></div>
    <div class="gc" data-c style="--cc:var(--purple)"><div class="gc-t"><span class="dot"></span>Avg Invoice</div><div class="sv">R 3,156</div><div class="sl">Per invoice</div></div>
    <div class="gc" data-c style="--cc:var(--yellow)"><div class="gc-t"><span class="dot"></span>Outstanding</div><div class="sv">R 21,450</div><div class="sd wn">3 overdue</div></div>
    <div class="gc" data-c style="--cc:var(--green)"><div class="gc-t"><span class="dot"></span>New Clients</div><div class="sv">2</div><div class="sl">This month</div></div>
  </div>

  <!-- Revenue bar chart + income statement -->
  <div class="g2">
    <div class="gc" data-c style="--cc:var(--s)">
      <div class="gc-t"><span class="dot"></span>Monthly Revenue — 2025</div>
      <div class="chart-bars" id="rev-chart">
        <!-- Rendered by JS -->
      </div>
    </div>
    <div class="gc" data-c style="--cc:var(--green)">
      <div class="gc-t"><span class="dot"></span>Income Statement — <span id="stmt-period">June 2025</span></div>
      <table class="tbl">
        <tbody>
          <tr><td style="color:var(--text2)">Service Revenue</td><td class="mono" style="text-align:right">R 64,000</td></tr>
          <tr><td style="color:var(--text2)">Product Revenue</td><td class="mono" style="text-align:right">R 20,320</td></tr>
          <tr><td style="font-weight:700;border-top:1px solid var(--border)">Gross Revenue</td><td class="mono" style="font-weight:700;text-align:right;border-top:1px solid var(--border)">R 84,320</td></tr>
          <tr><td style="color:var(--text2);padding-top:12px">Salaries</td><td class="mono" style="text-align:right">R 32,000</td></tr>
          <tr><td style="color:var(--text2)">Rent &amp; Utilities</td><td class="mono" style="text-align:right">R 8,400</td></tr>
          <tr><td style="color:var(--text2)">Stock Purchases</td><td class="mono" style="text-align:right">R 12,200</td></tr>
          <tr><td style="color:var(--text2)">Marketing</td><td class="mono" style="text-align:right">R 3,800</td></tr>
          <tr><td style="font-weight:700;border-top:1px solid var(--border)">Total Expenses</td><td class="mono" style="font-weight:700;text-align:right;border-top:1px solid var(--border)">R 56,400</td></tr>
          <tr><td style="font-weight:800;font-size:15px;color:var(--green);border-top:2px solid rgba(26,220,142,.3);padding-top:10px">Net Profit</td><td class="mono" style="font-weight:800;font-size:15px;color:var(--green);text-align:right;border-top:2px solid rgba(26,220,142,.3);padding-top:10px">R 27,920</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Revenue breakdown + expense breakdown -->
  <div class="g2">
    <div class="gc" data-c style="--cc:var(--p)">
      <div class="gc-t"><span class="dot"></span>Revenue by Category</div>
      <div style="display:flex;flex-direction:column;gap:13px">
        <div><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span>Consulting / Services</span><span class="mono" style="color:var(--p)">R 64,000</span></div><div class="prog"><div class="prog-f" style="width:76%;background:var(--p)"></div></div></div>
        <div><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span>Hardware Products</span><span class="mono" style="color:var(--a)">R 14,000</span></div><div class="prog"><div class="prog-f" style="width:17%;background:var(--a)"></div></div></div>
        <div><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span>Software Licenses</span><span class="mono" style="color:var(--green)">R 6,320</span></div><div class="prog"><div class="prog-f" style="width:7%;background:var(--green)"></div></div></div>
      </div>
      <div style="border-top:1px solid var(--border);margin-top:18px;padding-top:14px">
        <div style="font-family:'Instrument Serif',serif;font-size:28px">33.1%</div>
        <div style="font-size:12.5px;color:var(--text2);margin-top:2px">Profit margin — strong performance</div>
      </div>
    </div>
    <div class="gc" data-c style="--cc:var(--a)">
      <div class="gc-t"><span class="dot"></span>Expense Breakdown</div>
      <div style="display:flex;flex-direction:column;gap:13px">
        <div><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span>Salaries &amp; Staff</span><span class="mono">R 32,000 (57%)</span></div><div class="prog"><div class="prog-f" style="width:57%;background:#a855f7"></div></div></div>
        <div><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span>Stock Purchases</span><span class="mono">R 12,200 (22%)</span></div><div class="prog"><div class="prog-f" style="width:22%;background:var(--p)"></div></div></div>
        <div><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span>Rent &amp; Utilities</span><span class="mono">R 8,400 (15%)</span></div><div class="prog"><div class="prog-f" style="width:15%;background:var(--yellow)"></div></div></div>
        <div><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span>Marketing</span><span class="mono">R 3,800 (7%)</span></div><div class="prog"><div class="prog-f" style="width:7%;background:var(--s)"></div></div></div>
      </div>
    </div>
  </div>

  <!-- Top clients + invoice status -->
  <div class="g2">
    <div class="gc" data-c style="--cc:var(--yellow)">
      <div class="gc-t"><span class="dot"></span>Top Clients by Revenue</div>
      <table class="tbl">
        <thead><tr><th>Client</th><th>Invoiced</th><th>Paid</th><th>Status</th></tr></thead>
        <tbody>
          <tr><td>Nova Retail</td><td class="mono">R 12,500</td><td class="mono">R 0</td><td><span class="tag ty">Pending</span></td></tr>
          <tr><td>Orion Builders</td><td class="mono">R 18,000</td><td class="mono">R 0</td><td><span class="tag tb">Draft</span></td></tr>
          <tr><td>Tando Enterprises</td><td class="mono">R 7,200</td><td class="mono">R 7,200</td><td><span class="tag tg">Paid</span></td></tr>
          <tr><td>Apex Logistics</td><td class="mono">R 4,800</td><td class="mono">R 4,800</td><td><span class="tag tg">Paid</span></td></tr>
          <tr><td>Summit Trading</td><td class="mono">R 3,400</td><td class="mono">R 3,400</td><td><span class="tag tg">Paid</span></td></tr>
          <tr><td>BlueSky Media</td><td class="mono">R 2,900</td><td class="mono">R 0</td><td><span class="tag tr">Overdue</span></td></tr>
        </tbody>
      </table>
    </div>
    <div class="gc" data-c style="--cc:var(--green)">
      <div class="gc-t"><span class="dot"></span>Invoice Status Summary</div>
      <div style="display:flex;flex-direction:column;gap:14px;margin-top:4px">
        <div><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span style="color:var(--green)">✓ Paid (2)</span><span class="mono">R 15,400</span></div><div class="prog"><div class="prog-f" style="width:31%;background:var(--green)"></div></div></div>
        <div><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span style="color:var(--yellow)">⏳ Pending (2)</span><span class="mono">R 30,500</span></div><div class="prog"><div class="prog-f" style="width:62%;background:var(--yellow)"></div></div></div>
        <div><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span style="color:var(--a)">⚠ Overdue (1)</span><span class="mono">R 2,900</span></div><div class="prog"><div class="prog-f" style="width:6%;background:var(--a)"></div></div></div>
        <div><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span style="color:var(--text2)">📄 Draft (1)</span><span class="mono">R 18,000</span></div><div class="prog"><div class="prog-f" style="width:37%;background:rgba(255,255,255,.2)"></div></div></div>
      </div>
      <div style="border-top:1px solid var(--border);margin-top:16px;padding-top:14px;display:flex;justify-content:space-between">
        <div><div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.07em;margin-bottom:3px">Total Invoiced</div><div class="mono" style="font-size:16px;font-weight:500">R 66,800</div></div>
        <div style="text-align:right"><div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.07em;margin-bottom:3px">Collected</div><div class="mono" style="font-size:16px;font-weight:500;color:var(--green)">R 15,400</div></div>
      </div>
    </div>
  </div>

  <?php if($isCEO): ?>
  <!-- CEO-only: Payroll breakdown -->
  <div class="gc mb20" data-c style="--cc:var(--purple);margin-bottom:18px">
    <div class="gc-t"><span class="dot" style="background:var(--purple);box-shadow:0 0 7px var(--purple)"></span>CEO View — Payroll Breakdown (Confidential)</div>
    <table class="tbl">
      <thead><tr><th>Employee</th><th>Role</th><th>Gross Salary</th><th>UIF</th><th>Net Pay</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td>Sello Nkosi</td><td>CEO</td><td class="mono">R 55,000</td><td class="mono">R 148.72</td><td class="mono">R 38,851</td><td><span class="tag tg">Paid</span></td></tr>
        <tr><td>Thabo Molefe</td><td>Manager</td><td class="mono">R 32,000</td><td class="mono">R 148.72</td><td class="mono">R 22,051</td><td><span class="tag tg">Paid</span></td></tr>
        <tr><td>Lerato Dube</td><td>Employee</td><td class="mono">R 18,000</td><td class="mono">R 148.72</td><td class="mono">R 14,351</td><td><span class="tag tg">Paid</span></td></tr>
        <tr><td>Naledi Sithole</td><td>Employee</td><td class="mono">R 15,000</td><td class="mono">R 148.72</td><td class="mono">R 11,851</td><td><span class="tag tg">Paid</span></td></tr>
        <tr style="border-top:2px solid var(--border)"><td style="font-weight:700">TOTAL</td><td></td><td class="mono" style="font-weight:700">R 120,000</td><td class="mono" style="font-weight:700">R 594.88</td><td class="mono" style="font-weight:700">R 87,104</td><td></td></tr>
      </tbody>
    </table>
  </div>
  <?php endif; ?>

</div><!-- /wrap -->

<script>
/* ── Period switcher ── */
// Dynamically built from PHP — real DB values for current month
const periodData = {
  <?php
  $months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  foreach ($monthlyChart as $m) {
      $gross  = number_format((float)$m['paid_revenue'], 2, '.', '');
      $label  = $m['month_label'] . ' ' . date('Y');
      echo "'{$label}': {gross:'R " . number_format((float)$m['paid_revenue'], 0, '.', ',') . "', exp:'—', profit:'—', delta:'Live data'},\n";
  }
  ?>
};
function setPeriod(btn, period){
  document.querySelectorAll('.period-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  const d = periodData[period] || periodData['Jun 2025'];
  document.getElementById('r-gross').textContent  = d.gross;
  document.getElementById('r-exp').textContent    = d.exp;
  document.getElementById('r-profit').textContent = d.profit;
  document.getElementById('r-delta').textContent  = d.delta;
  document.getElementById('r-period').textContent = period;
  document.getElementById('stmt-period').textContent = period;
}

/* ── Revenue bar chart ── */
const months = [
  {m:'Jan',v:58200,color:'rgba(14,111,203,.4)'},
  {m:'Feb',v:62400,color:'rgba(14,111,203,.5)'},
  {m:'Mar',v:67100,color:'rgba(14,111,203,.55)'},
  {m:'Apr',v:71800,color:'rgba(14,111,203,.6)'},
  {m:'May',v:75000,color:'rgba(14,111,203,.7)'},
  {m:'Jun',v:84320,color:'var(--p)'},
];
const maxV = Math.max(...months.map(m=>m.v));
const chart = document.getElementById('rev-chart');
chart.innerHTML = months.map(m=>{
  const h = Math.round((m.v/maxV)*100);
  const fmtK = v => 'R '+(v/1000).toFixed(0)+'K';
  return `<div class="chart-bar-wrap">
    <div class="chart-bar-val">${fmtK(m.v)}</div>
    <div class="chart-bar" style="height:${h}%;background:${m.color}"></div>
    <div class="chart-bar-lbl">${m.m}</div>
  </div>`;
}).join('');
</script>
</body>
</html>