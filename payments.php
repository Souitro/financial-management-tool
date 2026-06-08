<?php
// ============================================================
// dashboard.php — Souitro Business Suite
// Full authenticated dashboard with live DB data
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

// Session hijack protection
if (
    isset($_SESSION['user_ip'], $_SESSION['user_ua']) &&
    (
        $_SESSION['user_ip'] !== $_SERVER['REMOTE_ADDR'] ||
        $_SESSION['user_ua'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')
    )
) {
    session_unset(); session_destroy();
    header('Location: login.php?err=security');
    exit;
}

// Idle timeout — 2 hours
if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > 7200) {
    session_unset(); session_destroy();
    header('Location: login.php?err=timeout');
    exit;
}

$current_user_id    = (int)$_SESSION['user_id'];
$current_company_id = (int)$_SESSION['company_id'];
$current_user_role  = $_SESSION['user_role'] ?? 'Employee';

// ── PDO Connection ──────────────────────────────────────────
$host    = '127.0.0.1';
$dbname  = 'souitro_db';
$dbuser  = 'root';
$dbpass  = '';
$charset = 'utf8mb4';

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$dbname;charset=$charset",
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

// ── Fetch open invoices for the payment modal ────────────────
$open_invoices = [];
try {
    $stmt = $pdo->prepare("
        SELECT i.id, i.invoice_number, i.total_amount, cl.name AS client_name
        FROM invoices i
        JOIN clients cl ON cl.id = i.client_id
        WHERE i.company_id = ? AND i.status IN ('sent','overdue')
        ORDER BY i.issue_date DESC
    ");
    $stmt->execute([$current_company_id]);
    $open_invoices = $stmt->fetchAll();
} catch(\PDOException $e) {}

// ── Handle Record Payment ────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'add_payment') {
    $invoice_id   = (int)($_POST['invoice_id']   ?? 0);
    $amount       = (float)($_POST['amount']     ?? 0);
    $payment_date = trim($_POST['payment_date']  ?? '');
    $method       = trim($_POST['method']        ?? 'EFT');
    $reference    = trim($_POST['reference']     ?? '');
    $notes        = trim($_POST['notes']         ?? '');

    if ($invoice_id > 0 && $amount > 0 && !empty($payment_date)) {
        try {
            $pdo->beginTransaction();

            // Verify invoice belongs to this company
            $stmt = $pdo->prepare("SELECT id, total_amount FROM invoices WHERE id=? AND company_id=? LIMIT 1");
            $stmt->execute([$invoice_id, $current_company_id]);
            $inv = $stmt->fetch();

            if ($inv) {
                // Insert payment
                $pdo->prepare("
                    INSERT INTO payments (company_id, invoice_id, recorded_by, amount, payment_date, method, reference, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ")->execute([
                    $current_company_id,
                    $invoice_id,
                    $current_user_id,
                    $amount,
                    $payment_date,
                    $method,
                    $reference ?: null,
                    $notes     ?: null,
                ]);

                // Check total payments against invoice total
                $stmt = $pdo->prepare("SELECT IFNULL(SUM(amount),0) FROM payments WHERE invoice_id=?");
                $stmt->execute([$invoice_id]);
                $total_paid = (float)$stmt->fetchColumn();

                // Mark invoice paid if fully covered
                $new_status = $total_paid >= (float)$inv['total_amount'] ? 'paid' : 'sent';
                $pdo->prepare("UPDATE invoices SET status=? WHERE id=?")->execute([$new_status, $invoice_id]);

                // Audit
                $pdo->prepare("
                    INSERT INTO audit_log (user_id, company_id, action, target, ip_address, user_agent)
                    VALUES (?, ?, 'PAYMENT_RECORDED', ?, ?, ?)
                ")->execute([
                    $current_user_id,
                    $current_company_id,
                    'invoices:' . $invoice_id,
                    $_SERVER['REMOTE_ADDR'],
                    $_SERVER['HTTP_USER_AGENT'] ?? '',
                ]);
            }

            $pdo->commit();
        } catch(\PDOException $e) {
            $pdo->rollBack();
        }
    }
    header('Location: payments.php');
    exit;
}

// ── Fetch all data ──────────────────────────────────────────
try {
    // User + company in one JOIN
    $stmt = $pdo->prepare("
        SELECT u.id, u.name, u.email, u.role, u.avatar_url, u.last_login,
               c.company_name, c.logo_url,
               c.primary_color, c.secondary_color, c.accent_color
        FROM users u
        JOIN companies c ON c.id = u.company_id
        WHERE u.id = ? AND u.company_id = ? AND u.is_active = 1
        LIMIT 1
    ");
    $stmt->execute([$current_user_id, $current_company_id]);
    $row = $stmt->fetch();
    if (!$row) { session_unset(); session_destroy(); header('Location: login.php?err=inactive'); exit; }

    $user = [
        'id'           => $row['id'],
        'name'         => $row['name'],
        'email'        => $row['email'],
        'role'         => $row['role'],
        'last_login'   => $row['last_login'],
        'company_name' => $row['company_name'],
        'brand'        => [
            'primary'   => $row['primary_color'],
            'secondary' => $row['secondary_color'],
            'accent'    => $row['accent_color'],
        ],
    ];
    $nameParts = array_filter(explode(' ', $user['name']));
    $initials  = strtoupper(substr(implode('', array_map(fn($w) => $w[0], $nameParts)), 0, 2));
    $isCEO     = ($user['role'] === 'CEO');
    $isManager = in_array($user['role'], ['CEO', 'Manager']);

    // KPI 1 — Current month paid revenue
    $stmt = $pdo->prepare("
        SELECT IFNULL(SUM(total_amount),0) AS v
        FROM invoices
        WHERE company_id=? AND status='paid'
          AND MONTH(issue_date)=MONTH(CURDATE()) AND YEAR(issue_date)=YEAR(CURDATE())
    ");
    $stmt->execute([$current_company_id]);
    $monthly_revenue = (float)$stmt->fetchColumn();

    // KPI 2 — Previous month paid revenue (for delta %)
    $stmt = $pdo->prepare("
        SELECT IFNULL(SUM(total_amount),0) AS v
        FROM invoices
        WHERE company_id=? AND status='paid'
          AND MONTH(issue_date)=MONTH(CURDATE()-INTERVAL 1 MONTH)
          AND YEAR(issue_date)=YEAR(CURDATE()-INTERVAL 1 MONTH)
    ");
    $stmt->execute([$current_company_id]);
    $prev_month_revenue = (float)$stmt->fetchColumn();
    $revenue_delta = $prev_month_revenue > 0
        ? round((($monthly_revenue - $prev_month_revenue) / $prev_month_revenue) * 100, 1)
        : 0;

    // KPI 3 — Outstanding receivables
    $stmt = $pdo->prepare("
        SELECT IFNULL(SUM(total_amount),0) AS v
        FROM invoices WHERE company_id=? AND status IN ('sent','overdue')
    ");
    $stmt->execute([$current_company_id]);
    $outstanding_debt = (float)$stmt->fetchColumn();

    // KPI 4 — Overdue count
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM invoices WHERE company_id=? AND status='overdue'");
    $stmt->execute([$current_company_id]);
    $overdue_count = (int)$stmt->fetchColumn();

    // KPI 5 — Low stock warnings
    $stmt = $pdo->prepare("
        SELECT COUNT(*) FROM inventory
        WHERE company_id=? AND quantity_on_hand <= reorder_level AND is_active=1
    ");
    $stmt->execute([$current_company_id]);
    $low_stock_warnings = (int)$stmt->fetchColumn();

    // KPI 6 — Active clients
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM clients WHERE company_id=? AND is_active=1");
    $stmt->execute([$current_company_id]);
    $total_clients = (int)$stmt->fetchColumn();

    // KPI 7 — Total invoices this month
    $stmt = $pdo->prepare("
        SELECT COUNT(*) FROM invoices
        WHERE company_id=?
          AND MONTH(issue_date)=MONTH(CURDATE()) AND YEAR(issue_date)=YEAR(CURDATE())
    ");
    $stmt->execute([$current_company_id]);
    $monthly_invoice_count = (int)$stmt->fetchColumn();

    // Recent invoices (last 6)
    $stmt = $pdo->prepare("
        SELECT i.invoice_number, i.total_amount, i.status, i.issue_date, i.due_date,
               cl.name AS client_name
        FROM invoices i
        JOIN clients cl ON cl.id = i.client_id
        WHERE i.company_id=?
        ORDER BY i.created_at DESC LIMIT 6
    ");
    $stmt->execute([$current_company_id]);
    $recent_invoices = $stmt->fetchAll();

    // Recent payments (last 5)
    $stmt = $pdo->prepare("
        SELECT p.amount, p.payment_date, p.method, p.reference,
               cl.name AS client_name, i.invoice_number
        FROM payments p
        JOIN invoices i ON i.id = p.invoice_id
        JOIN clients cl ON cl.id = i.client_id
        WHERE p.company_id=?
        ORDER BY p.payment_date DESC
    ");
    $stmt->execute([$current_company_id]);
    $recent_payments = $stmt->fetchAll();

    // Low stock items
    $stmt = $pdo->prepare("
        SELECT name, sku, quantity_on_hand, reorder_level, category
        FROM inventory
        WHERE company_id=? AND quantity_on_hand <= reorder_level AND is_active=1
        ORDER BY quantity_on_hand ASC LIMIT 5
    ");
    $stmt->execute([$current_company_id]);
    $low_stock_items = $stmt->fetchAll();

    // Top 5 clients by revenue
    $stmt = $pdo->prepare("
        SELECT cl.name,
               IFNULL(SUM(i.total_amount),0) AS total,
               IFNULL(SUM(CASE WHEN i.status='paid' THEN i.total_amount END),0) AS paid
        FROM clients cl
        LEFT JOIN invoices i ON i.client_id=cl.id AND i.company_id=?
        WHERE cl.company_id=? AND cl.is_active=1
        GROUP BY cl.id, cl.name
        ORDER BY total DESC LIMIT 5
    ");
    $stmt->execute([$current_company_id, $current_company_id]);
    $top_clients = $stmt->fetchAll();

    // Monthly revenue chart — last 6 months
    $stmt = $pdo->prepare("
        SELECT DATE_FORMAT(issue_date,'%b') AS mo,
               DATE_FORMAT(issue_date,'%Y-%m') AS mo_key,
               IFNULL(SUM(CASE WHEN status='paid' THEN total_amount END),0) AS revenue
        FROM invoices
        WHERE company_id=? AND issue_date >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
        GROUP BY mo_key, mo ORDER BY mo_key ASC LIMIT 6
    ");
    $stmt->execute([$current_company_id]);
    $chart_data = $stmt->fetchAll();

    // Invoice status breakdown
    $stmt = $pdo->prepare("
        SELECT status, COUNT(*) AS cnt, IFNULL(SUM(total_amount),0) AS total
        FROM invoices WHERE company_id=? GROUP BY status
    ");
    $stmt->execute([$current_company_id]);
    $inv_status = [];
    foreach ($stmt->fetchAll() as $r) $inv_status[$r['status']] = $r;

    // Audit log (last 6)
    $stmt = $pdo->prepare("
        SELECT action, target, ip_address, created_at
        FROM audit_log WHERE company_id=?
        ORDER BY created_at DESC LIMIT 6
    ");
    $stmt->execute([$current_company_id]);
    $recent_logs = $stmt->fetchAll();

    // Personal finance — latest month for this user
    $stmt = $pdo->prepare("
        SELECT net_salary, total_expenses, total_savings,
               financial_health_score, month_year, expense_breakdown, recommendations
        FROM personal_finance WHERE user_id=?
        ORDER BY month_year DESC LIMIT 1
    ");
    $stmt->execute([$current_user_id]);
    $pf = $stmt->fetch() ?: null;

    // All inventory for table
    $stmt = $pdo->prepare("
        SELECT name, sku, category, unit_price, quantity_on_hand, reorder_level, is_active
        FROM inventory WHERE company_id=? ORDER BY name ASC LIMIT 20
    ");
    $stmt->execute([$current_company_id]);
    $inventory_items = $stmt->fetchAll();

    // All clients for table
    $stmt = $pdo->prepare("
        SELECT cl.name, cl.email, cl.phone,
               COUNT(i.id) AS invoice_count,
               IFNULL(SUM(i.total_amount),0) AS lifetime_value
        FROM clients cl
        LEFT JOIN invoices i ON i.client_id=cl.id AND i.company_id=?
        WHERE cl.company_id=? AND cl.is_active=1
        GROUP BY cl.id, cl.name, cl.email, cl.phone
        ORDER BY lifetime_value DESC
    ");
    $stmt->execute([$current_company_id, $current_company_id]);
    $clients_list = $stmt->fetchAll();

    // Update session heartbeat
    try {
        $pdo->prepare("UPDATE user_sessions SET last_active=NOW() WHERE id=?")->execute([session_id()]);
    } catch(\PDOException $e) {}

} catch (\PDOException $e) {
    // Safe fallbacks
    $user               = ['id'=>$current_user_id,'name'=>'User','email'=>'','role'=>$current_user_role,'last_login'=>null,'company_name'=>'Souitro','brand'=>['primary'=>'#0e6fcb','secondary'=>'#00c8c8','accent'=>'#ff5e3a']];
    $initials           = 'U';
    $isCEO              = false;
    $isManager          = false;
    $monthly_revenue    = 0; $prev_month_revenue = 0; $revenue_delta = 0;
    $outstanding_debt   = 0; $overdue_count = 0;
    $low_stock_warnings = 0; $total_clients = 0; $monthly_invoice_count = 0;
    $recent_invoices    = []; $recent_payments = []; $low_stock_items = [];
    $top_clients        = []; $chart_data = []; $inv_status = [];
    $recent_logs        = []; $pf = null;
    $inventory_items    = []; $clients_list = [];
}

// ── Helpers ─────────────────────────────────────────────────
function fmtR(float $v): string {
    return 'R ' . number_format($v, 2, '.', ',');
}
function fmtRK(float $v): string {
    return $v >= 1000 ? 'R ' . number_format($v/1000,1).'K' : fmtR($v);
}
function statusTag(string $s): string {
    $map = [
        'paid'      => ['tg','Paid'],
        'sent'      => ['ty','Sent'],
        'overdue'   => ['tr','Overdue'],
        'draft'     => ['tb','Draft'],
        'cancelled' => ['tp','Cancelled'],
    ];
    [$cls,$lbl] = $map[$s] ?? ['tb',$s];
    return "<span class='tag $cls'>$lbl</span>";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Payments | <?= htmlspecialchars($user['company_name']) ?></title>
<link rel="icon" type="image/png" href="img/logo.png"/>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=DM+Sans:opsz,wght@9..40,300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
:root{
  --p:<?= htmlspecialchars($user['brand']['primary']) ?>;
  --s:<?= htmlspecialchars($user['brand']['secondary']) ?>;
  --a:<?= htmlspecialchars($user['brand']['accent']) ?>;
  --ink:#030c17;--ink2:#061320;--ink3:#0a1e30;
  --glass:rgba(255,255,255,.055);--glass2:rgba(255,255,255,.09);--glass3:rgba(255,255,255,.13);
  --border:rgba(255,255,255,.08);--border2:rgba(255,255,255,.15);
  --text:rgba(255,255,255,.92);--text2:rgba(255,255,255,.52);--text3:rgba(255,255,255,.25);
  --green:#1adc8e;--yellow:#f0b429;--purple:#a855f7;
  --sidebar:246px;--header:60px;--r:18px;--rb:12px;
  --ease:cubic-bezier(0.16,1,0.3,1);--spring:cubic-bezier(0.34,1.56,0.64,1);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden;-webkit-font-smoothing:antialiased}
body{font-family:'DM Sans',sans-serif;background:var(--ink);color:var(--text);font-size:14px;cursor:none}
#cur,#cur-r{position:fixed;border-radius:50%;pointer-events:none;z-index:9999;transform:translate(-50%,-50%);will-change:left,top}
#cur{width:10px;height:10px;background:var(--s);transition:width .15s,height .15s,background .2s;mix-blend-mode:screen}
#cur-r{width:34px;height:34px;border:1.5px solid rgba(0,200,200,.35);transition:left .09s ease-out,top .09s ease-out,width .2s,height .2s}
body.hov #cur{width:18px;height:18px;background:var(--a)}
body.hov #cur-r{width:46px;height:46px;border-color:rgba(255,94,58,.45)}
.rpl{position:fixed;border-radius:50%;background:rgba(0,200,200,.12);pointer-events:none;z-index:9990;transform:translate(-50%,-50%) scale(0);animation:rplOut .65s ease-out forwards}
@keyframes rplOut{to{transform:translate(-50%,-50%) scale(1);opacity:0}}
#bg{position:fixed;inset:0;z-index:0;background:radial-gradient(ellipse 70% 50% at 15% 5%,rgba(14,111,203,.2) 0%,transparent 55%),radial-gradient(ellipse 50% 40% at 85% 90%,rgba(0,200,200,.13) 0%,transparent 50%),radial-gradient(ellipse 40% 35% at 60% 40%,rgba(255,94,58,.07) 0%,transparent 50%),var(--ink)}
.blob{position:fixed;border-radius:50%;filter:blur(88px);pointer-events:none;z-index:2;will-change:transform}
#bl1{width:650px;height:650px;top:-180px;left:-160px;background:radial-gradient(circle,rgba(14,111,203,.28) 0%,transparent 65%);animation:bfl 18s ease-in-out infinite alternate}
#bl2{width:480px;height:480px;bottom:-100px;right:-80px;background:radial-gradient(circle,rgba(0,200,200,.2) 0%,transparent 65%);animation:bfl 14s ease-in-out infinite alternate-reverse;animation-delay:-6s}
#bl3{width:340px;height:340px;top:35%;left:52%;background:radial-gradient(circle,rgba(255,94,58,.13) 0%,transparent 65%);animation:bfl 11s ease-in-out infinite alternate;animation-delay:-9s}
@keyframes bfl{from{transform:translate(0,0) scale(1)}to{transform:translate(35px,-45px) scale(1.1)}}
#grid-ov{position:fixed;inset:0;z-index:3;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);background-size:64px 64px;mask-image:radial-gradient(ellipse 90% 90% at 50% 50%,black 20%,transparent 100%);-webkit-mask-image:radial-gradient(ellipse 90% 90% at 50% 50%,black 20%,transparent 100%)}
#shell{position:relative;z-index:4;display:grid;grid-template-columns:var(--sidebar) 1fr;grid-template-rows:var(--header) 1fr;height:100vh}
#sidebar{grid-row:1/-1;background:rgba(3,12,23,.78);backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;position:relative}
#sidebar::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--s),transparent);opacity:.4}
#sidebar::after{content:'';position:absolute;top:0;right:0;bottom:0;width:1px;background:linear-gradient(180deg,transparent 0%,var(--s) 50%,transparent 100%);opacity:.25}
.sb-logo{padding:18px 20px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border);flex-shrink:0}
.sb-logo-icon{width:38px;height:38px;border-radius:11px;flex-shrink:0;background:linear-gradient(135deg,var(--p),var(--s));display:flex;align-items:center;justify-content:center;font-family:'Instrument Serif',serif;font-size:19px;color:#fff;box-shadow:0 6px 24px rgba(14,111,203,.38)}
.sb-logo-text .co{font-family:'Instrument Serif',serif;font-size:14px;line-height:1.2;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:162px}
.sb-logo-text .stag{font-size:9.5px;color:var(--text3);letter-spacing:.07em;text-transform:uppercase;margin-top:2px}
.sb-nav{flex:1;overflow-y:auto;overflow-x:hidden;padding:12px 0;scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.07) transparent}
.sb-lbl{font-size:9.5px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--text3);padding:12px 20px 4px}
.sb-item{display:flex;align-items:center;gap:11px;padding:9px 18px;margin:1px 10px;border-radius:10px;color:var(--text2);font-size:13px;font-weight:500;cursor:pointer;transition:all .17s;border:1px solid transparent;position:relative;user-select:none;white-space:nowrap}
.sb-item svg{flex-shrink:0;opacity:.65;transition:opacity .15s;width:15px;height:15px}
.sb-item .sb-bdg{margin-left:auto;font-size:10px;font-weight:700;padding:2px 7px;border-radius:20px;background:rgba(255,94,58,.2);color:var(--a);flex-shrink:0}
.sb-item:hover{background:var(--glass2);color:var(--text);border-color:var(--border)}
.sb-item:hover svg{opacity:1}
.sb-item.active{background:rgba(14,111,203,.18);border-color:rgba(14,111,203,.28);color:#fff}
.sb-item.active svg{opacity:1}
.sb-item.active::before{content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;border-radius:0 3px 3px 0;background:var(--p)}
.sb-item.locked{opacity:.3;cursor:not-allowed;pointer-events:none}
.sb-item.prs{color:rgba(0,200,200,.7)}
.sb-item.prs:hover{background:rgba(0,200,200,.08);border-color:rgba(0,200,200,.18);color:var(--s)}
.sb-item.prs.active{background:rgba(0,200,200,.14);border-color:rgba(0,200,200,.28);color:var(--s)}
.sb-item.prs.active::before{background:var(--s)}
.sb-footer{border-top:1px solid var(--border);padding:12px 14px;flex-shrink:0}
.sb-user{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:10px;cursor:pointer;transition:background .17s}
.sb-user:hover{background:var(--glass2)}
.sb-av{width:32px;height:32px;border-radius:50%;flex-shrink:0;background:linear-gradient(135deg,var(--p),var(--a));display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;border:1.5px solid var(--border2)}
.sb-un{font-size:12.5px;font-weight:600;color:var(--text)}
.sb-ur{font-size:10px;color:var(--text3);margin-top:1px}
#topbar{background:rgba(3,12,23,.72);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 22px;gap:12px;z-index:10}
.tb-title{font-family:'Instrument Serif',serif;font-size:18px;font-weight:400;letter-spacing:-.01em;flex:1;color:var(--text)}
.tb-search{display:flex;align-items:center;gap:8px;background:var(--glass);border:1px solid var(--border);border-radius:10px;padding:7px 13px;font-size:13px;color:var(--text2);transition:all .2s;cursor:text}
.tb-search:hover{background:var(--glass2);border-color:var(--border2)}
.tb-search svg{opacity:.5;flex-shrink:0;width:14px;height:14px}
.tb-search kbd{font-family:'DM Mono',monospace;font-size:10px;background:rgba(255,255,255,.08);border:1px solid var(--border);border-radius:5px;padding:1px 5px;color:var(--text3);margin-left:6px}
#gs{background:none;border:none;outline:none;font-family:'DM Sans',sans-serif;font-size:13px;color:var(--text);width:130px}
.tb-btn{width:36px;height:36px;border-radius:10px;background:var(--glass);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all .17s;position:relative;color:var(--text2);flex-shrink:0}
.tb-btn:hover{background:var(--glass2);border-color:var(--border2);color:var(--text)}
.tb-btn svg{width:15px;height:15px}
.ndot{position:absolute;top:7px;right:7px;width:7px;height:7px;border-radius:50%;background:var(--a);border:1.5px solid var(--ink);animation:pd 2s ease-in-out infinite}
@keyframes pd{0%,100%{opacity:1}50%{opacity:.4}}
.tb-av{width:36px;height:36px;border-radius:50%;flex-shrink:0;background:linear-gradient(135deg,var(--p),var(--a));display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;border:2px solid var(--border2);cursor:pointer}
.rc{font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:4px 10px;border-radius:20px;flex-shrink:0}
.rc-CEO{background:rgba(240,180,41,.15);color:var(--yellow)}
.rc-Manager{background:rgba(0,200,200,.13);color:var(--s)}
.rc-Employee{background:rgba(14,111,203,.15);color:#5aabee}
#main{overflow-y:auto;overflow-x:hidden;padding:24px 26px 44px;scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.07) transparent}
.panel{display:none}
.panel.active{display:block;animation:panIn .42s var(--ease) forwards}
@keyframes panIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
.pg-hero{margin-bottom:22px}
.pg-hero h1{font-family:'Instrument Serif',serif;font-size:clamp(20px,2.4vw,28px);font-weight:400;letter-spacing:-.02em;margin-bottom:3px}
.pg-hero h1 em{font-style:italic;color:var(--s)}
.pg-hero p{font-size:13.5px;color:var(--text2);line-height:1.6}
.gc{background:var(--glass);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border:1px solid var(--border);border-radius:var(--r);padding:20px 22px;position:relative;overflow:hidden;will-change:transform;transition:box-shadow .3s,border-color .3s}
.gc::before{content:'';position:absolute;inset:0;border-radius:inherit;background:linear-gradient(135deg,rgba(255,255,255,.065) 0%,transparent 55%,rgba(255,255,255,.02) 100%);pointer-events:none}
.gc[data-c]::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:var(--r) var(--r) 0 0;background:var(--cc,var(--p))}
.gc:hover{border-color:rgba(255,255,255,.15);box-shadow:0 28px 72px rgba(0,0,0,.32)}
.gc-t{font-size:10.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text3);margin-bottom:14px;display:flex;align-items:center;gap:8px}
.gc-t .dot{width:6px;height:6px;border-radius:50%;background:var(--cc,var(--p));flex-shrink:0;box-shadow:0 0 7px var(--cc,var(--p))}
.g4{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:13px;margin-bottom:18px}
.g3{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:18px}
.g2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:15px;margin-bottom:18px}
.mb18{margin-bottom:18px}
.sv{font-family:'DM Mono',monospace;font-size:25px;font-weight:500;line-height:1;margin-bottom:4px;letter-spacing:-.02em}
.sl{font-size:11.5px;color:var(--text2);font-weight:500;margin-bottom:6px}
.sd{font-size:11.5px;font-weight:600}
.up{color:var(--green)}.dn{color:var(--a)}.wn{color:var(--yellow)}
.tag{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:20px;font-size:11.5px;font-weight:600}
.tg{background:rgba(26,220,142,.1);color:var(--green)}
.ty{background:rgba(240,180,41,.1);color:var(--yellow)}
.tr{background:rgba(255,94,58,.1);color:var(--a)}
.tb{background:rgba(14,111,203,.14);color:#5aabee}
.tt{background:rgba(0,200,200,.1);color:var(--s)}
.tp{background:rgba(168,85,247,.1);color:var(--purple)}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text3);padding:8px 12px;border-bottom:1px solid var(--border)}
.tbl td{padding:11px 12px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:rgba(255,255,255,.025)}
.mono{font-family:'DM Mono',monospace}
.btn{display:inline-flex;align-items:center;gap:7px;padding:9px 16px;border-radius:var(--rb);font-family:'DM Sans',sans-serif;font-size:13px;font-weight:600;cursor:pointer;border:none;transition:all .2s;user-select:none;white-space:nowrap}
.btn:active{transform:scale(.97)}
.btn-p{background:linear-gradient(135deg,var(--p),color-mix(in srgb,var(--p) 60%,var(--s)));color:#fff;box-shadow:0 6px 22px rgba(14,111,203,.3)}
.btn-p:hover{transform:translateY(-1px);box-shadow:0 10px 28px rgba(14,111,203,.45)}
.btn-t{background:linear-gradient(135deg,var(--s),color-mix(in srgb,var(--s) 65%,#0099ff));color:var(--ink);box-shadow:0 6px 22px rgba(0,200,200,.24)}
.btn-t:hover{transform:translateY(-1px)}
.btn-g{background:var(--glass2);border:1px solid var(--border);color:var(--text2)}
.btn-g:hover{color:var(--text);border-color:var(--border2)}
.btn-sm{padding:6px 12px;font-size:12px;border-radius:9px}
.li{width:100%;background:#0a1e30;border:1px solid var(--border);border-radius:9px;padding:10px 13px;font-family:'DM Sans',sans-serif;font-size:13.5px;color:var(--text);outline:none;transition:border .18s,background .18s;-webkit-appearance:none;appearance:none}
.li option{background:#0a1e30;color:rgba(255,255,255,.92)}
.li:focus{border-color:rgba(0,200,200,.5);background:rgba(0,200,200,.07);box-shadow:0 0 0 3px rgba(0,200,200,.09)}
.li::placeholder{color:var(--text3)}
.fg2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.fg3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
.fw{margin-bottom:13px}
.f-lbl{display:block;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text3);margin-bottom:6px}
.prog{height:5px;background:rgba(255,255,255,.07);border-radius:20px;overflow:hidden}
.prog-f{height:100%;border-radius:20px;transition:width .9s var(--ease)}
.chart-bars{display:flex;align-items:flex-end;gap:7px;height:110px;padding:0 4px}
.chart-bar-wrap{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px}
.chart-bar{width:100%;border-radius:5px 5px 0 0;min-height:4px;transition:height .8s cubic-bezier(.16,1,.3,1)}
.chart-bar-lbl{font-size:10px;color:var(--text3);font-family:'DM Mono',monospace}
.chart-bar-val{font-size:9.5px;color:var(--text2);font-family:'DM Mono',monospace;margin-bottom:2px}
.rv{opacity:0;transform:translateY(20px);transition:opacity .5s,transform .55s var(--ease)}
.rv.in{opacity:1;transform:none}
.modal-bg{position:fixed;inset:0;z-index:500;background:rgba(0,0,0,.58);backdrop-filter:blur(10px);display:none;align-items:center;justify-content:center;padding:20px}
.modal-bg.open{display:flex}
.modal-box{background:#07192a;border:1px solid var(--border);border-radius:20px;padding:26px 28px;width:min(520px,100%);max-height:88vh;overflow-y:auto;box-shadow:0 40px 100px rgba(0,0,0,.55);animation:panIn .3s var(--ease)}
.modal-box h3{font-family:'Instrument Serif',serif;font-size:20px;font-weight:400;margin-bottom:18px}
.mf{display:flex;gap:9px;justify-content:flex-end;margin-top:18px}
#ndrawer{position:fixed;top:var(--header);right:0;bottom:0;width:300px;background:#06172a;border-left:1px solid var(--border);z-index:300;transform:translateX(100%);transition:transform .3s var(--ease);display:flex;flex-direction:column}
#ndrawer.open{transform:translateX(0)}
.nd-hd{padding:18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.nd-hd h3{font-family:'Instrument Serif',serif;font-size:16px;font-weight:400}
.nd-list{flex:1;overflow-y:auto;padding:10px}
.nd-i{padding:11px 13px;border-radius:11px;margin-bottom:5px;border:1px solid var(--border);cursor:pointer;transition:background .15s}
.nd-i:hover{background:var(--glass2)}
.nd-i.unread{border-color:rgba(0,200,200,.2);background:rgba(0,200,200,.04)}
.nd-i .nt{font-size:13px;font-weight:600;margin-bottom:2px}
.nd-i .nd{font-size:12px;color:var(--text2);line-height:1.5}
.nd-i .nm{font-size:10.5px;color:var(--text3);margin-top:3px}
#tz{position:fixed;bottom:22px;right:22px;z-index:600;display:flex;flex-direction:column;gap:7px}
.t-i{background:#07192a;border:1px solid var(--border);border-radius:11px;padding:11px 17px;font-size:13.5px;display:flex;align-items:center;gap:9px;min-width:230px;box-shadow:0 14px 36px rgba(0,0,0,.4);animation:tIn .32s var(--spring) forwards}
.t-i.ts{border-color:rgba(26,220,142,.3)}
.t-i.te{border-color:rgba(255,94,58,.3)}
.t-i.ti{border-color:rgba(0,200,200,.3)}
@keyframes tIn{from{opacity:0;transform:translateY(16px) scale(.95)}to{opacity:1;transform:none}}
@keyframes tOut{to{opacity:0;transform:translateY(8px) scale(.95)}}
@media(max-width:768px){#shell{grid-template-columns:0 1fr}#sidebar{position:fixed;left:0;top:0;bottom:0;z-index:200;transform:translateX(-100%);transition:transform .3s var(--ease)}#sidebar.open{transform:translateX(0)}#main{padding:16px 14px 40px}.g4,.g3,.g2{grid-template-columns:1fr}}
</style>
</head>
<body>

<div id="cur"></div>
<div id="cur-r"></div>
<div id="bg"></div>
<div id="bl1" class="blob"></div>
<div id="bl2" class="blob"></div>
<div id="bl3" class="blob"></div>
<div id="grid-ov"></div>
<div id="tz"></div>

<!-- Notification drawer -->
<div id="ndrawer">
  <div class="nd-hd">
    <h3>Notifications</h3>
    <button class="btn btn-g btn-sm" onclick="toggleNotif()">Close ✕</button>
  </div>
  <div class="nd-list">
    <?php if($overdue_count > 0): ?>
    <div class="nd-i unread">
      <div class="nt">⚠ Overdue Invoices</div>
      <div class="nd"><?= $overdue_count ?> invoice(s) are overdue. Total: <?= fmtR($outstanding_debt) ?></div>
      <div class="nm">Action required</div>
    </div>
    <?php endif; ?>
    <?php if($low_stock_warnings > 0): ?>
    <div class="nd-i unread">
      <div class="nt">📦 Low Stock Alert</div>
      <div class="nd"><?= $low_stock_warnings ?> inventory item(s) at or below reorder level.</div>
      <div class="nm">Check inventory panel</div>
    </div>
    <?php endif; ?>
    <?php foreach(array_slice($recent_logs,0,3) as $log): ?>
    <div class="nd-i">
      <div class="nt"><?= htmlspecialchars($log['action']) ?></div>
      <div class="nd"><?= htmlspecialchars($log['target']) ?></div>
      <div class="nm"><?= date('d M H:i', strtotime($log['created_at'])) ?></div>
    </div>
    <?php endforeach; ?>
    <?php if(empty($recent_logs) && $overdue_count === 0 && $low_stock_warnings === 0): ?>
    <div style="text-align:center;color:var(--text3);padding:32px 0;font-size:13px">No notifications</div>
    <?php endif; ?>
  </div>
</div>

<div id="shell">

<!-- ══ SIDEBAR ══ -->
<aside id="sidebar">
  <div class="sb-logo">
    <div class="sb-logo-icon"><?= htmlspecialchars(mb_substr($user['company_name'],0,1)) ?></div>
    <div class="sb-logo-text">
      <div class="co"><?= htmlspecialchars($user['company_name']) ?></div>
      <div class="stag">Business Suite</div>
    </div>
  </div>
  <nav class="sb-nav">
    <div class="sb-lbl">Business</div>
    <div class="sb-item" data-panel="overview" onclick="window.location.href='dashboard.php'">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
      Overview
    </div>
    <div class="sb-item" data-panel="invoices" onclick="window.location.href='invoices.php'">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
      Invoices
      <?php if($overdue_count > 0): ?><span class="sb-bdg"><?= $overdue_count ?></span><?php endif; ?>
    </div>
    <div class="sb-item active" data-panel="payments" onclick="window.location.href='payments.php'">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
      Payments
    </div>
    <div class="sb-item" data-panel="inventory" onclick="window.location.href='inventory.php'">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
      Inventory
      <?php if($low_stock_warnings > 0): ?><span class="sb-bdg"><?= $low_stock_warnings ?></span><?php endif; ?>
    </div>
    <div class="sb-item <?= !$isManager ? 'locked' : '' ?>" data-panel="reports" onclick="window.location.href='report.php'">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
      Reports <?= !$isManager ? '🔒' : '' ?>
    </div>
    <div class="sb-item" data-panel="clients" onclick="window.location.href='clients.php'">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
      Clients
    </div>
    <div class="sb-lbl">Personal</div>
    <div class="sb-item prs" data-panel="personal" onclick="window.location.href='my-finance.php'">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
      My Finance
    </div>
    <div class="sb-lbl">System</div>
    <?php if($isCEO): ?>
    <div class="sb-item" data-panel="admin" onclick="window.location.href='admin.php'">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Admin Panel
    </div>
    <?php endif; ?>
    <div class="sb-item" onclick="window.location.href='profile.php'">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
      My Profile
    </div>
    <div class="sb-item" onclick="doLogout()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      Log Out
    </div>
  </nav>
  <div class="sb-footer">
    <div class="sb-user" onclick="window.location.href='profile.php'">
      <div class="sb-av"><?= htmlspecialchars($initials) ?></div>
      <div>
        <div class="sb-un"><?= htmlspecialchars($user['name']) ?></div>
        <div class="sb-ur"><?= htmlspecialchars($user['role']) ?> · <?= htmlspecialchars($user['company_name']) ?></div>
      </div>
    </div>
  </div>
</aside>

<!-- ══ TOPBAR ══ -->
<header id="topbar">
  <div class="tb-title" id="tb-title">Overview</div>
  <div class="tb-search">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    <input id="gs" placeholder="Search…" autocomplete="off"/>
    <kbd>⌘K</kbd>
  </div>
  <div class="tb-btn" onclick="toggleNotif()" title="Notifications">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
    <?php if($overdue_count > 0 || $low_stock_warnings > 0): ?><span class="ndot"></span><?php endif; ?>
  </div>
  <a href="invoice-generate.php" class="btn btn-p btn-sm" style="text-decoration:none">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
    New Invoice
  </a>
  <span class="rc rc-<?= htmlspecialchars($user['role']) ?>"><?= htmlspecialchars($user['role']) ?></span>
  <div class="tb-av" onclick="window.location.href='profile.php'" title="My Profile"><?= htmlspecialchars($initials) ?></div>
</header>

<!-- ══ MAIN ══ -->
<main id="main">

<!-- ════════════ PANEL: PAYMENTS ════════════ -->
<div class="panel active" id="panel-payments">
  <div class="pg-hero rv" style="display:flex;justify-content:space-between;align-items:flex-start">
    <div>
      <h1>Payments</h1>
      <p>All recorded payments · <?= htmlspecialchars($user['company_name']) ?></p>
    </div>
    <button class="btn btn-p" onclick="document.getElementById('modal-add-payment').classList.add('open')">+ Record Payment</button>
  </div>

  <div class="g3 rv">
    <div class="gc" data-c style="--cc:var(--green)">
      <div class="gc-t"><span class="dot"></span>Total Collected</div>
      <div class="sv"><?= fmtRK(array_sum(array_column($recent_payments,'amount'))) ?></div>
      <div class="sl">All time</div>
    </div>
    <div class="gc" data-c style="--cc:var(--yellow)">
      <div class="gc-t"><span class="dot"></span>Outstanding</div>
      <div class="sv"><?= fmtRK($outstanding_debt) ?></div>
      <div class="sl">Sent + overdue invoices</div>
    </div>
    <div class="gc" data-c style="--cc:var(--s)">
      <div class="gc-t"><span class="dot"></span>Overdue</div>
      <div class="sv"><?= $overdue_count ?></div>
      <div class="sl">Invoices past due date</div>
    </div>
  </div>

  <div class="gc rv" data-c style="--cc:var(--green)">
    <div class="gc-t"><span class="dot"></span>Payment History</div>
    <?php if(empty($recent_payments)): ?>
    <div style="text-align:center;color:var(--text3);padding:40px 0;font-size:13px">No payments recorded yet.</div>
    <?php else: ?>
    <table class="tbl">
      <thead><tr><th>Client</th><th>Invoice</th><th>Amount</th><th>Method</th><th>Reference</th><th>Date</th></tr></thead>
      <tbody>
        <?php foreach($recent_payments as $pay): ?>
        <tr>
          <td style="font-weight:500"><?= htmlspecialchars($pay['client_name']) ?></td>
          <td class="mono" style="font-size:12px"><?= htmlspecialchars($pay['invoice_number']) ?></td>
          <td class="mono" style="color:var(--green)"><?= fmtR((float)$pay['amount']) ?></td>
          <td><span class="tag tt"><?= htmlspecialchars(strtoupper($pay['method'])) ?></span></td>
          <td style="color:var(--text2);font-size:12.5px"><?= htmlspecialchars($pay['reference'] ?? '—') ?></td>
          <td style="color:var(--text2);font-size:12px"><?= date('d M Y', strtotime($pay['payment_date'])) ?></td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
    <?php endif; ?>
  </div>
</div>

<!-- Record Payment Modal -->
<div class="modal-bg" id="modal-add-payment">
  <div class="modal-box">
    <h3>Record Payment</h3>
    <form method="POST" action="payments.php">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>"/>
      <input type="hidden" name="action" value="add_payment"/>
      <div class="fw">
        <label class="f-lbl">Invoice</label>
        <select class="li" name="invoice_id" required>
          <option value="">— Select invoice —</option>
          <?php foreach($open_invoices as $inv): ?>
          <option value="<?= $inv['id'] ?>">
            <?= htmlspecialchars($inv['invoice_number']) ?> · <?= htmlspecialchars($inv['client_name']) ?> · <?= fmtR((float)$inv['total_amount']) ?>
          </option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="fw"><label class="f-lbl">Amount (R)</label><input class="li" type="number" name="amount" step="0.01" min="0.01" required placeholder="0.00"/></div>
      <div class="fw"><label class="f-lbl">Payment Date</label><input class="li" type="date" name="payment_date" required value="<?= date('Y-m-d') ?>"/></div>
      <div class="fw">
        <label class="f-lbl">Method</label>
        <select class="li" name="method">
          <option value="EFT">EFT</option>
          <option value="cash">Cash</option>
          <option value="card">Card</option>
          <option value="other">Other</option>
        </select>
      </div>
      <div class="fw"><label class="f-lbl">Reference (optional)</label><input class="li" name="reference" placeholder="Bank reference or note"/></div>
      <div class="fw"><label class="f-lbl">Notes (optional)</label><textarea class="li" name="notes" rows="2" placeholder="Any additional notes…"></textarea></div>
      <div class="mf">
        <button type="button" class="btn btn-g" onclick="document.getElementById('modal-add-payment').classList.remove('open')">Cancel</button>
        <button type="submit" class="btn btn-p">Record Payment</button>
      </div>
    </form>
  </div>
</div>

</main>
</div><!-- /shell -->

<script>
// ── App state from PHP ────────────────────────────────────
const APP = {
  role:    '<?= addslashes($user['role']) ?>',
  name:    '<?= addslashes($user['name']) ?>',
  initials:'<?= addslashes($initials) ?>',
  brand:   {primary:'<?= addslashes($user['brand']['primary']) ?>',secondary:'<?= addslashes($user['brand']['secondary']) ?>',accent:'<?= addslashes($user['brand']['accent']) ?>'}
};

// ── Custom cursor ─────────────────────────────────────────
const cur = document.getElementById('cur');
const curR= document.getElementById('cur-r');
document.addEventListener('mousemove', e => {
  cur.style.left = curR.style.left = e.clientX + 'px';
  cur.style.top  = curR.style.top  = e.clientY + 'px';
});
document.addEventListener('mousedown', e => {
  const r = document.createElement('div');
  r.className = 'rpl';
  r.style.cssText = `left:${e.clientX}px;top:${e.clientY}px;width:80px;height:80px`;
  document.body.appendChild(r);
  setTimeout(() => r.remove(), 700);
});
document.querySelectorAll('a,button,.sb-item,.btn,.tb-btn,.tb-av,.sb-user').forEach(el => {
  el.addEventListener('mouseenter', () => document.body.classList.add('hov'));
  el.addEventListener('mouseleave', () => document.body.classList.remove('hov'));
});

// ── Panel navigation ──────────────────────────────────────
const panels = {
  overview:  { el: document.getElementById('panel-overview'),  title: 'Overview'       },
  invoices:  { el: document.getElementById('panel-invoices'),  title: 'Invoices'       },
  payments:  { el: document.getElementById('panel-payments'),  title: 'Payments'       },
  inventory: { el: document.getElementById('panel-inventory'), title: 'Inventory'      },
  reports:   { el: document.getElementById('panel-reports'),   title: 'Reports'        },
  clients:   { el: document.getElementById('panel-clients'),   title: 'Clients'        },
  personal:  { el: document.getElementById('panel-personal'),  title: 'My Finance'     },
  admin:     { el: document.getElementById('panel-admin'),     title: 'Admin Panel'    },
};

function go(item) {
  const panelKey = item.dataset.panel;
  if (!panels[panelKey] || !panels[panelKey].el) return;
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(i => i.classList.remove('active'));
  panels[panelKey].el.classList.add('active');
  item.classList.add('active');
  document.getElementById('tb-title').textContent = panels[panelKey].title;
  trigReveal();
}

// ── Scroll reveal ─────────────────────────────────────────
function trigReveal() {
  setTimeout(() => {
    document.querySelectorAll('.panel.active .rv').forEach((el, i) => {
      setTimeout(() => el.classList.add('in'), i * 55);
    });
  }, 30);
}
trigReveal();

// ── Notifications ─────────────────────────────────────────
function toggleNotif() {
  document.getElementById('ndrawer').classList.toggle('open');
}
document.addEventListener('click', e => {
  const d = document.getElementById('ndrawer');
  if (d.classList.contains('open') && !d.contains(e.target) && !e.target.closest('.tb-btn'))
    d.classList.remove('open');
});

// ── Toast ─────────────────────────────────────────────────
function toast(msg, type = 'ts') {
  const z = document.getElementById('tz');
  const el = document.createElement('div');
  el.className = `t-i ${type}`;
  const icons = { ts: '✓', te: '✕', ti: 'ℹ' };
  const clrs  = { ts: 'var(--green)', te: 'var(--a)', ti: 'var(--s)' };
  el.innerHTML = `<span style="color:${clrs[type]||clrs.ts};font-size:15px;font-weight:700">${icons[type]||'✓'}</span> ${msg}`;
  z.appendChild(el);
  setTimeout(() => {
    el.style.animation = 'tOut .3s ease-in forwards';
    setTimeout(() => el.remove(), 300);
  }, 3500);
}

// ── Logout ────────────────────────────────────────────────
function doLogout() {
  if (confirm('Log out of Souitro?')) {
    toast('Logging out…', 'ti');
    setTimeout(() => window.location.href = 'logout.php', 1200);
  }
}

// ── Keyboard shortcut ─────────────────────────────────────
document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault();
    document.getElementById('gs')?.focus();
  }
  if (e.key === 'Escape') {
    document.getElementById('ndrawer')?.classList.remove('open');
  }
});

// Close modal when clicking outside
document.querySelectorAll('.modal-bg').forEach(bg => {
    bg.addEventListener('click', e => {
        if (e.target === bg) bg.classList.remove('open');
    });
});
</script>
</body>
</html>