<?php
// ============================================================
// invoice-generate.php - Invoice Creator + AJAX Save/Send
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
    if (
        $_SERVER['REQUEST_METHOD'] === 'POST' &&
        isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest'
    ) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Database unavailable.']);
        exit;
    }
    die('Database unavailable. Please contact support.');
}

// ── AJAX Handler Block ──────────────────────────────────────
if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest'
) {
    header('Content-Type: application/json');
    $action = $_POST['action'] ?? '';

    // ── ACTION: SAVE DRAFT or SEND INVOICE ─────────────────
    if (in_array($action, ['save_draft', 'send_invoice'], true)) {
        $invoiceNumber = trim($_POST['invoice_number'] ?? '');
        $clientId      = (int)($_POST['client_id'] ?? 0);
        $issueDate     = $_POST['issue_date'] ?? '';
        $dueDate       = $_POST['due_date']   ?? '';
        $taxRate       = (float)($_POST['tax_rate'] ?? 15);
        $notes         = trim($_POST['notes'] ?? '');
        $linesJson     = $_POST['lines'] ?? '[]';
        $status        = ($action === 'send_invoice') ? 'sent' : 'draft';

        // Validation
        if (empty($invoiceNumber)) {
            echo json_encode(['ok' => false, 'message' => 'Invoice number is required.']);
            exit;
        }
        if (empty($issueDate) || empty($dueDate)) {
            echo json_encode(['ok' => false, 'message' => 'Issue date and due date are required.']);
            exit;
        }

        $lines = json_decode($linesJson, true);
        if (!is_array($lines) || empty($lines)) {
            echo json_encode(['ok' => false, 'message' => 'At least one line item is required.']);
            exit;
        }

        // Client is required when sending, optional for draft
if ($action === 'send_invoice' && $clientId <= 0) {
    echo json_encode(['ok' => false, 'message' => 'A client must be selected before sending.']);
    exit;
}

      // Client required for both draft and send
if ($clientId <= 0) {
    echo json_encode(['ok' => false, 'message' => 'Please select a client before saving.']);
    exit;
}

// Verify client belongs to this company (tenant isolation)
$stmt = $pdo->prepare("SELECT id FROM clients WHERE id = ? AND company_id = ? AND is_active = 1 LIMIT 1");
$stmt->execute([$clientId, $current_company_id]);
if (!$stmt->fetch()) {
    echo json_encode(['ok' => false, 'message' => 'Invalid client selected.']);
    exit;
}

        // Calculate totals
        $subtotal = 0;
        foreach ($lines as $line) {
            $qty   = (float)($line['qty']   ?? 0);
            $price = (float)($line['price'] ?? 0);
            $subtotal += $qty * $price;
        }
        $taxAmount   = round($subtotal * ($taxRate / 100), 2);
        $totalAmount = round($subtotal + $taxAmount, 2);

        try {
            $pdo->beginTransaction();

            // Check for duplicate invoice number within company
            $stmt = $pdo->prepare("
                SELECT id FROM invoices
                WHERE invoice_number = ? AND company_id = ?
                LIMIT 1
            ");
            $stmt->execute([$invoiceNumber, $current_company_id]);
            $existing = $stmt->fetch();

            if ($existing) {
                // Update existing draft
                $invoiceId = (int)$existing['id'];
                $pdo->prepare("
                    UPDATE invoices
                    SET client_id = ?, issue_date = ?, due_date = ?,
                        subtotal = ?, tax_rate = ?, tax_amount = ?, total_amount = ?,
                        status = ?, notes = ?, updated_at = NOW()
                    WHERE id = ? AND company_id = ?
                ")->execute([
                    $clientId ?: null,
                    $issueDate, $dueDate,
                    $subtotal, $taxRate, $taxAmount, $totalAmount,
                    $status, $notes,
                    $invoiceId, $current_company_id
                ]);

                // Clear and re-insert line items
                $pdo->prepare("DELETE FROM invoice_items WHERE invoice_id = ?")->execute([$invoiceId]);
            } else {
                // Insert new invoice
                $stmt = $pdo->prepare("
                    INSERT INTO invoices
                        (company_id, client_id, created_by, invoice_number,
                         issue_date, due_date, subtotal, tax_rate, tax_amount, total_amount, status, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $current_company_id,
                    $clientId ?: null,
                    $current_user_id,
                    $invoiceNumber,
                    $issueDate, $dueDate,
                    $subtotal, $taxRate, $taxAmount, $totalAmount,
                    $status, $notes
                ]);
                $invoiceId = (int)$pdo->lastInsertId();
            }

            // Insert line items
            $lineStmt = $pdo->prepare("
                INSERT INTO invoice_items (invoice_id, description, quantity, unit_price, line_total)
                VALUES (?, ?, ?, ?, ?)
            ");
            foreach ($lines as $line) {
                $qty       = (float)($line['qty']   ?? 0);
                $price     = (float)($line['price'] ?? 0);
                $lineTotal = round($qty * $price, 2);
                $desc      = trim($line['desc'] ?? '');
                if (empty($desc) || $qty <= 0) continue;
                $lineStmt->execute([$invoiceId, $desc, $qty, $price, $lineTotal]);
            }

            // Audit
            $auditAction = ($action === 'send_invoice') ? 'INVOICE_SENT' : 'INVOICE_DRAFT_SAVED';
            $pdo->prepare("
                INSERT INTO audit_log (user_id, company_id, action, target, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            ")->execute([
                $current_user_id,
                $current_company_id,
                $auditAction,
                'invoices:' . $invoiceId,
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]);

            $pdo->commit();

            $msg = ($action === 'send_invoice')
                ? 'Invoice sent to client successfully.'
                : 'Invoice saved as draft.';

            echo json_encode(['ok' => true, 'message' => $msg, 'invoice_id' => $invoiceId]);
        } catch (\PDOException $e) {
            $pdo->rollBack();
            echo json_encode(['ok' => false, 'message' => 'Failed to save invoice. Please try again.']);
        }
        exit;
    }

    echo json_encode(['ok' => false, 'message' => 'Unknown action.']);
    exit;
}

// ── Fetch user + company + clients + next invoice number ────
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

    // Fetch active clients for this company
    $stmt = $pdo->prepare("
        SELECT id, name, email, address, vat_number
        FROM clients
        WHERE company_id = ? AND is_active = 1
        ORDER BY name ASC
    ");
    $stmt->execute([$current_company_id]);
    $clients = $stmt->fetchAll();

    // Auto-generate next invoice number (INV-YYYY-XXXX)
    $stmt = $pdo->prepare("
        SELECT COUNT(*) FROM invoices WHERE company_id = ?
    ");
    $stmt->execute([$current_company_id]);
    $invoiceCount  = (int)$stmt->fetchColumn();
    $nextInvoiceNo = 'INV-' . date('Y') . '-' . str_pad($invoiceCount + 1, 4, '0', STR_PAD_LEFT);

} catch (\PDOException $e) {
    $user          = ['name' => 'User', 'role' => $current_user_role, 'company_name' => '', 'brand' => ['primary' => '#0e6fcb', 'secondary' => '#00c8c8', 'accent' => '#ff5e3a']];
    $clients       = [];
    $nextInvoiceNo = 'INV-' . date('Y') . '-0001';
}
// ── HTML starts below ────────────────────────────────────────
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Invoice Generator | <?= htmlspecialchars($user['company_name']) ?></title>
<link rel="icon" type="image/png" href="img/logo.png"/>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=DM+Sans:opsz,wght@9..40,400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
:root{
  --p:#0e6fcb;--s:#00c8c8;--a:#ff5e3a;
  --ink:#030c17;--glass:rgba(255,255,255,.06);
  --border:rgba(255,255,255,.09);--border2:rgba(255,255,255,.16);
  --text:rgba(255,255,255,.92);--text2:rgba(255,255,255,.52);--text3:rgba(255,255,255,.25);
  --green:#1adc8e;--yellow:#f0b429;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'DM Sans',sans-serif;background:var(--ink);color:var(--text);min-height:100vh;font-size:14px}
/* Topbar */
.topbar{background:rgba(3,12,23,.85);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);
  padding:0 28px;height:58px;display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:100}
.topbar-title{font-family:'Instrument Serif',serif;font-size:18px;flex:1}
/* Layout */
.layout{display:grid;grid-template-columns:420px 1fr;gap:0;min-height:calc(100vh - 58px)}
/* Form panel */
.form-panel{background:rgba(6,19,32,.9);border-right:1px solid var(--border);padding:24px;overflow-y:auto;max-height:calc(100vh - 58px)}
/* Preview panel */
.preview-panel{padding:28px;overflow-y:auto;max-height:calc(100vh - 58px);background:rgba(3,12,23,.6)}
/* Shared */
.sec-title{font-family:'Instrument Serif',serif;font-size:15px;margin-bottom:14px;color:var(--text);display:flex;align-items:center;gap:8px}
.sec-title::before{content:'';width:3px;height:16px;background:var(--p);border-radius:2px;display:block}
.fw{margin-bottom:13px}
.f-lbl{display:block;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text3);margin-bottom:5px}
.li{width:100%;background:rgba(255,255,255,.06);border:1px solid var(--border);border-radius:9px;
  padding:10px 13px;font-family:'DM Sans',sans-serif;font-size:13.5px;color:var(--text);
  outline:none;transition:border .18s,background .18s;-webkit-appearance:none;appearance:none}
.li:focus{border-color:rgba(0,200,200,.5);background:rgba(0,200,200,.07)}
.li::placeholder{color:var(--text3)}
.fg2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.fg3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.divider{border:none;border-top:1px solid var(--border);margin:18px 0}
/* Line items */
.line-item{display:grid;grid-template-columns:1fr 70px 100px 28px;gap:8px;align-items:end;margin-bottom:8px}
.li-del{width:28px;height:28px;border-radius:7px;background:rgba(255,94,58,.1);border:1px solid rgba(255,94,58,.2);
  color:var(--a);font-size:14px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;flex-shrink:0}
.li-del:hover{background:rgba(255,94,58,.22)}
/* Buttons */
.btn{display:inline-flex;align-items:center;gap:7px;padding:9px 16px;border-radius:10px;
  font-family:'DM Sans',sans-serif;font-size:13px;font-weight:600;cursor:pointer;
  border:none;transition:all .2s;white-space:nowrap}
.btn-p{background:linear-gradient(135deg,var(--p),color-mix(in srgb,var(--p) 60%,var(--s)));color:#fff;box-shadow:0 6px 20px rgba(14,111,203,.3)}
.btn-p:hover{transform:translateY(-1px);box-shadow:0 10px 26px rgba(14,111,203,.44)}
.btn-t{background:linear-gradient(135deg,var(--s),color-mix(in srgb,var(--s) 65%,#0099ff));color:var(--ink);box-shadow:0 6px 20px rgba(0,200,200,.22)}
.btn-g{background:rgba(255,255,255,.08);border:1px solid var(--border);color:var(--text2)}
.btn-g:hover{color:var(--text);border-color:var(--border2)}
.btn-sm{padding:6px 12px;font-size:12px;border-radius:8px}
/* Tag */
.tag{display:inline-flex;align-items:center;padding:3px 9px;border-radius:20px;font-size:11px;font-weight:600}
.tg{background:rgba(26,220,142,.1);color:var(--green)}
.ty{background:rgba(240,180,41,.1);color:var(--yellow)}
.tr{background:rgba(255,94,58,.1);color:var(--a)}
/* ── INVOICE PREVIEW (white print-style) ── */
.inv-preview{
  background:#fff;border-radius:14px;
  color:#111;font-family:'DM Sans',sans-serif;
  font-size:13px;line-height:1.7;
  box-shadow:0 24px 80px rgba(0,0,0,.4);
  overflow:hidden;
}
.inv-header{
  background:linear-gradient(135deg,#0e6fcb,#00c8c8);
  padding:28px 32px;color:#fff;
  display:flex;justify-content:space-between;align-items:flex-start;
}
.inv-header .company{font-family:'Instrument Serif',serif;font-size:22px;font-weight:400;margin-bottom:4px}
.inv-header .company-details{font-size:12px;opacity:.85;line-height:1.6}
.inv-header .inv-label{font-size:36px;font-family:'Instrument Serif',serif;font-weight:400;text-align:right;opacity:.95}
.inv-header .inv-num{font-size:13px;opacity:.8;text-align:right;margin-top:2px;font-family:'DM Mono',monospace}
.inv-body{padding:28px 32px}
.inv-parties{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px}
.inv-party-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#888;margin-bottom:5px}
.inv-party-name{font-size:15px;font-weight:700;color:#111;margin-bottom:3px}
.inv-party-details{font-size:12px;color:#555;line-height:1.6}
.inv-meta-row{display:flex;gap:24px;margin-bottom:24px;padding:14px 16px;background:#f8f9fb;border-radius:10px}
.inv-meta-item .im-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#888;margin-bottom:3px}
.inv-meta-item .im-val{font-size:14px;font-weight:600;color:#111;font-family:'DM Mono',monospace}
.inv-items table{width:100%;border-collapse:collapse;margin-bottom:20px}
.inv-items thead tr{background:#f0f4f8}
.inv-items th{padding:10px 14px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#555}
.inv-items td{padding:11px 14px;border-bottom:1px solid #edf0f4;color:#333;vertical-align:middle}
.inv-items tr:last-child td{border-bottom:none}
.inv-items tr:hover td{background:#f8f9fb}
.inv-totals{display:flex;justify-content:flex-end;margin-bottom:20px}
.inv-totals-table{min-width:240px}
.inv-totals-table tr td{padding:5px 0;font-size:13px}
.inv-totals-table tr td:last-child{text-align:right;font-family:'DM Mono',monospace;font-weight:500}
.inv-total-final td{font-size:16px !important;font-weight:800 !important;color:#0e6fcb;border-top:2px solid #0e6fcb;padding-top:8px !important}
.inv-footer{background:#f8f9fb;padding:16px 32px;display:flex;justify-content:space-between;align-items:center;border-top:1px solid #edf0f4}
.inv-footer .bank{font-size:12px;color:#555;line-height:1.6}
.inv-footer .bank strong{color:#111;display:block;margin-bottom:2px}
.inv-footer .status-badge{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:20px;font-size:12px;font-weight:700}
.status-draft{background:#f0f4f8;color:#888}
.status-sent{background:#fff3d6;color:#c07c00}
.status-paid{background:#e6f7ef;color:#1a9e5e}
.li{width:100%;background:#0a1e30;border:1px solid var(--border);border-radius:9px;padding:10px 13px;font-family:'DM Sans',sans-serif;font-size:13.5px;color:var(--text);outline:none;transition:border .18s,background .18s;-webkit-appearance:none;appearance:none}
.li option{background:#0a1e30;color:rgba(255,255,255,.92)}
/* Totals summary at bottom of form */
.totals-box{background:rgba(14,111,203,.08);border:1px solid rgba(14,111,203,.2);border-radius:12px;padding:14px 16px;margin-top:14px}
.totals-row{display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px}
.totals-row.total{font-weight:700;font-size:15px;color:var(--p);border-top:1px solid rgba(14,111,203,.2);margin-top:8px;padding-top:8px}
.totals-row span:last-child{font-family:'DM Mono',monospace}
/* Action bar at bottom of form */
.form-actions{display:flex;flex-direction:column;gap:9px;margin-top:20px}
/* Toast */
#tz{position:fixed;bottom:22px;right:22px;z-index:600;display:flex;flex-direction:column;gap:7px}
.t-i{background:#07192a;border:1px solid rgba(26,220,142,.3);border-radius:11px;padding:11px 17px;
  font-size:13.5px;display:flex;align-items:center;gap:9px;min-width:220px;
  box-shadow:0 14px 36px rgba(0,0,0,.4);animation:tIn .32s cubic-bezier(.34,1.56,.64,1) forwards}
@keyframes tIn{from{opacity:0;transform:translateY(16px) scale(.95)}to{opacity:1;transform:none}}
@keyframes tOut{to{opacity:0;transform:translateY(8px) scale(.95)}}
/* Print styles */
@media print{
  body{background:#fff}
  .topbar,.form-panel{display:none}
  .layout{display:block}
  .preview-panel{padding:0;max-height:none;overflow:visible;background:#fff}
  .inv-preview{box-shadow:none;border-radius:0}
  #print-btn-area{display:none}
}
@media(max-width:900px){.layout{grid-template-columns:1fr}.form-panel,.preview-panel{max-height:none}.fg2{grid-template-columns:1fr}.line-item{grid-template-columns:1fr 60px 90px 28px}}
</style>
</head>
<body>

<div id="tz"></div>

<!-- Topbar -->
<div class="topbar">
  <a href="dashboard.php" style="color:var(--text2);font-size:13px;text-decoration:none;display:flex;align-items:center;gap:6px">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
    Dashboard
  </a>
  <div class="topbar-title">Invoice Generator</div>
  <button class="btn btn-g btn-sm" onclick="resetForm()">↺ Reset</button>
  <button class="btn btn-t btn-sm" onclick="saveDraft()">Save Draft</button>
  <button class="btn btn-p btn-sm" onclick="sendInvoice()">Send Invoice</button>
</div>

<div class="layout">

  <!-- ══ FORM PANEL ══ -->
  <div class="form-panel">

    <!-- Invoice info -->
    <div class="sec-title">Invoice Details</div>
    <div class="fg2">
      <div class="fw"><label class="f-lbl">Invoice Number</label><input class="li" id="inv-num" type="text" value="<?= htmlspecialchars($nextInvoiceNo) ?>"/></div>
      <div class="fw"><label class="f-lbl">Status</label>
        <select class="li" id="inv-status" onchange="updatePreview()">
          <option value="draft">Draft</option>
          <option value="sent">Sent</option>
          <option value="paid">Paid</option>
        </select>
      </div>
    </div>
    <div class="fg2">
      <div class="fw"><label class="f-lbl">Issue Date</label><input class="li" type="date" id="inv-date" oninput="updatePreview()"/></div>
      <div class="fw"><label class="f-lbl">Due Date</label><input class="li" type="date" id="inv-due" oninput="updatePreview()"/></div>
    </div>

    <hr class="divider"/>

    <!-- Client -->
    <div class="sec-title">Client</div>
    <div class="fw"><label class="f-lbl">Select Client</label>
      <select class="li" id="client-select" onchange="fillClient()">
        <option value="">- Select existing client -</option>
        <?php foreach ($clients as $c): ?>
        <option value="<?= $c['id'] ?>"
          data-name="<?= htmlspecialchars($c['name']) ?>"
          data-email="<?= htmlspecialchars($c['email'] ?? '') ?>"
          data-addr="<?= htmlspecialchars($c['address'] ?? '') ?>"
          data-vat="<?= htmlspecialchars($c['vat_number'] ?? '') ?>">
          <?= htmlspecialchars($c['name']) ?>
        </option>
        <?php endforeach; ?>
      </select>
    </div>
    <div class="fw"><label class="f-lbl">Client / Company Name</label><input class="li" id="c-name" placeholder="Company name…" oninput="updatePreview()"/></div>
    <div class="fw"><label class="f-lbl">Email</label><input class="li" type="email" id="c-email" placeholder="client@company.co.za" oninput="updatePreview()"/></div>
    <div class="fw"><label class="f-lbl">Billing Address</label><textarea class="li" id="c-addr" rows="2" placeholder="Street, City, Province" oninput="updatePreview()"></textarea></div>
    <div class="fw"><label class="f-lbl">Client VAT Number (optional)</label><input class="li" id="c-vat" placeholder="Leave blank if not VAT registered" oninput="updatePreview()"/></div>

    <hr class="divider"/>

    <!-- Line items -->
    <div class="sec-title">Line Items</div>
    <div id="line-items"></div>
    <button class="btn btn-g btn-sm" style="width:100%;justify-content:center;margin-bottom:4px" onclick="addLine()">+ Add Line Item</button>

    <!-- Totals -->
    <div class="fw" style="margin-top:14px"><label class="f-lbl">VAT Rate (%)</label><input class="li" type="number" id="vat-rate" value="15" min="0" max="100" oninput="updatePreview()"/></div>

    <div class="totals-box" id="totals-box">
      <div class="totals-row"><span>Subtotal</span><span id="t-sub">R 0.00</span></div>
      <div class="totals-row"><span>VAT (15%)</span><span id="t-vat">R 0.00</span></div>
      <div class="totals-row total"><span>Total Due</span><span id="t-total">R 0.00</span></div>
    </div>

    <hr class="divider"/>

    <!-- Notes / bank -->
    <div class="sec-title">Notes &amp; Payment</div>
    <div class="fw"><label class="f-lbl">Notes / Terms</label><textarea class="li" id="inv-notes" rows="3" placeholder="Payment terms, special conditions…" oninput="updatePreview()">Thank you for your business. Please use your invoice number as payment reference.</textarea></div>
    <div class="fw"><label class="f-lbl">Bank Account (shown on invoice)</label><input class="li" id="inv-bank" value="FNB – 6204 5678 123  |  Branch: 250655" oninput="updatePreview()"/></div>

    <div class="form-actions">
      <button class="btn btn-p" style="justify-content:center" onclick="sendInvoice()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
        Create &amp; Send to Client
      </button>
      <div style="display:flex;gap:9px">
        <button class="btn btn-g btn-sm" style="flex:1;justify-content:center" onclick="saveDraft()">Save Draft</button>
        <button class="btn btn-g btn-sm" style="flex:1;justify-content:center" onclick="window.print()">🖨 Print / PDF</button>
      </div>
      <a href="dashboard.php" style="text-align:center;font-size:13px;color:var(--text2);text-decoration:none;padding:6px">← Back to Dashboard</a>
    </div>
  </div>

  <!-- ══ PREVIEW PANEL ══ -->
  <div class="preview-panel">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px" id="print-btn-area">
      <div style="font-size:12px;color:var(--text2)">Live preview - updates as you type</div>
      <button class="btn btn-g btn-sm" onclick="window.print()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
        Print
      </button>
    </div>

    <div class="inv-preview" id="inv-preview">
      <!-- Header -->
      <div class="inv-header">
        <div>
          <div class="company"><?= htmlspecialchars($user['company_name']) ?></div>
          <div class="company-details">
            123 Innovation Park, Pretoria, GP 0001<br/>
            info@souitro.co.za  |  +27 12 345 6789<br/>
            VAT: 4580123456
          </div>
        </div>
        <div>
          <div class="inv-label">INVOICE</div>
          <div class="inv-num" id="prev-num">INV-2030</div>
        </div>
      </div>

      <div class="inv-body">
        <!-- Meta row -->
        <div class="inv-meta-row">
          <div class="inv-meta-item"><div class="im-label">Issue Date</div><div class="im-val" id="prev-date">-</div></div>
          <div class="inv-meta-item"><div class="im-label">Due Date</div><div class="im-val" id="prev-due">-</div></div>
          <div class="inv-meta-item"><div class="im-label">Status</div><div class="im-val" id="prev-status"><span class="tag tg" style="background:#e6f7ef;color:#1a9e5e">Draft</span></div></div>
        </div>

        <!-- Parties -->
        <div class="inv-parties">
          <div>
            <div class="inv-party-label">From</div>
            <div class="inv-party-name"><?= htmlspecialchars($user['company_name']) ?></div>
            <div class="inv-party-details">123 Innovation Park, Pretoria<br/>VAT: 4580123456</div>
          </div>
          <div>
            <div class="inv-party-label">Bill To</div>
            <div class="inv-party-name" id="prev-cname" style="color:#888">Select a client →</div>
            <div class="inv-party-details" id="prev-cdetails" style="color:#aaa">Client details will appear here</div>
          </div>
        </div>

        <!-- Line items table -->
        <div class="inv-items">
          <table>
            <thead><tr><th style="min-width:200px">Description</th><th style="text-align:right">Qty</th><th style="text-align:right">Unit Price</th><th style="text-align:right">Total</th></tr></thead>
            <tbody id="prev-items"><tr><td colspan="4" style="color:#aaa;text-align:center;padding:20px">Add line items to see them here</td></tr></tbody>
          </table>
        </div>

        <!-- Totals -->
        <div class="inv-totals">
          <table class="inv-totals-table">
            <tr><td style="color:#555">Subtotal</td><td id="prev-sub">R 0.00</td></tr>
            <tr><td style="color:#555" id="prev-vat-label">VAT (15%)</td><td id="prev-vat-amt">R 0.00</td></tr>
            <tr class="inv-total-final"><td><strong>Total Due</strong></td><td id="prev-total"><strong>R 0.00</strong></td></tr>
          </table>
        </div>

        <!-- Notes -->
        <div id="prev-notes-wrap" style="background:#f8f9fb;border-radius:9px;padding:13px 16px;margin-bottom:4px;font-size:12.5px;color:#555;line-height:1.6">
          <strong style="color:#333;display:block;margin-bottom:4px">Notes &amp; Terms</strong>
          <span id="prev-notes">Thank you for your business. Please use your invoice number as payment reference.</span>
        </div>
      </div>

      <!-- Footer -->
      <div class="inv-footer">
        <div class="bank">
          <strong>Payment Details</strong>
          <span id="prev-bank">FNB – 6204 5678 123  |  Branch: 250655</span><br/>
          <span style="color:#888">Reference: <strong id="prev-ref">INV-2030</strong></span>
        </div>
        <div id="prev-footer-status"><span class="inv-status status-draft">Draft</span></div>
      </div>
    </div>
  </div>
</div>

<script>
/* ── Seed default date values ── */
const today = new Date();
const addDays = (d,n) => { const r=new Date(d); r.setDate(r.getDate()+n); return r.toISOString().split('T')[0]; };
document.getElementById('inv-date').value = today.toISOString().split('T')[0];
document.getElementById('inv-due').value  = addDays(today, 14);

/* ── Line items state ── */
let lines = [];
let lineId = 0;

function addLine(desc='',qty=1,price=0){
  lineId++;
  lines.push({id:lineId, desc, qty:parseFloat(qty)||1, price:parseFloat(price)||0});
  renderLines();
  updatePreview();
}

function removeLine(id){
  lines = lines.filter(l=>l.id!==id);
  renderLines(); updatePreview();
}

function renderLines(){
  const el = document.getElementById('line-items');
  if(!lines.length){
    el.innerHTML='<div style="color:var(--text3);font-size:13px;text-align:center;padding:14px 0">No items yet - click Add Line Item</div>';
    return;
  }
  el.innerHTML = lines.map(l=>`
    <div class="line-item" data-id="${l.id}">
      <input class="li" value="${l.desc}" placeholder="Description…" style="font-size:13px;padding:8px 11px"
        oninput="lines.find(x=>x.id==${l.id}).desc=this.value;updatePreview()"/>
      <input class="li" type="number" value="${l.qty}" min="0" style="font-size:13px;padding:8px 10px;text-align:center;font-family:'DM Mono',monospace"
        oninput="lines.find(x=>x.id==${l.id}).qty=parseFloat(this.value)||0;updatePreview()"/>
      <input class="li" type="number" value="${l.price}" min="0" step="0.01" style="font-size:13px;padding:8px 10px;text-align:right;font-family:'DM Mono',monospace"
        oninput="lines.find(x=>x.id==${l.id}).price=parseFloat(this.value)||0;updatePreview()"/>
      <button class="li-del" onclick="removeLine(${l.id})">×</button>
    </div>`).join('');
}

/* ── Fill client details from select ── */
function fillClient(){
  const sel = document.getElementById('client-select');
  const opt = sel.selectedOptions[0];
  if(!opt.value) return;
  document.getElementById('c-name').value  = opt.dataset.name  || '';
  document.getElementById('c-email').value = opt.dataset.email || '';
  document.getElementById('c-addr').value  = opt.dataset.addr  || '';
  document.getElementById('c-vat').value   = opt.dataset.vat   || '';
  updatePreview();
}

/* ── Format currency ── */
const fmtR = n => 'R ' + parseFloat(n).toLocaleString('en-ZA',{minimumFractionDigits:2,maximumFractionDigits:2});

/* ── Live preview update ── */
function updatePreview(){
  const num    = document.getElementById('inv-num').value   || 'INV-XXXX';
  const date   = document.getElementById('inv-date').value  || '-';
  const due    = document.getElementById('inv-due').value   || '-';
  const status = document.getElementById('inv-status').value;
  const cname  = document.getElementById('c-name').value;
  const cemail = document.getElementById('c-email').value;
  const caddr  = document.getElementById('c-addr').value;
  const cvat   = document.getElementById('c-vat').value;
  const vatR   = (parseFloat(document.getElementById('vat-rate').value) || 15) / 100;
  const notes  = document.getElementById('inv-notes').value;
  const bank   = document.getElementById('inv-bank').value;

  // Invoice number & ref
  document.getElementById('prev-num').textContent = num;
  document.getElementById('prev-ref').textContent = num;

  // Dates
  document.getElementById('prev-date').textContent = date;
  document.getElementById('prev-due').textContent  = due;

  // Status badge
  const statusMap = {
    draft: {cls:'status-draft',lbl:'Draft'},
    sent:  {cls:'status-sent', lbl:'Sent'},
    paid:  {cls:'status-paid', lbl:'Paid'},
  };
  const sm = statusMap[status] || statusMap.draft;
  document.getElementById('prev-status').innerHTML =
    `<span class="inv-status ${sm.cls}" style="background:${sm.cls==='status-draft'?'#f0f4f8':sm.cls==='status-sent'?'#fff3d6':'#e6f7ef'};color:${sm.cls==='status-draft'?'#888':sm.cls==='status-sent'?'#c07c00':'#1a9e5e'};padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700">${sm.lbl}</span>`;
  document.getElementById('prev-footer-status').innerHTML =
    document.getElementById('prev-status').innerHTML;

  // Client
  document.getElementById('prev-cname').textContent    = cname || 'Client name';
  document.getElementById('prev-cname').style.color    = cname ? '#111' : '#aaa';
  document.getElementById('prev-cdetails').innerHTML   = [cemail,caddr,cvat?'VAT: '+cvat:''].filter(Boolean).join('<br/>') || 'Client details';
  document.getElementById('prev-cdetails').style.color = cname ? '#555' : '#aaa';

  // Line items
  const subtotal = lines.reduce((s,l)=>s+(l.qty*l.price),0);
  const vatAmt   = subtotal * vatR;
  const total    = subtotal + vatAmt;

  if(!lines.length){
    document.getElementById('prev-items').innerHTML =
      '<tr><td colspan="4" style="color:#aaa;text-align:center;padding:20px">Add line items to see them here</td></tr>';
  } else {
    document.getElementById('prev-items').innerHTML = lines.map(l=>`
      <tr>
        <td>${l.desc||'-'}</td>
        <td style="text-align:right;font-family:'DM Mono',monospace">${l.qty}</td>
        <td style="text-align:right;font-family:'DM Mono',monospace">${fmtR(l.price)}</td>
        <td style="text-align:right;font-family:'DM Mono',monospace;font-weight:600">${fmtR(l.qty*l.price)}</td>
      </tr>`).join('');
  }

  // Totals
  const vatPct = Math.round(vatR*100);
  document.getElementById('prev-vat-label').textContent = `VAT (${vatPct}%)`;
  document.getElementById('prev-sub').textContent  = fmtR(subtotal);
  document.getElementById('prev-vat-amt').textContent = fmtR(vatAmt);
  document.getElementById('prev-total').innerHTML  = `<strong>${fmtR(total)}</strong>`;

  // Form totals summary
  document.getElementById('t-sub').textContent   = fmtR(subtotal);
  document.getElementById('t-vat').textContent   = fmtR(vatAmt);
  document.getElementById('t-total').textContent = fmtR(total);

  // Notes & bank
  document.getElementById('prev-notes').textContent = notes;
  document.getElementById('prev-bank').textContent  = bank;
}

/* ── Actions ── */
// Replace the existing saveDraft(), sendInvoice() stubs with these:

async function postInvoice(actionName) {
  return fetch('invoice-generate.php', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Requested-With': 'XMLHttpRequest'
    },
    body: new URLSearchParams({
      action:          actionName,
      invoice_number:  document.getElementById('inv-num').value,
      client_id:       document.getElementById('client-select').value || '0',
      issue_date:      document.getElementById('inv-date').value,
      due_date:        document.getElementById('inv-due').value,
      tax_rate:        document.getElementById('vat-rate').value || '15',
      notes:           document.getElementById('inv-notes').value,
      lines:           JSON.stringify(lines.map(l => ({ desc: l.desc, qty: l.qty, price: l.price })))
    }).toString()
  }).then(r => r.json()).catch(() => ({ ok: false, message: 'Network error.' }));
}

async function saveDraft() {
  const res = await postInvoice('save_draft');
  toast(res.ok ? 'Invoice saved as draft!' : res.message, res.ok ? 'success' : 'error');
}

async function sendInvoice() {
  if (!document.getElementById('c-name').value) { toast('Please select a client first.', 'error'); return; }
  if (!lines.length) { toast('Please add at least one line item.', 'error'); return; }
  const res = await postInvoice('send_invoice');
  if (res.ok) {
    toast('Invoice sent to client!');
    document.getElementById('inv-status').value = 'sent';
    updatePreview();
  } else {
    toast(res.message, 'error');
  }
}
function resetForm(){
  if(!confirm('Reset all invoice data?')) return;
  document.getElementById('inv-num').value = '<?= htmlspecialchars($nextInvoiceNo) ?>';
  document.getElementById('inv-status').value = 'draft';
  document.getElementById('client-select').value = '';
  ['c-name','c-email','c-addr','c-vat'].forEach(id=>document.getElementById(id).value='');
  lines = []; lineId = 0;
  renderLines(); updatePreview();
  toast('Form reset.');
}
function toast(msg, type='success'){
  const z  = document.getElementById('tz');
  const el = document.createElement('div');
  el.className = 't-i';
  el.style.borderColor = type==='error' ? 'rgba(255,94,58,.3)' : 'rgba(26,220,142,.3)';
  el.innerHTML = `<span style="color:${type==='error'?'#ff5e3a':'#1adc8e'};font-size:15px;font-weight:700">${type==='error'?'✕':'✓'}</span> ${msg}`;
  z.appendChild(el);
  setTimeout(()=>{ el.style.animation='tOut .3s ease-in forwards'; setTimeout(()=>el.remove(),300); }, 3200);
}

/* ── Seed two default line items ── */
addLine('IT Consulting Services', 1, 6500);
addLine('Network Configuration', 1, 3500);
updatePreview();
</script>
</body>
</html>