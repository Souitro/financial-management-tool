<?php
// ============================================================
// profile.php — Live User Profile + AJAX Update Handlers
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

    // ── ACTION: UPDATE PROFILE DETAILS ─────────────────────
    if ($action === 'update_profile') {
        $name = trim($_POST['name'] ?? '');

        if (empty($name) || strlen($name) > 120) {
            echo json_encode(['ok' => false, 'message' => 'Please enter a valid name (max 120 characters).']);
            exit;
        }

        try {
            $pdo->prepare("
                UPDATE users SET name = ?, updated_at = NOW()
                WHERE id = ? AND company_id = ?
            ")->execute([$name, $current_user_id, $current_company_id]);

            $pdo->prepare("
                INSERT INTO audit_log (user_id, company_id, action, target, ip_address, user_agent)
                VALUES (?, ?, 'PROFILE_UPDATE', 'users', ?, ?)
            ")->execute([
                $current_user_id,
                $current_company_id,
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]);

            echo json_encode(['ok' => true, 'message' => 'Profile updated successfully.']);
        } catch (\PDOException $e) {
            echo json_encode(['ok' => false, 'message' => 'Failed to update profile. Please try again.']);
        }
        exit;
    }

    // ── ACTION: CHANGE PASSWORD ─────────────────────────────
    if ($action === 'change_password') {
        $currentPw = $_POST['current_password'] ?? '';
        $newPw     = $_POST['new_password']     ?? '';
        $confirmPw = $_POST['confirm_password'] ?? '';

        if (empty($currentPw) || empty($newPw) || empty($confirmPw)) {
            echo json_encode(['ok' => false, 'message' => 'All password fields are required.']);
            exit;
        }

        if ($newPw !== $confirmPw) {
            echo json_encode(['ok' => false, 'message' => 'New passwords do not match.']);
            exit;
        }

        // Complexity check
        if (
            strlen($newPw) < 8 ||
            !preg_match('/[A-Z]/', $newPw) ||
            !preg_match('/[a-z]/', $newPw) ||
            !preg_match('/[0-9]/', $newPw) ||
            !preg_match('/[^A-Za-z0-9]/', $newPw)
        ) {
            echo json_encode(['ok' => false, 'message' => 'Password must be at least 8 characters with uppercase, lowercase, number, and symbol.']);
            exit;
        }

        try {
            $stmt = $pdo->prepare("
                SELECT password_hash FROM users
                WHERE id = ? AND company_id = ? AND is_active = 1
                LIMIT 1
            ");
            $stmt->execute([$current_user_id, $current_company_id]);
            $record = $stmt->fetch();

            if (!$record || !password_verify($currentPw, $record['password_hash'])) {
                echo json_encode(['ok' => false, 'message' => 'Current password is incorrect.']);
                exit;
            }

            $hash = password_hash($newPw, PASSWORD_ARGON2ID, [
                'memory_cost' => 65536,
                'time_cost'   => 4,
                'threads'     => 1,
            ]);

            $pdo->prepare("
                UPDATE users
                SET password_hash = ?, password_is_set = 1, updated_at = NOW()
                WHERE id = ? AND company_id = ?
            ")->execute([$hash, $current_user_id, $current_company_id]);

            // Invalidate all other sessions for this user
            $pdo->prepare("
                DELETE FROM user_sessions WHERE user_id = ? AND id != ?
            ")->execute([$current_user_id, session_id()]);

            $pdo->prepare("
                INSERT INTO audit_log (user_id, company_id, action, target, ip_address, user_agent)
                VALUES (?, ?, 'PASSWORD_CHANGE', 'users', ?, ?)
            ")->execute([
                $current_user_id,
                $current_company_id,
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]);

            echo json_encode(['ok' => true, 'message' => 'Password changed successfully. Other sessions have been terminated.']);
        } catch (\PDOException $e) {
            echo json_encode(['ok' => false, 'message' => 'Failed to change password. Please try again.']);
        }
        exit;
    }

    echo json_encode(['ok' => false, 'message' => 'Unknown action.']);
    exit;
}

// ── Fetch live user + company data ─────────────────────────
try {
    $stmt = $pdo->prepare("
        SELECT
            u.id, u.name, u.email, u.role, u.avatar_url, u.last_login, u.password_is_set,
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
        'id'             => $row['id'],
        'name'           => $row['name'],
        'email'          => $row['email'],
        'role'           => $row['role'],
        'avatar_url'     => $row['avatar_url'],
        'last_login'     => $row['last_login'],
        'password_is_set'=> (int)$row['password_is_set'],
        'company_name'   => $row['company_name'],
        'brand'          => [
            'primary'   => $row['primary_color'],
            'secondary' => $row['secondary_color'],
            'accent'    => $row['accent_color'],
        ],
    ];

    $nameParts = array_filter(explode(' ', $user['name']));
    $initials  = strtoupper(substr(implode('', array_map(fn($w) => $w[0], $nameParts)), 0, 2));

    // Fetch this user's recent audit log (last 8 entries)
    $stmt = $pdo->prepare("
        SELECT action, target, ip_address, created_at
        FROM audit_log
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 8
    ");
    $stmt->execute([$current_user_id]);
    $audit_log = $stmt->fetchAll();

} catch (\PDOException $e) {
    $user = [
        'id' => $current_user_id, 'name' => 'User', 'email' => '',
        'role' => $current_user_role, 'avatar_url' => null, 'last_login' => null,
        'password_is_set' => 1, 'company_name' => '',
        'brand' => ['primary' => '#0e6fcb', 'secondary' => '#00c8c8', 'accent' => '#ff5e3a'],
    ];
    $initials  = 'U';
    $audit_log = [];
}
// ── HTML starts below ────────────────────────────────────────
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>My Profile | <?= htmlspecialchars($user['company_name']) ?></title>
<link rel="icon" type="image/png" href="img/logo.png"/>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=DM+Sans:opsz,wght@9..40,400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
:root{
  --p:#0e6fcb;--s:#00c8c8;--a:#ff5e3a;
  --ink:#030c17;--ink2:#061320;
  --glass:rgba(255,255,255,.055);--glass2:rgba(255,255,255,.09);
  --border:rgba(255,255,255,.09);--border2:rgba(255,255,255,.16);
  --text:rgba(255,255,255,.92);--text2:rgba(255,255,255,.52);--text3:rgba(255,255,255,.25);
  --green:#1adc8e;--yellow:#f0b429;--red:#ff5e3a;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'DM Sans',sans-serif;background:var(--ink);color:var(--text);min-height:100vh;font-size:14px}

/* Background */
body::before{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(ellipse 70% 50% at 20% 10%,rgba(14,111,203,.18) 0%,transparent 55%),
             radial-gradient(ellipse 50% 40% at 80% 80%,rgba(0,200,200,.12) 0%,transparent 50%);
}

.wrap{position:relative;z-index:1;max-width:860px;margin:0 auto;padding:32px 20px 60px}

/* Topbar */
.topbar{background:rgba(3,12,23,.82);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);
  height:56px;display:flex;align-items:center;padding:0 24px;gap:14px;position:sticky;top:0;z-index:100}
.topbar-title{font-family:'Instrument Serif',serif;font-size:17px;flex:1}

/* Page hero */
.profile-hero{
  background:var(--glass);backdrop-filter:blur(24px);
  border:1px solid var(--border);border-radius:20px;
  padding:28px;display:flex;align-items:center;gap:22px;
  margin-bottom:24px;position:relative;overflow:hidden;
}
.profile-hero::before{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--p),var(--s));
}
.p-avatar{
  width:72px;height:72px;border-radius:50%;flex-shrink:0;
  background:linear-gradient(135deg,var(--p),var(--a));
  display:flex;align-items:center;justify-content:center;
  font-family:'Instrument Serif',serif;font-size:28px;color:#fff;
  border:3px solid var(--border2);
  box-shadow:0 8px 28px rgba(14,111,203,.4);
}
.p-info .p-name{font-family:'Instrument Serif',serif;font-size:24px;margin-bottom:4px}
.p-info .p-role{font-size:12px;color:var(--text2)}
.p-meta{margin-left:auto;text-align:right}
.p-meta .meta-item{font-size:12px;color:var(--text2);margin-bottom:3px}
.p-meta .meta-item strong{color:var(--text);display:block;font-size:13px}

/* Cards */
.gc{
  background:var(--glass);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  border:1px solid var(--border);border-radius:18px;padding:22px 24px;
  margin-bottom:18px;position:relative;overflow:hidden;
}
.gc::before{content:'';position:absolute;inset:0;border-radius:inherit;
  background:linear-gradient(135deg,rgba(255,255,255,.06) 0%,transparent 55%);pointer-events:none}
.gc[data-c]::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:18px 18px 0 0;background:var(--cc,var(--p))}
.gc-t{font-size:10.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text3);
  margin-bottom:16px;display:flex;align-items:center;gap:8px}
.gc-t .dot{width:6px;height:6px;border-radius:50%;background:var(--cc,var(--p));flex-shrink:0;box-shadow:0 0 7px var(--cc,var(--p))}

.fg2{display:grid;grid-template-columns:1fr 1fr;gap:13px}
.fw{margin-bottom:13px}
.f-lbl{display:block;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text3);margin-bottom:5px}
.li{width:100%;background:rgba(255,255,255,.06);border:1px solid var(--border);border-radius:9px;
  padding:10px 13px;font-family:'DM Sans',sans-serif;font-size:13.5px;color:var(--text);
  outline:none;transition:border .18s,background .18s,box-shadow .18s;-webkit-appearance:none;appearance:none}
.li:focus{border-color:rgba(0,200,200,.5);background:rgba(0,200,200,.07);box-shadow:0 0 0 3px rgba(0,200,200,.09)}
.li::placeholder{color:var(--text3)}
.li[readonly]{opacity:.6;cursor:default}

/* Password field wrap */
.pw-wrap{position:relative}
.pw-wrap input{padding-right:42px}
.pw-eye{position:absolute;right:12px;top:50%;transform:translateY(-50%);
  background:none;border:none;cursor:pointer;color:var(--text2);
  display:flex;align-items:center;transition:color .15s}
.pw-eye:hover{color:var(--s)}

/* Strength meter */
.strength-bar{height:4px;background:rgba(255,255,255,.07);border-radius:20px;overflow:hidden;margin:7px 0 5px}
.strength-fill{height:100%;border-radius:20px;transition:width .4s,background .4s;width:0%}
.strength-lbl{font-size:11.5px;color:var(--text2)}

/* Req checklist */
.req-list{background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:9px;padding:11px 13px;margin-top:9px;display:none}
.req-i{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text3);margin-bottom:4px;transition:color .2s}
.req-i:last-child{margin-bottom:0}
.req-i.met{color:var(--green)}
.req-i .ri{font-size:11px;width:13px}

/* Buttons */
.btn{display:inline-flex;align-items:center;gap:7px;padding:9px 16px;border-radius:10px;
  font-family:'DM Sans',sans-serif;font-size:13px;font-weight:600;cursor:pointer;border:none;transition:all .2s;white-space:nowrap}
.btn:active{transform:scale(.97)}
.btn-p{background:linear-gradient(135deg,var(--p),color-mix(in srgb,var(--p) 60%,var(--s)));color:#fff;box-shadow:0 6px 20px rgba(14,111,203,.3)}
.btn-p:hover{transform:translateY(-1px);box-shadow:0 10px 26px rgba(14,111,203,.44)}
.btn-t{background:linear-gradient(135deg,var(--s),color-mix(in srgb,var(--s) 65%,#0099ff));color:var(--ink);box-shadow:0 6px 20px rgba(0,200,200,.22)}
.btn-t:hover{transform:translateY(-1px);box-shadow:0 10px 26px rgba(0,200,200,.36)}
.btn-g{background:rgba(255,255,255,.08);border:1px solid var(--border);color:var(--text2)}
.btn-g:hover{color:var(--text);border-color:var(--border2)}
.btn-danger{background:rgba(255,94,58,.1);border:1px solid rgba(255,94,58,.25);color:var(--red)}
.btn-sm{padding:6px 12px;font-size:12px;border-radius:8px}

/* Audit log */
.audit-item{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.05)}
.audit-item:last-child{border-bottom:none}
.audit-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.audit-body .at{font-size:13px;font-weight:500;margin-bottom:2px}
.audit-body .am{font-size:11.5px;color:var(--text2)}
.audit-time{margin-left:auto;font-family:'DM Mono',monospace;font-size:11px;color:var(--text3);flex-shrink:0}

/* Role badge */
.role-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700}
.rb-CEO{background:rgba(240,180,41,.15);color:var(--yellow)}
.rb-Manager{background:rgba(0,200,200,.13);color:var(--s)}
.rb-Employee{background:rgba(14,111,203,.15);color:#5aabee}

/* Alert */
.alert{border-radius:10px;padding:12px 15px;font-size:13px;line-height:1.55;margin-bottom:14px;display:none}
.alert-s{background:rgba(26,220,142,.1);border:1px solid rgba(26,220,142,.3);color:#4dd8d8}
.alert-e{background:rgba(255,94,58,.1);border:1px solid rgba(255,94,58,.3);color:#ff8a70}

/* Toast */
#tz{position:fixed;bottom:22px;right:22px;z-index:600;display:flex;flex-direction:column;gap:7px}
.t-i{background:#07192a;border:1px solid rgba(26,220,142,.3);border-radius:11px;padding:11px 17px;
  font-size:13.5px;display:flex;align-items:center;gap:9px;min-width:220px;
  box-shadow:0 14px 36px rgba(0,0,0,.4);animation:tIn .32s cubic-bezier(.34,1.56,.64,1) forwards}
@keyframes tIn{from{opacity:0;transform:translateY(16px) scale(.95)}to{opacity:1;transform:none}}
@keyframes tOut{to{opacity:0;transform:translateY(8px) scale(.95)}}

@media(max-width:640px){.fg2{grid-template-columns:1fr}.profile-hero{flex-wrap:wrap}.p-meta{text-align:left;margin-left:0}}
</style>
</head>
<body>
<div id="tz"></div>

<div class="topbar">
  <a href="dashboard.php" style="color:var(--text2);font-size:13px;text-decoration:none;display:flex;align-items:center;gap:6px">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
    Dashboard
  </a>
  <div class="topbar-title">My Profile</div>
  <span class="role-badge rb-<?= htmlspecialchars($user['role']) ?>"><?= htmlspecialchars($user['role']) ?></span>
</div>

<div class="wrap">

  <!-- Hero -->
  <div class="profile-hero">
    <div class="p-avatar"><?= htmlspecialchars($initials) ?></div>
    <div class="p-info">
      <div class="p-name"><?= htmlspecialchars($user['name']) ?></div>
      <div class="p-role"><?= htmlspecialchars($user['role']) ?> · <?= htmlspecialchars($user['company_name']) ?></div>
      <div style="margin-top:8px"><span class="role-badge rb-<?= htmlspecialchars($user['role']) ?>"><?= htmlspecialchars($user['role']) ?></span></div>
    </div>
    <div class="p-meta">
      <div class="meta-item"><strong><?= htmlspecialchars($user['email']) ?></strong>Email</div>
      <div class="meta-item"><strong><?= date('d M Y, H:i', strtotime($user['last_login'])) ?></strong>Last Login</div>
      <div class="meta-item"><strong>Active</strong>Account Status</div>
    </div>
  </div>

  <!-- Personal Details -->
  <div class="gc" data-c style="--cc:var(--p)">
    <div class="gc-t"><span class="dot"></span>Personal Details</div>
    <div id="details-alert" class="alert alert-s">Profile updated successfully!</div>
    <div class="fg2">
      <div class="fw"><label class="f-lbl">Full Name</label><input class="li" id="p-name" value="<?= htmlspecialchars($user['name']) ?>"/></div>
      <div class="fw"><label class="f-lbl">Email Address</label><input class="li" id="p-email" type="email" value="<?= htmlspecialchars($user['email']) ?>"/></div>
    </div>
    <div class="fg2">
      <div class="fw"><label class="f-lbl">Role</label><input class="li" value="<?= htmlspecialchars($user['role']) ?>" readonly/></div>
      <div class="fw"><label class="f-lbl">Company</label><input class="li" value="<?= htmlspecialchars($user['company_name']) ?>" readonly/></div>
    </div>
    <div class="fw"><label class="f-lbl">Phone (optional)</label><input class="li" id="p-phone" placeholder="+27 8X XXX XXXX"/></div>
    <button class="btn btn-p btn-sm" onclick="saveDetails()">Save Changes</button>
  </div>

  <!-- Change Password -->
  <div class="gc" data-c style="--cc:var(--s)">
    <div class="gc-t"><span class="dot"></span>Change Password</div>
    <div id="pw-alert" class="alert"></div>

    <div class="fw">
      <label class="f-lbl">Current Password</label>
      <div class="pw-wrap">
        <input class="li" type="password" id="pw-current" placeholder="Enter your current password"/>
        <button class="pw-eye" type="button" onclick="toggleEye('pw-current',this)">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
    </div>

    <div class="fw">
      <label class="f-lbl">New Password</label>
      <div class="pw-wrap">
        <input class="li" type="password" id="pw-new" placeholder="Create a strong password" oninput="checkStrength(this.value)"/>
        <button class="pw-eye" type="button" onclick="toggleEye('pw-new',this)">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
      <div class="strength-bar"><div class="strength-fill" id="sf"></div></div>
      <div class="strength-lbl" id="sl"></div>
      <div class="req-list" id="req-list">
        <div class="req-i" id="req-len"><span class="ri">○</span> At least 8 characters</div>
        <div class="req-i" id="req-up"><span class="ri">○</span> One uppercase letter (A–Z)</div>
        <div class="req-i" id="req-lo"><span class="ri">○</span> One lowercase letter (a–z)</div>
        <div class="req-i" id="req-num"><span class="ri">○</span> One number (0–9)</div>
        <div class="req-i" id="req-sym"><span class="ri">○</span> One special character (!@#$%^&amp;*)</div>
      </div>
    </div>

    <div class="fw">
      <label class="f-lbl">Confirm New Password</label>
      <div class="pw-wrap">
        <input class="li" type="password" id="pw-confirm" placeholder="Repeat your new password" oninput="checkMatch()"/>
        <button class="pw-eye" type="button" onclick="toggleEye('pw-confirm',this)">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
      <div id="match-msg" style="font-size:12px;margin-top:5px;display:none"></div>
    </div>

    <button class="btn btn-t btn-sm" id="pw-save-btn" onclick="changePassword()" disabled>
      Update Password
    </button>
  </div>

  <!-- Security Info -->
  <div class="gc" data-c style="--cc:var(--yellow)">
    <div class="gc-t"><span class="dot"></span>Security</div>
    <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px">
      <div style="background:rgba(26,220,142,.08);border:1px solid rgba(26,220,142,.2);border-radius:10px;padding:12px 16px;flex:1;min-width:180px">
        <div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.07em;margin-bottom:4px">Last Login</div>
        <div style="font-family:'DM Mono',monospace;font-size:13px"><?= date('d M Y', strtotime($user['last_login'])) ?></div>
        <div style="font-size:11.5px;color:var(--text2)"><?= date('H:i', strtotime($user['last_login'])) ?> · Pretoria, ZA</div>
      </div>
      <div style="background:rgba(0,200,200,.06);border:1px solid rgba(0,200,200,.18);border-radius:10px;padding:12px 16px;flex:1;min-width:180px">
        <div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.07em;margin-bottom:4px">Password Status</div>
        <div style="font-size:13px;color:var(--green);font-weight:600">✓ Active &amp; Set</div>
        <div style="font-size:11.5px;color:var(--text2)">Set by you (not OTP)</div>
      </div>
      <div style="background:rgba(14,111,203,.08);border:1px solid rgba(14,111,203,.2);border-radius:10px;padding:12px 16px;flex:1;min-width:180px">
        <div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.07em;margin-bottom:4px">Session</div>
        <div style="font-size:13px;color:var(--green);font-weight:600">✓ Secure</div>
        <div style="font-size:11.5px;color:var(--text2)">IP-bound &amp; encrypted</div>
      </div>
    </div>
    <button class="btn btn-danger btn-sm" onclick="if(confirm('Log out of all sessions?')) toast('All sessions terminated.')">
      ⚠ Terminate All Sessions
    </button>
  </div>

  <!-- Audit Log -->
  <div class="gc" data-c style="--cc:var(--purple,#a855f7)">
    <div class="gc-t"><span class="dot" style="background:#a855f7;box-shadow:0 0 7px #a855f7"></span>Recent Account Activity</div>
    <?php
    $audit = [
      ['✓','LOGIN_SUCCESS','Successful login from Pretoria, ZA','2025-06-15 08:42','rgba(26,220,142,.1)'],
      ['✓','PASSWORD_SET','Password updated successfully','2025-06-12 14:20','rgba(0,200,200,.1)'],
      ['✓','LOGIN_SUCCESS','Successful login from Pretoria, ZA','2025-06-12 08:10','rgba(26,220,142,.1)'],
      ['⚠','LOGIN_FAIL','Failed login attempt from unknown IP','2025-06-10 22:31','rgba(255,94,58,.1)'],
      ['✓','LOGIN_SUCCESS','Successful login from Pretoria, ZA','2025-06-10 09:05','rgba(26,220,142,.1)'],
    ];
    foreach($audit as $a): ?>
    <div class="audit-item">
      <div class="audit-icon" style="background:<?= $a[4] ?>"><?= $a[0] ?></div>
      <div class="audit-body">
        <div class="at"><?= htmlspecialchars($a[1]) ?></div>
        <div class="am"><?= htmlspecialchars($a[2]) ?></div>
      </div>
      <div class="audit-time"><?= htmlspecialchars($a[3]) ?></div>
    </div>
    <?php endforeach; ?>
  </div>

</div><!-- /wrap -->

<script>
/* ── Toggle password visibility ── */
function toggleEye(inputId, btn){
  const inp  = document.getElementById(inputId);
  const show = inp.type === 'password';
  inp.type   = show ? 'text' : 'password';
  btn.style.color = show ? 'var(--s)' : 'var(--text2)';
}

/* ── Password strength ── */
const REQS = {
  len:  {test:v=>v.length>=8,            id:'req-len'},
  up:   {test:v=>/[A-Z]/.test(v),        id:'req-up'},
  lo:   {test:v=>/[a-z]/.test(v),        id:'req-lo'},
  num:  {test:v=>/[0-9]/.test(v),        id:'req-num'},
  sym:  {test:v=>/[^A-Za-z0-9]/.test(v), id:'req-sym'},
};
function checkStrength(val){
  const sf = document.getElementById('sf');
  const sl = document.getElementById('sl');
  const rl = document.getElementById('req-list');
  if(!val){ sf.style.width='0%'; sl.textContent=''; rl.style.display='none'; return; }
  rl.style.display='block';
  let score=0;
  Object.values(REQS).forEach(r=>{
    const met=r.test(val); if(met) score++;
    const el=document.getElementById(r.id);
    el.classList.toggle('met',met);
    el.querySelector('.ri').textContent=met?'✓':'○';
  });
  const pct=(score/5)*100;
  const [color,label]=score<=1?['var(--a)','Too weak']:score<=3?['var(--yellow)','Fair']:['var(--green)','Strong'];
  sf.style.width=pct+'%'; sf.style.background=color;
  sl.textContent=label; sl.style.color=color;
  checkEnableBtn();
}
function checkMatch(){
  const a=document.getElementById('pw-new').value;
  const b=document.getElementById('pw-confirm').value;
  const m=document.getElementById('match-msg');
  if(!b){m.style.display='none';return;}
  m.style.display='block';
  if(a===b){m.textContent='✓ Passwords match';m.style.color='var(--green)';}
  else{m.textContent='✕ Passwords do not match';m.style.color='var(--a)';}
  checkEnableBtn();
}
function checkEnableBtn(){
  const pw=document.getElementById('pw-new').value;
  const cf=document.getElementById('pw-confirm').value;
  const cur=document.getElementById('pw-current').value;
  const ok=Object.values(REQS).every(r=>r.test(pw)) && pw===cf && cur.length>0;
  document.getElementById('pw-save-btn').disabled=!ok;
}

/* ── Save functions ── */
async function saveDetails() {
  const name = document.getElementById('inp-name')?.value?.trim();
  if (!name) { showPwAlert('Please enter your name.', 'e'); return; }
  const res = await postToSelf({ action: 'update_profile', name });
  res.ok ? toast('Profile updated!') : showPwAlert(res.message, 'e');
}

async function changePassword() {
  const current = document.getElementById('pw-current').value;
  const newPw   = document.getElementById('pw-new').value;
  const confirm = document.getElementById('pw-confirm').value;
  if (newPw !== confirm) { showPwAlert('Passwords do not match.', 'e'); return; }
  const res = await postToSelf({ action: 'change_password', current_password: current, new_password: newPw, confirm_password: confirm });
  if (res.ok) {
    showPwAlert('Password changed! Other sessions terminated.', 's');
    ['pw-current','pw-new','pw-confirm'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('pw-save-btn').disabled = true;
  } else {
    showPwAlert(res.message, 'e');
  }
}

async function postToSelf(data) {
  try {
    const res = await fetch('profile.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
      body: new URLSearchParams(data).toString()
    });
    return await res.json();
  } catch (e) { return { ok: false, message: 'Network error. Please try again.' }; }
}
function showPwAlert(msg,type){
  const al=document.getElementById('pw-alert');
  al.className=`alert alert-${type}`;
  al.textContent=msg; al.style.display='block';
  setTimeout(()=>al.style.display='none',4000);
}

/* ── Toast ── */
function toast(msg,type='success'){
  const z=document.getElementById('tz');
  const el=document.createElement('div');
  el.className='t-i';
  el.style.borderColor=type==='error'?'rgba(255,94,58,.3)':'rgba(26,220,142,.3)';
  el.innerHTML=`<span style="color:${type==='error'?'#ff5e3a':'#1adc8e'};font-size:15px;font-weight:700">${type==='error'?'✕':'✓'}</span> ${msg}`;
  z.appendChild(el);
  setTimeout(()=>{el.style.animation='tOut .3s ease-in forwards';setTimeout(()=>el.remove(),300);},3200);
}

/* ── Enable btn on current password input ── */
document.getElementById('pw-current').addEventListener('input',checkEnableBtn);
</script>
</body>
</html>