<?php
// ============================================================
// login.php — Auth Gateway + Embedded AJAX Handler
// Handles: password_login | otp_verify | set_password
// ============================================================
date_default_timezone_set('Africa/Johannesburg');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ── Company display config ──────────────────────────────────
$companyName    = 'Souitro Innovative Tech Solutions';
$companyTagline = 'Where Your Tech Vision Takes Root';
$logoLetter     = 'S';

// ── Already authenticated — bypass login ───────────────────
if (isset($_SESSION['user_id'], $_SESSION['company_id'])) {
    header('Location: dashboard.php');
    exit;
}

// ── PDO Connection ──────────────────────────────────────────
$host    = '127.0.0.1';
$db      = 'souitro_db';
$user    = 'root';
$pass    = '';
$charset = 'utf8mb4';

$dsn     = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
    // Sync MySQL session timezone with PHP
    $pdo->exec("SET time_zone = '+02:00'");
} catch (\PDOException $e) {
    // If DB is down during an AJAX call, return JSON error
    if (
        $_SERVER['REQUEST_METHOD'] === 'POST' &&
        isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest'
    ) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Database connection failed. Please try again later.']);
        exit;
    }
    // For page load failures, show a user-safe message
    die('System temporarily unavailable. Please contact support.');
}

// ── CSRF Token Generation ───────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// ── AJAX Handler Block ──────────────────────────────────────
if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest'
) {
    header('Content-Type: application/json');

    // CSRF Validation
    $submitted_csrf = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $submitted_csrf)) {
        echo json_encode(['ok' => false, 'message' => 'Security token mismatch. Please refresh the page.']);
        exit;
    }

    $action = $_POST['action'] ?? '';
    $email  = isset($_POST['email']) ? trim(strtolower($_POST['email'])) : '';

    // ── ACTION 1: PASSWORD LOGIN ────────────────────────────
    if ($action === 'password_login') {
        $password = $_POST['password'] ?? '';

        if (empty($email) || empty($password)) {
            echo json_encode(['ok' => false, 'message' => 'Please provide your email and password.']);
            exit;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo json_encode(['ok' => false, 'message' => 'Invalid email format.']);
            exit;
        }

        try {
            $stmt = $pdo->prepare("
                SELECT id, company_id, password_hash, password_is_set,
                       role, failed_attempts, locked_until
                FROM users
                WHERE email = ? AND is_active = 1
                LIMIT 1
            ");
            $stmt->execute([$email]);
            $record = $stmt->fetch();
        } catch (\PDOException $e) {
            echo json_encode(['ok' => false, 'message' => 'A server error occurred. Please try again.']);
            exit;
        }

        // Generic message to prevent user enumeration
        if (!$record) {
            echo json_encode(['ok' => false, 'message' => 'Invalid email or password.']);
            exit;
        }

        // Brute-force lock check
        if ($record['locked_until'] && strtotime($record['locked_until']) > time()) {
            $minsLeft = ceil((strtotime($record['locked_until']) - time()) / 60);
            echo json_encode(['ok' => false, 'message' => "Account locked. Try again in {$minsLeft} minute(s)."]);
            exit;
        }

        // New user — route to OTP setup flow
        if ((int)$record['password_is_set'] === 0) {
            $_SESSION['pending_email'] = $email;
            echo json_encode(['ok' => true, 'use_otp' => true, 'message' => 'Account setup required. Please enter your OTP.']);
            exit;
        }

        if (password_verify($password, $record['password_hash'])) {
            // Success — reset counters, set session
            try {
                $pdo->prepare("
                    UPDATE users
                    SET failed_attempts = 0, locked_until = NULL, last_login = NOW()
                    WHERE id = ?
                ")->execute([$record['id']]);

                // Register session in user_sessions table
                $pdo->prepare("
                    INSERT INTO user_sessions (id, user_id, ip_address, user_agent, last_active)
                    VALUES (?, ?, ?, ?, NOW())
                    ON DUPLICATE KEY UPDATE last_active = NOW()
                ")->execute([
                    session_id(),
                    $record['id'],
                    $_SERVER['REMOTE_ADDR'],
                    $_SERVER['HTTP_USER_AGENT'] ?? '',
                ]);

                // Write audit log
                $pdo->prepare("
                    INSERT INTO audit_log (user_id, company_id, action, target, ip_address, user_agent)
                    VALUES (?, ?, 'LOGIN_SUCCESS', 'users', ?, ?)
                ")->execute([
                    $record['id'],
                    $record['company_id'],
                    $_SERVER['REMOTE_ADDR'],
                    $_SERVER['HTTP_USER_AGENT'] ?? '',
                ]);
            } catch (\PDOException $e) {
                // Non-fatal — session still works even if logging fails
            }

            session_regenerate_id(true);
            $_SESSION['user_id']    = $record['id'];
            $_SESSION['company_id'] = $record['company_id'];
            $_SESSION['user_role']  = $record['role'];
            $_SESSION['user_ip']    = $_SERVER['REMOTE_ADDR'];
            $_SESSION['user_ua']    = $_SERVER['HTTP_USER_AGENT'] ?? '';
            $_SESSION['login_time'] = time();
            unset($_SESSION['pending_email']);

            echo json_encode(['ok' => true, 'redirect' => 'dashboard.php']);
        } else {
            // Failed attempt — increment counter
            $failed   = (int)$record['failed_attempts'] + 1;
            $lockTime = ($failed >= 5) ? date('Y-m-d H:i:s', strtotime('+15 minutes')) : null;

            try {
                $pdo->prepare("
                    UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?
                ")->execute([$failed, $lockTime, $record['id']]);

                $pdo->prepare("
                    INSERT INTO audit_log (user_id, company_id, action, target, ip_address, user_agent)
                    VALUES (?, ?, 'LOGIN_FAIL', 'users', ?, ?)
                ")->execute([
                    $record['id'],
                    $record['company_id'],
                    $_SERVER['REMOTE_ADDR'],
                    $_SERVER['HTTP_USER_AGENT'] ?? '',
                ]);
            } catch (\PDOException $e) { /* non-fatal */ }

            $msg = ($failed >= 5)
                ? 'Too many failed attempts. Account locked for 15 minutes.'
                : "Invalid email or password. Attempt {$failed} of 5.";

            echo json_encode(['ok' => false, 'message' => $msg]);
        }
        exit;
    }

    // ── ACTION 2: OTP VERIFY ───────────────────────────────
    if ($action === 'otp_verify') {
        $otp   = isset($_POST['otp']) ? trim($_POST['otp']) : '';
        $email = $_SESSION['pending_email'] ?? $email;

        if (empty($otp) || empty($email)) {
            echo json_encode(['ok' => false, 'message' => 'OTP and email are required.']);
            exit;
        }

        try {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND is_active = 1 LIMIT 1");
            $stmt->execute([$email]);
            $record = $stmt->fetch();

            if (!$record) {
                echo json_encode(['ok' => false, 'message' => 'User account not found.']);
                exit;
            }

            // Fetch the latest unused, unexpired OTP
            $stmt = $pdo->prepare("
                SELECT id, otp_hash
                FROM user_otp
                WHERE user_id = ? AND is_used = 0 AND expires_at > NOW()
                ORDER BY created_at DESC
                LIMIT 1
            ");
            $stmt->execute([$record['id']]);
            $otpRecord = $stmt->fetch();
        } catch (\PDOException $e) {
            echo json_encode(['ok' => false, 'message' => 'Server error during OTP verification.']);
            exit;
        }

        // Normalise input — strip dashes, uppercase
        $otpClean = strtoupper(str_replace('-', '', $otp));

        if ($otpRecord && password_verify($otpClean, $otpRecord['otp_hash'])) {
            try {
                $pdo->prepare("
                    UPDATE user_otp SET is_used = 1, used_at = NOW() WHERE id = ?
                ")->execute([$otpRecord['id']]);
            } catch (\PDOException $e) { /* non-fatal */ }

            $_SESSION['otp_verified_user_id'] = $record['id'];
            echo json_encode(['ok' => true, 'message' => 'OTP verified. Please set your password.']);
        } else {
            echo json_encode(['ok' => false, 'message' => 'Invalid or expired OTP. Please try again.']);
        }
        exit;
    }

    // ── ACTION 3: SET PASSWORD ─────────────────────────────
    if ($action === 'set_password') {
        $newPassword  = $_POST['new_password']     ?? '';
        $confirmPw    = $_POST['confirm_password'] ?? '';
        $userId       = $_SESSION['otp_verified_user_id'] ?? null;

        if (!$userId) {
            echo json_encode(['ok' => false, 'message' => 'Session expired. Please verify your OTP again.']);
            exit;
        }

        if ($newPassword !== $confirmPw) {
            echo json_encode(['ok' => false, 'message' => 'Passwords do not match.']);
            exit;
        }

        // Enforce complexity: min 8 chars, uppercase, lowercase, number, symbol
        if (
            strlen($newPassword) < 8 ||
            !preg_match('/[A-Z]/', $newPassword) ||
            !preg_match('/[a-z]/', $newPassword) ||
            !preg_match('/[0-9]/', $newPassword) ||
            !preg_match('/[^A-Za-z0-9]/', $newPassword)
        ) {
            echo json_encode(['ok' => false, 'message' => 'Password does not meet complexity requirements.']);
            exit;
        }

        $hash = password_hash($newPassword, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost'   => 4,
            'threads'     => 1,
        ]);

        try {
            $pdo->prepare("
                UPDATE users
                SET password_hash = ?, password_is_set = 1,
                    failed_attempts = 0, locked_until = NULL, last_login = NOW()
                WHERE id = ?
            ")->execute([$hash, $userId]);

            // Fetch user to build session
            $stmt = $pdo->prepare("SELECT id, company_id, role FROM users WHERE id = ? LIMIT 1");
            $stmt->execute([$userId]);
            $record = $stmt->fetch();

            // Audit
            $pdo->prepare("
                INSERT INTO audit_log (user_id, company_id, action, target, ip_address, user_agent)
                VALUES (?, ?, 'PASSWORD_SET', 'users', ?, ?)
            ")->execute([
                $record['id'],
                $record['company_id'],
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]);

            // Register session
            $pdo->prepare("
                INSERT INTO user_sessions (id, user_id, ip_address, user_agent, last_active)
                VALUES (?, ?, ?, ?, NOW())
                ON DUPLICATE KEY UPDATE last_active = NOW()
            ")->execute([
                session_id(),
                $record['id'],
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]);
        } catch (\PDOException $e) {
            echo json_encode(['ok' => false, 'message' => 'Failed to save password. Please try again.']);
            exit;
        }

        session_regenerate_id(true);
        $_SESSION['user_id']    = $record['id'];
        $_SESSION['company_id'] = $record['company_id'];
        $_SESSION['user_role']  = $record['role'];
        $_SESSION['user_ip']    = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_ua']    = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $_SESSION['login_time'] = time();
        unset($_SESSION['otp_verified_user_id'], $_SESSION['pending_email']);

        echo json_encode(['ok' => true, 'redirect' => 'dashboard.php']);
        exit;
    }

    // Unknown action
    echo json_encode(['ok' => false, 'message' => 'Unknown action.']);
    exit;
}
// ── End of AJAX block. HTML starts below this closing tag. ──
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Sign In | <?= htmlspecialchars($companyName) ?></title>
<link rel="icon" type="image/png" href="img/logo.png"/>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=DM+Sans:opsz,wght@9..40,300;400;500;600&display=swap" rel="stylesheet"/>
<style>
/* ============================================================
   SOUITRO LOGIN — Liquid Dark Luxury
   Aesthetic: Deep navy ink + liquid teal/coral accents
   Typography: Instrument Serif (display) + DM Sans (UI)
   ============================================================ */

:root {
  --ink:      #030d18;
  --ink2:     #071525;
  --ink3:     #0c2038;
  --blue:     #0e6fcb;
  --teal:     #00c8c8;
  --coral:    #ff5e3a;
  --gold:     #f0b429;
  --white:    #ffffff;
  --text:     rgba(255,255,255,.90);
  --text2:    rgba(255,255,255,.50);
  --text3:    rgba(255,255,255,.22);
  --border:   rgba(255,255,255,.09);
  --border2:  rgba(255,255,255,.16);
  --glass:    rgba(255,255,255,.055);
  --glass2:   rgba(255,255,255,.09);
  --r:        18px;
  --rb:       12px;
  --ease:     cubic-bezier(0.16,1,0.3,1);
  --spring:   cubic-bezier(0.34,1.56,0.64,1);
}

*, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
html, body {
  height:100%;
  font-family:'DM Sans', sans-serif;
  background: var(--ink);
  color: var(--text);
  overflow: hidden;
  cursor: none;
}

/* ── Custom cursor ── */
#cur, #cur-r {
  position:fixed; border-radius:50%;
  pointer-events:none; z-index:9999;
  transform:translate(-50%,-50%);
}
#cur {
  width:9px; height:9px;
  background: var(--teal);
  transition: width .15s, height .15s, background .2s;
  mix-blend-mode: screen;
}
#cur-r {
  width:32px; height:32px;
  border:1.5px solid rgba(0,200,200,.35);
  transition: left .09s ease-out, top .09s ease-out,
              width .22s, height .22s, border-color .22s;
}
body.hov #cur   { width:16px; height:16px; background:var(--coral); }
body.hov #cur-r { width:44px; height:44px; border-color:rgba(255,94,58,.45); }

/* ── Ripple ── */
.rpl {
  position:fixed; border-radius:50%;
  background:rgba(0,200,200,.13);
  pointer-events:none; z-index:9990;
  transform:translate(-50%,-50%) scale(0);
  animation:rplOut .6s ease-out forwards;
}
@keyframes rplOut { to { transform:translate(-50%,-50%) scale(1); opacity:0; } }

/* ── Full-page canvas background ── */
#bg-canvas { position:fixed; inset:0; z-index:0; }

/* ── Animated blobs ── */
.blob {
  position:fixed; border-radius:50%;
  filter:blur(90px); pointer-events:none; z-index:1;
  will-change:transform;
}
#b1 { width:700px; height:700px; top:-200px; left:-200px;
      background:radial-gradient(circle,rgba(14,111,203,.30) 0%,transparent 65%);
      animation:bf 16s ease-in-out infinite alternate; }
#b2 { width:500px; height:500px; bottom:-120px; right:-120px;
      background:radial-gradient(circle,rgba(0,200,200,.22) 0%,transparent 65%);
      animation:bf 12s ease-in-out infinite alternate-reverse; animation-delay:-5s; }
#b3 { width:360px; height:360px; top:30%; left:50%;
      background:radial-gradient(circle,rgba(255,94,58,.15) 0%,transparent 65%);
      animation:bf 10s ease-in-out infinite alternate; animation-delay:-8s; }
@keyframes bf {
  from { transform:translate(0,0) scale(1); }
  to   { transform:translate(40px,-50px) scale(1.12); }
}

/* ── Grid overlay texture ── */
#grid-overlay {
  position:fixed; inset:0; z-index:2; pointer-events:none;
  background-image:
    linear-gradient(rgba(255,255,255,.022) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.022) 1px, transparent 1px);
  background-size:60px 60px;
  mask-image:radial-gradient(ellipse 80% 80% at 50% 50%,
               black 30%, transparent 100%);
  -webkit-mask-image:radial-gradient(ellipse 80% 80% at 50% 50%,
               black 30%, transparent 100%);
}

/* ── Layout ── */
#layout {
  position:relative; z-index:3;
  display:grid;
  grid-template-columns:1fr 1fr;
  height:100vh;
}

/* ── LEFT PANEL — Brand ── */
#left {
  display:flex; flex-direction:column;
  justify-content:space-between;
  padding:48px;
  border-right:1px solid var(--border);
  position:relative; overflow:hidden;
}

.brand-logo {
  display:flex; align-items:center; gap:14px;
}
.brand-icon {
  width:48px; height:48px; border-radius:14px;
  background:linear-gradient(135deg,var(--blue),var(--teal));
  display:flex; align-items:center; justify-content:center;
  font-family:'Instrument Serif', serif;
  font-size:24px; font-weight:400; color:#fff;
  box-shadow:0 8px 28px rgba(14,111,203,.4);
  flex-shrink:0;
}
.brand-text .name {
  font-family:'Instrument Serif', serif;
  font-size:20px; font-weight:400; color:var(--text);
  letter-spacing:-.01em;
}
.brand-text .tagline {
  font-size:11.5px; color:var(--text3);
  letter-spacing:.06em; text-transform:uppercase;
  margin-top:2px;
}

/* Hero text */
.left-hero { flex:1; display:flex; flex-direction:column; justify-content:center; }
.left-hero .eyebrow {
  font-size:11px; font-weight:600; letter-spacing:.14em;
  text-transform:uppercase;
  color:var(--teal);
  margin-bottom:20px;
  display:flex; align-items:center; gap:10px;
}
.left-hero .eyebrow::before {
  content:'';
  display:block; width:28px; height:1.5px;
  background:var(--teal); border-radius:2px;
}
.left-hero h1 {
  font-family:'Instrument Serif', serif;
  font-size:clamp(38px,4vw,58px);
  font-weight:400; line-height:1.05;
  letter-spacing:-.02em;
  margin-bottom:22px;
}
.left-hero h1 em {
  font-style:italic; color:var(--teal);
}
.left-hero p {
  font-size:15px; color:var(--text2);
  line-height:1.75; max-width:360px;
}

/* Feature pills */
.feature-pills {
  display:flex; flex-wrap:wrap; gap:8px; margin-top:32px;
}
.fp {
  display:flex; align-items:center; gap:7px;
  background:var(--glass); border:1px solid var(--border);
  border-radius:40px; padding:7px 14px;
  font-size:12px; color:var(--text2);
  transition:all .2s;
}
.fp:hover { background:var(--glass2); color:var(--text); border-color:var(--border2); }
.fp .fp-dot { width:6px; height:6px; border-radius:50%; flex-shrink:0; }

/* Bottom stat strip */
.left-stats {
  display:flex; gap:28px;
  padding-top:28px;
  border-top:1px solid var(--border);
}
.ls-item .ls-val {
  font-family:'Instrument Serif', serif;
  font-size:26px; line-height:1;
  color:var(--text);
}
.ls-item .ls-label {
  font-size:11px; color:var(--text3);
  text-transform:uppercase; letter-spacing:.06em;
  margin-top:3px;
}

/* Vertical teal line accent */
#left::before {
  content:'';
  position:absolute; top:0; right:0; bottom:0; width:1px;
  background:linear-gradient(180deg,transparent 0%,var(--teal) 50%,transparent 100%);
  opacity:.35;
}

/* ── RIGHT PANEL — Form ── */
#right {
  display:flex; align-items:center; justify-content:center;
  padding:40px;
}

.form-shell {
  width:100%; max-width:420px;
}

/* Step indicator */
.steps {
  display:flex; align-items:center; gap:0; margin-bottom:36px;
}
.step {
  display:flex; align-items:center; gap:8px;
  font-size:12px; font-weight:600; color:var(--text3);
  transition:color .3s;
}
.step.active { color:var(--teal); }
.step.done   { color:var(--text2); }
.step-num {
  width:26px; height:26px; border-radius:50%;
  border:1.5px solid currentColor;
  display:flex; align-items:center; justify-content:center;
  font-size:11px; font-weight:700;
  transition:all .3s;
  flex-shrink:0;
}
.step.active .step-num {
  background:var(--teal); border-color:var(--teal); color:var(--ink);
}
.step.done .step-num {
  background:rgba(255,255,255,.08); border-color:rgba(255,255,255,.15);
}
.step-line {
  flex:1; height:1px; background:var(--border); margin:0 10px;
  transition:background .3s;
}
.step-line.done { background:rgba(0,200,200,.35); }

/* Form header */
.form-head { margin-bottom:28px; }
.form-head .fh-title {
  font-family:'Instrument Serif', serif;
  font-size:28px; font-weight:400;
  letter-spacing:-.01em; margin-bottom:6px;
  transition:all .3s;
}
.form-head .fh-sub {
  font-size:13.5px; color:var(--text2); line-height:1.6;
}

/* Input fields */
.field { margin-bottom:16px; }
label.lbl {
  display:block; font-size:11px; font-weight:600;
  text-transform:uppercase; letter-spacing:.08em;
  color:var(--text3); margin-bottom:7px;
}
.inp-wrap { position:relative; }
.inp-wrap .ico {
  position:absolute; left:14px; top:50%;
  transform:translateY(-50%);
  color:var(--text3); pointer-events:none;
  transition:color .2s;
  display:flex; align-items:center;
}
.liq-inp {
  width:100%;
  background:var(--glass);
  border:1px solid var(--border);
  border-radius:var(--rb);
  padding:13px 14px 13px 44px;
  font-family:'DM Sans', sans-serif;
  font-size:15px; font-weight:400;
  color:var(--text); outline:none;
  transition:border .2s, background .2s, box-shadow .2s;
  -webkit-appearance:none; appearance:none;
}
.liq-inp:focus {
  border-color:rgba(0,200,200,.55);
  background:rgba(0,200,200,.07);
  box-shadow:0 0 0 4px rgba(0,200,200,.08);
}
.liq-inp:focus ~ .ico,
.inp-wrap:focus-within .ico { color:var(--teal); }
.liq-inp::placeholder { color:var(--text3); }

/* Password eye toggle */
.eye-btn {
  position:absolute; right:14px; top:50%;
  transform:translateY(-50%);
  background:none; border:none; cursor:pointer;
  color:var(--text3); padding:4px;
  transition:color .2s; display:flex; align-items:center;
}
.eye-btn:hover { color:var(--teal); }

/* OTP input — segmented look */
.otp-wrap {
  display:flex; gap:10px; align-items:center;
}
.otp-wrap .otp-mid {
  font-size:18px; color:var(--text3); font-weight:300;
  flex-shrink:0;
}
.otp-part {
  flex:1;
  background:var(--glass);
  border:1px solid var(--border);
  border-radius:var(--rb);
  padding:14px 0;
  font-family:'DM Sans', sans-serif;
  font-size:20px; font-weight:600; letter-spacing:.2em;
  color:var(--teal); text-align:center; outline:none;
  text-transform:uppercase;
  transition:border .2s, background .2s, box-shadow .2s;
  -webkit-appearance:none; appearance:none;
}
.otp-part:focus {
  border-color:rgba(0,200,200,.6);
  background:rgba(0,200,200,.08);
  box-shadow:0 0 0 4px rgba(0,200,200,.1);
}
.otp-part::placeholder { color:var(--text3); font-size:14px; letter-spacing:.1em; }

/* Password strength meter */
#strength-meter { margin-top:8px; display:none; }
.sm-track {
  height:4px; background:rgba(255,255,255,.07);
  border-radius:20px; overflow:hidden; margin-bottom:6px;
}
.sm-fill {
  height:100%; border-radius:20px;
  transition:width .4s var(--ease), background .4s;
}
.sm-label { font-size:11.5px; color:var(--text2); }

/* Password requirements checklist */
#pw-reqs {
  display:none;
  background:rgba(255,255,255,.04);
  border:1px solid var(--border); border-radius:10px;
  padding:12px 14px; margin-top:10px;
}
.req-item {
  display:flex; align-items:center; gap:8px;
  font-size:12px; color:var(--text3);
  margin-bottom:5px; transition:color .2s;
}
.req-item:last-child { margin-bottom:0; }
.req-item.met { color:var(--teal); }
.req-item .req-icon { font-size:11px; width:14px; flex-shrink:0; }

/* Submit button */
.sub-btn {
  width:100%; padding:14px;
  background:linear-gradient(135deg, var(--blue), color-mix(in srgb, var(--blue) 55%, var(--teal)));
  border:none; border-radius:var(--rb);
  font-family:'DM Sans', sans-serif;
  font-size:15px; font-weight:600;
  color:#fff; cursor:pointer;
  transition:all .25s;
  position:relative; overflow:hidden;
  box-shadow:0 8px 28px rgba(14,111,203,.38);
  display:flex; align-items:center; justify-content:center; gap:10px;
  margin-top:6px;
}
.sub-btn::before {
  content:'';
  position:absolute; inset:0;
  background:linear-gradient(135deg,rgba(255,255,255,.12),transparent);
  opacity:0; transition:opacity .2s;
  border-radius:inherit;
}
.sub-btn:hover::before { opacity:1; }
.sub-btn:hover { transform:translateY(-2px); box-shadow:0 14px 36px rgba(14,111,203,.52); }
.sub-btn:active { transform:scale(.98); }
.sub-btn:disabled { opacity:.5; cursor:not-allowed; transform:none; }
.sub-btn.loading::after {
  content:'';
  width:16px; height:16px; border-radius:50%;
  border:2px solid rgba(255,255,255,.3);
  border-top-color:#fff;
  animation:spin .6s linear infinite;
}
@keyframes spin { to { transform:rotate(360deg); } }

/* Mode toggle link */
.mode-toggle {
  text-align:center; margin-top:20px;
  font-size:13px; color:var(--text2);
}
.mode-toggle a {
  color:var(--teal); text-decoration:none; font-weight:600;
  transition:opacity .2s;
}
.mode-toggle a:hover { opacity:.75; }

/* Error / success message */
.msg-box {
  border-radius:10px; padding:12px 16px;
  font-size:13px; line-height:1.5;
  margin-bottom:16px; display:none;
  animation:msgIn .3s var(--ease) forwards;
}
@keyframes msgIn { from { opacity:0; transform:translateY(-6px); } to { opacity:1; transform:none; } }
.msg-box.error   { background:rgba(255,94,58,.1); border:1px solid rgba(255,94,58,.3); color:#ff8a70; }
.msg-box.success { background:rgba(0,200,200,.1); border:1px solid rgba(0,200,200,.3); color:#4dd8d8; }
.msg-box.info    { background:rgba(14,111,203,.1); border:1px solid rgba(14,111,203,.3); color:#6ab4f0; }

/* Success checkmark screen */
#success-screen {
  display:none; text-align:center; padding:20px 0;
  animation:panelIn .5s var(--ease) forwards;
}
.check-circle {
  width:72px; height:72px; border-radius:50%;
  background:rgba(0,200,200,.12); border:2px solid rgba(0,200,200,.35);
  display:flex; align-items:center; justify-content:center;
  font-size:30px; margin:0 auto 20px;
  animation:popIn .5s var(--spring) forwards;
}
@keyframes popIn { from { transform:scale(0); } to { transform:scale(1); } }
#success-screen h3 {
  font-family:'Instrument Serif', serif;
  font-size:24px; margin-bottom:8px;
}
#success-screen p { font-size:14px; color:var(--text2); }

/* Panel transitions */
@keyframes panelIn {
  from { opacity:0; transform:translateY(16px); }
  to   { opacity:1; transform:none; }
}
.panel { animation:panelIn .4s var(--ease); }

/* Responsive */
@media (max-width:800px) {
  #layout { grid-template-columns:1fr; }
  #left   { display:none; }
  #right  { padding:28px 20px; }
}
</style>
</head>
<body>

<!-- Cursor -->
<div id="cur"></div>
<div id="cur-r"></div>

<!-- Background -->
<canvas id="bg-canvas"></canvas>
<div id="b1" class="blob"></div>
<div id="b2" class="blob"></div>
<div id="b3" class="blob"></div>
<div id="grid-overlay"></div>

<div id="layout">

  <!-- ══════════ LEFT — BRAND PANEL ══════════ -->
  <div id="left">
    <div class="brand-logo">
      <div class="brand-icon"><?= htmlspecialchars($logoLetter) ?></div>
      <div class="brand-text">
        <div class="name"><?= htmlspecialchars($companyName) ?></div>
        <div class="tagline"><?= htmlspecialchars($companyTagline) ?></div>
      </div>
    </div>

    <div class="left-hero">
      <div class="eyebrow">Business &amp; Personal Finance Platform</div>
      <h1>Manage your<br/>business with<br/><em>clarity.</em></h1>
      <p>An all-in-one platform built for South African SMEs — invoicing, inventory, payments, reports, and personal budget planning in one secure place.</p>

      <div class="feature-pills">
        <div class="fp"><span class="fp-dot" style="background:#0e6fcb"></span> Invoicing</div>
        <div class="fp"><span class="fp-dot" style="background:#00c8c8"></span> Payments</div>
        <div class="fp"><span class="fp-dot" style="background:#f0b429"></span> Inventory</div>
        <div class="fp"><span class="fp-dot" style="background:#ff5e3a"></span> Reports</div>
        <div class="fp"><span class="fp-dot" style="background:#a855f7"></span> Personal Budget</div>
        <div class="fp"><span class="fp-dot" style="background:#1adc8e"></span> Role-Based Access</div>
      </div>
    </div>

    <div class="left-stats">
      <div class="ls-item"><div class="ls-val">3</div><div class="ls-label">Access Roles</div></div>
      <div class="ls-item"><div class="ls-val">256-bit</div><div class="ls-label">AES Encrypted</div></div>
      <div class="ls-item"><div class="ls-val">100%</div><div class="ls-label">Private Data</div></div>
    </div>
  </div>

  <!-- ══════════ RIGHT — FORM PANEL ══════════ -->
  <div id="right">
    <div class="form-shell">

      <!-- Step progress indicator -->
      <div class="steps" id="steps">
        <div class="step active" id="st1">
          <div class="step-num">1</div>
          <span>Sign In</span>
        </div>
        <div class="step-line" id="sl1"></div>
        <div class="step" id="st2">
          <div class="step-num">2</div>
          <span>Verify OTP</span>
        </div>
        <div class="step-line" id="sl2"></div>
        <div class="step" id="st3">
          <div class="step-num">3</div>
          <span>Set Password</span>
        </div>
      </div>

      <!-- Message box -->
      <div class="msg-box" id="msg-box"></div>

      <!-- ── SCREEN 1: Email Entry ── -->
      <div id="screen-email" class="panel">
        <div class="form-head">
          <div class="fh-title">Welcome back</div>
          <div class="fh-sub">Enter your email address to continue.</div>
        </div>
        <form id="form-email" onsubmit="handleEmailSubmit(event)">
        <input type="hidden" name="csrf_token" id="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>"/>
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>"/>
          <div class="field">
            <label class="lbl" for="inp-email">Email Address</label>
            <div class="inp-wrap">
              <svg class="ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
              <input class="liq-inp" type="email" id="inp-email" name="email"
                     placeholder="you@company.co.za" required autocomplete="email"/>
            </div>
          </div>
          <button class="sub-btn" type="submit" id="btn-email">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
            Continue
          </button>
        </form>
        <div class="mode-toggle">
          New user? <a href="#" onclick="showOtpMode(); return false;">Use your one-time password →</a>
        </div>
      </div>

      <!-- ── SCREEN 2A: Password Login ── -->
      <div id="screen-password" class="panel" style="display:none">
        <div class="form-head">
          <div class="fh-title" id="pw-greeting">Sign in</div>
          <div class="fh-sub" id="pw-email-display">Enter your password to continue.</div>
        </div>
        <form id="form-password" onsubmit="handlePasswordSubmit(event)">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>"/>
          <input type="hidden" id="pw-email-hidden" name="email"/>
          <input type="hidden" name="action" value="password_login"/>
          <div class="field">
            <label class="lbl" for="inp-password">Password</label>
            <div class="inp-wrap">
              <svg class="ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              <input class="liq-inp" type="password" id="inp-password" name="password"
                     placeholder="Enter your password" required autocomplete="current-password"/>
              <button type="button" class="eye-btn" onclick="togglePw('inp-password',this)" tabindex="-1">
                <svg id="eye-icon-pw" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              </button>
            </div>
          </div>
          <button class="sub-btn" type="submit" id="btn-pw">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            Sign In
          </button>
        </form>
        <div class="mode-toggle">
          <a href="#" onclick="showScreen('screen-email');return false;">← Back</a>
          &nbsp;&nbsp;|&nbsp;&nbsp;
          <a href="#" onclick="showOtpMode();return false;">Reset with OTP</a>
        </div>
      </div>

      <!-- ── SCREEN 2B: OTP Entry (first login / reset) ── -->
      <div id="screen-otp" class="panel" style="display:none">
        <div class="form-head">
          <div class="fh-title">Enter your OTP</div>
          <div class="fh-sub">Enter the one-time password provided by your administrator. It expires in <strong style="color:var(--teal)">24 hours</strong>.</div>
        </div>
        <form id="form-otp" onsubmit="handleOtpSubmit(event)">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>"/>
          <input type="hidden" id="otp-email-hidden" name="email"/>
          <input type="hidden" name="action" value="otp_login"/>

          <div class="field">
            <label class="lbl">Email Address</label>
            <div class="inp-wrap">
              <svg class="ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
              <input class="liq-inp" type="email" id="otp-email-input" name="email"
                     placeholder="you@company.co.za" required autocomplete="email"/>
            </div>
          </div>

          <div class="field">
            <label class="lbl">One-Time Password</label>
            <!-- Split OTP: XXXX-XXXX -->
            <div class="otp-wrap">
              <input class="otp-part" type="text" id="otp-p1"
                     maxlength="4" placeholder="XXXX"
                     autocomplete="off" spellcheck="false"
                     oninput="otpInput(this,'otp-p2')"
                     onkeydown="otpBack(event,this,null)"/>
              <span class="otp-mid">–</span>
              <input class="otp-part" type="text" id="otp-p2"
                     maxlength="4" placeholder="XXXX"
                     autocomplete="off" spellcheck="false"
                     oninput="otpInput(this,null)"
                     onkeydown="otpBack(event,this,'otp-p1')"/>
              <!-- Hidden full OTP field assembled by JS -->
              <input type="hidden" id="otp-full" name="otp"/>
            </div>
          </div>

          <button class="sub-btn" type="submit" id="btn-otp">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Verify OTP
          </button>
        </form>
        <div class="mode-toggle">
          <a href="#" onclick="showScreen('screen-email');return false;">← Back to sign in</a>
        </div>
      </div>

      <!-- ── SCREEN 3: Set New Password ── -->
      <div id="screen-setpw" class="panel" style="display:none">
        <div class="form-head">
          <div class="fh-title">Set your password</div>
          <div class="fh-sub">Choose a strong password. You'll use this to sign in from now on.</div>
        </div>
        <form id="form-setpw" onsubmit="handleSetPwSubmit(event)">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>"/>
          <input type="hidden" name="action" value="set_password"/>

          <div class="field">
            <label class="lbl" for="inp-newpw">New Password</label>
            <div class="inp-wrap">
              <svg class="ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              <input class="liq-inp" type="password" id="inp-newpw" name="new_password"
                     placeholder="Create a strong password" required autocomplete="new-password"
                     oninput="checkStrength(this.value)"/>
              <button type="button" class="eye-btn" onclick="togglePw('inp-newpw',this)" tabindex="-1">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              </button>
            </div>
            <!-- Strength meter -->
            <div id="strength-meter">
              <div class="sm-track">
                <div class="sm-fill" id="sm-fill" style="width:0%;background:var(--coral)"></div>
              </div>
              <div class="sm-label" id="sm-label">Too short</div>
            </div>
            <!-- Requirements checklist -->
            <div id="pw-reqs">
              <div class="req-item" id="req-len">
                <span class="req-icon">○</span> At least 8 characters
              </div>
              <div class="req-item" id="req-upper">
                <span class="req-icon">○</span> One uppercase letter (A–Z)
              </div>
              <div class="req-item" id="req-lower">
                <span class="req-icon">○</span> One lowercase letter (a–z)
              </div>
              <div class="req-item" id="req-num">
                <span class="req-icon">○</span> One number (0–9)
              </div>
              <div class="req-item" id="req-sym">
                <span class="req-icon">○</span> One special character (!@#$%^&amp;*)
              </div>
            </div>
          </div>

          <div class="field">
            <label class="lbl" for="inp-confirmpw">Confirm Password</label>
            <div class="inp-wrap">
              <svg class="ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              <input class="liq-inp" type="password" id="inp-confirmpw" name="confirm_password"
                     placeholder="Repeat your password" required autocomplete="new-password"
                     oninput="checkMatch()"/>
              <button type="button" class="eye-btn" onclick="togglePw('inp-confirmpw',this)" tabindex="-1">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              </button>
            </div>
            <div id="match-msg" style="font-size:12px;margin-top:6px;display:none"></div>
          </div>

          <button class="sub-btn" type="submit" id="btn-setpw" disabled>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="20 6 9 17 4 12"/></svg>
            Activate My Account
          </button>
        </form>
      </div>

      <!-- ── SCREEN 4: Success ── -->
      <div id="success-screen">
        <div class="check-circle">✓</div>
        <h3>You're all set!</h3>
        <p id="success-msg">Redirecting to your dashboard…</p>
        <div style="margin-top:20px">
          <div style="height:3px;background:var(--border);border-radius:2px;overflow:hidden">
            <div id="redirect-bar" style="height:100%;background:linear-gradient(90deg,var(--blue),var(--teal));width:0%;transition:width 2.5s linear;border-radius:2px"></div>
          </div>
        </div>
      </div>

    </div><!-- /form-shell -->
  </div><!-- /right -->
</div><!-- /layout -->

<script>
/* ============================================================
   SOUITRO LOGIN — JavaScript
   1. Cursor + ripples
   2. Liquid wave canvas
   3. Blob parallax
   4. Multi-step form flow
   5. OTP split inputs
   6. Password strength + requirements
   7. Form submission (AJAX → PHP)
   8. Step indicator
   ============================================================ */

// ─── 1. CURSOR ───────────────────────────────────────────────
const $c  = document.getElementById('cur');
const $cr = document.getElementById('cur-r');
let cx=0,cy=0,rx=0,ry=0;

document.addEventListener('mousemove', e => {
  cx=e.clientX; cy=e.clientY;
  $c.style.left=cx+'px'; $c.style.top=cy+'px';
});
(function loopRing(){
  rx+=(cx-rx)*.11; ry+=(cy-ry)*.11;
  $cr.style.left=rx+'px'; $cr.style.top=ry+'px';
  requestAnimationFrame(loopRing);
})();

document.querySelectorAll('button,a,input,.fp').forEach(el=>{
  el.addEventListener('mouseenter', ()=>document.body.classList.add('hov'));
  el.addEventListener('mouseleave', ()=>document.body.classList.remove('hov'));
});
document.addEventListener('click', e=>{
  const r=document.createElement('div');
  r.className='rpl';
  r.style.cssText=`left:${e.clientX}px;top:${e.clientY}px;width:160px;height:160px`;
  document.body.appendChild(r);
  setTimeout(()=>r.remove(),600);
});
document.addEventListener('mousedown',()=>{
  $c.style.width='16px';$c.style.height='16px';$c.style.background='var(--coral)';
});
document.addEventListener('mouseup',()=>{
  $c.style.width='9px';$c.style.height='9px';$c.style.background='var(--teal)';
});

// ─── 2. LIQUID WAVE CANVAS ───────────────────────────────────
const cv  = document.getElementById('bg-canvas');
const ctx = cv.getContext('2d');
let W,H,t=0;
function resizeCv(){W=cv.width=innerWidth;H=cv.height=innerHeight;}
resizeCv(); window.addEventListener('resize',resizeCv);

const waves=[
  {y:.18,amp:32,fr:.009,sp:.005,col:'rgba(14,111,203,.06)'},
  {y:.28,amp:24,fr:.013,sp:.008,col:'rgba(0,200,200,.045)'},
  {y:.72,amp:38,fr:.007,sp:.006,col:'rgba(14,111,203,.055)'},
  {y:.84,amp:28,fr:.011,sp:.009,col:'rgba(0,200,200,.04)'},
];
function drawWaves(){
  ctx.clearRect(0,0,W,H);
  waves.forEach(w=>{
    ctx.beginPath();
    ctx.moveTo(0,H);
    for(let x=0;x<=W;x+=3){
      const y=H*w.y+Math.sin(x*w.fr+t*w.sp*60)*w.amp;
      ctx.lineTo(x,y);
    }
    ctx.lineTo(W,H); ctx.closePath();
    ctx.fillStyle=w.col; ctx.fill();
  });
}
function waveLoop(ts){t=ts; drawWaves(); requestAnimationFrame(waveLoop);}
requestAnimationFrame(waveLoop);

// ─── 3. BLOB PARALLAX ────────────────────────────────────────
const blobs=[
  {el:document.getElementById('b1'),f:.022},
  {el:document.getElementById('b2'),f:.016},
  {el:document.getElementById('b3'),f:.03},
];
document.addEventListener('mousemove',e=>{
  const ox=e.clientX-innerWidth/2, oy=e.clientY-innerHeight/2;
  blobs.forEach(b=>{
    b.el.style.transform=`translate(${ox*b.f}px,${oy*b.f}px)`;
  });
});

// ─── 4. MULTI-STEP FORM FLOW ─────────────────────────────────
let currentEmail = '';
let currentScreen = 'screen-email';

function showScreen(id, step) {
  // Hide all
  ['screen-email','screen-password','screen-otp','screen-setpw','success-screen']
    .forEach(s => {
      const el = document.getElementById(s);
      if (el) el.style.display = 'none';
    });
  const target = document.getElementById(id);
  if (target) { target.style.display = 'block'; target.classList.add('panel'); }
  currentScreen = id;
  if (step) updateSteps(step);
  clearMsg();
}

function updateSteps(active) {
  // active: 1, 2, or 3
  for(let i=1;i<=3;i++){
    const st  = document.getElementById('st'+i);
    const sl  = document.getElementById('sl'+(i));
    if(!st) continue;
    st.classList.remove('active','done');
    if(i < active)  { st.classList.add('done'); if(sl) sl.classList.add('done'); }
    if(i === active) st.classList.add('active');
    if(i > active && sl) sl.classList.remove('done');
  }
}

function showOtpMode() {
  const email = document.getElementById('inp-email')?.value || '';
  if (email) {
    document.getElementById('otp-email-input').value = email;
  }
  showScreen('screen-otp', 2);
}

// ── Email step: decide which sub-flow ──
async function handleEmailSubmit(e) {
  e.preventDefault();
  const email = document.getElementById('inp-email').value.trim();
  if (!email) return;
  currentEmail = email;

  // In production: POST to check if user has set password
  // For demo: always show password screen
  // Real call:
  // const res = await postJSON({ action:'check_email', email });
  // if (!res.ok) { showMsg(res.message,'error'); return; }
  // if (res.needs_otp) showOtpMode(); else showPasswordScreen();

  showPasswordScreen(email);
}

function showPasswordScreen(email) {
  document.getElementById('pw-email-hidden').value  = email || currentEmail;
  document.getElementById('pw-greeting').textContent = 'Welcome back';
  document.getElementById('pw-email-display').textContent =
    'Signing in as ' + (email || currentEmail);
  showScreen('screen-password', 1);
  setTimeout(() => document.getElementById('inp-password').focus(), 100);
}

// ── Password login submit ──
async function handlePasswordSubmit(e) {
  e.preventDefault();
  const btn  = document.getElementById('btn-pw');
  const data = {
    action:       'password_login',
    email:        document.getElementById('pw-email-hidden').value,
    password:     document.getElementById('inp-password').value,
    csrf_token:   e.target.querySelector('[name="csrf_token"]').value,
  };

  setLoading(btn, true);
  const res = await postJSON(data);
  setLoading(btn, false);

  if (!res.ok) {
    if (res.use_otp) {
      showMsg('Your account needs to be activated. Switching to OTP flow.', 'info');
      setTimeout(() => {
        document.getElementById('otp-email-input').value = data.email;
        showScreen('screen-otp', 2);
      }, 1800);
    } else {
      showMsg(res.message, 'error');
      shakeForm('form-password');
    }
    return;
  }

  showSuccess('Password verified. Taking you to your dashboard…');
  setTimeout(() => window.location.href = res.redirect || 'dashboard.php', 2500);
}

// ── OTP submit ──
async function handleOtpSubmit(e) {
  e.preventDefault();
  const p1  = document.getElementById('otp-p1').value.trim();
  const p2  = document.getElementById('otp-p2').value.trim();
  const otp = (p1+'-'+p2).toUpperCase();
  document.getElementById('otp-full').value = otp;

  if (p1.length < 4 || p2.length < 4) {
    showMsg('Please enter the complete 8-character OTP.', 'error');
    return;
  }

  const btn   = document.getElementById('btn-otp');
  const email = document.getElementById('otp-email-input').value.trim();
  const data  = {
    action:     'otp_login',
    email,
    otp,
    csrf_token: e.target.querySelector('[name="csrf_token"]').value,
  };

  setLoading(btn, true);
  const res = await postJSON(data);
  setLoading(btn, false);

  if (!res.ok) {
    showMsg(res.message, 'error');
    shakeForm('form-otp');
    // Clear OTP fields on failure
    document.getElementById('otp-p1').value='';
    document.getElementById('otp-p2').value='';
    document.getElementById('otp-p1').focus();
    return;
  }

  // OTP passed — move to set-password step
  showMsg('OTP verified! Please create your password.', 'success');
  setTimeout(() => {
    showScreen('screen-setpw', 3);
    document.getElementById('inp-newpw').focus();
  }, 900);
}

// ── Set password submit ──
async function handleSetPwSubmit(e) {
  e.preventDefault();
  const newPw  = document.getElementById('inp-newpw').value;
  const confPw = document.getElementById('inp-confirmpw').value;

  if (newPw !== confPw) {
    showMsg('Passwords do not match. Please try again.', 'error');
    return;
  }

  const btn  = document.getElementById('btn-setpw');
  const data = {
    action:           'set_password',
    new_password:     newPw,
    confirm_password: confPw,
    csrf_token:       e.target.querySelector('[name="csrf_token"]').value,
  };

  setLoading(btn, true);
  const res = await postJSON(data);
  setLoading(btn, false);

  if (!res.ok) {
    showMsg(res.message, 'error');
    return;
  }

  showSuccess('Password set! Your account is now active. Redirecting…');
  setTimeout(() => window.location.href = res.redirect || 'dashboard.php', 2500);
}

// ─── 5. OTP SPLIT INPUTS ─────────────────────────────────────
function otpInput(el, nextId) {
  el.value = el.value.toUpperCase().replace(/[^A-Z0-9]/g,'');
  if (el.value.length >= 4 && nextId) {
    document.getElementById(nextId).focus();
  }
  // Assemble full OTP
  const p1 = document.getElementById('otp-p1').value;
  const p2 = document.getElementById('otp-p2').value;
  document.getElementById('otp-full').value = (p1+'-'+p2).toUpperCase();
}

function otpBack(e, el, prevId) {
  if (e.key === 'Backspace' && el.value === '' && prevId) {
    const prev = document.getElementById(prevId);
    prev.focus();
    prev.value = prev.value.slice(0,-1);
  }
}

// Auto-paste handler — if user pastes XXXXXXXX or XXXX-XXXX
document.getElementById('otp-p1')?.addEventListener('paste', e=>{
  e.preventDefault();
  const raw = (e.clipboardData||window.clipboardData)
              .getData('text').toUpperCase().replace(/[^A-Z0-9]/g,'');
  if (raw.length >= 8) {
    document.getElementById('otp-p1').value = raw.slice(0,4);
    document.getElementById('otp-p2').value = raw.slice(4,8);
    document.getElementById('otp-full').value =
      raw.slice(0,4)+'-'+raw.slice(4,8);
    document.getElementById('otp-p2').focus();
  }
});

// ─── 6. PASSWORD STRENGTH ────────────────────────────────────
const requirements = {
  len:   { test: v => v.length >= 8,            id:'req-len'   },
  upper: { test: v => /[A-Z]/.test(v),          id:'req-upper' },
  lower: { test: v => /[a-z]/.test(v),          id:'req-lower' },
  num:   { test: v => /[0-9]/.test(v),          id:'req-num'   },
  sym:   { test: v => /[^A-Za-z0-9]/.test(v),   id:'req-sym'   },
};

function checkStrength(val) {
  const meter = document.getElementById('strength-meter');
  const reqs  = document.getElementById('pw-reqs');
  const fill  = document.getElementById('sm-fill');
  const lbl   = document.getElementById('sm-label');

  if (!val) { meter.style.display='none'; reqs.style.display='none'; return; }
  meter.style.display='block'; reqs.style.display='block';

  let score = 0;
  Object.values(requirements).forEach(r => {
    const met = r.test(val);
    if (met) score++;
    const el  = document.getElementById(r.id);
    el.classList.toggle('met', met);
    el.querySelector('.req-icon').textContent = met ? '✓' : '○';
  });

  const pct   = (score/5)*100;
  const color = score<=1?'var(--coral)':score<=3?'var(--gold)':'var(--teal)';
  const label = ['','Too weak','Weak','Fair','Strong','Very strong'][score] || '';
  fill.style.width=pct+'%'; fill.style.background=color;
  lbl.textContent=label; lbl.style.color=color;

  checkEnableSetBtn();
}

function checkMatch() {
  const a = document.getElementById('inp-newpw').value;
  const b = document.getElementById('inp-confirmpw').value;
  const m = document.getElementById('match-msg');
  if (!b) { m.style.display='none'; return; }
  m.style.display='block';
  if (a===b) {
    m.textContent='✓ Passwords match'; m.style.color='var(--teal)';
  } else {
    m.textContent='✕ Passwords do not match'; m.style.color='var(--coral)';
  }
  checkEnableSetBtn();
}

function checkEnableSetBtn() {
  const pw   = document.getElementById('inp-newpw').value;
  const cf   = document.getElementById('inp-confirmpw').value;
  const ok   = Object.values(requirements).every(r=>r.test(pw)) && pw===cf;
  document.getElementById('btn-setpw').disabled = !ok;
}

// ─── 7. AJAX HELPER ──────────────────────────────────────────
async function postJSON(data) {
  // Always attach the CSRF token from the hidden field
  const token = document.getElementById('csrf_token')?.value || '';
  const payload = Object.assign({}, data, { csrf_token: token });

  try {
    const res = await fetch('login.php', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: new URLSearchParams(payload).toString(),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return await res.json();
  } catch (err) {
    console.error('postJSON error:', err);
    return simulateResponse(data); // Remove simulateResponse in production
  }
}

// Demo simulator (remove in production)
function simulateResponse(data) {
  if (data.action === 'password_login') {
    if (data.password === 'Demo@1234') return { ok:true, redirect:'dashboard.php' };
    return { ok:false, message:'Invalid password. (Demo: use Demo@1234)' };
  }
  if (data.action === 'otp_login') {
    if (data.otp === 'ABCD-EFGH') return { ok:true, message:'OTP verified!' };
    return { ok:false, message:'Invalid OTP. (Demo: use ABCD-EFGH)' };
  }
  if (data.action === 'set_password') {
    return { ok:true, redirect:'dashboard.php' };
  }
  return { ok:false, message:'Unknown action.' };
}

// ─── 8. UI UTILITIES ─────────────────────────────────────────
function setLoading(btn, loading) {
  btn.disabled = loading;
  btn.classList.toggle('loading', loading);
  if (!loading) btn.classList.remove('loading');
}

function showMsg(text, type='error') {
  const el = document.getElementById('msg-box');
  el.className = `msg-box ${type}`;
  el.textContent = text;
  el.style.display = 'block';
}

function clearMsg() {
  const el = document.getElementById('msg-box');
  el.style.display = 'none';
  el.textContent = '';
}

function showSuccess(msg) {
  ['screen-email','screen-password','screen-otp','screen-setpw']
    .forEach(s=>{ const el=document.getElementById(s); if(el) el.style.display='none'; });
  document.getElementById('steps').style.display = 'none';
  const ss = document.getElementById('success-screen');
  ss.style.display='block';
  document.getElementById('success-msg').textContent = msg;
  // Animate redirect bar
  requestAnimationFrame(()=>{
    document.getElementById('redirect-bar').style.width='100%';
  });
}

function togglePw(inputId, btn) {
  const inp  = document.getElementById(inputId);
  const show = inp.type === 'password';
  inp.type   = show ? 'text' : 'password';
  btn.style.color = show ? 'var(--teal)' : 'var(--text3)';
}

function shakeForm(formId) {
  const form = document.getElementById(formId);
  if (!form) return;
  form.style.animation = 'none';
  form.offsetHeight; // reflow
  form.style.animation = 'shake .4s ease';
}

// Add shake keyframes dynamically
const shakeKf = document.createElement('style');
shakeKf.textContent = `
@keyframes shake {
  0%,100%{transform:translateX(0)}
  20%{transform:translateX(-8px)}
  40%{transform:translateX(8px)}
  60%{transform:translateX(-6px)}
  80%{transform:translateX(6px)}
}`;
document.head.appendChild(shakeKf);

// Init
updateSteps(1);
</script>
</body>
</html>