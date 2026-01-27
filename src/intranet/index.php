<?php
define('SECURE_ACCESS', true);

// 1. Configurações e Logs
ini_set('display_errors', 0);
ini_set('log_errors', 1);
$logDir = __DIR__ . '/data/logs';
if (!is_dir($logDir)) @mkdir($logDir, 0755, true);
ini_set('error_log', $logDir . '/intranet_errors.log');
header_remove('X-Powered-By');
ini_set('expose_php', 'Off');

// Redirecionamento HTTPS
$is_localhost = ($_SERVER['SERVER_NAME'] === 'localhost' || $_SERVER['REMOTE_ADDR'] === '127.0.0.1' || $_SERVER['REMOTE_ADDR'] === '::1');
if (!$is_localhost && (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on')) {
    $host = filter_var($_SERVER['HTTP_HOST'], FILTER_SANITIZE_STRING);
    $uri = filter_var($_SERVER['REQUEST_URI'], FILTER_SANITIZE_STRING);
    header("Location: https://$host$uri", true, 301);
    exit();
}

// Security Headers
$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-$nonce' https://cdnjs.cloudflare.com https://www.googletagmanager.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; img-src 'self' https: data:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://ipapi.co; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content;");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Conexão DB
require_once __DIR__ . '/data/config/db_config.php';

// Sessão
if (session_status() == PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_strict_mode', '1');
    if (!$is_localhost) ini_set('session.cookie_secure', '1');
    session_start();
}

// I18N Mock
if (!function_exists('__')) { function __($key) { return $key; } }
if (!function_exists('current_lang')) { function current_lang() { return 'pt'; } }

// Setup Inicial de DB (Cria tabela users se não existir)
try {
    $db = SecureDatabase::getInstance()->getConnection();
    
    // Tabela Users
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Tabela Security Logs (se não existir)
    $db->exec("CREATE TABLE IF NOT EXISTS security_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        event_type VARCHAR(50),
        ip_address VARCHAR(45),
        details TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )");


    // Cria admin se não existir (Fallback local ainda útil para dev/emergency se implementar)
    $stmt = $db->query("SELECT count(*) FROM users");
    if ($stmt->fetchColumn() == 0) {
        $passHash = password_hash('admin123', PASSWORD_DEFAULT);
        $db->prepare("INSERT INTO users (username, password_hash) VALUES ('admin', ?)")->execute([$passHash]);
    }
} catch (Exception $e) {
    die("Erro crítico de inicialização: " . $e->getMessage());
}

// --- Lógica de Rotação de Logs (Auto-Delete > 24h) ---
function cleanOldLogs($db) {
    try {
        $db->exec("DELETE FROM security_logs WHERE timestamp < NOW() - INTERVAL 24 HOUR");
    } catch (Exception $e) { 
        error_log("Erro ao limpar logs antigos: " . $e->getMessage());
    }
}
cleanOldLogs($db);

// --- Autenticação Webmail (IMAP/POP3) ---
function authenticateWithMailServer($email, $password) {
    // Validação básica do email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return false;

    $host = 'webmail.coiengenharia.com.br';
    
    // Tenta via IMAP (Porta 143 com TLS ou 993 SSL)
    if (function_exists('imap_open')) {
        // Tenta SSL na 993 primeiro (Mais seguro)
        $mbox = @imap_open("{{$host}:993/imap/ssl}INBOX", $email, $password, OP_HALFOPEN, 1);
        if ($mbox) {
            imap_close($mbox);
            return true;
        }
        
        // Tenta porta 143 com TLS/novalidate-cert
        $mbox = @imap_open("{{$host}:143/imap/tls/novalidate-cert}INBOX", $email, $password, OP_HALFOPEN, 1);
        if ($mbox) {
            imap_close($mbox);
            return true;
        }
    }

    // Fallback: Tentativa via Socket POP3 (110) se IMAP falhar ou não existir
    try {
        $fp = @fsockopen($host, 110, $errno, $errstr, 5); // 5s timeout
        if ($fp) {
            $banner = fgets($fp, 512);
            if (strpos($banner, '+OK') === 0) {
                fputs($fp, "USER $email\r\n");
                $userResp = fgets($fp, 512);
                if (strpos($userResp, '+OK') === 0) {
                    fputs($fp, "PASS $password\r\n");
                    $passResp = fgets($fp, 512);
                    fputs($fp, "QUIT\r\n");
                    fclose($fp);
                    if (strpos($passResp, '+OK') === 0) {
                        return true;
                    }
                }
            }
            fclose($fp);
        }
    } catch (Exception $e) {}

    return false;
}


// Lógica de Login/Logout
$error = '';
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header("Location: index.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_SESSION['user_id'])) {
    $inputUser = trim($_POST['username'] ?? '');
    $inputPass = $_POST['password'] ?? '';
    
    // Prevent bruteforce
    if (!isset($_SESSION['login_attempts'])) $_SESSION['login_attempts'] = 0;
    
    if ($_SESSION['login_attempts'] > 10) {
        $error = "Muitas tentativas. Aguarde.";
    } else {
        $loginSuccess = false;
        $dbUser = null;

        // 1. TENTATIVA LOCAL (DB)
        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$inputUser]);
        $localUser = $stmt->fetch();

        if ($localUser && password_verify($inputPass, $localUser['password_hash'])) {
            $loginSuccess = true;
            $dbUser = $localUser;
        } 
        // 2. TENTATIVA WEBMAIL (Se não logou local e parece email)
        elseif (filter_var($inputUser, FILTER_VALIDATE_EMAIL)) {
            if (authenticateWithMailServer($inputUser, $inputPass)) {
                $loginSuccess = true;
                // Busca ou Cria usuário local para o email autenticado
                if ($localUser) {
                    $dbUser = $localUser;
                } else {
                    // Cria usuário placeholder
                    $db->prepare("INSERT INTO users (username, password_hash) VALUES (?, 'WEBMAIL_AUTH')")->execute([$inputUser]);
                    $stmtId = $db->prepare("SELECT * FROM users WHERE username = ?");
                    $stmtId->execute([$inputUser]);
                    $dbUser = $stmtId->fetch();
                }
            }
        }

        if ($loginSuccess && $dbUser) {
            // SESSÃO
            $_SESSION['user_id'] = $dbUser['id']; // ID Inteiro Real
            $_SESSION['username'] = $dbUser['username'];
            $_SESSION['login_attempts'] = 0;
            
            // RBAC
            if (strtolower($dbUser['username']) === 'contato@coiengenharia.com.br' || $dbUser['username'] === 'admin') {
                $_SESSION['is_admin'] = true;
                $_SESSION['role_label'] = 'Administrador';
            } else {
                $_SESSION['is_admin'] = false;
                $_SESSION['role_label'] = 'Visualizador/Fiscal';
            }

            // Log de Sucesso
            try {
                $db->prepare("INSERT INTO security_logs (event_type, ip_address, details) VALUES ('login_success', ?, ?)")
                   ->execute([$_SERVER['REMOTE_ADDR'], "User: " . $dbUser['username']]);
            } catch(Exception $e) {}

            header("Location: index.php");
            exit;
        } else {
            $_SESSION['login_attempts']++;
            $error = "Usuário ou senha inválidos.";
            
            // Log de Falha
            try {
                $db->prepare("INSERT INTO security_logs (event_type, ip_address, details) VALUES ('login_fail', ?, ?)")
                   ->execute([$_SERVER['REMOTE_ADDR'], "Tentativa: $inputUser"]);
            } catch(Exception $e) {}
        }
    }
}

$isLogged = isset($_SESSION['user_id']);
$isAdmin = $_SESSION['is_admin'] ?? false; // Variável auxiliar para a View

// --- Coleta de Dados para Dashboard ---
$health = [];
$invasions = [];
if ($isLogged) {
    // 1. Health Checks
    $health['ssl'] = ($is_localhost || (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'));
    $health['errors_off'] = (ini_get('display_errors') == 0);
    $health['session_secure'] = (ini_get('session.cookie_httponly') == 1);
    $health['logs_active'] = is_writable($logDir);

    // 2. Invasion Logs (Últimas 24h, exceto sucesso e operações de GED)
    try {
        $stmt = $db->query("SELECT * FROM security_logs WHERE event_type NOT LIKE 'ged_%' AND event_type != 'login_success' AND timestamp > NOW() - INTERVAL 24 HOUR ORDER BY timestamp DESC LIMIT 20");
        $invasions = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch(Exception $e) {}

    // 3. Activity Logs (Apenas Uploads/Downloads/Pastas)
    $activities = [];
    try {
        $stmt = $db->query("SELECT * FROM security_logs WHERE event_type LIKE 'ged_%' AND timestamp > NOW() - INTERVAL 24 HOUR ORDER BY timestamp DESC LIMIT 20");
        $activities = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch(Exception $e) {}
}
?>
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intranet - COI Engenharia</title>
    <link rel="icon" href="LOGO.png" type="image/png">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Montserrat:wght@600;700;800&display=swap" rel="stylesheet">
    <!-- Ícones (Feather Icons via CDN) -->
    <script src="https://unpkg.com/feather-icons"></script>
    <style>
        :root {
            --navy-primary: #0D2C54;
            --navy-dark: #071830;
            --orange-safety: #F26419;
            --white: #FFFFFF;
            --grey-light: #F3F4F6;
            --grey-border: #E5E7EB;
            --success: #10B981;
            --danger: #EF4444;
        }
        body { font-family: 'Inter', sans-serif; background: var(--grey-light); margin: 0; display: flex; flex-direction: column; min-height: 100vh; color: #1F2937; }
        
        /* Layout Geral */
        .app-container { display: flex; flex: 1; height: 100vh; overflow: hidden; }
        
        /* Sidebar */
        .sidebar {
            width: 260px;
            background: var(--navy-primary);
            color: white;
            display: flex;
            flex-direction: column;
            padding: 1.5rem;
            transition: all 0.3s;
        }
        .sidebar-header { display: flex; align-items: center; gap: 10px; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .sidebar-header img { height: 32px; filter: brightness(0) invert(1); }
        .sidebar-header span { font-weight: 700; font-family: 'Montserrat', sans-serif; font-size: 1.1rem; }
        
        .nav-link {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 0.8rem 1rem;
            color: rgba(255,255,255,0.7);
            text-decoration: none;
            border-radius: 6px;
            margin-bottom: 0.5rem;
            transition: all 0.2s;
        }
        .nav-link:hover, .nav-link.active { background: rgba(255,255,255,0.1); color: white; }
        .nav-link.active { border-left: 3px solid var(--orange-safety); }
        .nav-link i { width: 20px; }

        /* Main Content */
        .main-content {
            flex: 1;
            overflow-y: auto;
            padding: 2rem;
            background: var(--grey-light);
        }

        /* Login Layout (Sem Sidebar) */
        .login-wrapper {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background: linear-gradient(135deg, var(--navy-primary) 0%, var(--navy-dark) 100%);
            padding: 1rem;
        }
        .login-box {
            background: white;
            padding: 2.5rem;
            border-radius: 12px;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);
            width: 100%;
            max-width: 420px;
        }
        .login-header { text-align: center; margin-bottom: 2rem; }
        .login-header img { height: 200px; margin-bottom: 1rem; }
        .form-group { margin-bottom: 1.25rem; }
        .form-control {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--grey-border);
            border-radius: 6px;
            font-size: 0.95rem;
            transition: border-color 0.2s;
            box-sizing: border-box;
        }
        .form-control:focus { outline: none; border-color: var(--navy-primary); ring: 2px solid rgba(13, 44, 84, 0.1); }
        .btn-login {
            width: 100%;
            padding: 0.75rem;
            background: var(--orange-safety);
            color: white;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn-login:disabled { background: #E5E7EB; color: #9CA3AF; cursor: not-allowed; }
        .btn-login:hover:not(:disabled) { background: #d9530e; }
        
        /* Dashboard Components */
        .page-header { margin-bottom: 2rem; }
        .page-header h1 { font-family: 'Montserrat', sans-serif; color: var(--navy-primary); margin: 0; }
        
        /* Cards de Status */
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .status-card {
            background: white;
            padding: 1.25rem;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            gap: 1rem;
            border-left: 4px solid transparent;
        }
        .status-card.success { border-left-color: var(--success); }
        .status-card.danger { border-left-color: var(--danger); }
        
        .status-icon {
            width: 40px; height: 40px;
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.2rem;
        }
        .success .status-icon { background: #DCFCE7; color: var(--success); }
        .danger .status-icon { background: #FEE2E2; color: var(--danger); }
        
        /* Invasion Logs Table */
        .table-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            overflow: hidden;
            margin-bottom: 2rem;
        }
        .card-header { padding: 1rem 1.5rem; border-bottom: 1px solid var(--grey-border); display: flex; justify-content: space-between; align-items: center; }
        .card-header h3 { margin: 0; font-size: 1.1rem; color: var(--navy-primary); display: flex; align-items: center; gap: 8px; }
        
        table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        th { background: #F9FAFB; text-align: left; padding: 0.75rem 1.5rem; color: #6B7280; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
        td { padding: 0.75rem 1.5rem; border-top: 1px solid var(--grey-border); color: #374151; }
        tr:hover { background: #F9FAFB; }
        
        .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 500; }
        .badge-red { background: #FEE2E2; color: #B91C1C; }
        .badge-role { background: #DBEAFE; color: #1E40AF; }

        /* Aviso Legal */
        .legal-notice {
            background: #F8FAFC;
            border: 1px solid #E2E8F0;
            padding: 1rem;
            border-radius: 6px;
            font-size: 0.8rem;
            color: #64748B;
            margin-bottom: 1.5rem;
            text-align: justify;
            line-height: 1.4;
        }
        .legal-notice strong { color: var(--navy-primary); display: block; margin-bottom: 0.5rem; }

        /* Tools Grid */
        .tools-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1.5rem; }
        .tool-card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); transition: transform 0.2s; }
        .tool-card:hover { transform: translateY(-2px); box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
        .tool-card h3 { margin-top: 0; color: var(--navy-primary); font-size: 1.1rem; }
        .tool-card p { font-size: 0.9rem; color: #6B7280; margin-bottom: 1.5rem; }
        
        /* Restricted State */
        .tool-card.restricted { opacity: 0.7; pointer-events: none; }
        .tool-card.restricted .btn-login { background: #9CA3AF; }

        /* Mobile */
        @media (max-width: 768px) {
            .app-container { flex-direction: column; height: auto; }
            .sidebar { width: 100%; padding: 1rem; }
            .main-content { padding: 1rem; }
            .login-box { padding: 1.5rem; }
            .status-grid { grid-template-columns: 1fr 1fr; }
        }
    </style>
</head>
<body>

<?php if (!$isLogged): ?>
    <!-- TELA DE LOGIN -->
    <div class="login-wrapper">
        <div class="login-box">
            <div class="login-header">
                <img src="LOGO.png" alt="COI Engenharia">
                <h2 style="color:var(--navy-primary); margin:0;">Intranet Corporativa</h2>
            </div>

            <div class="legal-notice">
                <strong>⚖️ AVISO LEGAL E TERMOS DE USO</strong>
                O acesso a este sistema é restrito a colaboradores autorizados da COI Engenharia. 
                Todas as ações realizadas neste ambiente são monitoradas para fins de auditoria e segurança, 
                conforme previsto na Lei Geral de Proteção de Dados (LGPD) e normativas internas. 
                Tentativas de acesso não autorizado serão registradas e poderão resultar em sanções legais.
            </div>

            <?php if ($error): ?>
                <div style="background:#FEF2F2; color:#B91C1C; padding:0.75rem; border-radius:6px; margin-bottom:1rem; text-align:center; font-size:0.9rem;">
                    <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>

            <form method="POST">
                <div class="form-group">
                    <label style="display:block; margin-bottom:0.5rem; font-weight:500; font-size:0.9rem;">Email Corporativo ou Usuário</label>
                    <input type="text" name="username" class="form-control" placeholder="seu.nome@coiengenharia.com.br ou usuario" required autofocus>
                </div>
                <div class="form-group">
                    <label style="display:block; margin-bottom:0.5rem; font-weight:500; font-size:0.9rem;">Senha</label>
                    <input type="password" name="password" class="form-control" placeholder="••••••••" required>
                </div>
                <button type="submit" class="btn-login">ACESSAR SISTEMA</button>
            </form>
            
            <div style="text-align:center; margin-top:1.5rem;">
                <a href="index.php" style="color:#6B7280; font-size:0.85rem; text-decoration:none;">&larr; Voltar ao site principal</a>
            </div>
        </div>
    </div>

<?php else: ?>
    <!-- DASHBOARD -->
    <div class="app-container">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="sidebar-header">
                <img src="LOGO.png" alt="COI">
                <span>Intranet</span>
            </div>
            <nav style="flex:1;">
                <?php if ($isAdmin): ?>
                    <a href="#" class="nav-link active"><i data-feather="grid"></i> Visão Geral</a>
                    <a href="documents.php" class="nav-link"><i data-feather="file-text"></i> Documentos</a>
                <?php endif; ?>
                <a href="obras.php" class="nav-link"><i data-feather="book-open"></i> Diário de Obras</a>
                <a href="obras.php" class="nav-link"><i data-feather="hard-drive"></i> Obras</a>
                <?php if ($isAdmin): ?>
                    <a href="admin_users.php" class="nav-link"><i data-feather="users"></i> Usuários</a>
                    <a href="#" class="nav-link"><i data-feather="settings"></i> Configurações</a>
                <?php endif; ?>
            </nav>
            <div style="padding:1rem 0; font-size:0.8rem; color:rgba(255,255,255,0.5); border-top:1px solid rgba(255,255,255,0.1);">
                <div style="margin-bottom:0.5rem;">Logado como:</div>
                <div style="color:white; font-weight:600; overflow:hidden; text-overflow:ellipsis;"><?= htmlspecialchars($_SESSION['username']) ?></div>
                <div style="margin-top:0.2rem;"><span class="badge" style="background:rgba(255,255,255,0.2);"><?= $_SESSION['role_label'] ?></span></div>
            </div>
            <div style="margin-top:1rem;">
                <a href="?action=logout" class="nav-link" style="color:#FCA5A5;"><i data-feather="log-out"></i> Sair do Sistema</a>
            </div>
        </aside>

        <!-- Content -->
        <main class="main-content">
            <div class="page-header">
                <h1>Visão Geral do Sistema</h1>
                <p style="color:#6B7280; margin-top:0.5rem;">Monitoramento em tempo real.</p>
            </div>

            <!-- Health Indicators -->
            <div class="status-grid">
                <!-- SSL -->
                <div class="status-card <?= $health['ssl'] ? 'success' : 'danger' ?>">
                    <div class="status-icon"><i data-feather="<?= $health['ssl'] ? 'lock' : 'unlock' ?>"></i></div>
                    <div>
                        <div style="font-size:0.8rem; color:#6B7280; text-transform:uppercase;">Conexão Segura</div>
                        <div style="font-weight:700; color:var(--navy-primary);"><?= $health['ssl'] ? 'SSL Ativo' : 'Não Seguro' ?></div>
                    </div>
                </div>
                
                <!-- Errors -->
                <div class="status-card <?= $health['errors_off'] ? 'success' : 'danger' ?>">
                    <div class="status-icon"><i data-feather="<?= $health['errors_off'] ? 'eye-off' : 'eye' ?>"></i></div>
                    <div>
                        <div style="font-size:0.8rem; color:#6B7280; text-transform:uppercase;">Erros PHP</div>
                        <div style="font-weight:700; color:var(--navy-primary);"><?= $health['errors_off'] ? 'Ocultos' : 'Expostos' ?></div>
                    </div>
                </div>

                <!-- Session -->
                <div class="status-card <?= $health['session_secure'] ? 'success' : 'danger' ?>">
                    <div class="status-icon"><i data-feather="shield"></i></div>
                    <div>
                        <div style="font-size:0.8rem; color:#6B7280; text-transform:uppercase;">Sessão</div>
                        <div style="font-weight:700; color:var(--navy-primary);"><?= $health['session_secure'] ? 'Protegida' : 'Vulnerável' ?></div>
                    </div>
                </div>

                <!-- System Logs -->
                <div class="status-card <?= $health['logs_active'] ? 'success' : 'danger' ?>">
                    <div class="status-icon"><i data-feather="activity"></i></div>
                    <div>
                        <div style="font-size:0.8rem; color:#6B7280; text-transform:uppercase;">Monitoramento</div>
                        <div style="font-weight:700; color:var(--navy-primary);">Ativo (24h)</div>
                    </div>
                </div>
            </div>

            <!-- Invasion Logs Table -->
            <div class="table-card">
                <div class="card-header">
                    <h3><i data-feather="alert-triangle" style="color:var(--orange-safety);"></i> Tentativas de Acesso / Invasão (Últimas 24h)</h3>
                    <span class="badge badge-red" style="font-size:0.7rem;"><?= count($invasions) ?> Eventos</span>
                </div>
                <?php if (empty($invasions)): ?>
                    <div style="padding:2rem; text-align:center; color:#9CA3AF;">
                        <i data-feather="check-circle" style="width:48px; height:48px; color:var(--success); margin-bottom:1rem;"></i>
                        <p>Nenhuma tentativa de invasão ou falha de login detectada nas últimas 24 horas.</p>
                    </div>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Data/Hora</th>
                                <th>Tipo de Evento</th>
                                <th>Endereço IP</th>
                                <th>Detalhes</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($invasions as $inv): ?>
                            <tr>
                                <td><?= date('d/m/Y H:i', strtotime($inv['timestamp'])) ?></td>
                                <td><span class="badge badge-red"><?= htmlspecialchars($inv['event_type']) ?></span></td>
                                <td style="font-family:monospace;"><?= htmlspecialchars($inv['ip_address']) ?></td>
                                <td><?= htmlspecialchars($inv['details']) ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <!-- Activity Logs Table (GED) -->
             <div class="table-card" style="border-top: 4px solid var(--navy-primary);">
                <div class="card-header">
                    <h3><i data-feather="file-text" style="color:var(--navy-primary);"></i> Atividades Recentes (Arquivos)</h3>
                    <span class="badge" style="background:#E2E8F0; color:#475569;"><?= count($activities) ?> Eventos</span>
                </div>
                <?php if (empty($activities)): ?>
                    <div style="padding:2rem; text-align:center; color:#9CA3AF;">
                        <p>Nenhuma atividade de arquivo recente.</p>
                    </div>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Data/Hora</th>
                                <th>Ação</th>
                                <th>Usuário/IP</th>
                                <th>Detalhes</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($activities as $act): 
                                $badgeColor = 'badge-role'; // Blue
                                if(strpos($act['event_type'], 'delete') !== false) $badgeColor = 'badge-red';
                            ?>
                            <tr>
                                <td><?= date('d/m/Y H:i', strtotime($act['timestamp'])) ?></td>
                                <td><span class="badge <?= $badgeColor ?>"><?= htmlspecialchars($act['event_type']) ?></span></td>
                                <td style="font-family:monospace;"><?= htmlspecialchars($act['ip_address']) ?></td>
                                <td><?= htmlspecialchars($act['details']) ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <!-- Ferramentas Grid -->
            <div class="tools-grid">
                <div class="tool-card">
                    <h3>Documentos Normativos</h3>
                    <p>Acesse as últimas revisões das normas ISO 9001 e procedimentos internos.</p>
                    <button class="btn-login" style="background:var(--navy-primary);">Acessar Arquivos</button>
                </div>
                
                <!-- Card Restrito para não-Admins: REMOVIDO (Movido para sidebar) -->
                
                <div class="tool-card">
                    <h3>Holerites e RH</h3>
                    <p>Consulta de demonstrativos de pagamento e banco de horas.</p>
                    <button class="btn-login" style="background:var(--navy-primary);">Portal Colaborador</button>
                </div>
                
                <?php if ($isAdmin): ?>
                    <div class="tool-card">
                        <h3 style="color:var(--orange-safety);">Gerenciar Acessos</h3>
                        <p>Controle de usuários e permissões do sistema.</p>
                        <a href="admin_users.php" class="btn-login" style="display:block; text-align:center; text-decoration:none;">Acessar Admin</a>
                    </div>
                <?php endif; ?>
            </div>

        </main>
    </div>
    
    <!-- Initialize Feather Icons -->
    <script>
        feather.replace();
    </script>
<?php endif; ?>
</body>
</html>
