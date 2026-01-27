<?php
define('SECURE_ACCESS', true); // Permite acesso aos arquivos de configuração
// 1. CONFIGURAÇÕES GLOBAIS DE SEGURANÇA E ERROS
// --------------------------------------------------------------------
// Ocultar erros do usuário final (Security through Obscurity - Camada 1)
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
ini_set('log_errors', 1);
// Define local seguro para logs (tenta usar diretório data, senão temp do sistema)
$logDir = __DIR__ . '/intranet.coiengenharia.com.br/data/logs';
if (!is_dir($logDir)) {
    @mkdir($logDir, 0755, true);
    if (!is_dir($logDir)) $logDir = sys_get_temp_dir();
}
ini_set('error_log', $logDir . '/php_errors.log'); 

// Desabilitar exposição da versão do PHP nos headers
header_remove('X-Powered-By');
ini_set('expose_php', 'Off');

// 2. REDIRECIONAMENTO HTTPS E HSTS (CRÍTICO PARA SEGURANÇA)
// --------------------------------------------------------------------
// Verifica se não é localhost para forçar HTTPS
$is_localhost = ($_SERVER['SERVER_NAME'] === 'localhost' || $_SERVER['REMOTE_ADDR'] === '127.0.0.1' || $_SERVER['REMOTE_ADDR'] === '::1');

if (!$is_localhost && (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on')) {
    // Proteção contra host header injection
    $host = filter_var($_SERVER['HTTP_HOST'], FILTER_SANITIZE_STRING);
    $uri = filter_var($_SERVER['REQUEST_URI'], FILTER_SANITIZE_STRING);
    header("Location: https://$host$uri", true, 301);
    exit();
}

if (!$is_localhost) {
    // HSTS: Força navegadores a lembrarem que este site é apenas HTTPS por 1 ano
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
}

// 3. SECURITY HEADERS & CSP
// --------------------------------------------------------------------
// Nonce criptográfico para permitir scripts específicos inline
$nonce = base64_encode(random_bytes(16));

// Política de Segurança de Conteúdo (CSP) Rigorosa
// Nota: 'unsafe-inline' em style-src mantido para compatibilidade com AOS e styles dinâmicos
header("Content-Security-Policy: " .
    "default-src 'self'; " .
    "script-src 'self' 'unsafe-inline' 'nonce-$nonce' https://cdnjs.cloudflare.com https://www.googletagmanager.com https://cdn.iubenda.com https://cs.iubenda.com https://unpkg.com https://ajax.googleapis.com blob:; " .
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://unpkg.com; " .
    "img-src 'self' https: data: blob:; " .
    "font-src 'self' https://fonts.gstatic.com; " .
    "connect-src 'self' https://www.google-analytics.com https://cs.iubenda.com https://ip-api.com https://www.gstatic.com blob:; " .
    "frame-src 'self' https://www.youtube.com; " .
    "object-src 'none'; " .
    "base-uri 'self'; " .
    "form-action 'self'; " .
    "frame-ancestors 'none'; " .
    "upgrade-insecure-requests; " .
    "block-all-mixed-content;"
);

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY'); // Proteção contra Clickjacking
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=()');

// 4. GESTÃO DE SESSÃO SEGURA
// --------------------------------------------------------------------
if (session_status() == PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', '1'); // Impede acesso via JS (XSS protection)
    ini_set('session.cookie_samesite', 'Strict'); // Proteção contra CSRF
    ini_set('session.use_strict_mode', '1'); // Previne Session Fixation
    ini_set('session.sid_length', '48');
    ini_set('session.sid_bits_per_character', '6');
    
    if (!$is_localhost) {
        ini_set('session.cookie_secure', '1'); // Apenas trafega em HTTPS
    }
    
    session_start();
}

// Rotação de ID de sessão periódica (Hardening)
if (!isset($_SESSION['last_regeneration'])) {
    $_SESSION['last_regeneration'] = time();
} elseif (time() - $_SESSION['last_regeneration'] > 300) { // Regenera a cada 5 min
    session_regenerate_id(true);
    $_SESSION['last_regeneration'] = time();
}

// Token CSRF
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Geração de Request ID para rastreamento
$request_id = uniqid('req_', true);
header("X-Request-Id: $request_id");

// 6. SISTEMA DE MONITORAMENTO E LOGS
// --------------------------------------------------------------------
require_once __DIR__ . '/intranet.coiengenharia.com.br/data/config/db_config.php';

try {
    $db = SecureDatabase::getInstance()->getConnection();
    $current_ip = get_client_ip();
    $current_url = $_SERVER['REQUEST_URI'] ?? '/';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    // Tentativa simples de geolocalização (Simulada para performance, ideal usar API em cronjob)
    // Em um sistema real, usaríamos GeoIP2 database local
    $country = 'Brasil (Detectado)'; 

    $stmt = $db->prepare("INSERT INTO site_visits (ip_address, page_url, user_agent, country) VALUES (?, ?, ?, ?)");
    $stmt->execute([$current_ip, $current_url, $user_agent, $country]);

} catch (Exception $e) {
    // Falha silenciosa no log de visitas para não parar o site
    error_log("Erro log visita: " . $e->getMessage());
}

// 5. FUNÇÕES UTILITÁRIAS E DE LOG
// --------------------------------------------------------------------
require_once __DIR__ . '/includes/i18n.php';

/**

/**
 * Obtém o IP real do cliente, lidando com Proxies/Cloudflare.
 * CRÍTICO: Evita bloquear o IP do proxy e garante logs corretos.
 */
function get_client_ip() {
    $ipaddress = '';
    if (isset($_SERVER['HTTP_CF_CONNECTING_IP']))
        $ipaddress = $_SERVER['HTTP_CF_CONNECTING_IP']; // Cloudflare
    else if (isset($_SERVER['HTTP_X_FORWARDED_FOR']))
        $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
    else if (isset($_SERVER['HTTP_CLIENT_IP']))
        $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
    else if (isset($_SERVER['REMOTE_ADDR']))
        $ipaddress = $_SERVER['REMOTE_ADDR'];
    else
        $ipaddress = 'UNKNOWN';

    $ip_list = explode(',', $ipaddress);
    $ip = trim($ip_list[0]);
    
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

function coi_sanitize_string($input) {
    if (!is_string($input)) return '';
    return htmlspecialchars(trim($input), ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function coi_sanitize_array($array) {
    if (!is_array($array)) return [];
    $sanitized = [];
    foreach ($array as $key => $value) {
        $clean_key = coi_sanitize_string($key);
        if (is_array($value)) {
            $sanitized[$clean_key] = coi_sanitize_array($value);
        } else {
            $sanitized[$clean_key] = coi_sanitize_string($value);
        }
    }
    return $sanitized;
}

// Sanitizar superglobais
$_GET = coi_sanitize_array($_GET);
$_POST = coi_sanitize_array($_POST);
$_COOKIE = coi_sanitize_array($_COOKIE);

// Função de Log Segura
function coi_log($level, $message, $context = []) {
    global $request_id, $logDir;
    
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'req_id' => $request_id,
        'lvl' => $level,
        'msg' => $message,
        'ip' => get_client_ip(),
        'ua' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'uri' => $_SERVER['REQUEST_URI'] ?? '',
        'method' => $_SERVER['REQUEST_METHOD'] ?? '',
        'ctx' => $context
    ];
    
    $logFile = $logDir . '/security_' . date('Y-m-d') . '.log';
    @file_put_contents($logFile, json_encode($logEntry) . "\n", FILE_APPEND | LOCK_EX);
}

// 6. RATE LIMITING & ANTI-BOT (Baseado no IP Real)
// --------------------------------------------------------------------
function checkRateLimit($ip, $maxRequests = 30, $timeWindow = 60) {
    // Ignora verificação para Localhost
    if ($ip === '127.0.0.1' || $ip === '::1') return true;

    $rateDir = __DIR__ . '/intranet.coiengenharia.com.br/data/rate_limits';
    if (!is_dir($rateDir)) {
        if (!@mkdir($rateDir, 0755, true)) return true; // Fail open
    }
    
    $rateFile = $rateDir . '/' . md5($ip) . '.json';
    $currentTime = time();
    $data = ['requests' => 0, 'window_start' => $currentTime];
    
    if (file_exists($rateFile)) {
        $content = @file_get_contents($rateFile);
        if ($content) {
            $decoded = json_decode($content, true);
            if ($decoded) $data = $decoded;
        }
    }
    
    // Lógica de Janela
    if ($currentTime - $data['window_start'] < $timeWindow) {
        if ($data['requests'] >= $maxRequests) {
            coi_log('warning', 'Rate limit exceeded', ['ip' => $ip]);
            return false; 
        }
        $data['requests']++;
    } else {
        $data = ['requests' => 1, 'window_start' => $currentTime];
    }
    
    @file_put_contents($rateFile, json_encode($data), LOCK_EX);
    return true;
}

$client_ip = get_client_ip();
if (!checkRateLimit($client_ip)) {
    http_response_code(429);
    die('Muitas requisições. Por favor, aguarde alguns momentos.'); 
}

// 7. LÓGICA DE BANCO DE DADOS E GEOLOCALIZAÇÃO
// --------------------------------------------------------------------
function getGeolocationFromIP($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return ['country' => 'Local', 'country_code' => 'LC', 'city' => 'Local'];
    }
    
    try {
        $context = stream_context_create(['http' => ['timeout' => 2]]);
        $response = @file_get_contents("http://ip-api.com/json/{$ip}?fields=status,country,countryCode,city,lat,lon", false, $context);
        
        if ($response) {
            $data = json_decode($response, true);
            if ($data && $data['status'] === 'success') {
                return $data;
            }
        }
    } catch (Exception $e) {
        // Silently fail
    }
    return ['country' => 'Unknown', 'country_code' => 'UN', 'city' => 'Unknown'];
}

function logVisitWithGeolocation() {
    $dbConfigPath = __DIR__ . '/intranet.coiengenharia.com.br/data/config/db.php'; // Caminho preferencial
    if (!file_exists($dbConfigPath)) $dbConfigPath = 'admin/db.php'; // Fallback
    
    if (file_exists($dbConfigPath)) {
        try {
            require_once $dbConfigPath;
            if (function_exists('getConnection')) {
                if (!isset($_SESSION['visit_logged'])) {
                    $pdo = getConnection();
                    $ip = get_client_ip();
                    $geoData = getGeolocationFromIP($ip);
                    
                    // Cria tabela se não existir
                    $createTable = "CREATE TABLE IF NOT EXISTS visit_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        ip_address VARCHAR(45) NOT NULL,
                        country VARCHAR(100),
                        country_code VARCHAR(2),
                        city VARCHAR(100),
                        latitude DECIMAL(10, 8),
                        longitude DECIMAL(11, 8),
                        user_agent TEXT,
                        referer TEXT,
                        visit_date DATETIME DEFAULT CURRENT_TIMESTAMP
                    )";
                    $pdo->exec($createTable);
                    
                    $sql = "INSERT INTO visit_logs (ip_address, country, country_code, city, latitude, longitude, user_agent, referer) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([
                        $ip, 
                        $geoData['country'] ?? null, 
                        $geoData['countryCode'] ?? null, 
                        $geoData['city'] ?? null, 
                        $geoData['lat'] ?? null, 
                        $geoData['lon'] ?? null, 
                        $_SERVER['HTTP_USER_AGENT'] ?? '',
                        $_SERVER['HTTP_REFERER'] ?? ''
                    ]);
                    $_SESSION['visit_logged'] = true;
                }
            }
        } catch (Exception $e) {
            coi_log('error', 'DB Error in logs', ['msg' => $e->getMessage()]);
        }
    }
}

logVisitWithGeolocation();

// Contador de Visitas Simples
$counter_file = 'contador_visitas.txt';
if (!file_exists($counter_file)) file_put_contents($counter_file, '0');
$handle = fopen($counter_file, 'c+');
if ($handle) {
    if (flock($handle, LOCK_EX | LOCK_NB)) {
        $visitas = (int)fread($handle, filesize($counter_file) ?: 1);
        if (!isset($_SESSION['visit_counted'])) {
            $visitas++;
            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, $visitas);
            $_SESSION['visit_counted'] = true;
        }
        flock($handle, LOCK_UN);
    }
    fclose($handle);
}

// 7.1 API DO CHATBOT (GEMINI)
// --------------------------------------------------------------------
if (isset($_GET['action']) && $_GET['action'] === 'chat') {
    header('Content-Type: application/json');
    
    // Verifica Rate Limit (usa a função checkRateLimit definida anteriormente)
    $ip = get_client_ip();
    if (!checkRateLimit($ip, 20, 60)) { // 20 req/min
        echo json_encode(['error' => 'Muitas requisições. Aguarde um momento.']);
        exit;
    }

    $input = json_decode(file_get_contents('php://input'), true);
    $userMessage = $input['message'] ?? '';

    if (empty($userMessage)) {
        echo json_encode(['error' => 'Mensagem vazia.']);
        exit;
    }

    $apiKey = $_ENV['GEMINI_API_KEY'] ?? '';
    if (empty($apiKey)) {
        echo json_encode(['error' => 'Erro interno: Chave de API não configurada.']);
        exit;
    }

    // Configuração do Gemini 2.0 Flash
    $url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" . $apiKey;
    
    // Prompt do Sistema
    $systemPrompt = "Você é o assistente virtual da COI Engenharia. Responda de forma curta, profissional e prestativa em português. " .
                    "A COI Engenharia é especializada em obras industriais, infraestrutura, pavimentação e terraplenagem de alta complexidade. " .
                    "Oferecemos soluções técnicas, cumprimento de prazos e conformidade normativa. " .
                    "Contato: (24) 99841-6319 | contato@coiengenharia.com.br. " .
                    "Se perguntarem preços, diga que depende do escopo e sugira solicitar orçamento. " .
                    "Nunca invente dados técnicos que não estão no contexto.";

    $data = [
        "contents" => [
            [
                "parts" => [
                    ["text" => $systemPrompt . "\n\nUsuário: " . $userMessage]
                ]
            ]
        ]
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    
    // SSL Verification (Windows/Dev vs Prod)
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    }

    $response = curl_exec($ch);
    
    if (curl_errno($ch)) {
        echo json_encode(['error' => 'Erro de conexão AI: ' . curl_error($ch)]);
    } else {
        $decoded = json_decode($response, true);
        if (isset($decoded['candidates'][0]['content']['parts'][0]['text'])) {
            echo json_encode(['reply' => $decoded['candidates'][0]['content']['parts'][0]['text']]);
        } else {
            // Fallback para erro da API
            $errorMsg = $decoded['error']['message'] ?? 'Resposta inválida da IA.';
            echo json_encode(['error' => $errorMsg]);
        }
    }
    
    curl_close($ch);
    exit;
}

// 8. PROCESSAMENTO DE FORMULÁRIO (ANTI-SPAM & SEGURANÇA)
// --------------------------------------------------------------------

// Sistema Honeypot Dinâmico
if (!isset($_SESSION['honeypot_name'])) {
    $prefixes = ['user', 'email', 'phone', 'form', 'contact'];
    $suffixes = ['_check', '_val', '_ref', '_data'];
    $_SESSION['honeypot_name'] = $prefixes[array_rand($prefixes)] . $suffixes[array_rand($suffixes)] . '_' . substr(md5(uniqid()), 0, 5);
}

function isSuspicious($input) {
    $forbidden = ['\r', '\n', '%0a', '%0d', 'Content-Type:', 'bcc:', 'to:', 'cc:', 'X-Mailer:', 'MIME-Version:', '\0'];
    foreach ($forbidden as $f) {
        if (stripos($input, $f) !== false) return true;
    }
    return false;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Valida CSRF
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        coi_log('warning', 'CSRF Inválido');
        header('Location: ' . $_SERVER['PHP_SELF'] . '?status=csrf_error');
        exit();
    }
    
    // Valida Honeypot (Campos escondidos que só robôs preenchem)
    $honeypot_name = $_SESSION['honeypot_name'];
    // Verifica o campo dinâmico, website, url, e os extras do formulário original
    if (!empty($_POST[$honeypot_name]) || !empty($_POST['website']) || !empty($_POST['url']) || !empty($_POST['hp']) || !empty($_POST['campo_extra'])) {
        coi_log('warning', 'Honeypot ativado (Bot bloqueado)');
        header('Location: ' . $_SERVER['PHP_SELF'] . '?status=success'); 
        exit();
    }

    // Validação de Referer/Origin
    $origin = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? '';
    $allowed_host = $_SERVER['HTTP_HOST'];
    if ($origin && strpos($origin, $allowed_host) === false) {
        coi_log('warning', 'Origin inválido', ['origin' => $origin]);
        header('Location: ' . $_SERVER['PHP_SELF'] . '?status=error');
        exit();
    }

    // Sanitização e Validação de Dados
    $nome = filter_input(INPUT_POST, 'nome', FILTER_SANITIZE_STRING);
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $mensagem = filter_input(INPUT_POST, 'mensagem', FILTER_SANITIZE_STRING);
    $servico = filter_input(INPUT_POST, 'servico', FILTER_SANITIZE_STRING);

    $errors = [];
    
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Email inválido';
    if (strlen($nome) < 2 || strlen($nome) > 100) $errors[] = 'Nome inválido';
    if (strlen($mensagem) < 10) $errors[] = 'Mensagem muito curta';
    if (isSuspicious($nome) || isSuspicious($email) || isSuspicious($mensagem)) {
        $errors[] = 'Conteúdo suspeito';
        coi_log('alert', 'Tentativa de Injeção de Header', ['email' => $email]);
    }

    if (empty($errors)) {
        $to = 'contato@coiengenharia.com.br'; 
        $subject = 'Novo Contato Site - ' . $nome;
        
        $body = "Nova mensagem do site:\n\n";
        $body .= "Nome: $nome\n";
        $body .= "Email: $email\n";
        $body .= "Serviço: $servico\n";
        $body .= "IP: " . get_client_ip() . "\n\n";
        $body .= "Mensagem:\n$mensagem\n";
        
        // Headers de Email Otimizados
        $headers = "From: no-reply@coiengenharia.com.br\r\n"; // Altere para um email válido do seu domínio se possível
        $headers .= "Reply-To: $email\r\n";
        $headers .= "X-Mailer: PHP/" . phpversion();
        $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
        
        // Proteção contra timing attacks
        $start_time = microtime(true);

        if (mail($to, $subject, $body, $headers)) {
            // Simula tempo constante
            $elapsed = microtime(true) - $start_time;
            if ($elapsed < 0.5) usleep((0.5 - $elapsed) * 1000000);
            
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            header('Location: ' . $_SERVER['PHP_SELF'] . '?status=success');
        } else {
            coi_log('error', 'Falha na função mail() do PHP');
            header('Location: ' . $_SERVER['PHP_SELF'] . '?status=error');
        }
    } else {
        header('Location: ' . $_SERVER['PHP_SELF'] . '?status=error');
    }
    exit();
}
?>
<!DOCTYPE html>
<html lang="<?= current_lang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= __('meta.title') ?></title>
    <meta name="description" content="<?= __('meta.description') ?>">
    <link rel="manifest" href="manifest.json">
    <meta name="theme-color" content="#0D2C54">
    <link rel="icon" href="LOGO.png" type="image/png">

    <!-- SEO & i18n -->
    <link rel="alternate" hreflang="pt" href="https://<?php echo $_SERVER['HTTP_HOST']; ?>/?lang=pt" />
    <link rel="alternate" hreflang="en" href="https://<?php echo $_SERVER['HTTP_HOST']; ?>/?lang=en" />
    <link rel="alternate" hreflang="es" href="https://<?php echo $_SERVER['HTTP_HOST']; ?>/?lang=es" />
    <link rel="alternate" hreflang="x-default" href="https://<?php echo $_SERVER['HTTP_HOST']; ?>/?lang=pt" />
    
    <!-- Fonts: Inter (Institucional) + Montserrat (Headings) -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Montserrat:wght@600;700;800&display=swap" rel="stylesheet">
    
    <!-- AOS Animation (Restaurado com moderação corporativa) -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/aos/2.3.4/aos.css" rel="stylesheet">

    <!-- Google Tag Manager & Iubenda -->
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-HGZKM1EY2C"></script>
    <script nonce="<?php echo $nonce; ?>">
      window.dataLayer = window.dataLayer || [];
      function gtag(){dataLayer.push(arguments);}
      gtag('js', new Date());
      gtag('config', 'G-HGZKM1EY2C');
    </script>

    <style>
        /* DESIGN SYSTEM CORPORATIVO 2026 */
        :root {
            /* Palette Institucional */
            --navy-primary: #0D2C54;
            --navy-dark: #071830;
            --orange-safety: #F26419;
            --grey-light: #F3F4F6;
            --grey-medium: #9CA3AF;
            --grey-dark: #374151;
            --white: #FFFFFF;
            
            /* Typography */
            --font-body: 'Inter', sans-serif;
            --font-heading: 'Montserrat', sans-serif;
            
            /* Spacing */
            --section-padding: 6rem 2rem;
            --container-width: 1280px;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: var(--font-body);
            color: var(--grey-dark);
            line-height: 1.6;
            background-color: var(--white);
            overflow-x: hidden;
        }

        h1, h2, h3, h4 { font-family: var(--font-heading); color: var(--navy-primary); font-weight: 700; }
        a { text-decoration: none; transition: all 0.3s ease; }
        ul { list-style: none; }

        /* UTILITIES */
        .container { max-width: var(--container-width); margin: 0 auto; padding: 0 1.5rem; }
        .section { padding: var(--section-padding); }
        .bg-light { background-color: var(--grey-light); }
        .bg-navy { background-color: var(--navy-primary); color: var(--white); }
        .text-center { text-align: center; }
        .text-orange { color: var(--orange-safety); }
        
        .btn {
            display: inline-block;
            padding: 1rem 2rem;
            border-radius: 4px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            cursor: pointer;
            border: none;
        }
        .btn-primary {
            background-color: var(--orange-safety);
            color: var(--white);
        }
        .btn-primary:hover {
            background-color: #d9530e;
            transform: translateY(-2px);
        }
        .btn-outline {
            border: 2px solid var(--white);
            color: var(--white);
            background: transparent;
        }
        .btn-outline:hover {
            background: rgba(255,255,255,0.1);
            color: var(--white);
        }

        /* HEADER CORPORATIVO */
        header {
            position: fixed;
            top: 0;
            width: 100%;
            background: transparent;
            transition: all 0.4s ease;
            z-index: 1000;
            padding: 1.5rem 0;
        }
        header.scrolled {
            background: var(--white);
            padding: 1rem 0;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        nav { display: flex; justify-content: space-between; align-items: center; }
        
        /* Logo: Inicia branco (filtro), volta ao original no scroll */
        .logo img { height: 45px; transition: all 0.3s; filter: brightness(0) invert(1); }
        header.scrolled .logo img { filter: none; }
        
        .nav-links { display: flex; gap: 2rem; }
        /* Links: Iniciam brancos */
        .nav-links a { color: var(--white); font-weight: 500; font-size: 0.95rem; text-shadow: 0 2px 4px rgba(0,0,0,0.5); }
        /* Links: Voltam a azul no scroll */
        header.scrolled .nav-links a { color: var(--navy-primary); text-shadow: none; }
        
        .nav-links a:hover { color: var(--orange-safety); }
        .nav-cta { display: none; } /* Mobile hidden */

        @media(min-width: 992px) { .nav-cta { display: block; } }

        /* MOBILE MENU */
        .mobile-menu-btn {
            display: none;
            background: none;
            border: none;
            cursor: pointer;
            z-index: 1001;
        }
        .mobile-menu-btn span {
            display: block;
            width: 25px;
            height: 3px;
            background-color: var(--white); /* Inicia branco */
            margin: 5px 0;
            transition: all 0.3s;
            box-shadow: 0 1px 2px rgba(0,0,0,0.5);
        }
        header.scrolled .mobile-menu-btn span {
            background-color: var(--navy-primary); /* Volta a azul no scroll */
            box-shadow: none;
        }

        /* HERO SECTION */
        .hero {
            height: 90vh;
            position: relative;
            display: flex;
            align-items: center;
            color: var(--white);
            background: var(--navy-dark);
        }
        .hero-video {
            position: absolute;
            top: 0; left: 0; width: 100%; height: 100%;
            object-fit: cover;
            object-position: center;
            opacity: 0.4;
        }
        .hero-content {
            position: relative;
            z-index: 2;
            max-width: 800px;
        }
        .hero-tag {
            background: rgba(242, 100, 25, 0.2);
            color: var(--orange-safety);
            padding: 0.5rem 1rem;
            border-radius: 4px;
            font-size: 0.9rem;
            font-weight: 600;
            display: inline-block;
            margin-bottom: 1.5rem;
            border: 1px solid var(--orange-safety);
        }
        .hero h1 {
            font-size: 3.5rem;
            color: var(--white);
            margin-bottom: 1.5rem;
            line-height: 1.2;
        }
        .hero p {
            font-size: 1.2rem;
            color: #e5e7eb;
            margin-bottom: 2.5rem;
            max-width: 600px;
        }

        /* STATS BAR */
        .stats {
            background: var(--navy-primary);
            color: var(--white);
            padding: 3rem 0;
            margin-top: -4rem;
            position: relative;
            z-index: 10;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 2rem;
            text-align: center;
        }
        .stat-item h3 { color: var(--white); font-size: 2.5rem; margin-bottom: 0.5rem; }
        .stat-item p { font-size: 0.9rem; opacity: 0.8; text-transform: uppercase; letter-spacing: 1px; }

        /* SOBRE (INSTITUCIONAL) */
        .about-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 4rem;
            align-items: center;
        }
        .about-text h2 { font-size: 2.5rem; margin-bottom: 1.5rem; }
        .about-text p { margin-bottom: 1.5rem; color: #555; }
        .about-cards {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-top: 2rem;
        }
        .feature-card {
            background: var(--grey-light);
            padding: 1.5rem;
            border-left: 4px solid var(--orange-safety);
        }
        .feature-card h4 { font-size: 1.1rem; margin-bottom: 0.5rem; }
        .feature-card p { font-size: 0.9rem; margin: 0; }

        /* SERVIÇOS */
        .services-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-top: 3rem;
        }
        .service-card {
            background: var(--white);
            padding: 2.5rem;
            border: 1px solid #e5e7eb;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        .service-card:hover {
            border-color: var(--orange-safety);
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.05);
        }
        .service-icon {
            width: 60px; height: 60px;
            background: var(--navy-primary);
            color: var(--white);
            display: flex; align-items: center; justify-content: center;
            margin-bottom: 1.5rem;
            border-radius: 4px;
        }
        .service-card h3 { font-size: 1.4rem; margin-bottom: 1rem; }
        .service-list li {
            padding: 0.3rem 0;
            font-size: 0.95rem;
            color: #666;
            display: flex; align-items: center;
        }
        .service-list li::before {
            content: "•"; color: var(--orange-safety);
            font-weight: bold; margin-right: 0.5rem;
        }

        /* PORTFÓLIO (CARDS TÉCNICOS) */
        .project-card {
            display: flex;
            background: var(--white);
            border: 1px solid #e5e7eb;
            margin-bottom: 2rem;
            transition: all 0.3s;
        }
        .project-card:hover { box-shadow: 0 10px 25px rgba(0,0,0,0.08); }
        .project-img {
            width: 40%;
            min-height: 300px;
            position: relative;
            overflow: hidden;
        }
        .project-img img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            position: absolute;
            top: 0;
            left: 0;
            transition: transform 0.5s ease;
        }
        .project-card:hover .project-img img {
            transform: scale(1.05);
        }
        .project-info { width: 60%; padding: 3rem; display: flex; flex-direction: column; justify-content: center; }
        .project-meta {
            font-size: 0.85rem;
            color: var(--orange-safety);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 0.5rem;
        }
        .project-info h3 { font-size: 1.8rem; margin-bottom: 1rem; }
        .project-details {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-top: 2rem;
            border-top: 1px solid #eee;
            padding-top: 1.5rem;
        }
        .detail-item h5 { font-size: 0.9rem; color: #888; margin-bottom: 0.25rem; }
        .detail-item p { font-weight: 600; color: var(--navy-primary); }

        /* COMPLIANCE SECTION */
        .compliance {
            background: var(--navy-dark);
            color: var(--white);
            text-align: center;
        }
        .compliance h2 { color: var(--white); }
        .cert-grid {
            display: flex;
            justify-content: center;
            gap: 4rem;
            margin-top: 3rem;
            flex-wrap: wrap;
        }
        .cert-item { opacity: 0.7; transition: opacity 0.3s; }
        .cert-item:hover { opacity: 1; }
        .cert-item img { height: 60px; filter: grayscale(100%) brightness(200%); }

        /* CONTACT FORM */
        .contact-wrapper {
            display: grid;
            grid-template-columns: 1fr 1.5fr;
            gap: 4rem;
            background: var(--white);
            box-shadow: 0 20px 50px rgba(0,0,0,0.05);
            border-radius: 8px;
            overflow: hidden;
        }
        .contact-info {
            background: var(--navy-primary);
            color: var(--white);
            padding: 4rem;
        }
        .contact-info h3 { color: var(--white); margin-bottom: 2rem; }
        .info-item { margin-bottom: 2rem; }
        .info-item strong { display: block; font-size: 0.9rem; opacity: 0.7; margin-bottom: 0.5rem; }
        .info-item p { font-size: 1.2rem; font-weight: 500; }
        
        .contact-form-box { padding: 4rem; }
        .form-group { margin-bottom: 1.5rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; font-size: 0.9rem; }
        .form-control {
            width: 100%;
            padding: 1rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: var(--font-body);
        }
        .form-control:focus { outline: none; border-color: var(--navy-primary); }

        /* FOOTER */
        footer {
            background: #051020;
            color: #8899a6;
            padding: 4rem 0 2rem;
            font-size: 0.9rem;
        }
        .footer-grid {
            display: grid;
            grid-template-columns: 1.5fr 1fr 1fr 1fr;
            gap: 3rem;
            margin-bottom: 3rem;
        }
        .footer h4 { color: var(--white); margin-bottom: 1.5rem; font-size: 1.1rem; }
        .footer ul li { margin-bottom: 0.8rem; }
        .footer a { color: #8899a6; }
        .footer a:hover { color: var(--orange-safety); }
        .footer-bottom {
            border-top: 1px solid #1a2636;
            padding-top: 2rem;
            display: flex;
            justify-content: space-between;
        }

        /* MOBILE MENU (Overridden previously defined styles) */
        .mobile-menu-btn span {
            /* This is handled by the header styles above now, but we ensure specificity if needed */
            /* Removed here to avoid conflict with the new header styles */
        }
        /* ... existing mobile menu styles ... */
        .mobile-menu {
            position: fixed;
            top: 0; right: -100%;
            width: 80%;
            height: 100vh;
            background: var(--white);
            z-index: 1000;
            padding: 6rem 2rem;
            transition: right 0.4s ease;
            box-shadow: -5px 0 30px rgba(0,0,0,0.1);
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }
        .mobile-menu.active { right: 0; }
        .mobile-menu a {
            font-size: 1.2rem;
            color: var(--navy-primary);
            font-weight: 600;
            border-bottom: 1px solid #eee;
            padding-bottom: 1rem;
        }
        .mobile-overlay {
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 999;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s;
        }
        .mobile-overlay.active { opacity: 1; visibility: visible; }

        /* RESPONSIVE */
        @media(max-width: 992px) {
            .hero-video {
                object-fit: contain;
                height: 100%;
            }
            .hero h1 { font-size: 2.5rem; }
            .about-grid, .project-card, .contact-wrapper, .footer-grid { grid-template-columns: 1fr; }
            .project-img { width: 100%; min-height: 250px; }
            .project-card { flex-direction: column; }
            .project-info { width: 100%; padding: 2rem; }
            .nav-links, .nav-cta { display: none; } 
            .mobile-menu-btn { display: block; }
        }

        @media(max-width: 480px) {
            .hero h1 { font-size: 2rem; }
            .section { padding: 4rem 1.5rem; }
            .stats-grid { grid-template-columns: 1fr; }
            .contact-form-box { padding: 2rem; }
        }
        /* LIGHTBOX */
        .lightbox {
            display: none;
            position: fixed;
            z-index: 2000;
            padding-top: 50px;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.9);
        }
        .lightbox-content {
            margin: auto;
            display: block;
            width: 80%;
            max-width: 1200px;
            max-height: 80vh;
            object-fit: contain;
        }
        .close-lightbox {
            position: absolute;
            top: 15px;
            right: 35px;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            transition: 0.3s;
            cursor: pointer;
        }
        .close-lightbox:hover,
        .close-lightbox:focus {
            color: var(--orange-safety);
            text-decoration: none;
            cursor: pointer;
        }
        .project-img {
            cursor: pointer;
        }

        /* TEXT MODAL */
        .text-modal {
            display: none;
            position: fixed;
            z-index: 2001;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.8);
            align-items: center;
            justify-content: center;
        }
        .text-modal-content {
            background-color: #fff;
            margin: auto;
            padding: 3rem;
            border-radius: 8px;
            width: 90%;
            max-width: 600px;
            position: relative;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            font-family: var(--font-body);
        }
        .text-modal-close {
            position: absolute;
            top: 15px;
            right: 20px;
            color: #aaa;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            transition: 0.3s;
        }
        .text-modal-close:hover {
            color: var(--orange-safety);
        }
        .clickable-info {
            cursor: pointer;
            position: relative;
        }
        .clickable-info::after {
            content: "<?= __('projects.view_details') ?>";
            position: absolute;
            bottom: 1rem;
            right: 1rem;
            font-size: 0.8rem;
            color: var(--orange-safety);
            opacity: 0;
            transition: opacity 0.3s;
        }
        .clickable-info:hover::after {
            opacity: 1;
        }
    /* CLIENTS GRID */
    .clients-section {
        background-color: var(--white);
        padding: 4rem 0;
        text-align: center;
    }
    .clients-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 2rem;
        align-items: center;
        justify-items: center;
        margin-top: 3rem;
    }
    @media(min-width: 768px) {
        .clients-grid {
            grid-template-columns: repeat(4, 1fr);
        }
    }
    .client-logo {
        max-width: 150px;
        max-height: 80px;
        opacity: 0.7;
        filter: grayscale(100%);
        transition: all 0.3s ease;
        object-fit: contain;
    }
    .client-logo:hover {
        opacity: 1;
        filter: grayscale(0%);
        transform: scale(1.05);
    }
    </style>
    <script type="application/ld+json" nonce="<?php echo $nonce; ?>">
    {
      "@context": "https://schema.org",
      "@type": "EngineeringConstructionBusiness",
      "name": "COI Engenharia",
      "alternateName": "COI Construções Obras Industriais",
      "url": "https://coiengenharia.com.br",
      "logo": "https://coiengenharia.com.br/LOGO.png",
      "description": "Especialistas em construção pesada, terraplenagem e gestão de ativos. Entregamos solidez e conformidade normativa para grandes empreendimentos.",
      "address": {
        "@type": "PostalAddress",
        "addressLocality": "São Paulo",
        "addressRegion": "SP",
        "addressCountry": "BR"
      },
      "contactPoint": {
        "@type": "ContactPoint",
        "telephone": "+55-24-99841-6319",
        "contactType": "customer service",
        "email": "contato@coiengenharia.com.br"
      },
      "sameAs": [
        "https://www.linkedin.com/company/108664081/"
      ]
    }
    </script>
</head>
<body>

    <header>
        <div class="container">
            <nav>
                <a href="#" class="logo">
                    <img src="LOGO.png" alt="COI ENGENHARIA">
                </a>
                <ul class="nav-links">
                    <li><a href="#about"><?= __('nav.about') ?></a></li>
                    <li><a href="#services"><?= __('nav.services') ?></a></li>
                    <li><a href="#projects"><?= __('nav.portfolio') ?></a></li>
                    <li><a href="fotos.php"><?= __('nav.photos') ?></a></li>
                    <li><a href="videos.php"><?= __('nav.videos') ?></a></li>
                    <li><a href="#compliance"><?= __('nav.compliance') ?></a></li>
                    <li><a href="https://intranet.coiengenharia.com.br/" class="nav-link-intranet">Intranet</a></li>
                    <li><a href="#contact"><?= __('nav.contact') ?></a></li>
                    <li class="lang-switch" style="display: flex; align-items: center; gap: 0.5rem; margin-left:1rem;">
                        <a href="?lang=pt" title="Português" style="padding: 0; text-decoration: none; display: flex; align-items: center; gap: 4px; <?= current_lang() == 'pt' ? 'color:var(--orange-safety); font-weight:800;' : 'opacity:0.7;' ?>">
                            <img src="https://flagcdn.com/20x15/br.png" alt="Brasil" width="20" height="15"> PT
                        </a>
                        <span style="color:white; opacity:0.3;">|</span>
                        <a href="?lang=en" title="English" style="padding: 0; text-decoration: none; display: flex; align-items: center; gap: 4px; <?= current_lang() == 'en' ? 'color:var(--orange-safety); font-weight:800;' : 'opacity:0.7;' ?>">
                            <img src="https://flagcdn.com/20x15/us.png" alt="USA" width="20" height="15"> EN
                        </a>
                        <span style="color:white; opacity:0.3;">|</span>
                        <a href="?lang=es" title="Español" style="padding: 0; text-decoration: none; display: flex; align-items: center; gap: 4px; <?= current_lang() == 'es' ? 'color:var(--orange-safety); font-weight:800;' : 'opacity:0.7;' ?>">
                            <img src="https://flagcdn.com/20x15/es.png" alt="España" width="20" height="15"> ES
                        </a>
                    </li>
                    <li style="margin-left: 0.5rem;">
                        <a href="https://www.linkedin.com/company/108664081/" target="_blank" title="LinkedIn" style="color: white; display: flex; align-items: center;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 16 16">
                                <path d="M0 1.146C0 .513.526 0 1.175 0h13.65C15.474 0 16 .513 16 1.146v13.708c0 .633-.526 1.146-1.175 1.146H1.175C.526 16 0 15.487 0 14.854V1.146zm4.943 12.248V6.169H2.542v7.225h2.401zm-1.2-8.212c.837 0 1.358-.554 1.358-1.248-.015-.709-.52-1.248-1.342-1.248-.822 0-1.359.54-1.359 1.248 0 .694.521 1.248 1.327 1.248h.016zm4.908 8.212V9.359c0-.216.016-.432.08-.586.173-.431.568-.878 1.232-.878.869 0 1.216.662 1.216 1.634v3.865h2.401V9.25c0-2.22-1.184-3.252-2.764-3.252-1.274 0-1.845.7-2.165 1.193v.025h-.016a5.54 5.54 0 0 1 .016-.025V6.169h-2.4c.03.678 0 7.225 0 7.225h2.4z"/>
                            </svg>
                        </a>
                    </li>
                </ul>


    <style>
        /* Chatbot 2.0 Styles */
        #coi-chatbot-container {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 9999;
            font-family: 'Inter', sans-serif;
        }

        /* Toggle Button */
        #coi-chat-toggle {
            width: 60px;
            height: 60px;
            background-color: var(--navy-primary);
            color: white;
            border: none;
            border-radius: 50%;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            position: relative;
        }

        #coi-chat-toggle:hover {
            transform: scale(1.1);
            background-color: var(--orange-safety);
        }

        .online-badge {
            position: absolute;
            top: 2px;
            right: 2px;
            width: 14px;
            height: 14px;
            background-color: #10B981;
            border: 2px solid white;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
            100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        /* Chat Window */
        #coi-chat-window {
            position: absolute;
            bottom: 80px;
            right: 0;
            width: 380px;
            height: 550px;
            background-color: white;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            transition: all 0.3s cubic-bezier(0.165, 0.84, 0.44, 1);
            transform-origin: bottom right;
            opacity: 1;
            transform: scale(1);
        }

        #coi-chat-window.hidden {
            opacity: 0;
            transform: scale(0.7);
            pointer-events: none;
            visibility: hidden;
        }

        /* Header */
        .chat-header {
            background: linear-gradient(135deg, var(--navy-primary), var(--navy-dark));
            padding: 1rem;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header-info {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .header-info .avatar {
            width: 40px;
            height: 40px;
            background: white;
            border-radius: 50%;
            padding: 2px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .header-info .avatar img {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            object-fit: cover;
        }

        .header-info h3 {
            margin: 0;
            font-size: 1rem;
            color: white;
            font-weight: 600;
        }

        .status-text {
            font-size: 0.75rem;
            color: #6EE7B7;
            display: block;
        }

        .close-btn {
            background: none;
            border: none;
            color: white;
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0 5px;
            opacity: 0.8;
        }
        .close-btn:hover { opacity: 1; }

        /* Messages Area */
        .chat-messages {
            flex: 1;
            padding: 1rem;
            overflow-y: auto;
            background-color: #F9FAFB;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .message {
            display: flex;
            flex-direction: column;
            max-width: 85%;
            animation: fadeIn 0.3s ease;
        }

        .message.bot { align-self: flex-start; }
        .message.user { align-self: flex-end; align-items: flex-end; }

        .message-content {
            padding: 0.8rem 1rem;
            border-radius: 12px;
            font-size: 0.95rem;
            line-height: 1.5;
            position: relative;
            word-wrap: break-word;
        }

        .message.bot .message-content {
            background-color: white;
            color: var(--grey-dark);
            border-bottom-left-radius: 2px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            border: 1px solid #E5E7EB;
        }

        .message.user .message-content {
            background-color: var(--navy-primary);
            color: white;
            border-bottom-right-radius: 2px;
            box-shadow: 0 2px 5px rgba(13, 44, 84, 0.2);
        }

        .message-content ul {
            margin-left: 1.5rem;
            margin-top: 0.5rem;
            list-style-type: disc;
        }

        .message-time {
            font-size: 0.7rem;
            color: #9CA3AF;
            margin-top: 4px;
            padding: 0 4px;
        }

        /* Input Area */
        .chat-input-wrapper {
            padding: 1rem;
            background: white;
            border-top: 1px solid #E5E7EB;
            display: flex;
            align-items: flex-end;
            gap: 10px;
        }

        #chat-input {
            flex: 1;
            border: 1px solid #E5E7EB;
            border-radius: 20px;
            padding: 10px 15px;
            font-family: inherit;
            font-size: 0.95rem;
            resize: none;
            max-height: 100px;
            outline: none;
            transition: border-color 0.2s;
        }

        #chat-input:focus {
            border-color: var(--navy-primary);
        }

        #send-btn {
            background-color: var(--orange-safety);
            color: white;
            border: none;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        #send-btn:hover {
            background-color: #D9530E;
        }

        #send-btn:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }

        .chat-footer {
            text-align: center;
            font-size: 0.7rem;
            color: #9CA3AF;
            padding-bottom: 5px;
            background: white;
        }

        /* Loading Dots */
        .typing-indicator span {
            display: inline-block;
            width: 6px;
            height: 6px;
            background-color: #9CA3AF;
            border-radius: 50%;
            animation: typing 1.4s infinite ease-in-out both;
            margin: 0 2px;
        }
        .typing-indicator span:nth-child(1) { animation-delay: -0.32s; }
        .typing-indicator span:nth-child(2) { animation-delay: -0.16s; }

        @keyframes typing {
            0%, 80%, 100% { transform: scale(0); }
            40% { transform: scale(1); }
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Mobile Responsive */
        @media (max-width: 480px) {
            #coi-chat-window {
                position: fixed;
                bottom: 0;
                right: 0;
                width: 100%;
                height: 100%;
                border-radius: 0;
                z-index: 10000;
            }
            #coi-chat-toggle {
                bottom: 15px;
                right: 15px;
            }
        }
    </style>

    <script nonce="<?php echo $nonce; ?>">
        // Chatbot 2.0 Logic
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Chatbot script initialized'); // Debug log

            const chatWindow = document.getElementById('coi-chat-window');
            const chatMessages = document.getElementById('chat-messages');
            const chatInput = document.getElementById('chat-input');
            const sendBtn = document.getElementById('send-btn');
            const toggleBtn = document.getElementById('coi-chat-toggle');
            const closeBtn = document.getElementById('coi-chat-close');
            let isChatOpen = false;

            // Verificar se os elementos existem
            if (!chatWindow || !chatInput || !sendBtn || !toggleBtn) {
                console.error('Elementos do Chatbot não encontrados!');
                return;
            }

            function toggleChat() {
                isChatOpen = !isChatOpen;
                if (isChatOpen) {
                    chatWindow.classList.remove('hidden');
                    // Pequeno delay para garantir visibilidade antes do foco
                    setTimeout(() => chatInput.focus(), 100);
                } else {
                    chatWindow.classList.add('hidden');
                }
            }
            
            toggleBtn.addEventListener('click', function(e) {
                e.preventDefault();
                toggleChat();
            });
            
            if (closeBtn) {
                closeBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    toggleChat();
                });
            }

            // Auto-resize do textarea
            chatInput.addEventListener('input', function() {
                this.style.height = 'auto';
                this.style.height = this.scrollHeight + 'px';
            });

            // Enviar com Enter
            chatInput.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendChatMessage();
                }
            });

            // Enviar com Clique
            sendBtn.addEventListener('click', function(e) {
                e.preventDefault();
                console.log('Botão enviar clicado'); // Debug log
                sendChatMessage();
            });

            function scrollToBottom() {
                if(chatMessages) chatMessages.scrollTop = chatMessages.scrollHeight;
            }

            function addMessage(text, sender, isHtml = false) {
                const div = document.createElement('div');
                div.className = `message ${sender}`;
                
                const contentDiv = document.createElement('div');
                contentDiv.className = 'message-content';
                if (isHtml) {
                    contentDiv.innerHTML = text;
                } else {
                    contentDiv.innerText = text;
                }
                
                const timeDiv = document.createElement('div');
                timeDiv.className = 'message-time';
                const now = new Date();
                timeDiv.innerText = now.getHours().toString().padStart(2, '0') + ':' + now.getMinutes().toString().padStart(2, '0');

                div.appendChild(contentDiv);
                div.appendChild(timeDiv);
                chatMessages.appendChild(div);
                scrollToBottom();
            }

            function showTyping() {
                const id = 'typing-' + Date.now();
                const div = document.createElement('div');
                div.className = 'message bot';
                div.id = id;
                div.innerHTML = `
                    <div class="message-content">
                        <div class="typing-indicator">
                            <span></span><span></span><span></span>
                        </div>
                    </div>
                `;
                chatMessages.appendChild(div);
                scrollToBottom();
                return id;
            }

            function removeTyping(id) {
                const el = document.getElementById(id);
                if (el) el.remove();
            }

            async function sendChatMessage() {
                const msg = chatInput.value.trim();
                console.log('Enviando mensagem:', msg); // Debug log

                if (!msg) return;

                // Determine Language
                const urlParams = new URLSearchParams(window.location.search);
                let currentLang = urlParams.get('lang');
                if (!currentLang) {
                     const match = document.cookie.match(new RegExp('(^| )lang=([^;]+)'));
                     if (match) currentLang = match[2];
                }
                if (!currentLang) currentLang = 'pt';

                // UI Updates
                chatInput.value = '';
                chatInput.style.height = 'auto';
                addMessage(msg, 'user');
                sendBtn.disabled = true;

                const typingId = showTyping();

                try {
                    const response = await fetch('chat_api.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ message: msg, lang: currentLang })
                    });

                    const data = await response.json();
                    removeTyping(typingId);

                    if (data.reply) {
                        const formattedReply = data.reply.replace(/\n/g, '<br>');
                        const htmlReply = formattedReply.replace(/•\s?(.*?)(<br>|$)/g, '<li>$1</li>');
                        const finalHtml = htmlReply.includes('<li>') ? htmlReply : formattedReply;
                        addMessage(finalHtml, 'bot', true);
                    } else if (data.error) {
                        addMessage("⚠️ " + data.error, 'bot');
                    } else {
                        addMessage("Desculpe, não entendi a resposta.", 'bot');
                    }

                } catch (error) {
                    console.error('Chat Error:', error);
                    removeTyping(typingId);
                    addMessage("😔 Desculpe, estou com problemas de conexão no momento. Tente novamente mais tarde.", 'bot');
                } finally {
                    sendBtn.disabled = false;
                    chatInput.focus();
                }
            }
        });
    </script>
                <!-- Mobile Toggle -->
                <button class="mobile-menu-btn" aria-label="Menu">
                    <span></span>
                    <span></span>
                    <span></span>
                </button>
            </nav>
        </div>
    </header>

    <!-- Mobile Navigation -->
    <div class="mobile-overlay"></div>
    <div class="mobile-menu">
        <a href="#about"><?= __('nav.about') ?></a>
        <a href="#services"><?= __('nav.services') ?></a>
        <a href="#projects"><?= __('nav.portfolio') ?></a>
        <a href="fotos.php"><?= __('nav.photos') ?></a>
        <a href="videos.php"><?= __('nav.videos') ?></a>
        <a href="#compliance"><?= __('nav.compliance') ?></a>
        <a href="https://intranet.coiengenharia.com.br/" class="nav-link-intranet">Intranet</a>
        <a href="#contact"><?= __('nav.contact') ?></a>
        <div style="display:flex; gap:0.5rem; padding-left:0; margin-top:1rem; justify-content:flex-start; flex-wrap: wrap;">
             <a href="?lang=pt" style="border:none; width:auto; padding:0.5rem; display: flex; align-items: center; gap: 4px; <?= current_lang() == 'pt' ? 'color:var(--orange-safety); font-weight:800;' : 'opacity:0.7;' ?>">
                <img src="https://flagcdn.com/20x15/br.png" alt="Brasil" width="20" height="15"> PT
             </a>
             <a href="?lang=en" style="border:none; width:auto; padding:0.5rem; display: flex; align-items: center; gap: 4px; <?= current_lang() == 'en' ? 'color:var(--orange-safety); font-weight:800;' : 'opacity:0.7;' ?>">
                <img src="https://flagcdn.com/20x15/us.png" alt="USA" width="20" height="15"> EN
             </a>
             <a href="?lang=es" style="border:none; width:auto; padding:0.5rem; display: flex; align-items: center; gap: 4px; <?= current_lang() == 'es' ? 'color:var(--orange-safety); font-weight:800;' : 'opacity:0.7;' ?>">
                <img src="https://flagcdn.com/20x15/es.png" alt="España" width="20" height="15"> ES
             </a>
        </div>
        <div style="padding-left:0; margin-top:0.5rem;">
            <a href="https://www.linkedin.com/company/108664081/" target="_blank" style="border:none; width:auto; padding:0.5rem; display: flex; align-items: center; gap: 0.5rem; color: var(--navy-primary); font-weight: 600;">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 16 16">
                    <path d="M0 1.146C0 .513.526 0 1.175 0h13.65C15.474 0 16 .513 16 1.146v13.708c0 .633-.526 1.146-1.175 1.146H1.175C.526 16 0 15.487 0 14.854V1.146zm4.943 12.248V6.169H2.542v7.225h2.401zm-1.2-8.212c.837 0 1.358-.554 1.358-1.248-.015-.709-.52-1.248-1.342-1.248-.822 0-1.359.54-1.359 1.248 0 .694.521 1.248 1.327 1.248h.016zm4.908 8.212V9.359c0-.216.016-.432.08-.586.173-.431.568-.878 1.232-.878.869 0 1.216.662 1.216 1.634v3.865h2.401V9.25c0-2.22-1.184-3.252-2.764-3.252-1.274 0-1.845.7-2.165 1.193v.025h-.016a5.54 5.54 0 0 1 .016-.025V6.169h-2.4c.03.678 0 7.225 0 7.225h2.4z"/>
                </svg>
                LinkedIn
            </a>
        </div>
        <a href="#contact" class="btn btn-primary" style="color: white; text-align: center; border:none;"><?= __('nav.cta') ?></a>
    </div>

    <section class="hero">
        <video class="hero-video" autoplay loop muted playsinline poster="capa.webp">
            <source src="video.mp4" type="video/mp4">
        </video>
        <div class="container hero-content" data-aos="fade-up">
            <span class="hero-tag"><?= __('hero.tag') ?></span>
            <h1><?= __('hero.title') ?></h1>
            <p><?= __('hero.text') ?></p>
            <div style="display:flex; gap:1rem;">
                <a href="#projects" class="btn btn-primary"><?= __('hero.cta_portfolio') ?></a>
                <a href="#services" class="btn btn-outline"><?= __('hero.cta_solutions') ?></a>
            </div>
        </div>
    </section>

    <div class="stats">
        <div class="container">
            <div class="stats-grid">
                <div class="stat-item" data-aos="fade-up" data-aos-delay="100">
                    <h3>+29</h3>
                    <p><?= __('stats.projects') ?></p>
                </div>
                <div class="stat-item" data-aos="fade-up" data-aos-delay="200">
                    <h3>750k</h3>
                    <p><?= __('stats.earthworks') ?></p>
                </div>
                <div class="stat-item" data-aos="fade-up" data-aos-delay="300">
                    <h3>100%</h3>
                    <p><?= __('stats.compliance') ?></p>
                </div>
                <div class="stat-item" data-aos="fade-up" data-aos-delay="400">
                    <h3>11</h3>
                    <p><?= __('stats.years') ?></p>
                </div>
            </div>
        </div>
    </div>

    <section id="about" class="section">
        <div class="container">
            <div class="about-grid">
                <div class="about-text" data-aos="fade-right">
                    <h4 class="text-orange"><?= __('about.tag') ?></h4>
                    <h2><?= __('about.title') ?></h2>
                    <p><?= __('about.text1') ?></p>
                    <p><?= __('about.text2') ?></p>
                    
                    <div class="about-cards">
                        <div class="feature-card">
                            <h4><?= __('about.card1_title') ?></h4>
                            <p><?= __('about.card1_text') ?></p>
                        </div>
                        <div class="feature-card">
                            <h4><?= __('about.card2_title') ?></h4>
                            <p><?= __('about.card2_text') ?></p>
                        </div>
                    </div>
                </div>
                <div class="about-image" data-aos="fade-left">
                    <img src="pgf.webp" alt="Obra Corporativa" style="width:100%; border-radius:8px; box-shadow:0 20px 40px rgba(0,0,0,0.1);" loading="lazy">
                </div>
            </div>
        </div>
    </section>

    <section id="services" class="section bg-light">
        <div class="container">
            <div class="text-center" style="max-width:700px; margin:0 auto 4rem;">
                <h4 class="text-orange"><?= __('services_section.tag') ?></h4>
                <h2><?= __('services_section.title') ?></h2>
                <p><?= __('services_section.description') ?></p>
            </div>

            <div class="services-grid">
                <!-- Card 1 -->
                <div class="service-card" data-aos="fade-up">
                    <div class="service-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21h18"/><path d="M5 21V7l8-4 8 4v14"/><path d="M8 9l8 4"/><path d="M16 9l-8 4"/></svg>
                    </div>
                    <h3><?= __('services_section.card1.title') ?></h3>
                    <ul class="service-list">
                        <?php foreach(__('services_section.card1.list') as $item): ?>
                            <li><?= $item ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>

                <!-- Card 2 -->
                <div class="service-card" data-aos="fade-up" data-aos-delay="100">
                    <div class="service-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z"/><path d="M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2"/><path d="M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2"/><path d="M10 6h4"/><path d="M10 10h4"/><path d="M10 14h4"/><path d="M10 18h4"/></svg>
                    </div>
                    <h3><?= __('services_section.card2.title') ?></h3>
                    <ul class="service-list">
                        <?php foreach(__('services_section.card2.list') as $item): ?>
                            <li><?= $item ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>

                <!-- Card 3 -->
                <div class="service-card" data-aos="fade-up" data-aos-delay="200">
                    <div class="service-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><path d="M12 13v6"/><path d="M9 16l3-3 3 3"/></svg>
                    </div>
                    <h3><?= __('services_section.card3.title') ?></h3>
                    <ul class="service-list">
                        <?php foreach(__('services_section.card3.list') as $item): ?>
                            <li><?= $item ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>
        </div>
    </section>

    <section id="projects" class="section">
        <div class="container">
            <div class="text-center" style="margin-bottom:4rem;">
                <h4 class="text-orange"><?= __('projects.tag') ?></h4>
                <h2><?= __('projects.title') ?></h2>
            </div>

            <!-- Project 1 -->
            <div class="project-card" data-aos="fade-up">
                <div class="project-img">
                    <img src="citrosuco.webp" alt="<?= __('project_items.citrosuco.title') ?>" loading="lazy">
                </div>
                <div class="project-info clickable-info" data-full-description="<?= htmlspecialchars(__('project_items.citrosuco.full_desc')) ?>">
                    <span class="project-meta"><?= __('project_items.citrosuco.location') ?></span>
                    <h3><?= __('project_items.citrosuco.title') ?></h3>
                    <p><?= __('project_items.citrosuco.subtitle') ?></p>
                    <div class="project-details">
                        <div class="detail-item">
                            <h5><?= __('projects.scope') ?></h5>
                            <p><?= __('project_items.citrosuco.val_scope') ?></p>
                        </div>
                        <div class="detail-item">
                            <h5><?= __('projects.impact') ?></h5>
                            <p><?= __('project_items.citrosuco.val_impact') ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Project 2 -->
            <div class="project-card" data-aos="fade-up">
                <div class="project-img">
                    <img src="pgf.webp" alt="<?= __('project_items.pgf.title') ?>" loading="lazy">
                </div>
                <div class="project-info clickable-info" data-full-description="<?= htmlspecialchars(__('project_items.pgf.full_desc')) ?>">
                    <span class="project-meta"><?= __('project_items.pgf.location') ?></span>
                    <h3><?= __('project_items.pgf.title') ?></h3>
                    <p><?= __('project_items.pgf.subtitle') ?></p>
                    <div class="project-details">
                        <div class="detail-item">
                            <h5><?= __('projects.client') ?></h5>
                            <p><?= __('project_items.pgf.val_client') ?></p>
                        </div>
                        <div class="detail-item">
                            <h5><?= __('projects.complexity') ?></h5>
                            <p><?= __('project_items.pgf.val_complex') ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Project 3 -->
            <div class="project-card" data-aos="fade-up">
                <div class="project-img">
                    <img src="angra3.webp" alt="<?= __('project_items.angra.title') ?>" loading="lazy">
                </div>
                <div class="project-info clickable-info" data-full-description="<?= htmlspecialchars(__('project_items.angra.full_desc')) ?>">
                    <span class="project-meta"><?= __('project_items.angra.location') ?></span>
                    <h3><?= __('project_items.angra.title') ?></h3>
                    <p><?= __('project_items.angra.subtitle') ?></p>
                    <div class="project-details">
                        <div class="detail-item">
                            <h5><?= __('projects.sector') ?></h5>
                            <p><?= __('project_items.angra.val_sector') ?></p>
                        </div>
                        <div class="detail-item">
                            <h5><?= __('projects.focus') ?></h5>
                            <p><?= __('project_items.angra.val_focus') ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Project 4: Assaí -->
            <div class="project-card" data-aos="fade-up">
                <div class="project-img">
                    <img src="fotos/1660049092221.webp" alt="<?= __('project_items.assai.title') ?>" loading="lazy">
                </div>
                <div class="project-info clickable-info" data-full-description="<?= htmlspecialchars(__('project_items.assai.full_desc')) ?>">
                    <span class="project-meta"><?= __('project_items.assai.location') ?></span>
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                         <h3><?= __('project_items.assai.title') ?></h3>
                    </div>
                    <p><?= __('project_items.assai.subtitle') ?></p>
                    <div class="project-details">
                        <div class="detail-item">
                            <h5><?= __('projects.client') ?></h5>
                            <p><?= __('project_items.assai.val_client') ?></p>
                        </div>
                        <div class="detail-item">
                            <h5><?= __('projects.scope') ?></h5>
                            <p><?= __('project_items.assai.val_scope') ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Project 5: Beto Carrero -->
            <div class="project-card" data-aos="fade-up">
                <div class="project-img">
                    <img src="fotos/1626308519987.webp" alt="<?= __('project_items.beto.title') ?>" loading="lazy">
                </div>
                <div class="project-info clickable-info" data-full-description="<?= htmlspecialchars(__('project_items.beto.full_desc')) ?>">
                    <span class="project-meta"><?= __('project_items.beto.location') ?></span>
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                         <h3><?= __('project_items.beto.title') ?></h3>
                    </div>
                    <p><?= __('project_items.beto.subtitle') ?></p>
                    <div class="project-details">
                        <div class="detail-item">
                            <h5><?= __('projects.client') ?></h5>
                            <p><?= __('project_items.beto.val_client') ?></p>
                        </div>
                        <div class="detail-item">
                            <h5><?= __('projects.area') ?></h5>
                            <p><?= __('project_items.beto.val_area') ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Project 6: Loteamento Atibaia -->
            <div class="project-card" data-aos="fade-up">
                <div class="project-img">
                    <img src="fotos/atibaia_opt.webp" alt="<?= __('project_items.atibaia.title') ?>" loading="lazy">
                </div>
                <div class="project-info clickable-info" data-full-description="<?= htmlspecialchars(__('project_items.atibaia.full_desc')) ?>">
                    <span class="project-meta"><?= __('project_items.atibaia.location') ?></span>
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                         <h3><?= __('project_items.atibaia.title') ?></h3>
                    </div>
                    <p><?= __('project_items.atibaia.subtitle') ?></p>
                    <div class="project-details">
                        <div class="detail-item">
                            <h5><?= __('projects.type') ?></h5>
                            <p><?= __('project_items.atibaia.val_type') ?></p>
                        </div>
                        <div class="detail-item">
                            <h5><?= __('projects.scope') ?></h5>
                            <p><?= __('project_items.atibaia.val_scope') ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Project 7: Ponto de Parada e Descanso EIXO-SP -->
            <div class="project-card" data-aos="fade-up">
                <div class="project-img">
                    <img src="fotos/galia.webp" alt="<?= __('project_items.galia.title') ?>" loading="lazy">
                </div>
                <div class="project-info clickable-info" data-full-description="<?= htmlspecialchars(__('project_items.galia.full_desc')) ?>">
                    <span class="project-meta"><?= __('project_items.galia.location') ?></span>
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                         <h3><?= __('project_items.galia.title') ?></h3>
                    </div>
                    <p><?= __('project_items.galia.subtitle') ?></p>
                    <div class="project-details">
                        <div class="detail-item">
                            <h5><?= __('projects.client') ?></h5>
                            <p><?= __('project_items.galia.val_client') ?></p>
                        </div>
                        <div class="detail-item">
                            <h5><?= __('projects.area') ?></h5>
                            <p><?= __('project_items.galia.val_area') ?></p>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </section>

    <!-- Clients Section -->
    <section id="clients" class="clients-section">
        <div class="container">
            <h2 style="color:var(--navy-primary);"><?= __('clients_section.title') ?></h2>
            <p style="color:var(--gray-light); max-width:600px; margin: 1rem auto;"><?= __('clients_section.subtitle') ?></p>
            
            <div class="clients-grid">
                <img src="logos/assai.png" alt="Assaí Atacadista" class="client-logo" loading="lazy">
                <img src="logos/muffato.svg" alt="Grupo Muffato" class="client-logo" loading="lazy">
                <img src="logos/Eletro.png" alt="Eletronuclear" class="client-logo" loading="lazy">
                <img src="logos/eixo_sp.png" alt="EIXO-SP" class="client-logo" loading="lazy">
                <img src="logos/citrosuco.png" alt="Citrosuco" class="client-logo" loading="lazy">
                <img src="logos/Caprem.svg" alt="Caprem" class="client-logo" loading="lazy">
                <img src="logos/beto_carrero.png" alt="Beto Carrero" class="client-logo" loading="lazy">
                <img src="logos/pavican.png" alt="Pavican" class="client-logo" loading="lazy">
            </div>
        </div>
    </section>

    <section id="compliance" class="section compliance">
        <div class="container">
            <h2><?= __('compliance.title') ?></h2>
            <p style="max-width:700px; margin:1.5rem auto 0; opacity:0.9;">
                <?= __('compliance.text') ?>
            </p>
            <div class="cert-grid">
                <div class="cert-item">
                    <h4 style="color:white; border-bottom:2px solid var(--orange-safety); display:inline-block; padding-bottom:0.5rem;">NR-18 / NR-35</h4>
                    <p style="font-size:0.8rem; margin-top:0.5rem;"><?= __('compliance.nr18') ?></p>
                </div>
                <div class="cert-item">
                    <h4 style="color:white; border-bottom:2px solid var(--orange-safety); display:inline-block; padding-bottom:0.5rem;">ISO 9001</h4>
                    <p style="font-size:0.8rem; margin-top:0.5rem;"><?= __('compliance.iso') ?></p>
                </div>
                <div class="cert-item">
                    <h4 style="color:white; border-bottom:2px solid var(--orange-safety); display:inline-block; padding-bottom:0.5rem;">CREA</h4>
                    <p style="font-size:0.8rem; margin-top:0.5rem;"><?= __('compliance.crea') ?></p>
                </div>
                <div class="cert-item">
                    <h4 style="color:white; border-bottom:2px solid var(--orange-safety); display:inline-block; padding-bottom:0.5rem;">LGPD</h4>
                    <p style="font-size:0.8rem; margin-top:0.5rem;"><?= __('compliance.lgpd') ?></p>
                </div>
            </div>
        </div>
    </section>

    <!-- Visualização 3D / BIM (Simulação Interativa) -->
    <section id="innovation" class="section" style="background-color: var(--light-gray);">
        <div class="container">
            <div class="section-header" data-aos="fade-up">
                <div class="section-subtitle"><?= __('innovation.subtitle') ?></div>
                <h2 class="section-title"><?= __('innovation.title') ?></h2>
                <p class="section-description"><?= __('innovation.description') ?></p>
            </div>
            
            <div class="bim-viewer-container" data-aos="zoom-in" style="position:relative; height:500px; background:#000; border-radius:12px; overflow:hidden; display:flex; align-items:center; justify-content:center;">
                <!-- PHP Scan for Models -->
                <?php
                    $modelFiles = glob('models/*.glb');
                    $models = [];
                    foreach ($modelFiles as $file) {
                        $models[] = [
                            'path' => $file,
                            'name' => ucfirst(str_replace(['models/', '.glb', '_', '-'], ['', '', ' ', ' '], $file))
                        ];
                    }
                    $defaultModel = $models[0]['path'] ?? '';
                ?>

                <!-- Model Selector UI -->
                <div class="model-selector-ui">
                    <label for="modelSelect">Escolha o Projeto:</label>
                    <select id="modelSelect">
                        <?php foreach ($models as $model): ?>
                            <option value="<?= htmlspecialchars($model['path']) ?>"><?= htmlspecialchars($model['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                
                <style>
                    .model-selector-ui {
                        position: absolute;
                        top: 20px;
                        left: 20px;
                        z-index: 100;
                        background: rgba(255, 255, 255, 0.2);
                        backdrop-filter: blur(10px);
                        padding: 10px 15px;
                        border-radius: 8px;
                        border: 1px solid rgba(255, 255, 255, 0.3);
                        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                        display: flex;
                        flex-direction: column;
                        gap: 5px;
                    }
                    .model-selector-ui label {
                        color: white;
                        font-size: 0.8rem;
                        font-weight: 600;
                        text-transform: uppercase;
                        letter-spacing: 1px;
                    }
                    .model-selector-ui select {
                        background: rgba(0, 0, 0, 0.5);
                        color: white;
                        border: 1px solid rgba(255,255,255,0.3);
                        padding: 8px;
                        border-radius: 4px;
                        font-family: var(--font-body);
                        cursor: pointer;
                        outline: none;
                        font-size: 0.95rem;
                    }
                    .model-selector-ui select:hover {
                        background: rgba(0, 0, 0, 0.7);
                        border-color: var(--orange-safety);
                    }
                    .model-selector-ui select option {
                        background: #333;
                        color: white;
                    }
                    /* Mobile Adjustment */
                    @media(max-width: 480px) {
                        .model-selector-ui {
                            top: 15px;
                            left: 15px;
                            right: auto; 
                            width: auto;
                            max-width: 60%; /* Leave space for AR button (Top Right) */
                        }
                        .model-selector-ui select {
                            font-size: 0.9rem; 
                            padding: 8px; 
                            width: 100%;
                        }
                    }
                </style>

                <!-- Placeholder para Model Viewer -->
                <script type="module" src="https://ajax.googleapis.com/ajax/libs/model-viewer/3.4.0/model-viewer.min.js"></script>
                
                <!-- Usando o modelo dinâmico -->
                <model-viewer 
                    id="main-viewer"
                    src="<?= $defaultModel ?>" 
                    alt="Modelo 3D Interativo"
                    ar
                    ar-modes="webxr scene-viewer quick-look"
                    camera-controls
                    auto-rotate
                    shadow-intensity="1.5"
                    shadow-softness="0.5"
                    exposure="1.0"
                    tone-mapping="commerce"
                    style="width: 100%; height: 100%; background-color: #f0f0f0;"
                >
                    <div slot="progress-bar"></div>
                    <button slot="ar-button" id="ar-button" style="background-color: white; border-radius: 4px; border: none; position: absolute; top: 16px; right: 16px; padding: 8px 16px; font-weight: bold; cursor: pointer; z-index: 100;">
                        <?= __('innovation.ar_button') ?>
                    </button>
                    <div id="error" slot="error" style="background-color: #e74c3c; color: white; padding: 10px; border-radius: 4px; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); display: none;">
                        <?= __('innovation.error') ?>
                    </div>
                </model-viewer>
                
                    <script>
                        const modelViewer = document.getElementById('main-viewer');
                        const arButton = document.getElementById('ar-button');
                        const modelSelect = document.getElementById('modelSelect');
                        
                        // Handle Model Switch
                        if(modelSelect) {
                            modelSelect.addEventListener('change', (e) => {
                                const newPath = e.target.value;
                                console.log('Switching model to:', newPath);
                                // Show loading feedback if desired, model-viewer handles it natively with the progress bar
                                modelViewer.src = newPath;
                            });
                        }
                        
                        // Force AR activation on click
                        if(arButton) {
                            arButton.addEventListener('click', () => {
                                if (modelViewer.canActivateAR) {
                                    modelViewer.activateAR();
                                } else {
                                    alert('AR não disponível neste dispositivo/navegador.');
                                }
                            });
                        }

                    modelViewer.addEventListener('error', (e) => {
                        console.error('Erro no model-viewer:', e);
                        const errorDiv = document.getElementById('error');
                        if (errorDiv) {
                            errorDiv.style.display = 'block';
                            errorDiv.innerText = '<?= __('innovation.error') ?>';
                        }
                    });
                    modelViewer.addEventListener('load', () => {
                        console.log('Modelo 3D carregado com sucesso!');
                    });
                </script>
                
                <div style="position:absolute; bottom:20px; left:20px; background:rgba(0,0,0,0.7); color:white; padding:1rem; border-radius:8px; pointer-events:none;">
                    <strong><?= __('innovation.overlay_title') ?></strong><br>
                    <small><?= __('innovation.overlay_text') ?></small>
                </div>
            </div>
        </div>
    </section>

    <!-- Chatbot 2.0 (Gemini Powered) -->
    <div id="coi-chatbot-container">
        <!-- Floating Button -->
        <button id="coi-chat-toggle" aria-label="Abrir Chat">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
            </svg>
            <span class="online-badge"></span>
        </button>

        <!-- Chat Window -->
        <div id="coi-chat-window" class="hidden">
            <div class="chat-header">
                <div class="header-info">
                    <div class="avatar">
                        <img src="LOGO.png" alt="AI">
                    </div>
                    <div>
                        <h3><?= __('chat.title') ?></h3>
                        <span class="status-text">● <?= __('chat.status') ?></span>
                    </div>
                </div>
                <button class="close-btn" id="coi-chat-close" aria-label="<?= __('chat.close_btn') ?? 'Fechar' ?>">×</button>
            </div>
            
            <div id="chat-messages" class="chat-messages">
                <div class="message bot-message">
                    <img class="bot-avatar" src="LOGO.png" alt="Bot">
                    <div class="message-content">
                        <?= __('chat.greeting') ?> 
                        <br><br>
                        <?= __('chat.help_intro') ?>
                        <ul>
                            <?php foreach(__('chat.help_items') as $item): ?>
                                <li><?= $item ?></li>
                            <?php endforeach; ?>
                        </ul>
                        <?= __('chat.prompt') ?>
                    </div>
                    <div class="message-time">Agora</div>
                </div>
            </div>

            <div class="chat-input-wrapper">
                <textarea id="chat-input" placeholder="<?= __('chat.placeholder') ?>" rows="1" oninput="autoResize(this)" onkeydown="handleChatKey(event)"></textarea>
                <button id="send-btn" onclick="sendChatMessage()" aria-label="<?= __('chat.send_btn') ?? 'Enviar' ?>">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="22" y1="2" x2="11" y2="13"></line>
                        <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                    </svg>
                </button>
            </div>

        </div>
    </div>





    <!-- ESG & Sustentabilidade -->
    <section id="esg" class="section" style="background-color: var(--white);">
        <div class="container">
            <div class="section-header" data-aos="fade-up">
                <div class="section-subtitle"><?= __('esg.subtitle') ?></div>
                <h2 class="section-title"><?= __('esg.title') ?></h2>
                <p class="section-description"><?= __('esg.description') ?></p>
            </div>
            
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:2rem; margin-top:3rem;">
                <!-- Environmental -->
                <div class="esg-card" data-aos="fade-up" data-aos-delay="100" style="padding:2rem; border-radius:12px; background:rgba(255,255,255,0.9); border-left:4px solid #10b981; box-shadow:0 4px 20px rgba(0,0,0,0.05);">
                    <h3 style="color:var(--navy-primary); margin-bottom:1rem; display:flex; align-items:center; gap:0.5rem;">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
                        <?= __('esg.env_title') ?>
                    </h3>
                    <p style="font-size:0.95rem; color:var(--text-light);">
                        <?= __('esg.env_text') ?>
                    </p>
                </div>
                
                <!-- Social -->
                <div class="esg-card" data-aos="fade-up" data-aos-delay="200" style="padding:2rem; border-radius:12px; background:rgba(255,255,255,0.9); border-left:4px solid #3b82f6; box-shadow:0 4px 20px rgba(0,0,0,0.05);">
                    <h3 style="color:var(--navy-primary); margin-bottom:1rem; display:flex; align-items:center; gap:0.5rem;">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                        <?= __('esg.social_title') ?>
                    </h3>
                    <p style="font-size:0.95rem; color:var(--text-light);">
                        <?= __('esg.social_text') ?>
                    </p>
                </div>
                
                <!-- Governance -->
                <div class="esg-card" data-aos="fade-up" data-aos-delay="300" style="padding:2rem; border-radius:12px; background:rgba(255,255,255,0.9); border-left:4px solid #f59e0b; box-shadow:0 4px 20px rgba(0,0,0,0.05);">
                    <h3 style="color:var(--navy-primary); margin-bottom:1rem; display:flex; align-items:center; gap:0.5rem;">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                        <?= __('esg.gov_title') ?>
                    </h3>
                    <p style="font-size:0.95rem; color:var(--text-light);">
                        <?= __('esg.gov_text') ?>
                    </p>
                </div>
            </div>
        </div>
    </section>

    <section id="contact" class="section bg-light">
        <div class="container">
            <div class="contact-wrapper">
                <div class="contact-info">
                    <h3><?= __('contact.title') ?></h3>
                    <div class="info-item">
                        <strong><?= __('contact.items.corporate') ?></strong>
                        <p>contato@coiengenharia.com.br</p>
                    </div>
                    <div class="info-item">
                        <strong><?= __('contact.items.phone') ?></strong>
                        <p>(24) 99841-6319</p>
                    </div>
                    <div class="info-item">
                        <strong><?= __('contact.items.area') ?></strong>
                        <p><?= __('contact.items.area_value') ?></p>
                    </div>
                    <div style="margin-top:3rem;">
                        <a href="https://wa.me/5524998416319" class="btn btn-outline" style="border-color:white;"><?= __('contact.cta_chat') ?></a>
                    </div>
                </div>
                <div class="contact-form-box">
                    <h3 style="color:var(--navy-primary); margin-bottom:2rem;"><?= __('contact.form.title') ?></h3>
                    
                    <form method="POST" action="">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <!-- Honeypot Fields -->
                        <div style="display:none;">
                            <label>Não preencha este campo:</label>
                            <input type="text" name="<?php echo $_SESSION['honeypot_name']; ?>">
                        </div>
                        <input type="text" name="website" style="display:none;" tabindex="-1" autocomplete="off">
                        
                        <div class="form-group">
                            <label><?= __('contact.form.name') ?></label>
                            <input type="text" name="nome" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label><?= __('contact.form.email') ?></label>
                            <input type="email" name="email" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label><?= __('contact.form.service') ?></label>
                            <select name="servico" class="form-control">
                                <option value="Engenharia">Engenharia Civil</option>
                                <option value="Infraestrutura">Infraestrutura</option>
                                <option value="Pavimentação">Pavimentação</option>
                                <option value="Consultoria">Consultoria</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label><?= __('contact.form.message') ?></label>
                            <textarea name="mensagem" class="form-control" rows="4" required></textarea>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width:100%;"><?= __('contact.form.submit') ?></button>
                    </form>
                </div>
            </div>
        </div>
    </section>

    <footer>
        <div class="container" style="color: white;">
            <div class="footer-grid">
                <div>
                    <img src="LOGO.png" alt="COI Logo" style="height:35px; margin-bottom:1.5rem; filter: brightness(0) invert(1);">
                    <p style="color: white;"><?= __('footer.about') ?></p>
                </div>
                <div>
                    <h4 style="color: white;"><?= __('footer.titles.inst') ?></h4>
                    <ul style="color: white;">
                        <li><a href="#about" style="color: white;"><?= __('nav.about') ?></a></li>
                        <li><a href="#compliance" style="color: white;"><?= __('nav.compliance') ?></a></li>
                        <li><a href="#projects" style="color: white;"><?= __('nav.portfolio') ?></a></li>
                    </ul>
                </div>
                <div>
                    <h4 style="color: white;"><?= __('footer.titles.services') ?></h4>
                    <ul style="color: white;">
                        <li><a href="#services" style="color: white;"><?= __('footer.links.civil') ?></a></li>
                        <li><a href="#services" style="color: white;"><?= __('footer.links.infra') ?></a></li>
                        <li><a href="#services" style="color: white;"><?= __('footer.links.paving') ?></a></li>
                    </ul>
                </div>
                <div>
                    <h4 style="color: white;"><?= __('footer.titles.contact') ?></h4>
                    <ul style="color: white;">
                        <li>contato@coiengenharia.com.br</li>
                        <li>(24) 99841-6319</li>
                        <li><?= __('footer.links.national') ?></li>
                        <li style="margin-top: 1rem;">
                             <a href="https://www.linkedin.com/company/108664081/" target="_blank" style="color: white; display: inline-flex; align-items: center; gap: 0.5rem;">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 16 16">
                                    <path d="M0 1.146C0 .513.526 0 1.175 0h13.65C15.474 0 16 .513 16 1.146v13.708c0 .633-.526 1.146-1.175 1.146H1.175C.526 16 0 15.487 0 14.854V1.146zm4.943 12.248V6.169H2.542v7.225h2.401zm-1.2-8.212c.837 0 1.358-.554 1.358-1.248-.015-.709-.52-1.248-1.342-1.248-.822 0-1.359.54-1.359 1.248 0 .694.521 1.248 1.327 1.248h.016zm4.908 8.212V9.359c0-.216.016-.432.08-.586.173-.431.568-.878 1.232-.878.869 0 1.216.662 1.216 1.634v3.865h2.401V9.25c0-2.22-1.184-3.252-2.764-3.252-1.274 0-1.845.7-2.165 1.193v.025h-.016a5.54 5.54 0 0 1 .016-.025V6.169h-2.4c.03.678 0 7.225 0 7.225h2.4z"/>
                                </svg>
                                LinkedIn
                             </a>
                        </li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom" style="border-top: 1px solid rgba(255,255,255,0.1); color: white;">
                <p>&copy; 2026 COI ENGENHARIA. <?= __('footer.rights') ?></p>
                <p>CNPJ: 62.049.623/0001-06 | Empresa registrada no CREA</p>
            </div>
        </div>
    </footer>

    <!-- Lightbox Modal -->
    <div id="lightbox" class="lightbox">
        <span class="close-lightbox">&times;</span>
        <img class="lightbox-content" id="lightbox-img">
    </div>

    <!-- Text Modal -->
    <div id="text-modal" class="text-modal">
        <div class="text-modal-content">
            <span class="text-modal-close">&times;</span>
            <div id="text-modal-body"></div>
        </div>
    </div>

    <!-- Scripts -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/aos/2.3.4/aos.js"></script>
    <script nonce="<?php echo $nonce; ?>">
        AOS.init({
            duration: 800,
            once: true,
            offset: 100
        });
        
        // Sticky Header Logic
        const header = document.querySelector('header');
        
        function updateHeader() {
            if (window.scrollY > 50) {
                header.classList.add('scrolled');
            } else {
                header.classList.remove('scrolled');
            }
        }

        window.addEventListener('scroll', updateHeader);
        // Initial check
        updateHeader();

        // Mobile Menu Logic
        const mobileBtn = document.querySelector('.mobile-menu-btn');
        const mobileMenu = document.querySelector('.mobile-menu');
        const mobileOverlay = document.querySelector('.mobile-overlay');
        const mobileLinks = document.querySelectorAll('.mobile-menu a');

        function toggleMenu() {
            mobileMenu.classList.toggle('active');
            mobileOverlay.classList.toggle('active');
            document.body.style.overflow = mobileMenu.classList.contains('active') ? 'hidden' : '';
        }

        mobileBtn.addEventListener('click', toggleMenu);
        mobileOverlay.addEventListener('click', toggleMenu);
        
        mobileLinks.forEach(link => {
            link.addEventListener('click', toggleMenu);
        });

        // Lightbox Logic
        const lightbox = document.getElementById('lightbox');
        const lightboxImg = document.getElementById('lightbox-img');
        const closeBtn = document.querySelector('.close-lightbox');
        const projectImages = document.querySelectorAll('.project-img');

        projectImages.forEach(wrapper => {
            wrapper.addEventListener('click', function() {
                const img = this.querySelector('img');
                if (img) {
                    lightbox.style.display = "flex";
                    lightbox.style.alignItems = "center";
                    lightbox.style.justifyContent = "center";
                    lightboxImg.src = img.src;
                    lightboxImg.alt = img.alt || 'Imagem do Projeto';
                }
            });
        });

        // PWA Service Worker Registration
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                navigator.serviceWorker.register('/sw.js')
                    .then(registration => {
                        console.log('SW registered: ', registration);
                    })
                    .catch(registrationError => {
                        console.log('SW registration failed: ', registrationError);
                    });
            });
        }
    </script>
    
    <script nonce="<?php echo $nonce; ?>">
        // Re-declare variables to ensure scope visibility
        const lightboxEl = document.getElementById('lightbox');
        const closeBtnEl = document.querySelector('.close-lightbox');
        
        if (closeBtnEl) {
            closeBtnEl.addEventListener('click', () => {
                if(lightboxEl) lightboxEl.style.display = "none";
            });
        }

        if (lightboxEl) {
            lightboxEl.addEventListener('click', (e) => {
                if (e.target === lightboxEl) {
                    lightboxEl.style.display = "none";
                }
            });
        }

        // Text Modal Logic
        const textModal = document.getElementById('text-modal');
        const textModalBody = document.getElementById('text-modal-body');
        const textModalClose = document.querySelector('.text-modal-close');
        const projectInfos = document.querySelectorAll('.clickable-info');

        projectInfos.forEach(info => {
            info.addEventListener('click', function(e) {
                // Prevent triggering if clicking on links or buttons inside
                if (e.target.tagName === 'A' || e.target.tagName === 'BUTTON') return;

                const description = this.getAttribute('data-full-description');
                if (description) {
                    textModalBody.innerHTML = description;
                    textModal.style.display = "flex";
                }
            });
        });

        if (textModalClose) {
            textModalClose.addEventListener('click', () => {
                textModal.style.display = "none";
            });
        }

        if (textModal) {
            textModal.addEventListener('click', (e) => {
                if (e.target === textModal) {
                    textModal.style.display = "none";
                }
            });
        }
    </script>
    

</body>
</html>
