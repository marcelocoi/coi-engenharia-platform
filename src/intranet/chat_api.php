<?php
define('SECURE_ACCESS', true); // Permite acesso aos arquivos de configuração

// 1. CONFIGURAÇÕES GLOBAIS DE SEGURANÇA E ERROS
// --------------------------------------------------------------------
// Ocultar erros do usuário final (Security through Obscurity - Camada 1)
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
ini_set('log_errors', 1);

// [HIGIENIZADO] Define local seguro para logs (Caminho relativo ao repositório)
$logDir = __DIR__ . '/../intranet/data/logs';
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
// [HIGIENIZADO] Caminho relativo para config
require_once __DIR__ . '/../config/db_config.php';

try {
    $db = SecureDatabase::getInstance()->getConnection();
    $current_ip = get_client_ip();
    $current_url = $_SERVER['REQUEST_URI'] ?? '/';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    // Tentativa simples de geolocalização
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
 * Obtém o IP real do cliente, lidando com Proxies/Cloudflare.
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
    if ($ip === '127.0.0.1' || $ip === '::1') return true;

    // [HIGIENIZADO] Caminho relativo para rate limits na Intranet
    $rateDir = __DIR__ . '/../intranet/data/rate_limits';
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
    // [HIGIENIZADO] Busca a configuração segura
    $dbConfigPath = __DIR__ . '/../config/db_config.php';
    
    if (file_exists($dbConfigPath)) {
        try {
            require_once $dbConfigPath;
            // Adaptação para usar SecureDatabase se getConnection global não existir
            $pdo = SecureDatabase::getInstance()->getConnection();
            
            if (!isset($_SESSION['visit_logged'])) {
                $ip = get_client_ip();
                $geoData = getGeolocationFromIP($ip);
                
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
// A lógica foi movida para src/intranet/chat_api.php, mas se houver chamada direta aqui:
// Mantemos o endpoint apenas como proxy ou removemos se o frontend chamar direto o outro arquivo.
// O código original mantinha a lógica inline, vamos assumir que o frontend chama 'chat_api.php' agora.

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
    
    // Valida Honeypot
    $honeypot_name = $_SESSION['honeypot_name'];
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
        // [HIGIENIZADO] Email genérico ou via ENV
        $to = getenv('CONTACT_EMAIL') ?: 'contato@coiengenharia.com.br'; 
        $subject = 'Novo Contato Site - ' . $nome;
        
        $body = "Nova mensagem do site:\n\n";
        $body .= "Nome: $nome\n";
        $body .= "Email: $email\n";
        $body .= "Serviço: $servico\n";
        $body .= "IP: " . get_client_ip() . "\n\n";
        $body .= "Mensagem:\n$mensagem\n";
        
        $headers = "From: no-reply@coiengenharia.com.br\r\n"; 
        $headers .= "Reply-To: $email\r\n";
        $headers .= "X-Mailer: PHP/" . phpversion();
        $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
        
        $start_time = microtime(true);

        if (mail($to, $subject, $body, $headers)) {
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