<?php
// includes/i18n.php

// Ensure session is started (index.php handles this usually, but safety check)
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// 1. Determine Language
$allowed_langs = ['pt', 'en', 'es'];
$lang_code = 'pt'; // Default

// Priority: GET > SESSION > COOKIE > BROWSER
if (isset($_GET['lang']) && in_array($_GET['lang'], $allowed_langs)) {
    $lang_code = $_GET['lang'];
    $_SESSION['lang'] = $lang_code;
    setcookie('lang', $lang_code, time() + (86400 * 30), "/", "", true, true); // 30 days, Secure, HttpOnly
} elseif (isset($_SESSION['lang']) && in_array($_SESSION['lang'], $allowed_langs)) {
    $lang_code = $_SESSION['lang'];
} elseif (isset($_COOKIE['lang']) && in_array($_COOKIE['lang'], $allowed_langs)) {
    $lang_code = $_COOKIE['lang'];
    $_SESSION['lang'] = $lang_code;
} else {
    // Detect Browser Language
    $browser_lang = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '', 0, 2);
    if (in_array($browser_lang, $allowed_langs)) {
        $lang_code = $browser_lang;
    }
}

// 2. Load Translations with Fallback
$default_lang_file = __DIR__ . "/../locales/pt.json";
$target_lang_file = __DIR__ . "/../locales/{$lang_code}.json";

// 1. Load Portuguese (Base)
$base_translations = [];
if (file_exists($default_lang_file)) {
    $base_translations = json_decode(file_get_contents($default_lang_file), true) ?? [];
}

// 2. Load Target Language
$target_translations = [];
if ($lang_code !== 'pt' && file_exists($target_lang_file)) {
    $target_translations = json_decode(file_get_contents($target_lang_file), true) ?? [];
}

// 3. Merge: Recursive overwrite (Base + Target)
// Any key missing in Target will keep the Base (PT) value.
if ($lang_code === 'pt') {
    $GLOBALS['translations'] = $base_translations;
} else {
    $GLOBALS['translations'] = array_replace_recursive($base_translations, $target_translations);
}

// 3. Helper Function
if (!function_exists('__')) {
    function __($key, $default = '') {
        $keys = explode('.', $key);
        $value = $GLOBALS['translations'];
        
        foreach ($keys as $k) {
            if (isset($value[$k])) {
                $value = $value[$k];
            } else {
                return $default ?: $key;
            }
        }
        
        if (is_array($value)) return $value; // Return array if key points to one (e.g. lists)
        return $value;
    }
}

// 4. Helper for Current Lang
function current_lang() {
    global $lang_code;
    return $lang_code;
}
?>
