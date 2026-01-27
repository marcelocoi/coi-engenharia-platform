<?php
define('SECURE_ACCESS', true);
require_once __DIR__ . '/data/config/db_config.php';

// --- Session & Auth ---
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$isAdmin = $_SESSION['is_admin'] ?? false;
$baseDir = __DIR__ . '/data/ged_repository';

// --- Helper Functions ---
function getRelativePath($path, $base) {
    $rel = str_replace($base, '', $path);
    return trim($rel, '/\\');
}

function cleanPath($path) {
    return str_replace(['..', './'], '', $path);
}

// Fix Windows Encoding
function safeEncode($str) {
    if (!mb_detect_encoding($str, 'UTF-8', true)) {
        return mb_convert_encoding($str, 'UTF-8', 'CP1252');
    }
    return $str;
}

// --- Request Handling ---
$currentRelPath = isset($_GET['path']) ? cleanPath($_GET['path']) : '';
$baseDir = __DIR__ . '/data/ged_repository';

$currentFullPath = realpath($baseDir . '/' . $currentRelPath);

if (!$currentFullPath || strpos($currentFullPath, $baseDir) !== 0) {
    $currentFullPath = $baseDir;
    $currentRelPath = '';
}

// --- AJAX Upload Handler ---
if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['ged_file_ajax'])) {
    header('Content-Type: application/json');
    $file = $_FILES['ged_file_ajax'];
    if ($file['error'] === UPLOAD_ERR_OK) {
        $uploadFile = $currentFullPath . '/' . basename($file['name']);
        if (move_uploaded_file($file['tmp_name'], $uploadFile)) {
             // Log Upload
            try {
                $db = SecureDatabase::getInstance()->getConnection();
                $db->prepare("INSERT INTO security_logs (event_type, ip_address, details) VALUES ('ged_upload', ?, ?)")
                   ->execute([$_SERVER['REMOTE_ADDR'], "File: " . basename($file['name']) . " in $currentRelPath by " . $_SESSION['username']]);
            } catch(Exception $e) {}
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Falha ao mover arquivo.']);
        }
    } else {
        echo json_encode(['success' => false, 'error' => 'Erro no upload PHP: ' . $file['error']]);
    }
    exit;
}

// --- Bulk Actions Handler ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['bulk_action'])) {
    $sFiles = json_decode($_POST['selected_files'] ?? '[]', true);
    
    // Bulk Delete
    if ($_POST['bulk_action'] === 'delete' && $isAdmin) {
        foreach ($sFiles as $file) {
            $item = cleanPath($file);
            $itemPath = realpath($currentFullPath . '/' . $item);
            if ($itemPath && strpos($itemPath, $currentFullPath) === 0 && file_exists($itemPath)) {
                if (is_dir($itemPath)) {
                    if (count(scandir($itemPath)) == 2) @rmdir($itemPath);
                } else {
                    unlink($itemPath);
                }
                // Log
                try {
                    $db = SecureDatabase::getInstance()->getConnection();
                    $db->prepare("INSERT INTO security_logs (event_type, ip_address, details) VALUES ('ged_bulk_delete', ?, ?)")
                       ->execute([$_SERVER['REMOTE_ADDR'], "Deleted item in $currentRelPath by " . $_SESSION['username']]);
                } catch(Exception $e) {}
            }
        }
        header("Location: ?path=" . urlencode($currentRelPath));
        exit;
    }
    
    // Bulk Download
    if ($_POST['bulk_action'] === 'download') {
        if (!empty($sFiles)) {
            $zipName = 'download_' . date('Ymd_His') . '.zip';
            $zipPath = sys_get_temp_dir() . '/' . $zipName;
            $zip = new ZipArchive();
            if ($zip->open($zipPath, ZipArchive::CREATE) === TRUE) {
                foreach ($sFiles as $file) {
                    $item = cleanPath($file);
                    $itemPath = realpath($currentFullPath . '/' . $item);
                    if ($itemPath && strpos($itemPath, $currentFullPath) === 0 && file_exists($itemPath)) {
                        if (is_file($itemPath)) {
                            $zip->addFile($itemPath, $item);
                        }
                    }
                }
                $zip->close();
                
                // Log
                try {
                     $db = SecureDatabase::getInstance()->getConnection();
                     $db->prepare("INSERT INTO security_logs (event_type, ip_address, details) VALUES ('ged_bulk_download', ?, ?)")
                        ->execute([$_SERVER['REMOTE_ADDR'], "Zip Download: " . count($sFiles) . " items in $currentRelPath by " . $_SESSION['username']]);
                } catch(Exception $e) {}

                header('Content-Type: application/zip');
                header('Content-disposition: attachment; filename='.$zipName);
                header('Content-Length: ' . filesize($zipPath));
                readfile($zipPath);
                unlink($zipPath);
                exit;
            }
        }
    }
}

// Handle New Folder
if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['new_folder'])) {
    // Allow Unicode letters (p{L}), numbers, hyphens, underscores, spaces
    $folderName = preg_replace('/[^\p{L}0-9\-\_\s]/u', '', $_POST['new_folder']);
    if ($folderName) {
        @mkdir($currentFullPath . '/' . $folderName);
        try {
            $db = SecureDatabase::getInstance()->getConnection();
            $db->prepare("INSERT INTO security_logs (event_type, ip_address, details) VALUES ('ged_new_folder', ?, ?)")
                ->execute([$_SERVER['REMOTE_ADDR'], "Folder: $folderName in $currentRelPath by " . $_SESSION['username']]);
        } catch(Exception $e) {}
        header("Location: ?path=" . urlencode($currentRelPath));
        exit;
    }
}

// Handle Delete
if ($isAdmin && isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['item'])) {
    $item = cleanPath($_GET['item']);
    $itemPath = realpath($currentFullPath . '/' . $item);
    if ($itemPath && strpos($itemPath, $currentFullPath) === 0 && file_exists($itemPath)) {
        if (is_dir($itemPath)) {
            if (count(scandir($itemPath)) == 2) @rmdir($itemPath);
        } else {
            @unlink($itemPath);
        }
        try {
            $db = SecureDatabase::getInstance()->getConnection();
            $db->prepare("INSERT INTO security_logs (event_type, ip_address, details) VALUES ('ged_delete', ?, ?)")
               ->execute([$_SERVER['REMOTE_ADDR'], "Deleted: $item in $currentRelPath by " . $_SESSION['username']]);
        } catch(Exception $c) {}
        header("Location: ?path=" . urlencode($currentRelPath));
        exit;
    }
}

// --- Directory Listing ---
$items = scandir($currentFullPath);
$folders = [];
$files = [];

foreach ($items as $item) {
    if ($item === '.' || $item === '..') continue;
    $displayItem = safeEncode($item);
    $path = $currentFullPath . '/' . $item;
    if (is_dir($path)) {
        $folders[] = ['name' => $item, 'display' => $displayItem];
    } else {
        $files[] = ['name' => $item, 'display' => $displayItem];
    }
}

// Build Breadcrumbs
$crumbs = [];
if ($currentRelPath) {
    $parts = explode('/', $currentRelPath);
    $build = '';
    foreach ($parts as $part) {
        if ($part === '') continue;
        $build .= ($build === '' ? '' : '/') . $part;
        $crumbs[] = ['name' => safeEncode($part), 'path' => $build];
    }
}
?>
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gerenciador de Arquivos - COI Engenharia</title>
    <link rel="icon" href="LOGO.png" type="image/png">
    <link href="https://fonts.googleapis.com/css2?family=Segoe+UI:wght@300;400;600&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/feather-icons"></script>
    <style>
        :root {
            /* Windows 11 Inspired Palette */
            --bg-app: #f3f3f3;
            --bg-panel: #ffffff;
            --bg-header: #f3f3f3;
            --border-light: #e5e5e5;
            --accent-blue: #0078d4;
            --accent-hover: #e0eef9;
            --accent-select: #cce8ff;
            --text-main: #202020;
            --text-secondary: #606060;
            --folder-yellow: #ffe680; /* Base for filter */
            --success: #107C10;
            --danger: #C50F1F;
        }

        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-app);
            margin: 0;
            display: flex;
            flex-direction: column;
            height: 100vh;
            color: var(--text-main);
            overflow: hidden;
        }

        /* --- File Explorer Grid Layout --- */
        .app-window {
            display: grid;
            grid-template-rows: auto auto 1fr auto;
            height: 100%;
        }

        /* 1. Title/Tab Bar (Top) */
        .window-header {
            background: var(--bg-header);
            padding: 8px 16px;
            display: flex;
            gap: 12px;
            align-items: center;
            border-bottom: 1px solid var(--border-light);
            -webkit-app-region: drag; /* Electron feel */
        }
        .window-title { font-size: 12px; font-weight: 600; color: var(--text-main); display: flex; align-items: center; gap: 8px; }
        .window-title img { height: 16px; }

        /* 2. Command Ribbon */
        .command-bar {
            background: var(--bg-panel);
            padding: 6px 12px;
            border-bottom: 1px solid var(--border-light);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .cmd-btn {
            background: transparent;
            border: 1px solid transparent;
            border-radius: 4px;
            padding: 6px 10px;
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            color: var(--text-main);
            cursor: pointer;
            transition: all 0.1s;
        }
        .cmd-btn:hover { background: var(--bg-app); }
        .cmd-btn:active { background: #e5e5e5; }
        .cmd-btn i { width: 16px; height: 16px; stroke-width: 1.5px; }
        .separator { width: 1px; height: 20px; background: var(--border-light); margin: 0 4px; }
        
        .address-bar-container {
            flex: 1;
            display: flex;
            align-items: center;
            gap: 8px;
            margin-left: 12px;
        }
        .nav-btn { background: transparent; border: none; cursor: pointer; color: var(--text-secondary); padding: 4px; border-radius: 4px; }
        .nav-btn:hover { background: var(--bg-app); color: var(--text-main); }

        .address-bar {
            flex: 1;
            background: var(--bg-panel);
            border: 1px solid var(--border-light);
            border-radius: 4px;
            padding: 5px 10px;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .address-segment { display: flex; align-items: center; color: var(--text-secondary); text-decoration: none; padding: 0 4px; border-radius: 2px; }
        .address-segment:hover { background: var(--bg-app); color: var(--text-main); }
        .address-divider { color: #ccc; font-size: 10px; }

        /* 3. Main Content Area (Split Panes) */
        .workspace {
            display: flex;
            overflow: hidden;
            background: var(--bg-panel);
        }

        /* Sidebar - Navigation Pane */
        .sidebar {
            width: 240px;
            border-right: 1px solid var(--border-light);
            padding: 12px 0;
            font-size: 13px;
            display: flex;
            flex-direction: column;
            background: #fafafa;
        }
        .nav-group { margin-bottom: 12px; }
        .nav-group-title { padding: 4px 16px; font-size: 11px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }
        .nav-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 6px 16px;
            color: var(--text-main);
            text-decoration: none;
            cursor: pointer;
            border-left: 3px solid transparent;
        }
        .nav-item:hover { background: #f0f0f0; }
        .nav-item.active { background: var(--accent-hover); color: var(--accent-blue); border-left-color: var(--accent-blue); font-weight: 500; }
        .nav-item i { width: 16px; height: 16px; }

        /* Main File View */
        .file-view {
            flex: 1;
            padding: 16px;
            overflow-y: auto;
            position: relative;
        }
        .file-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 8px; /* Tighter gap */
            align-items: flex-start;
        }

        /* Windows 11 Style Item Card */
        .explorer-item {
            width: 100px;
            padding: 8px;
            border: 1px solid transparent;
            border-radius: 4px;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            cursor: default; /* Arrow cursor usually */
            position: relative;
            transition: background 0.1s, border-color 0.1s;
        }
        .explorer-item:hover {
            background: var(--accent-hover);
            border-color: rgba(0, 120, 212, 0.1);
        }
        .explorer-item.selected {
            background: var(--accent-select);
            border-color: rgba(0, 120, 212, 0.4);
        }

        /* Icon styling */
        .icon-box {
            width: 48px;
            height: 48px;
            margin-bottom: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        /* Custom Folder Color via CSS Filter */
        .icon-box.folder svg { 
            /* Convert grey feather icon to folder yellow */
            fill: #FDCE5E;
            color: #E6AC00; /* Stroke */
            width: 42px; height: 42px;
            stroke-width: 1px;
        }
        
        /* Generic File Icon */
        .icon-box.file svg {
            fill: #fafafa;
            color: #888;
            width: 36px; height: 36px;
            stroke-width: 1px;
        }

        .item-label {
            font-size: 12px;
            color: var(--text-main);
            word-wrap: break-word;
            width: 100%;
            line-height: 1.3;
            max-height: 38px; /* 3 lines max */
            overflow: hidden;
            text-overflow: ellipsis;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
        }

        /* Checkbox overlay (hidden unless hover/selected) */
        .item-check {
            position: absolute;
            top: 4px;
            left: 4px;
            width: 14px; height: 14px;
            border: 1px solid #999;
            background: white;
            opacity: 0;
            cursor: pointer;
        }
        .explorer-item:hover .item-check, .explorer-item.selected .item-check, .item-check:checked {
            opacity: 1;
        }

        /* 4. Status Bar (Bottom) */
        .status-bar {
            background: var(--bg-app); /* Matches footer */
            border-top: 1px solid var(--border-light);
            padding: 4px 16px;
            font-size: 11px;
            color: var(--text-main);
            display: flex;
            gap: 20px;
        }

        /* Selection Rect (for bulk select) - Simple CSS logic */
        /* Dropzone */
        .drop-zone { display: none; position: absolute; inset: 0; background: rgba(0,120,212, 0.2); border: 2px dashed var(--accent-blue); z-index: 100; pointer-events: none; justify-content: center; align-items: center; font-size: 24px; color: var(--accent-blue); font-weight: 600; }

        /* Modal */
        .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.4); z-index: 200; align-items: center; justify-content: center; }
        .modal-box { background: white; padding: 20px; border-radius: 8px; width: 350px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
        .form-input { width: 100%; box-sizing: border-box; padding: 8px; border: 1px solid #ccc; border-radius: 4px; margin-top: 8px; }
        .modal-btns { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
        
        /* Context Menu (Custom) */
        #contextMenu {
            display: none;
            position: absolute;
            background: white;
            border: 1px solid #ccc;
            box-shadow: 2px 2px 10px rgba(0,0,0,0.2);
            z-index: 500;
            width: 150px;
            padding: 4px 0;
            border-radius: 4px;
        }
        .ctx-item {
            padding: 8px 16px;
            font-size: 12px;
            cursor: pointer;
            display: flex; align-items: center; gap: 8px;
        }
        .ctx-item:hover { background: #f0f0f0; }
        .ctx-item.delete { color: var(--danger); }
        /* Mobile Responsiveness */
        .menu-toggle { display: none; background: transparent; border: none; color: white; cursor: pointer; padding: 4px; }
        
        @media (max-width: 768px) {
            .sidebar {
                position: fixed;
                top: 0; left: 0; bottom: 0;
                width: 250px;
                background: #fafafa;
                z-index: 1000;
                transform: translateX(-100%);
                transition: transform 0.3s ease;
                box-shadow: 2px 0 10px rgba(0,0,0,0.1);
            }
            .sidebar.show { transform: translateX(0); }
            
            .menu-toggle { display: block; margin-right: 12px; }
            
            .command-bar { overflow-x: auto; white-space: nowrap; -webkit-overflow-scrolling: touch; padding-bottom: 8px; }
            .command-bar::-webkit-scrollbar { height: 4px; }
            .command-bar::-webkit-scrollbar-thumb { background: #ccc; border-radius: 2px; }
            
            .address-bar-container { min-width: 200px; } /* Ensure address bar doesn't shrink too much */
            .file-grid { justify-content: center; } /* Center items on small screens */
            
            /* Overlay when sidebar is open */
            .sidebar-overlay {
                display: none;
                position: fixed;
                inset: 0;
                background: rgba(0,0,0,0.5);
                z-index: 999;
            }
            .sidebar.show + .sidebar-overlay { display: block; }
        }
    </style>
</head>
<body oncontextmenu="return false;">

<div class="app-window">
    <!-- 1. Header with Tabs feel -->
    <div class="window-header">
        <button class="menu-toggle" onclick="toggleSidebar()"><i data-feather="menu"></i></button>
        <a href="index.php" style="text-decoration:none;" title="Voltar para Intranet"><i data-feather="arrow-left" style="width:16px; color:#666;"></i></a>
        <div class="window-title">
            <img src="LOGO.png" alt="">
            <span>Gerenciador de Arquivos</span>
        </div>
    </div>

    <!-- 2. Command Ribbon -->
    <div class="command-bar">
        <?php if($isAdmin): ?>
            <button class="cmd-btn" onclick="openModal('folderModal')">
                <i data-feather="folder-plus" style="color:#E6AC00;"></i> Novo
            </button>
            <div style="position:relative;">
                <input type="file" id="fileInput" multiple style="display:none;" onchange="handleFileSelect(this.files)">
                <button class="cmd-btn" onclick="document.getElementById('fileInput').click()">
                    <i data-feather="upload"></i> Upload
                </button>
            </div>
            <div class="separator"></div>
            <button class="cmd-btn" onclick="deleteSelected()" id="btnDelete" style="display:none;">
                <i data-feather="trash-2" style="color:var(--danger);"></i> Excluir
            </button>
        <?php endif; ?>
        
        <button class="cmd-btn" onclick="downloadSelected()" id="btnDownload" style="display:none;">
            <i data-feather="download"></i> Baixar ZIP
        </button>

        <!-- Address Bar -->
        <div class="address-bar-container">
            <button class="nav-btn" onclick="history.back()"><i data-feather="arrow-left" style="width:14px;"></i></button>
            <button class="nav-btn"><i data-feather="arrow-up" style="width:14px;" onclick="location.href='?path=<?= urlencode(dirname($currentRelPath) == '.' ? '' : dirname($currentRelPath)) ?>'"></i></button>
            <div class="address-bar">
                <i data-feather="monitor" style="width:14px; color:#666;"></i>
                <div class="address-divider">></div>
                <a href="?path=" class="address-segment">Este Computador</a>
                <?php foreach($crumbs as $crumb): ?>
                    <div class="address-divider">></div>
                    <a href="?path=<?= urlencode($crumb['path']) ?>" class="address-segment"><?= htmlspecialchars($crumb['name']) ?></a>
                <?php endforeach; ?>
            </div>
            <button class="nav-btn" onclick="location.reload()"><i data-feather="rotate-cw" style="width:14px;"></i></button>
        </div>
        
        <div class="separator"></div>
        <div style="font-size:12px; font-weight:600; color:var(--accent-blue);"><?= htmlspecialchars($_SESSION['username']) ?></div>
    </div>

    <!-- 3. Workspace -->
    <div class="workspace">
        <!-- Sidebar -->
        <div class="sidebar" id="appSidebar">
            <div class="nav-group">
                <div class="nav-group-title">Acesso Rápido</div>
                <div class="nav-item active"><i data-feather="star" style="fill:#FDCE5E; color:#E6AC00;"></i> Principais</div>
                <div class="nav-item"><i data-feather="clock"></i> Recentes</div>
            </div>
            <div class="nav-group">
                <div class="nav-group-title">Locais</div>
                <div class="nav-item" onclick="location.href='?path='"><i data-feather="monitor"></i> Este Computador</div>
                <div class="nav-item"><i data-feather="hard-drive"></i> Rede (Obras)</div>
                <div class="nav-item"><i data-feather="trash"></i> Lixeira</div>
            </div>
        </div>
        <div class="sidebar-overlay" onclick="toggleSidebar()"></div>

        <!-- Main View -->
        <div class="file-view" id="mainView" ondragover="showDrop(event)" ondragleave="hideDrop(event)" ondrop="handleDrop(event)">
            <div id="dropOverlay" class="drop-zone">Solte arquivos aqui</div>

            <!-- Upload List (Toast style) -->
            <div id="uploadListContainer" style="position:absolute; bottom:20px; right:20px; width:300px; background:white; box-shadow:0 4px 12px rgba(0,0,0,0.15); border-radius:8px; padding:12px; display:none; z-index:200;">
                <div style="font-weight:600; margin-bottom:8px; font-size:12px;">Carregando arquivos...</div>
                <div id="uploadList" style="max-height:150px; overflow-y:auto; font-size:11px;"></div>
                <button id="startUploadBtn" onclick="startUploadQueue()" class="cmd-btn" style="width:100%; justify-content:center; margin-top:8px; background:#f0f0f0;">Iniciar</button>
            </div>

            <div class="file-grid">
                <?php if(empty($folders) && empty($files)): ?>
                    <div style="width:100%; text-align:center; padding-top:100px; color:#999;">
                        <i data-feather="folder" style="width:48px; height:48px; opacity:0.3;"></i>
                        <p>Esta pasta está vazia.</p>
                    </div>
                <?php endif; ?>

                <?php foreach($folders as $folder): ?>
                <div class="explorer-item" 
                     onclick="selectItem(this, event)" 
                     ondblclick="location.href='?path=<?= urlencode(($currentRelPath ? $currentRelPath . '/' : '') . $folder['name']) ?>'"
                     oncontextmenu="showContext(event, '<?= $folder['name'] ?>', 'folder')"
                     data-name="<?= $folder['name'] ?>">
                    <input type="checkbox" class="item-check" value="<?= htmlspecialchars($folder['name']) ?>" onclick="event.stopPropagation(); updateToolbar()">
                    <div class="icon-box folder"><i data-feather="folder"></i></div>
                    <div class="item-label"><?= htmlspecialchars($folder['display']) ?></div>
                </div>
                <?php endforeach; ?>

                <?php foreach($files as $file): ?>
                <?php 
                    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                    $icon = 'file';
                    if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) { $icon = 'image'; }
                    if ($ext === 'pdf') { $icon = 'file-text'; }
                    if (in_array($ext, ['zip', 'rar'])) { $icon = 'archive'; }
                    $dlUrl = "download.php?path=" . urlencode(($currentRelPath ? $currentRelPath . '/' : '') . $file['name']);
                ?>
                <div class="explorer-item" 
                     onclick="selectItem(this, event)" 
                     ondblclick="window.open('<?= $dlUrl ?>', '_blank')"
                     oncontextmenu="showContext(event, '<?= $file['name'] ?>', 'file')"
                     data-name="<?= $file['name'] ?>">
                    <input type="checkbox" class="item-check" value="<?= htmlspecialchars($file['name']) ?>" onclick="event.stopPropagation(); updateToolbar()">
                    <div class="icon-box file"><i data-feather="<?= $icon ?>"></i></div>
                    <div class="item-label"><?= htmlspecialchars($file['display']) ?></div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <!-- 4. Status Bar -->
    <div class="status-bar">
        <span><?= count($folders) + count($files) ?> itens</span>
        <span id="selectedCountText"></span>
        <span style="margin-left:auto;"><i data-feather="layout" style="width:12px;"></i> Visualização em Grade</span>
    </div>
</div>

<!-- Modal -->
<div id="folderModal" class="modal-overlay">
    <div class="modal-box">
        <h3 style="margin:0 0 10px 0; font-size:16px;">Criar Nova Pasta</h3>
        <form method="POST">
            <input type="text" name="new_folder" class="form-input" placeholder="Nome da pasta" required autofocus>
            <div class="modal-btns">
                <button type="button" onclick="document.getElementById('folderModal').style.display='none'" class="cmd-btn">Cancelar</button>
                <button type="submit" class="cmd-btn" style="background:var(--accent-blue); color:white;">Criar</button>
            </div>
        </form>
    </div>
</div>

<!-- Context Menu -->
<div id="contextMenu">
    <div class="ctx-item" onclick="alert('Funcionalidade simulada: Abrir')"><i data-feather="external-link" style="width:14px;"></i> Abrir</div>
    <?php if($isAdmin): ?>
    <div class="separator" style="width:100%; height:1px; margin:4px 0;"></div>
    <div class="ctx-item delete" onclick="deleteContextItem()"><i data-feather="trash-2" style="width:14px;"></i> Excluir</div>
    <?php endif; ?>
</div>

<!-- Hidden Bulk Form -->
<form id="bulkForm" method="POST" style="display:none;">
    <input type="hidden" name="bulk_action" id="bulkActionInput">
    <input type="hidden" name="selected_files" id="selectedFilesInput">
</form>

<script>
    feather.replace();

    // --- Mobile Sidebar ---
    function toggleSidebar() {
        document.getElementById('appSidebar').classList.toggle('show');
    }

    // --- UI Interactions ---
    function selectItem(el, e) {
        // Simple selection logic (Ctrl/Metakey for multi ignored for simplicity, mostly single select focus)
        // If clicking background, clear
        document.querySelectorAll('.explorer-item').forEach(i => i.classList.remove('selected'));
        el.classList.add('selected');
        
        // Auto-check the checkbox for logic
        const cb = el.querySelector('.item-check');
        // cb.checked = !cb.checked; // Toggle on click? Windows explorer is click selects, check is separate.
        // Let's stick to simple click = highlight. Checkbox = layout action.
        updateToolbar();
    }

    // Click outside to deselect
    document.getElementById('mainView').addEventListener('click', function(e) {
        if(e.target === this || e.target.id === 'dropOverlay') {
            document.querySelectorAll('.explorer-item').forEach(i => i.classList.remove('selected'));
            document.getElementById('contextMenu').style.display = 'none';
        }
    });

    function updateToolbar() {
        const checks = document.querySelectorAll('.item-check:checked');
        const count = checks.length;
        document.getElementById('selectedCountText').innerText = count > 0 ? count + ' selecionado(s)' : '';
        
        const btnDel = document.getElementById('btnDelete');
        const btnDown = document.getElementById('btnDownload');
        if(btnDel) btnDel.style.display = count > 0 ? 'flex' : 'none';
        btnDown.style.display = count > 0 ? 'flex' : 'none';
    }

    // Modal
    function openModal(id) { document.getElementById(id).style.display = 'flex'; document.querySelector('#'+id+' input').focus(); }
    
    // Drag Drop
    function showDrop(e) { e.preventDefault(); document.getElementById('dropOverlay').style.display = 'flex'; }
    function hideDrop(e) { document.getElementById('dropOverlay').style.display = 'none'; }
    function handleDrop(e) {
        e.preventDefault();
        document.getElementById('dropOverlay').style.display = 'none';
        handleFileSelect(e.dataTransfer.files);
    }

    // Context Menu
    let contextItem = null;
    function showContext(e, name, type) {
        e.preventDefault();
        const menu = document.getElementById('contextMenu');
        menu.style.display = 'block';
        menu.style.left = e.pageX + 'px';
        menu.style.top = e.pageY + 'px';
        contextItem = name;
        
        // Select the item visually
        document.querySelectorAll('.explorer-item').forEach(i => i.classList.remove('selected'));
        e.currentTarget.classList.add('selected');
    }
    
    function deleteContextItem() {
        if(confirm('Excluir ' + contextItem + '?')) {
            window.location.href = '?path=<?= urlencode($currentRelPath) ?>&action=delete&item=' + encodeURIComponent(contextItem);
        }
    }

    // Bulk Logic
    function deleteSelected() {
        submitBulk('delete');
    }
    function downloadSelected() {
        submitBulk('download');
    }
    function submitBulk(action) {
        if(action === 'delete' && !confirm('Excluir selecionados?')) return;
        const checkboxes = document.querySelectorAll('.item-check:checked');
        const files = Array.from(checkboxes).map(cb => cb.value);
        document.getElementById('bulkActionInput').value = action;
        document.getElementById('selectedFilesInput').value = JSON.stringify(files);
        document.getElementById('bulkForm').submit();
    }

    // Upload Logic (Simplified)
    let uploadQueue = [];
    function handleFileSelect(files) {
        const btn = document.getElementById('startUploadBtn');
        document.getElementById('uploadListContainer').style.display = 'block';
        for (let file of files) {
            uploadQueue.push({ file: file, status: 'pending', id: Math.random().toString(36).substr(2, 9), progress: 0 });
        }
        renderQueue();
    }

    function renderQueue() {
        const list = document.getElementById('uploadList');
        list.innerHTML = '';
        uploadQueue.forEach(item => {
            let color = 'black';
            if(item.status === 'success') color = 'green';
            if(item.status === 'error') color = 'red';
            list.innerHTML += `<div style="color:${color}; border-bottom:1px solid #eee; padding:2px;">${item.file.name} - ${item.status}</div>`;
        });
    }

    function startUploadQueue() {
        const next = uploadQueue.find(i => i.status === 'pending');
        if(!next) { window.location.reload(); return; }
        
        next.status = 'uploading';
        renderQueue();
        
        const fd = new FormData();
        fd.append('ged_file_ajax', next.file);
        
        fetch('?path=<?= urlencode($currentRelPath) ?>', { method: 'POST', body: fd })
        .then(r => r.json())
        .then(d => {
            next.status = d.success ? 'success' : 'error';
            renderQueue();
            startUploadQueue();
        })
        .catch(e => {
            next.status = 'error';
            renderQueue();
            startUploadQueue();
        });
    }
</script>

</body>
</html>
