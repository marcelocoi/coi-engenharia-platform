<?php
define('SECURE_ACCESS', true);
require_once __DIR__ . '/data/config/db_config.php';
require_once __DIR__ . '/data/classes/Construction.php';

session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

// Get Construction Context
$constructionId = isset($_GET['construction_id']) ? (int)$_GET['construction_id'] : null;

// Validation
if (!$constructionId) {
    // If no ID provided, redirect to selection page
    header('Location: obras.php');
    exit;
}

$db = null;
$constructionModel = null;
$construction = null;
$dbError = null;

try {
    $db = SecureDatabase::getInstance()->getConnection();
    $constructionModel = new Construction($db);
    $construction = $constructionModel->getById($constructionId);
} catch (Exception $e) {
    $dbError = $e->getMessage();
}

if (!$construction && !$dbError) {
    die("Obra não encontrada.");
}
if ($dbError) {
    // Show error page inline instead of dying immediately if we want to keep layout, 
    // but without construction data layout is broken. So just show error.
    die("<h3>Erro ao carregar obra</h3><p>" . htmlspecialchars($dbError) . "</p>" . (strpos($dbError, 'exist') !== false ? '<a href="run_migration.php">Rodar Instalação</a>' : ''));
}

// Check Access
$username = $_SESSION['username'];
$userId = $_SESSION['user_id'];
$isAdmin = $_SESSION['is_admin'] ?? false;

if (!$constructionModel->hasAccess($userId, $constructionId, $isAdmin)) {
    die("Acesso negado a esta obra.");
}

// --- Handle Form Submission (POST) ---
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    
    // NEW LOG
    if ($_POST['action'] === 'save_log') {
        try {
            $date = $_POST['work_date'];
            $w_am = $_POST['weather_morning'];
            $w_pm = $_POST['weather_afternoon'];
            $wc_am = $_POST['condition_morning'] ?? 'Praticável';
            $wc_pm = $_POST['condition_afternoon'] ?? 'Praticável';
            $acts = $_POST['activities_text'];
            $occs = $_POST['occurrences_text'];
            
            // Workforce JSON (Expanded)
            $team = [
                'motorista_pipa' => (int)($_POST['wf_motorista_pipa'] ?? 0),
                'op_motoniveladora' => (int)($_POST['wf_op_motoniveladora'] ?? 0),
                'op_rolo' => (int)($_POST['wf_op_rolo'] ?? 0),
                'motorista_tracado' => (int)($_POST['wf_motorista_tracado'] ?? 0),
                'pedreiro' => (int)($_POST['wf_pedreiro'] ?? 0),
                'servente' => (int)($_POST['wf_servente'] ?? 0),
                'op_escavadeira' => (int)($_POST['wf_op_escavadeira'] ?? 0),
                'op_retro' => (int)($_POST['wf_op_retro'] ?? 0),
                'laboratorista' => (int)($_POST['wf_laboratorista'] ?? 0),
                'eng_civil' => (int)($_POST['wf_eng_civil'] ?? 0),
                'op_pa' => (int)($_POST['wf_op_pa'] ?? 0),
                'ajudante_topografia' => (int)($_POST['wf_ajudante_topografia'] ?? 0),
                'topografo' => (int)($_POST['wf_topografo'] ?? 0),
                'encarregado' => (int)($_POST['wf_encarregado'] ?? 0)
            ];
            $jsonTeam = json_encode($team);

            // Equipment JSON
            $equipment = [
                'rolo_pe_carneiro' => (int)($_POST['eq_rolo_pe_carneiro'] ?? 0),
                'motoniveladora' => (int)($_POST['eq_motoniveladora'] ?? 0),
                'caminhao_pipa' => (int)($_POST['eq_caminhao_pipa'] ?? 0),
                'caminhao_toco' => (int)($_POST['eq_caminhao_toco'] ?? 0),
                'carregadeira' => (int)($_POST['eq_carregadeira'] ?? 0),
                'escavadeira' => (int)($_POST['eq_escavadeira'] ?? 0),
                'retroescavadeira' => (int)($_POST['eq_retroescavadeira'] ?? 0),
                'rolo_compactador' => (int)($_POST['eq_rolo_compactador'] ?? 0),
                'trator_grade' => (int)($_POST['eq_trator_grade'] ?? 0),
                'caminhao_basc' => (int)($_POST['eq_caminhao_basc'] ?? 0),
                'caminhao_munck' => (int)($_POST['eq_caminhao_munck'] ?? 0)
            ];
            $jsonEquip = json_encode($equipment);
            
            // Insert Log with construction_id
            $stmt = $db->prepare("INSERT INTO construction_logs (construction_id, work_date, weather_morning, weather_afternoon, weather_condition_morning, weather_condition_afternoon, workforce_json, equipment_json, activities_text, occurrences_text, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$constructionId, $date, $w_am, $w_pm, $wc_am, $wc_pm, $jsonTeam, $jsonEquip, $acts, $occs, $username]);
            $logId = $db->lastInsertId();
            
            // Handle Photos
            if (!empty($_FILES['photos']['name'][0])) {
                $uploadDir = __DIR__ . '/data/uploads/diario_obras/';
                if (!is_dir($uploadDir)) mkdir($uploadDir, 0755, true);
                
                foreach ($_FILES['photos']['name'] as $key => $name) {
                    if ($_FILES['photos']['error'][$key] === 0) {
                        $tmp = $_FILES['photos']['tmp_name'][$key];
                        $ext = pathinfo($name, PATHINFO_EXTENSION);
                        $newName = 'log_' . $logId . '_' . uniqid() . '.' . $ext;
                        if (move_uploaded_file($tmp, $uploadDir . $newName)) {
                            // Link photo to log 
                            $db->prepare("INSERT INTO construction_photos (log_id, file_path) VALUES (?, ?)")
                               ->execute([$logId, $newName]);
                        }
                    }
                }
            }
            
            $msg = 'success|Diário lançado com sucesso!';
        } catch (Exception $e) {
            $msg = 'error|Erro ao salvar: ' . $e->getMessage();
        }
    }
    
    // APPROVE LOG
    if ($_POST['action'] === 'approve_log' && $isAdmin) {
        try {
            $logId = (int)$_POST['log_id'];
            
            // Map Emails to Names (reused logic)
            $approverParams = [
                'contato@coiengenharia.com.br' => 'Eng. Marcelo Barros',
                'admin' => 'Administrador do Sistema'
            ];
            $approverName = $approverParams[$username] ?? $username;
            
            $stmt = $db->prepare("UPDATE construction_logs SET approved_by_name = ?, approved_at = NOW() WHERE id = ?");
            $stmt->execute([$approverName, $logId]);
            
            $msg = 'success|Diário aprovado com sucesso!';
        } catch (Exception $e) {
            $msg = 'error|Erro ao aprovar: ' . $e->getMessage();
        }
    }
}

// --- Fetch Data ---
$view = $_GET['view'] ?? 'dashboard'; // dashboard, list

// Get Logs for this construction
$logs = $db->prepare("SELECT * FROM construction_logs WHERE construction_id = ? ORDER BY work_date DESC");
$logs->execute([$constructionId]);
$allLogs = $logs->fetchAll();

// Stats
$totalLogs = count($allLogs);
$totalActivities = 0; // Placeholder
$totalOccurrences = 0; // Placeholder
$totalPhotos = 0;

// Calculate stats
foreach ($allLogs as $l) {
    if ($l['occurrences_text']) $totalOccurrences++;
}

// Get total photos
$stmtP = $db->prepare("SELECT count(p.id) FROM construction_photos p JOIN construction_logs l ON p.log_id = l.id WHERE l.construction_id = ?");
$stmtP->execute([$constructionId]);
$totalPhotos = $stmtP->fetchColumn();

// Recent Photos (Limit 8)
$stmtRP = $db->prepare("
    SELECT p.file_path, p.description, l.work_date 
    FROM construction_photos p 
    JOIN construction_logs l ON p.log_id = l.id 
    WHERE l.construction_id = ? 
    ORDER BY l.work_date DESC, p.id DESC 
    LIMIT 8
");
$stmtRP->execute([$constructionId]);
$recentPhotos = $stmtRP->fetchAll();

?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($construction['name']) ?> - Diário de Obras</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/feather-icons"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary: #0D2C54;
            --accent: #F26419;
            --bg: #F3F4F6;
            --white: #FFFFFF;
            --text: #1F2937;
            --gray: #6B7280;
            --sidebar-width: 250px;
        }
        body { font-family: 'Inter', sans-serif; background: var(--bg); margin: 0; color: var(--text); display: flex; min-height: 100vh; }
        
        /* Sidebar */
        .sidebar {
            width: var(--sidebar-width);
            background: white;
            border-right: 1px solid #E5E7EB;
            display: flex; flex-direction: column;
            position: fixed; height: 100vh;
            z-index: 100;
            transition: transform 0.3s ease;
        }
        .sidebar-header { padding: 1.5rem; border-bottom: 1px solid #E5E7EB; display: flex; justify-content: space-between; align-items: center; }
        .sidebar-title { font-family: 'Montserrat', sans-serif; font-weight: 700; color: var(--primary); font-size: 1.1rem; }
        .sidebar-img { width: 100%; height: 120px; object-fit: cover; border-radius: 8px; margin-top: 1rem; }
        .close-sidebar { display: none; background: none; border: none; cursor: pointer; color: var(--primary); }
        
        .nav-menu { flex: 1; padding: 1rem; display: flex; flex-direction: column; gap: 0.5rem; }
        .nav-item {
            display: flex; align-items: center; gap: 10px;
            padding: 0.8rem 1rem;
            color: var(--gray);
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            transition: all 0.2s;
        }
        .nav-item:hover, .nav-item.active { background: #F3F4F6; color: var(--primary); }
        .nav-item.active { background: #E0E7FF; color: var(--primary); font-weight: 600; }
        
        /* Main Content */
        .main-content {
            margin-left: var(--sidebar-width);
            flex: 1;
            padding: 2rem;
            width: 100%;
            transition: margin-left 0.3s ease;
        }
        
        /* Header */
        .top-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .page-title { font-size: 1.5rem; font-weight: 700; color: var(--primary); display: flex; align-items: center; gap: 10px; }
        .back-btn { display: flex; align-items: center; gap: 5px; color: var(--gray); text-decoration: none; font-size: 0.9rem; }
        .back-btn:hover { color: var(--primary); }
        .menu-btn { display: none; background: none; border: none; cursor: pointer; color: var(--primary); }
        
        /* Stats Cards */
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1.5rem; margin-bottom: 2rem; }
        .stat-card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-top: 4px solid var(--accent); }
        .stat-val { font-size: 2.2rem; font-weight: 700; color: var(--primary); margin: 0.5rem 0; }
        .stat-label { color: var(--gray); font-size: 0.9rem; }
        
        /* Section Cards */
        .section-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
        .card { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; height: 100%; }
        .card-header { padding: 1rem 1.5rem; border-bottom: 1px solid #E5E7EB; display: flex; justify-content: space-between; align-items: center; }
        .card-title { font-weight: 600; color: var(--primary); }
        .card-body { padding: 1.5rem; }
        
        /* Table */
        .table-responsive { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 600px; }
        th { text-align: left; padding: 0.8rem; background: #F9FAFB; color: var(--gray); font-size: 0.8rem; text-transform: uppercase; font-weight: 600; }
        td { padding: 0.8rem; border-bottom: 1px solid #E5E7EB; font-size: 0.9rem; }
        tr:last-child td { border-bottom: none; }
        
        /* Gallery */
        .gallery-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5rem; }
        .gallery-img { width: 100%; height: 80px; object-fit: cover; border-radius: 4px; cursor: pointer; }
        
        /* Buttons */
        .btn { background: var(--accent); color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 6px; cursor: pointer; font-weight: 600; }
        .btn-sm { padding: 0.3rem 0.6rem; font-size: 0.8rem; }
        .status-badge { padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; color: white; }
        
        /* Mobile */
        @media (max-width: 1024px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .section-grid { grid-template-columns: 1fr; }
        }
        @media (max-width: 768px) {
            .sidebar { transform: translateX(-100%); width: 80%; max-width: 300px; }
            .sidebar.open { transform: translateX(0); box-shadow: 5px 0 15px rgba(0,0,0,0.2); }
            .main-content { margin-left: 0; padding: 1rem; }
            .stats-grid { grid-template-columns: 1fr; }
            .menu-btn { display: block; margin-right: 15px; }
            .close-sidebar { display: block; }
            .top-header { flex-wrap: wrap; gap: 1rem; }
            .gallery-grid { grid-template-columns: repeat(2, 1fr); }
            .page-title { font-size: 1.2rem; }
        }
    </style>
</head>
<body>

<!-- Sidebar -->
<div class="sidebar" id="sidebar">
    <div class="sidebar-header">
        <div class="sidebar-title">COI ENGENHARIA</div>
        <button class="close-sidebar" onclick="toggleSidebar()"><i data-feather="x"></i></button>
    </div>
    
    <div style="padding: 0 1rem;">
         <?php if($construction['image_path']): ?>
            <img src="<?= htmlspecialchars($construction['image_path']) ?>" class="sidebar-img">
        <?php else: ?>
            <div style="width:100%; height:120px; background:#ddd; border-radius:8px; display:flex; align-items:center; justify-content:center; color:#666; margin-top:1rem;">Sem Imagem</div>
        <?php endif; ?>
        <div style="margin-top:0.5rem; font-weight:600; font-size:0.9rem;"><?= htmlspecialchars($construction['name']) ?></div>
        <div style="font-size:0.8rem; color:#666;"><?= htmlspecialchars($construction['address'] ?? '') ?></div>
    </div>

    <div class="nav-menu">
        <a href="?construction_id=<?= $constructionId ?>&view=dashboard" class="nav-item <?= $view === 'dashboard' ? 'active' : '' ?>">
            <i data-feather="grid" style="width:18px;"></i> Visão Geral
        </a>
        <a href="?construction_id=<?= $constructionId ?>&view=list" class="nav-item <?= $view === 'list' ? 'active' : '' ?>">
            <i data-feather="list" style="width:18px;"></i> Lista de Diários
            <span style="margin-left:auto; background:#E5E7EB; padding:2px 8px; border-radius:10px; font-size:0.7rem;"><?= $totalLogs ?></span>
        </a>
        <a href="reports.php?construction_id=<?= $constructionId ?>" class="nav-item">
            <i data-feather="bar-chart-2" style="width:18px;"></i> Relatórios
        </a>
        <div style="flex:1;"></div>
        <a href="obras.php" class="nav-item">
            <i data-feather="arrow-left" style="width:18px;"></i> Voltar para Obras
        </a>
    </div>
</div>

<!-- Main Content -->
<div class="main-content">

    <div class="top-header">
        <div class="page-title">
            <button class="menu-btn" onclick="toggleSidebar()"><i data-feather="menu"></i></button>
            <a href="obras.php" class="back-btn"><i data-feather="arrow-left"></i></a>
            <?= $construction['id'] ?> - <?= htmlspecialchars($construction['name']) ?>
        </div>
        <div>
            <button class="btn" onclick="openModal()">+ ADICIONAR DIÁRIO</button>
        </div>
    </div>

    <?php if ($msg): list($type, $text) = explode('|', $msg); ?>
        <div style="background: <?= $type === 'error' ? '#FDE8E8' : '#DEF7EC' ?>; color: <?= $type === 'error' ? '#9B1C1C' : '#03543F' ?>; padding: 1rem; border-radius: 8px; margin-bottom: 2rem;">
            <?= $text ?>
        </div>
    <?php endif; ?>

    <?php if($view === 'dashboard'): ?>
    <!-- Stats -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-val"><?= $totalLogs ?></div>
            <div class="stat-label">Relatórios <i data-feather="file-text" style="width:14px;"></i></div>
        </div>
        <div class="stat-card" style="border-top-color: #10B981;">
            <div class="stat-val">--</div>
            <div class="stat-label">Atividades <i data-feather="list" style="width:14px;"></i></div>
        </div>
        <div class="stat-card" style="border-top-color: #F59E0B;">
            <div class="stat-val"><?= $totalOccurrences ?></div>
            <div class="stat-label">Ocorrências <i data-feather="alert-triangle" style="width:14px;"></i></div>
        </div>
        <div class="stat-card" style="border-top-color: #6366F1;">
            <div class="stat-val"><?= $totalPhotos ?></div>
            <div class="stat-label">Fotos <i data-feather="camera" style="width:14px;"></i></div>
        </div>
    </div>

    <div class="section-grid">
        <!-- Recent Logs -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">Relatórios Recentes</span>
                <a href="?construction_id=<?= $constructionId ?>&view=list" style="font-size:0.8rem; color:var(--accent); text-decoration:none;">Ver tudo</a>
            </div>
            <div class="card-body" style="padding:0;">
                <div class="table-responsive">
                    <table style="width:100%;">
                        <thead>
                            <tr>
                                <th>Data</th>
                                <th>Nº</th>
                                <th>Status</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach(array_slice($allLogs, 0, 5) as $l): ?>
                            <tr>
                                <td><a href="diario_view.php?id=<?= $l['id'] ?>" style="color:var(--accent); font-weight:600; text-decoration:none;"><?= date('d/m/Y', strtotime($l['work_date'])) ?></a></td>
                                <td><?= $l['id'] ?></td>
                                <td>
                                    <?php if($l['approved_by_name']): ?>
                                        <span class="status-badge" style="background:#10B981;">Aprovado</span>
                                    <?php else: ?>
                                        <span class="status-badge" style="background:#F59E0B;">Pendente</span>
                                    <?php endif; ?>
                                </td>
                                <td style="display:flex; gap:5px;">
                                    <a href="diario_view.php?id=<?= $l['id'] ?>" class="btn btn-sm" style="background:var(--primary);"><i data-feather="eye" style="width:12px;"></i></a>
                                    <?php if($isAdmin && !$l['approved_by_name']): ?>
                                        <form method="POST" style="display:inline;" onsubmit="return confirm('Aprovar este diário?')">
                                            <input type="hidden" name="action" value="approve_log">
                                            <input type="hidden" name="log_id" value="<?= $l['id'] ?>">
                                            <button type="submit" class="btn btn-sm" style="background:#10B981;" title="Aprovar"><i data-feather="check" style="width:12px;"></i></button>
                                        </form>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Recent Photos -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">Fotos Recentes</span>
                <a href="#" style="font-size:0.8rem; color:var(--accent); text-decoration:none;">Ver tudo</a>
            </div>
            <div class="card-body">
                <div class="gallery-grid">
                    <?php 
                    $jsonPhotos = [];
                    foreach($recentPhotos as $index => $p) {
                         $jsonPhotos[] = [
                             'src' => "data/uploads/diario_obras/" . $p['file_path'],
                             'desc' => $p['description'] ?? ''
                         ];
                    ?>
                        <div style="height:80px; overflow:hidden; border-radius:4px;">
                            <img src="data/uploads/diario_obras/<?= $p['file_path'] ?>" class="gallery-img" onclick="openLightbox(<?= $index ?>)" style="width:100%; height:100%; object-fit:cover;">
                        </div>
                    <?php } ?>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Info Footer -->
    <div class="card">
        <div class="card-header">
            <span class="card-title">Informações da Obra</span>
        </div>
        <div class="card-body" style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:20px; font-size:0.9rem;">
            <div>
                <strong>Status</strong><br>
                <span class="status-badge" style="background:var(--primary);"><?= htmlspecialchars($construction['status']) ?></span>
            </div>
            <div>
                <strong>Nº do Contrato</strong><br>
                <?= htmlspecialchars($construction['contract_number'] ?? '-') ?>
            </div>
            <div>
                <strong>Prazo Decorrido</strong><br>
                <div style="background:#E5E7EB; height:10px; width:200px; border-radius:5px; margin-top:5px; overflow:hidden;">
                    <div style="background:var(--accent); height:100%; width:70%;"></div> <!-- Placeholder % -->
                </div>
                <small>70%</small>
            </div>
            <div>
                <strong>Previsão de Término</strong><br>
                <?= $construction['end_date_prediction'] ? date('d/m/Y', strtotime($construction['end_date_prediction'])) : '-' ?>
            </div>
        </div>
    </div>

    <?php elseif($view === 'list'): ?>
        
        <!-- Full List View -->
        <div class="card">
             <div class="card-header">
                <span class="card-title">Todos os Relatórios</span>
            </div>
            <div class="card-body" style="padding:0;">
                <div class="table-responsive">
                    <table id="logsTable">
                         <thead>
                            <tr>
                                <th>Data</th>
                                <th>Clima</th>
                                <th>Atividades</th>
                                <th>Responsável</th>
                                <th>Aprovação</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($allLogs as $log): ?>
                            <tr>
                                <td><strong><?= date('d/m/Y', strtotime($log['work_date'])) ?></strong></td>
                                <td>
                                    <?= htmlspecialchars($log['weather_morning']) ?> (<?= htmlspecialchars($log['weather_condition_morning'] ?? 'Praticável') ?>) / 
                                    <?= htmlspecialchars($log['weather_afternoon']) ?> (<?= htmlspecialchars($log['weather_condition_afternoon'] ?? 'Praticável') ?>)
                                </td>
                                <td style="max-width:300px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"><?= htmlspecialchars($log['activities_text']) ?></td>
                                <td><?= htmlspecialchars($log['created_by']) ?></td>
                                <td>
                                    <?php if($log['approved_by_name']): ?>
                                        <span class="status-badge" style="background:#10B981;">Aprovado</span>
                                    <?php else: ?>
                                        <span class="status-badge" style="background:#F59E0B;">Pendente</span>
                                    <?php endif; ?>
                                </td>
                                <td style="display:flex; gap:5px;">
                                    <a href="diario_print.php?id=<?= $log['id'] ?>" target="_blank" class="btn btn-sm" style="background:var(--primary);">PDF</a>
                                     <?php if($isAdmin && !$log['approved_by_name']): ?>
                                        <form method="POST" style="display:inline;" onsubmit="return confirm('Aprovar este diário?')">
                                            <input type="hidden" name="action" value="approve_log">
                                            <input type="hidden" name="log_id" value="<?= $log['id'] ?>">
                                            <button type="submit" class="btn btn-sm" style="background:#10B981;" title="Aprovar"><i data-feather="check" style="width:12px;"></i></button>
                                        </form>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

    <?php endif; ?>

</div>

<!-- OLD FORM IN MODAL (Updated) -->
<div id="entryModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:200; align-items:center; justify-content:center;">
    <div style="background:white; padding:2rem; border-radius:8px; width:90%; max-width:800px; max-height:90vh; overflow-y:auto;">
        <div style="display:flex; justify-content:space-between; margin-bottom:1rem;">
            <h3>Novo Diário de Obra</h3>
            <button onclick="document.getElementById('entryModal').style.display='none'" style="background:none; border:none; cursor:pointer;"><i data-feather="x"></i></button>
        </div>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="action" value="save_log">
            
             <div style="display:grid; grid-template-columns: 1fr; gap:1rem; margin-bottom: 20px;">
                <!-- Date -->
                <div><label style="font-weight:600; display:block; margin-bottom:5px;">Data</label><input type="date" name="work_date" style="width:100%; padding:10px; border:1px solid #ccc; border-radius:4px;" required value="<?= date('Y-m-d') ?>"></div>
                
                 <!-- Clima Row -->
                 <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
                    <div>
                        <label style="font-weight:600; display:block; margin-bottom:5px;">Clima Manhã</label>
                        <div style="display:flex; gap:5px;">
                            <select name="weather_morning" style="flex:1; padding:10px; border:1px solid #ccc; border-radius:4px;" required>
                                <option value="Sol">Sol</option>
                                <option value="Nublado">Nublado</option>
                                <option value="Chuva">Chuva</option>
                            </select>
                            <select name="condition_morning" style="flex:1; padding:10px; border:1px solid #ccc; border-radius:4px;" required>
                                <option value="Praticável">Praticável</option>
                                <option value="N/Praticável">N/Praticável</option>
                            </select>
                        </div>
                    </div>
                    <div>
                        <label style="font-weight:600; display:block; margin-bottom:5px;">Clima Tarde</label>
                         <div style="display:flex; gap:5px;">
                            <select name="weather_afternoon" style="flex:1; padding:10px; border:1px solid #ccc; border-radius:4px;" required>
                                <option value="Sol">Sol</option>
                                <option value="Nublado">Nublado</option>
                                <option value="Chuva">Chuva</option>
                            </select>
                            <select name="condition_afternoon" style="flex:1; padding:10px; border:1px solid #ccc; border-radius:4px;" required>
                                <option value="Praticável">Praticável</option>
                                <option value="N/Praticável">N/Praticável</option>
                            </select>
                        </div>
                    </div>
                 </div>
            </div>
            
            <hr style="margin:1rem 0; border:0; border-top:1px solid #eee;">
            
                        <div style="display:flex; gap:20px; flex-wrap:wrap;">
                <div style="flex:1; min-width:300px;">
                    <label><strong>Mão de Obra</strong></label>
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; background:#f9fafb; padding:10px; border-radius:6px; font-size:0.85rem;">
                         <span><input type="number" name="wf_eng_civil" value="0" style="width:40px;"> Eng. Civil</span>
                         <span><input type="number" name="wf_encarregado" value="0" style="width:40px;"> Encarregado</span>
                         <span><input type="number" name="wf_motorista_pipa" value="0" style="width:40px;"> Mot. Pipa</span>
                         <span><input type="number" name="wf_op_motoniveladora" value="0" style="width:40px;"> Op. Patrol</span>
                         <span><input type="number" name="wf_op_rolo" value="0" style="width:40px;"> Op. Rolo</span>
                         <span><input type="number" name="wf_motorista_tracado" value="0" style="width:40px;"> Mot. Traçado</span>
                         <span><input type="number" name="wf_pedreiro" value="0" style="width:40px;"> Pedreiro</span>
                         <span><input type="number" name="wf_servente" value="0" style="width:40px;"> Servente</span>
                         <span><input type="number" name="wf_op_escavadeira" value="0" style="width:40px;"> Op. Escavad.</span>
                         <span><input type="number" name="wf_op_retro" value="0" style="width:40px;"> Op. Retro</span>
                         <span><input type="number" name="wf_laboratorista" value="0" style="width:40px;"> Laboratorista</span>
                         <span><input type="number" name="wf_op_pa" value="0" style="width:40px;"> Op. Pá Carreg.</span>
                         <span><input type="number" name="wf_topografo" value="0" style="width:40px;"> Topógrafo</span>
                         <span><input type="number" name="wf_ajudante_topografia" value="0" style="width:40px;"> Ajud. Topo</span>
                    </div>
                </div>

                <div style="flex:1; min-width:300px;">
                    <label><strong>Equipamentos</strong></label>
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; background:#f9fafb; padding:10px; border-radius:6px; font-size:0.85rem;">
                        <span><input type="number" name="eq_rolo_pe_carneiro" value="0" style="width:40px;"> Rolo P.C.</span>
                        <span><input type="number" name="eq_motoniveladora" value="0" style="width:40px;"> Motoniveladora</span>
                        <span><input type="number" name="eq_caminhao_pipa" value="0" style="width:40px;"> Cam. Pipa</span>
                        <span><input type="number" name="eq_caminhao_toco" value="0" style="width:40px;"> Cam. Toco</span>
                        <span><input type="number" name="eq_carregadeira" value="0" style="width:40px;"> Carregadeira</span>
                        <span><input type="number" name="eq_escavadeira" value="0" style="width:40px;"> Escavadeira</span>
                        <span><input type="number" name="eq_retroescavadeira" value="0" style="width:40px;"> Retroescavad.</span>
                        <span><input type="number" name="eq_rolo_compactador" value="0" style="width:40px;"> Rolo Compact.</span>
                        <span><input type="number" name="eq_trator_grade" value="0" style="width:40px;"> Trator c/ Grade</span>
                        <span><input type="number" name="eq_caminhao_basc" value="0" style="width:40px;"> Cam. Basc.</span>
                        <span><input type="number" name="eq_caminhao_munck" value="0" style="width:40px;"> Cam. Munck</span>
                    </div>
                </div>
            </div>
            <br>
            
            <label><strong>Atividades</strong></label>
            <textarea name="activities_text" rows="4" style="width:100%; padding:8px; margin-bottom:1rem; border:1px solid #ccc; border-radius:4px;" required></textarea>
            
            <label><strong>Ocorrências</strong></label>
            <textarea name="occurrences_text" rows="2" style="width:100%; padding:8px; margin-bottom:1rem; border:1px solid #ccc; border-radius:4px;"></textarea>
            
            <label><strong>Fotos</strong></label>
            <input type="file" name="photos[]" multiple accept="image/*" style="margin-bottom:1rem;">

            <button type="submit" class="btn" style="width:100%;">SALVAR DIÁRIO</button>
        </form>
    </div>
</div>

<!-- LIGHTBOX MODAL -->
<div id="lightboxModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.9); z-index:500; align-items:center; justify-content:center;">
    <button onclick="closeLightbox()" style="position:absolute; top:20px; right:20px; background:none; border:none; color:white; cursor:pointer; padding:10px;"><i data-feather="x" style="width:32px; height:32px;"></i></button>
    
    <button onclick="changeImage(-1)" style="position:absolute; left:20px; background:none; border:none; color:white; cursor:pointer; padding:20px; z-index:510;"><i data-feather="chevron-left" style="width:48px; height:48px;"></i></button>
    
    <div style="max-width:90%; max-height:90%; display:flex; flex-direction:column; align-items:center;">
        <img id="lightboxImg" src="" style="max-width:100%; max-height:80vh; object-fit:contain; border-radius:4px;">
        <p id="lightboxDesc" style="color:white; margin-top:10px; font-size:1.1rem; text-align:center;"></p>
    </div>

    <button onclick="changeImage(1)" style="position:absolute; right:20px; background:none; border:none; color:white; cursor:pointer; padding:20px; z-index:510;"><i data-feather="chevron-right" style="width:48px; height:48px;"></i></button>
</div>

<script>
    feather.replace();
    
    // Modal Form
    function openModal() {
        document.getElementById('entryModal').style.display = 'flex';
    }

    function toggleSidebar() {
        document.getElementById('sidebar').classList.toggle('open');
    }

    // Lightbox Logic
    const galleryImages = <?= json_encode($jsonPhotos ?? []) ?>;
    let currentImageIndex = 0;

    function openLightbox(index) {
        if (galleryImages.length === 0) return;
        currentImageIndex = index;
        updateLightbox();
        document.getElementById('lightboxModal').style.display = 'flex';
    }

    function closeLightbox() {
        document.getElementById('lightboxModal').style.display = 'none';
    }

    function changeImage(dir) {
        currentImageIndex += dir;
        if (currentImageIndex < 0) currentImageIndex = galleryImages.length - 1;
        if (currentImageIndex >= galleryImages.length) currentImageIndex = 0;
        updateLightbox();
    }

    function updateLightbox() {
        const imgParams = galleryImages[currentImageIndex];
        const img = document.getElementById('lightboxImg');
        const desc = document.getElementById('lightboxDesc');
        
        // Add loading state behavior if needed, for now just swap
        img.src = imgParams.src;
        desc.innerText = imgParams.desc || '';
    }

    // Close on Escape
    document.addEventListener('keydown', function(event) {
        if (event.key === "Escape") {
            closeLightbox();
        }
        if (event.key === "ArrowLeft") {
            changeImage(-1);
        }
        if (event.key === "ArrowRight") {
            changeImage(1);
        }
    });
</script>

</body>
</html>
