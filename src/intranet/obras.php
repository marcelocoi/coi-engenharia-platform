<?php
define('SECURE_ACCESS', true);
require_once __DIR__ . '/data/config/db_config.php';
require_once __DIR__ . '/data/classes/Construction.php';

session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$userId = $_SESSION['user_id'];
$isAdmin = $_SESSION['is_admin'] ?? false;
$username = $_SESSION['username'];

$db = null;
$constructionModel = null;
$constructions = [];
$dbError = null;

try {
    $db = SecureDatabase::getInstance()->getConnection();
    $constructionModel = new Construction($db);
    
    // Fetch Constructions
    if ($isAdmin) {
        $constructions = $constructionModel->getAll();
    } else {
        $constructions = $constructionModel->getForUser($userId);
    }
} catch (Exception $e) {
    $dbError = $e->getMessage();
}

// Fetch Constructions


// Stats per construction
if ($db && !empty($constructions)) {
foreach ($constructions as &$c) {
    // Count logs
    $stmt = $db->prepare("SELECT count(*) FROM construction_logs WHERE construction_id = ?");
    $stmt->execute([$c['id']]);
    $c['total_logs'] = $stmt->fetchColumn();
    
    // Count photos
    $stmt = $db->prepare("
        SELECT count(p.id) FROM construction_photos p 
        JOIN construction_logs l ON p.log_id = l.id 
        WHERE l.construction_id = ?
    ");
    $stmt->execute([$c['id']]);
    $c['total_photos'] = $stmt->fetchColumn();
}
}
unset($c);

?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Minhas Obras - COI Engenharia</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/feather-icons"></script>
    <style>
        :root {
            --primary: #0D2C54;
            --accent: #F26419;
            --bg: #F3F4F6;
            --white: #FFFFFF;
            --text: #1F2937;
            --gray: #9CA3AF;
        }
        body { font-family: 'Inter', sans-serif; background: var(--bg); margin: 0; color: var(--text); padding-bottom: 40px; }
        
        .glass-header {
            background: var(--primary);
            color: white;
            padding: 1rem 2rem;
            display: flex; justify-content: space-between; align-items: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .app-title { font-family: 'Montserrat', sans-serif; font-weight: 700; font-size: 1.2rem; display: flex; align-items: center; gap: 10px; }
        
        .container { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }
        
        /* Filters */
        .toolbar {
            background: white; padding: 1rem; border-radius: 8px; margin-bottom: 2rem;
            display: flex; gap: 1rem; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            flex-wrap: wrap;
        }
        .search-box { flex: 1; position: relative; }
        .search-box input {
            width: 100%; padding: 0.6rem 0.6rem 0.6rem 2.5rem;
            border: 1px solid #D1D5DB; border-radius: 6px; font-family: inherit;
        }
        .search-box i { position: absolute; left: 0.8rem; top: 50%; transform: translateY(-50%); color: var(--gray); width: 16px; }
        
        /* Grid */
        .obras-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1.5rem; }
        
        .obra-card {
            background: white; border-radius: 12px; overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05); transition: transform 0.2s;
            text-decoration: none; color: inherit; display: block;
            border: 1px solid transparent;
        }
        .obra-card:hover { transform: translateY(-5px); box-shadow: 0 10px 15px rgba(0,0,0,0.1); border-color: var(--accent); }
        
        .card-img { height: 160px; background: #eee; position: relative; }
        .card-img img { width: 100%; height: 100%; object-fit: cover; }
        .status-badge {
            position: absolute; top: 10px; left: 10px;
            background: var(--accent); color: white;
            padding: 4px 10px; border-radius: 20px;
            font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
        }
        
        .card-body { padding: 1.5rem; }
        .obra-title { font-weight: 700; font-size: 1.1rem; color: var(--primary); margin-bottom: 0.5rem; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
        .obra-meta { font-size: 0.85rem; color: #666; margin-bottom: 1rem; display: flex; align-items: center; gap: 5px; }
        
        .card-stats {
            display: flex; gap: 15px; padding-top: 1rem; border-top: 1px solid #eee;
        }
        .stat { display: flex; align-items: center; gap: 5px; font-size: 0.8rem; color: #666; }
        
        .btn-add { background: var(--accent); color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 6px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 5px; text-decoration: none; }
        
    </style>
</head>
<body>

<header class="glass-header">
    <div class="app-title">
        <i data-feather="grid"></i> COI ENGENHARIA
    </div>
    <div style="display:flex; gap:1rem; align-items:center;">
        <span style="font-size:0.9rem; opacity:0.8;">Olá, <?= htmlspecialchars($username) ?></span>
        
        <?php if($isAdmin): ?>
            <a href="admin_constructions.php" class="btn-add" style="font-size:0.8rem; padding: 0.4rem 0.8rem;">
                <i data-feather="settings" style="width:14px;"></i> Admin
            </a>
        <?php endif; ?>
        
        <a href="index.php" style="color:white; text-decoration:none;"><i data-feather="home"></i></a>
    </div>
</header>

<div class="container">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
        <h2 style="color:var(--primary); margin:0;">Obras (<?= count($constructions) ?>)</h2>
        <?php if($isAdmin): ?>
            <a href="admin_constructions.php?action=new" class="btn-add"><i data-feather="plus"></i> ADICIONAR</a>
        <?php endif; ?>
    </div>

    <?php if (isset($dbError)): ?>
        <div style="background:#FDE8E8; color:#9B1C1C; padding:1rem; border-radius:8px; margin-bottom:2rem;">
            <strong>Erro no Sistema:</strong> Não foi possível carregar as obras. <br>
            <small><?= htmlspecialchars($dbError) ?></small>
            <?php if(strpos($dbError, 'exist') !== false): ?>
                <br><br>
                <a href="run_migration.php" target="_blank" style="text-decoration:underline;">Clique aqui para tentar rodar a instalação do Banco de Dados</a>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <div class="toolbar">
        <div class="search-box">
            <i data-feather="search"></i>
            <input type="text" id="searchInput" placeholder="Pesquisar obras..." onkeyup="filterObras()">
        </div>
        <select class="search-box" style="width:auto; max-width:200px; padding-left:0.6rem;" onchange="filterStatus()" id="statusFilter">
            <option value="all">Todos os status</option>
            <option value="Em andamento">Em andamento</option>
            <option value="Concluído">Concluído</option>
            <option value="Planejamento">Planejamento</option>
        </select>
    </div>

    <div class="obras-grid" id="obrasGrid">
        <?php foreach($constructions as $c): ?>
            <a href="diario_obras.php?construction_id=<?= $c['id'] ?>" class="obra-card" data-name="<?= strtolower($c['name']) ?>" data-status="<?= $c['status'] ?>">
                <div class="card-img">
                    <?php if($c['image_path']): ?>
                        <img src="<?= htmlspecialchars($c['image_path']) ?>" alt="Obra">
                    <?php else: ?>
                        <div style="width:100%; height:100%; display:flex; align-items:center; justify-content:center; background:linear-gradient(45deg, #0D2C54, #1a4b8c);">
                            <i data-feather="map" style="color:white; width:40px; height:40px; opacity:0.5;"></i>
                        </div>
                    <?php endif; ?>
                    <div class="status-badge" style="background: <?= $c['status'] == 'Concluído' ? '#10B981' : '#F26419' ?>">
                        <?= htmlspecialchars($c['status']) ?>
                    </div>
                </div>
                <div class="card-body">
                    <div class="obra-title"><?= htmlspecialchars($c['name']) ?></div>
                    <div class="obra-meta">
                        <i data-feather="map-pin" style="width:14px;"></i> 
                        <?= htmlspecialchars($c['address'] ?? 'Local não informado') ?>
                    </div>
                    
                    <div class="card-stats">
                        <div class="stat"><i data-feather="file-text" style="width:14px;"></i> <?= $c['total_logs'] ?> Relatórios</div>
                        <div class="stat"><i data-feather="camera" style="width:14px;"></i> <?= $c['total_photos'] ?> Fotos</div>
                    </div>
                </div>
            </a>
        <?php endforeach; ?>
    </div>
</div>

<script>
    feather.replace();

    function filterObras() {
        const term = document.getElementById('searchInput').value.toLowerCase();
        const cards = document.querySelectorAll('.obra-card');
        
        cards.forEach(card => {
            const name = card.getAttribute('data-name');
            if (name.includes(term)) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });
    }

    function filterStatus() {
        const status = document.getElementById('statusFilter').value;
        const cards = document.querySelectorAll('.obra-card');

        cards.forEach(card => {
            const cardStatus = card.getAttribute('data-status');
            if (status === 'all' || cardStatus === status) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });
    }
</script>

</body>
</html>
