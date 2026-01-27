<?php
class Construction {
    private $db;
    public function __construct($db) { $this->db = $db; }

    public function getAll() {
        $stmt = $this->db->query("SELECT * FROM constructions ORDER BY created_at DESC");
        return $stmt->fetchAll();
    }
    public function getForUser($userId) {
        // Implementar lógica de permissão por usuário se necessário
        return $this->getAll(); 
    }
    public function getById($id) {
        $stmt = $this->db->prepare("SELECT * FROM constructions WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch();
    }
    public function hasAccess($userId, $constructionId, $isAdmin) {
        return true; // Simplificado para exemplo
    }
}
?>