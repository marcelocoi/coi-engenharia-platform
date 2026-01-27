<?php
// Renomeie este arquivo para db_config.php e insira credenciais reais.
class SecureDatabase {
    private static $instance = null;
    private $pdo;

    private function __construct() {
        $host = getenv('DB_HOST') ?: 'localhost';
        $db   = getenv('DB_NAME') ?: 'coi_engenharia_db';
        $user = getenv('DB_USER') ?: 'root';
        $pass = getenv('DB_PASS') ?: '';

        try {
            $this->pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8mb4", $user, $pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (PDOException $e) {
            error_log("DB Connection Error: " . $e->getMessage());
            die("Erro de conexão com banco de dados.");
        }
    }

    public static function getInstance() {
        if (self::$instance == null) self::$instance = new SecureDatabase();
        return self::$instance;
    }

    public function getConnection() {
        return $this->pdo;
    }
}
?>