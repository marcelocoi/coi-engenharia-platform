SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

-- Tabela de Usuários
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL UNIQUE,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('admin','user') DEFAULT 'user',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Logs de Segurança
CREATE TABLE IF NOT EXISTS `security_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_type` varchar(50) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `details` text,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Obras
CREATE TABLE IF NOT EXISTS `constructions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `address` varchar(255),
  `contract_number` varchar(50),
  `status` varchar(50) DEFAULT 'Planejamento',
  `end_date_prediction` date,
  `image_path` varchar(255),
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Diário de Obras (Logs)
CREATE TABLE IF NOT EXISTS `construction_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `construction_id` int(11) NOT NULL,
  `work_date` date NOT NULL,
  `weather_morning` varchar(50),
  `weather_afternoon` varchar(50),
  `weather_condition_morning` varchar(50),
  `weather_condition_afternoon` varchar(50),
  `workforce_json` json,
  `equipment_json` json,
  `activities_text` text,
  `occurrences_text` text,
  `created_by` varchar(100),
  `approved_by_name` varchar(100) DEFAULT NULL,
  `approved_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`construction_id`) REFERENCES `constructions`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Fotos
CREATE TABLE IF NOT EXISTS `construction_photos` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `log_id` int(11) NOT NULL,
  `file_path` varchar(255) NOT NULL,
  `description` varchar(255),
  PRIMARY KEY (`id`),
  FOREIGN KEY (`log_id`) REFERENCES `construction_logs`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;