CREATE DATABASE IF NOT EXISTS `holocron_auth`;
USE `holocron_auth`;

CREATE TABLE IF NOT EXISTS `accounts` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(64) NOT NULL UNIQUE,
  `password_hash` VARCHAR(128) NOT NULL,
  `email` VARCHAR(128) DEFAULT NULL,
  `session_token` VARCHAR(64) DEFAULT NULL,
  `server_id` VARCHAR(32) DEFAULT NULL,
  `account_level` TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login` TIMESTAMP NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed default admin and single-player accounts
INSERT IGNORE INTO `accounts` (`id`, `username`, `password_hash`, `account_level`) 
VALUES (1, 'admin', 'admin', 100), (2, 'player', 'player', 0);
