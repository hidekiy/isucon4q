CREATE TABLE IF NOT EXISTS `users` (
  `id` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `login` varchar(255) NOT NULL UNIQUE,
  `password_hash` varchar(255) NOT NULL,
  `salt` varchar(255) NOT NULL
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `login_log` (
  `id` bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `created_at` datetime NOT NULL,
  `user_id` int,
  `login` varchar(255) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `succeeded` tinyint NOT NULL,
  KEY `succeeded_2` (`succeeded`,`user_id`,`id`)
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `ban_user` (
  `user_id` int NOT NULL PRIMARY KEY,
  `failures` int NOT NULL
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `ban_ip` (
  `ip` varchar(255) NOT NULL PRIMARY KEY,
  `failures` int NOT NULL
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `last_login` (
  `user_id` int NOT NULL PRIMARY KEY,
  `created_at` datetime NOT NULL,
  `ip` varchar(255) NOT NULL
) DEFAULT CHARSET=utf8;
