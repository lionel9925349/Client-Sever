CREATE DATABASE IF NOT EXISTS `userman` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `userman`;

CREATE TABLE `userlist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `givenName` varchar(255) NOT NULL,
  `familyName` varchar(255) NOT NULL,
  `creationTime` varchar(32) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `userlist` (`id`, `username`, `password`, `givenName`, `familyName`, `creationTime`) VALUES
(1, 'admin', 'c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec', 'Peter', 'Kneisel', '24.9.2022, 12:24:59');

/*
Die Logindaten für den angelegten Nutzer lauten:
Username: admin
Password: admin
*/