-- Project Holocron: Pre-made Level 80 Test Characters with Endgame Gear
USE `holocron_characters`;

INSERT INTO `characters` (`guid`, `account_id`, `name`, `level`, `gender`, `species`, `class_id`, `discipline_id`, `zone_id`, `pos_x`, `pos_y`, `pos_z`, `orientation`)
VALUES (80001, 1, 'Master Vaelin', 80, 0, 1, 1, 1, 1, 8.5, 0, 15, 0)
ON DUPLICATE KEY UPDATE `level`=80, `name`='Master Vaelin';

INSERT INTO `characters` (`guid`, `account_id`, `name`, `level`, `gender`, `species`, `class_id`, `discipline_id`, `zone_id`, `pos_x`, `pos_y`, `pos_z`, `orientation`)
VALUES (80002, 1, 'Lord Malor', 80, 0, 1, 6, 1, 1, -4, 0, 22, 0)
ON DUPLICATE KEY UPDATE `level`=80, `name`='Lord Malor';

INSERT INTO `characters` (`guid`, `account_id`, `name`, `level`, `gender`, `species`, `class_id`, `discipline_id`, `zone_id`, `pos_x`, `pos_y`, `pos_z`, `orientation`)
VALUES (80003, 1, 'Mando Fett', 80, 0, 1, 7, 1, 1, 12, 0, -8, 0)
ON DUPLICATE KEY UPDATE `level`=80, `name`='Mando Fett';

INSERT INTO `characters` (`guid`, `account_id`, `name`, `level`, `gender`, `species`, `class_id`, `discipline_id`, `zone_id`, `pos_x`, `pos_y`, `pos_z`, `orientation`)
VALUES (80004, 1, 'Captain Rhyse', 80, 0, 1, 3, 1, 1, 0, 0, 30, 0)
ON DUPLICATE KEY UPDATE `level`=80, `name`='Captain Rhyse';

INSERT INTO `characters` (`guid`, `account_id`, `name`, `level`, `gender`, `species`, `class_id`, `discipline_id`, `zone_id`, `pos_x`, `pos_y`, `pos_z`, `orientation`)
VALUES (80005, 1, 'Darth Vindicator', 80, 0, 1, 5, 1, 1, 0, 0, 0, 0)
ON DUPLICATE KEY UPDATE `level`=80, `name`='Darth Vindicator';

INSERT INTO `characters` (`guid`, `account_id`, `name`, `level`, `gender`, `species`, `class_id`, `discipline_id`, `zone_id`, `pos_x`, `pos_y`, `pos_z`, `orientation`)
VALUES (80006, 1, 'Havoc Commander', 80, 0, 1, 4, 1, 1, 0, 0, 0, 0)
ON DUPLICATE KEY UPDATE `level`=80, `name`='Havoc Commander';
