CREATE TABLE `security_actor_session` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`actor_label` text DEFAULT 'browser' NOT NULL,
	`browser_session_id` text DEFAULT '' NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`last_origin` text DEFAULT '' NOT NULL,
	`last_url` text DEFAULT '' NOT NULL,
	`material_summary` text DEFAULT '{}' NOT NULL,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_security_actor_session_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `security_browser_page` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`browser_session_id` text NOT NULL,
	`page_role` text DEFAULT 'primary' NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`last_url` text DEFAULT '' NOT NULL,
	`title` text DEFAULT '' NOT NULL,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_security_browser_page_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_security_browser_page_browser_session_id_security_browser_session_id_fk` FOREIGN KEY (`browser_session_id`) REFERENCES `security_browser_session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `security_browser_session` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`actor_session_id` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`headless` integer DEFAULT true NOT NULL,
	`user_agent` text DEFAULT '' NOT NULL,
	`navigation_index` integer DEFAULT 0 NOT NULL,
	`last_origin` text DEFAULT '' NOT NULL,
	`last_url` text DEFAULT '' NOT NULL,
	`last_error_code` text DEFAULT '' NOT NULL,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_security_browser_session_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_security_browser_session_actor_session_id_security_actor_session_id_fk` FOREIGN KEY (`actor_session_id`) REFERENCES `security_actor_session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `security_execution_attempt` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`actor_session_id` text,
	`browser_session_id` text,
	`page_id` text,
	`tool_name` text DEFAULT '' NOT NULL,
	`action` text DEFAULT '' NOT NULL,
	`status` text DEFAULT '' NOT NULL,
	`error_code` text DEFAULT '' NOT NULL,
	`notes` text DEFAULT '{}' NOT NULL,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_security_execution_attempt_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `security_target_profile` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`origin` text NOT NULL,
	`status` text DEFAULT 'baseline' NOT NULL,
	`concurrency_budget` integer DEFAULT 1 NOT NULL,
	`pacing_ms` integer DEFAULT 0 NOT NULL,
	`jitter_ms` integer DEFAULT 0 NOT NULL,
	`retry_budget` integer DEFAULT 0 NOT NULL,
	`browser_preferred` integer DEFAULT false NOT NULL,
	`last_signal` text DEFAULT '' NOT NULL,
	`notes` text DEFAULT '{}' NOT NULL,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_security_target_profile_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX `security_actor_session_session_idx` ON `security_actor_session` (`session_id`);--> statement-breakpoint
CREATE INDEX `security_actor_session_status_idx` ON `security_actor_session` (`status`);--> statement-breakpoint
CREATE INDEX `security_browser_page_session_idx` ON `security_browser_page` (`session_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `security_browser_page_role_uidx` ON `security_browser_page` (`browser_session_id`,`page_role`);--> statement-breakpoint
CREATE INDEX `security_browser_session_session_idx` ON `security_browser_session` (`session_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `security_browser_session_actor_uidx` ON `security_browser_session` (`actor_session_id`);--> statement-breakpoint
CREATE INDEX `security_execution_attempt_session_idx` ON `security_execution_attempt` (`session_id`);--> statement-breakpoint
CREATE INDEX `security_execution_attempt_actor_idx` ON `security_execution_attempt` (`actor_session_id`);--> statement-breakpoint
CREATE INDEX `security_execution_attempt_tool_action_idx` ON `security_execution_attempt` (`tool_name`,`action`);--> statement-breakpoint
CREATE INDEX `security_target_profile_session_idx` ON `security_target_profile` (`session_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `security_target_profile_origin_uidx` ON `security_target_profile` (`session_id`,`origin`);