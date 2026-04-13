import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core"
import { SessionTable } from "../../session/session.sql"
import type { SessionID } from "../../session/schema"
import { Timestamps } from "../../storage/schema.sql"

export type SecurityActorSessionID = string & { __brand: "SecurityActorSessionID" }
export type SecurityBrowserSessionID = string & { __brand: "SecurityBrowserSessionID" }
export type SecurityBrowserPageID = string & { __brand: "SecurityBrowserPageID" }
export type SecurityExecutionAttemptID = string & { __brand: "SecurityExecutionAttemptID" }
export type SecurityTargetProfileID = string & { __brand: "SecurityTargetProfileID" }

export const SecurityActorSessionTable = sqliteTable(
  "security_actor_session",
  {
    id: text().$type<SecurityActorSessionID>().primaryKey(),
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    actor_label: text().notNull().default("browser"),
    browser_session_id: text().$type<SecurityBrowserSessionID>().notNull().default("" as SecurityBrowserSessionID),
    status: text().notNull().default("active"),
    last_origin: text().notNull().default(""),
    last_url: text().notNull().default(""),
    material_summary: text({ mode: "json" }).$type<Record<string, unknown>>().notNull().default({}),
    ...Timestamps,
  },
  (table) => [
    index("security_actor_session_session_idx").on(table.session_id),
    index("security_actor_session_status_idx").on(table.status),
  ],
)

export const SecurityBrowserSessionTable = sqliteTable(
  "security_browser_session",
  {
    id: text().$type<SecurityBrowserSessionID>().primaryKey(),
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    actor_session_id: text()
      .$type<SecurityActorSessionID>()
      .notNull()
      .references(() => SecurityActorSessionTable.id, { onDelete: "cascade" }),
    status: text().notNull().default("active"),
    headless: integer({ mode: "boolean" }).notNull().default(true),
    user_agent: text().notNull().default(""),
    navigation_index: integer().notNull().default(0),
    last_origin: text().notNull().default(""),
    last_url: text().notNull().default(""),
    last_error_code: text().notNull().default(""),
    ...Timestamps,
  },
  (table) => [
    index("security_browser_session_session_idx").on(table.session_id),
    uniqueIndex("security_browser_session_actor_uidx").on(table.actor_session_id),
  ],
)

export const SecurityBrowserPageTable = sqliteTable(
  "security_browser_page",
  {
    id: text().$type<SecurityBrowserPageID>().primaryKey(),
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    browser_session_id: text()
      .$type<SecurityBrowserSessionID>()
      .notNull()
      .references(() => SecurityBrowserSessionTable.id, { onDelete: "cascade" }),
    page_role: text().notNull().default("primary"),
    status: text().notNull().default("active"),
    last_url: text().notNull().default(""),
    title: text().notNull().default(""),
    ...Timestamps,
  },
  (table) => [
    index("security_browser_page_session_idx").on(table.session_id),
    uniqueIndex("security_browser_page_role_uidx").on(table.browser_session_id, table.page_role),
  ],
)

export const SecurityExecutionAttemptTable = sqliteTable(
  "security_execution_attempt",
  {
    id: text().$type<SecurityExecutionAttemptID>().primaryKey(),
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    actor_session_id: text().$type<SecurityActorSessionID>(),
    browser_session_id: text().$type<SecurityBrowserSessionID>(),
    page_id: text().$type<SecurityBrowserPageID>(),
    tool_name: text().notNull().default(""),
    action: text().notNull().default(""),
    status: text().notNull().default(""),
    error_code: text().notNull().default(""),
    notes: text({ mode: "json" }).$type<Record<string, unknown>>().notNull().default({}),
    ...Timestamps,
  },
  (table) => [
    index("security_execution_attempt_session_idx").on(table.session_id),
    index("security_execution_attempt_actor_idx").on(table.actor_session_id),
    index("security_execution_attempt_tool_action_idx").on(table.tool_name, table.action),
  ],
)

export const SecurityTargetProfileTable = sqliteTable(
  "security_target_profile",
  {
    id: text().$type<SecurityTargetProfileID>().primaryKey(),
    session_id: text()
      .$type<SessionID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    origin: text().notNull(),
    status: text().notNull().default("baseline"),
    concurrency_budget: integer().notNull().default(1),
    pacing_ms: integer().notNull().default(0),
    jitter_ms: integer().notNull().default(0),
    retry_budget: integer().notNull().default(0),
    browser_preferred: integer({ mode: "boolean" }).notNull().default(false),
    last_signal: text().notNull().default(""),
    notes: text({ mode: "json" }).$type<Record<string, unknown>>().notNull().default({}),
    ...Timestamps,
  },
  (table) => [
    index("security_target_profile_session_idx").on(table.session_id),
    uniqueIndex("security_target_profile_origin_uidx").on(table.session_id, table.origin),
  ],
)
