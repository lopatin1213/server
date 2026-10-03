use log::info;
use rusqlite::Connection;

use super::core::AppState;

impl AppState {
    // ---- Миграция: last_seen + индексы ----
    pub fn migrate_db(conn: &mut Connection) -> Result<(), String> {
        {
            let mut stmt = conn
                .prepare("PRAGMA table_info(users)")
                .map_err(|e| e.to_string())?;
            let mut has_last_seen = false;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| e.to_string())?;
            for name in rows {
                if name.map_err(|e| e.to_string())? == "last_seen" {
                    has_last_seen = true;
                    break;
                }
            }
            if !has_last_seen {
                conn.execute(
                    "ALTER TABLE users ADD COLUMN last_seen INTEGER DEFAULT 0",
                    [],
                )
                .map_err(|e| e.to_string())?;
                info!("Добавлен столбец last_seen в таблицу users");
            }
        }

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_fcm_user ON fcm_tokens(user_id)",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hidden_user ON hidden_messages(user_id)",
            [],
        )
        .map_err(|e| e.to_string())?;

        Ok(())
    }

    // ---- Миграция: messages/group_messages/channel_messages к id ----
    pub fn migrate_msg_ids(conn: &mut Connection) -> Result<(), String> {
        let is_int_id = |conn: &Connection, table: &str| -> Result<bool, String> {
            let mut stmt = conn
                .prepare(&format!("PRAGMA table_info({})", table))
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
                })
                .map_err(|e| e.to_string())?;
            for r in rows {
                let (name, ty) = r.map_err(|e| e.to_string())?;
                if name == "id" {
                    return Ok(ty.to_uppercase().contains("INTEGER"));
                }
            }
            Ok(false)
        };

        if is_int_id(conn, "messages")?
            && is_int_id(conn, "group_messages")?
            && is_int_id(conn, "channel_messages")?
        {
            return Ok(());
        }

        info!("Миграция: конвертирую id в INTEGER AUTOINCREMENT");
        conn.execute("PRAGMA foreign_keys = OFF", [])
            .map_err(|e| e.to_string())?;

        let result = (|| -> Result<(), String> {
            if !is_int_id(conn, "messages")? {
                conn.execute_batch(
                    r#"
                    CREATE TABLE messages_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender_username TEXT NOT NULL,
                        recipient_username TEXT NOT NULL,
                        content TEXT NOT NULL,
                        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO messages_new (sender_username, recipient_username, content, sent_at)
                        SELECT sender_username, recipient_username, content, sent_at
                        FROM messages ORDER BY sent_at ASC, rowid ASC;
                    DROP TABLE messages;
                    ALTER TABLE messages_new RENAME TO messages;
                    "#,
                )
                .map_err(|e| format!("messages: {}", e))?;
            }
            if !is_int_id(conn, "group_messages")? {
                conn.execute_batch(
                    r#"
                    CREATE TABLE group_messages_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        group_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
                        sender_username TEXT NOT NULL,
                        content TEXT NOT NULL,
                        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO group_messages_new (group_id, sender_username, content, sent_at)
                        SELECT group_id, sender_username, content, sent_at
                        FROM group_messages ORDER BY sent_at ASC, rowid ASC;
                    DROP TABLE group_messages;
                    ALTER TABLE group_messages_new RENAME TO group_messages;
                    "#,
                )
                .map_err(|e| format!("group_messages: {}", e))?;
            }
            if !is_int_id(conn, "channel_messages")? {
                conn.execute_batch(
                    r#"
                    CREATE TABLE channel_messages_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
                        sender_username TEXT NOT NULL,
                        content TEXT NOT NULL,
                        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO channel_messages_new (channel_id, sender_username, content, sent_at)
                        SELECT channel_id, sender_username, content, sent_at
                        FROM channel_messages ORDER BY sent_at ASC, rowid ASC;
                    DROP TABLE channel_messages;
                    ALTER TABLE channel_messages_new RENAME TO channel_messages;
                    "#,
                )
                .map_err(|e| format!("channel_messages: {}", e))?;
            }
            Ok(())
        })();

        conn.execute("PRAGMA foreign_keys = ON", [])
            .map_err(|e| e.to_string())?;
        result
    }

    // ---- Миграция: fcm_tokens к сессии ----
    pub fn migrate_fcm_tokens(conn: &mut Connection) -> Result<(), String> {
        let mut has_session_token = false;
        {
            let mut stmt = conn
                .prepare("PRAGMA table_info(fcm_tokens)")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| e.to_string())?;
            for name in rows {
                if name.map_err(|e| e.to_string())? == "session_token" {
                    has_session_token = true;
                    break;
                }
            }
        }
        if has_session_token {
            return Ok(());
        }

        info!("Миграция: пересоздаю fcm_tokens с привязкой к сессии");
        conn.execute("PRAGMA foreign_keys = OFF", [])
            .map_err(|e| e.to_string())?;

        let result = (|| -> Result<(), String> {
            conn.execute_batch(
                r#"
                DROP TABLE IF EXISTS fcm_tokens_new;
                CREATE TABLE fcm_tokens_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    session_token TEXT REFERENCES sessions(token) ON DELETE CASCADE,
                    token TEXT NOT NULL,
                    device_name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(token)
                );
                INSERT INTO fcm_tokens_new (user_id, session_token, token, device_name, created_at)
                    SELECT f.user_id,
                           (SELECT s.token FROM sessions s
                            WHERE s.user_id = f.user_id
                            ORDER BY s.last_seen DESC, s.created_at DESC
                            LIMIT 1),
                           f.token, f.device_name, f.created_at
                    FROM fcm_tokens f
                    WHERE f.id = (
                        SELECT MAX(f2.id) FROM fcm_tokens f2 WHERE f2.token = f.token
                    );
                DROP TABLE fcm_tokens;
                ALTER TABLE fcm_tokens_new RENAME TO fcm_tokens;
                "#,
            )
            .map_err(|e| format!("fcm_tokens migration: {}", e))?;
            Ok(())
        })();

        conn.execute("PRAGMA foreign_keys = ON", [])
            .map_err(|e| e.to_string())?;
        result
    }

    // ---- Миграция: username → user_id во всех таблицах ----
    pub fn migrate_user_ids(conn: &mut Connection) -> Result<(), String> {
        let has_user_id = |conn: &Connection, table: &str, col: &str| -> Result<bool, String> {
            let mut stmt = conn
                .prepare(&format!("PRAGMA table_info({})", table))
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| e.to_string())?;
            for name in rows {
                if name.map_err(|e| e.to_string())? == col {
                    return Ok(true);
                }
            }
            Ok(false)
        };

        if has_user_id(conn, "messages", "sender_id")? {
            return Ok(());
        }

        info!("Миграция: привязка сообщений к user_id");
        conn.execute("PRAGMA foreign_keys = OFF", [])
            .map_err(|e| e.to_string())?;

        let result = (|| -> Result<(), String> {
            conn.execute_batch(
                r#"
                CREATE TABLE messages_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO messages_new (id, sender_id, recipient_id, content, sent_at)
                    SELECT m.id, u1.id, u2.id, m.content, m.sent_at
                    FROM messages m
                    JOIN users u1 ON u1.username = m.sender_username
                    JOIN users u2 ON u2.username = m.recipient_username;
                DROP TABLE messages;
                ALTER TABLE messages_new RENAME TO messages;
                "#,
            )
            .map_err(|e| format!("messages: {}", e))?;

            conn.execute_batch(
                r#"
                CREATE TABLE group_messages_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
                    sender_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO group_messages_new (id, group_id, sender_id, content, sent_at)
                    SELECT gm.id, gm.group_id, u.id, gm.content, gm.sent_at
                    FROM group_messages gm
                    JOIN users u ON u.username = gm.sender_username;
                DROP TABLE group_messages;
                ALTER TABLE group_messages_new RENAME TO group_messages;
                "#,
            )
            .map_err(|e| format!("group_messages: {}", e))?;

            conn.execute_batch(
                r#"
                CREATE TABLE channel_messages_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
                    sender_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO channel_messages_new (id, channel_id, sender_id, content, sent_at)
                    SELECT cm.id, cm.channel_id, u.id, cm.content, cm.sent_at
                    FROM channel_messages cm
                    JOIN users u ON u.username = cm.sender_username;
                DROP TABLE channel_messages;
                ALTER TABLE channel_messages_new RENAME TO channel_messages;
                "#,
            )
            .map_err(|e| format!("channel_messages: {}", e))?;

            conn.execute_batch(
                r#"
                CREATE TABLE groups_new (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    creator_id TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO groups_new (id, name, creator_id, created_at)
                    SELECT g.id, g.name, u.id, g.created_at
                    FROM groups g
                    JOIN users u ON u.username = g.creator_username;
                DROP TABLE groups;
                ALTER TABLE groups_new RENAME TO groups;
                "#,
            )
            .map_err(|e| format!("groups: {}", e))?;

            conn.execute_batch(
                r#"
                CREATE TABLE group_members_new (
                    group_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member')),
                    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (group_id, user_id)
                );
                INSERT INTO group_members_new (group_id, user_id, role, joined_at)
                    SELECT gm.group_id, u.id, gm.role, gm.joined_at
                    FROM group_members gm
                    JOIN users u ON u.username = gm.username;
                DROP TABLE group_members;
                ALTER TABLE group_members_new RENAME TO group_members;
                "#,
            )
            .map_err(|e| format!("group_members: {}", e))?;

            conn.execute_batch(
                r#"
                CREATE TABLE channels_new (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    creator_id TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO channels_new (id, name, creator_id, created_at)
                    SELECT c.id, c.name, u.id, c.created_at
                    FROM channels c
                    JOIN users u ON u.username = c.creator_username;
                DROP TABLE channels;
                ALTER TABLE channels_new RENAME TO channels;
                "#,
            )
            .map_err(|e| format!("channels: {}", e))?;

            conn.execute_batch(
                r#"
                CREATE TABLE channel_subscribers_new (
                    channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
                    user_id TEXT NOT NULL,
                    subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (channel_id, user_id)
                );
                INSERT INTO channel_subscribers_new (channel_id, user_id, subscribed_at)
                    SELECT cs.channel_id, u.id, cs.subscribed_at
                    FROM channel_subscribers cs
                    JOIN users u ON u.username = cs.username;
                DROP TABLE channel_subscribers;
                ALTER TABLE channel_subscribers_new RENAME TO channel_subscribers;
                "#,
            )
            .map_err(|e| format!("channel_subscribers: {}", e))?;

            Ok(())
        })();

        conn.execute("PRAGMA foreign_keys = ON", [])
            .map_err(|e| e.to_string())?;
        result
    }

    // ---- Миграция: reply_to_id ----
    pub fn migrate_reply_to_id(conn: &mut Connection) -> Result<(), String> {
        let has_reply_col = |conn: &Connection, table: &str| -> Result<bool, String> {
            let mut stmt = conn
                .prepare(&format!("PRAGMA table_info({})", table))
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| e.to_string())?;
            for name in rows {
                if name.map_err(|e| e.to_string())? == "reply_to_id" {
                    return Ok(true);
                }
            }
            Ok(false)
        };

        for table in ["messages", "group_messages", "channel_messages"] {
            if !has_reply_col(conn, table)? {
                conn.execute(
                    &format!("ALTER TABLE {} ADD COLUMN reply_to_id INTEGER", table),
                    [],
                )
                .map_err(|e| format!("{}: {}", table, e))?;
                info!("Добавлен столбец reply_to_id в {}", table);
            }
        }
        Ok(())
    }

    // ---- Миграция: read_status ----
    pub fn migrate_read_status(conn: &mut Connection) -> Result<(), String> {
        let has_col = |conn: &Connection, table: &str, col: &str| -> Result<bool, String> {
            let mut stmt = conn
                .prepare(&format!("PRAGMA table_info({})", table))
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| e.to_string())?;
            for name in rows {
                if name.map_err(|e| e.to_string())? == col {
                    return Ok(true);
                }
            }
            Ok(false)
        };

        if !has_col(conn, "messages", "read_at")? {
            conn.execute("ALTER TABLE messages ADD COLUMN read_at TIMESTAMP", [])
                .map_err(|e| e.to_string())?;
            info!("Добавлен столбец read_at в messages");
        }
        if !has_col(conn, "group_messages", "first_read_at")? {
            conn.execute(
                "ALTER TABLE group_messages ADD COLUMN first_read_at TIMESTAMP",
                [],
            )
            .map_err(|e| e.to_string())?;
            info!("Добавлен столбец first_read_at в group_messages");
        }

        conn.execute(
            "CREATE TABLE IF NOT EXISTS channel_message_views (
                channel_msg_id INTEGER NOT NULL,
                user_id TEXT NOT NULL,
                viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (channel_msg_id, user_id)
            )",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_channel_views_msg ON channel_message_views(channel_msg_id)",
            [],
        )
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    // ---- init ----
    pub fn init_db(conn: &mut Connection) -> Result<(), String> {
        let sql = r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                display_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                device_name TEXT,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                content TEXT NOT NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                creator_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member')),
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (group_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
                sender_id TEXT NOT NULL,
                content TEXT NOT NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS fcm_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                session_token TEXT REFERENCES sessions(token) ON DELETE CASCADE,
                token TEXT NOT NULL,
                device_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(token)
            );
            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                creator_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS channel_subscribers (
                channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL,
                subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (channel_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS channel_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
                sender_id TEXT NOT NULL,
                content TEXT NOT NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS hidden_messages (
                user_id TEXT NOT NULL,
                kind INTEGER NOT NULL,
                msg_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, kind, msg_id)
            );
        "#;
        conn.execute_batch(sql)
            .map_err(|e| format!("Ошибка создания таблиц: {}", e))?;

        Self::migrate_db(conn)?;
        Self::migrate_fcm_tokens(conn)?;
        Self::migrate_msg_ids(conn)?;
        Self::migrate_user_ids(conn)?;
        Self::migrate_reply_to_id(conn)?;
        Self::migrate_read_status(conn)?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id)",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_id)",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_channel_messages_channel ON channel_messages(channel_id)",
            [],
        )
            .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_fcm_user ON fcm_tokens(user_id)",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_fcm_session ON fcm_tokens(session_token)",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hidden_user ON hidden_messages(user_id)",
            [],
        )
        .map_err(|e| e.to_string())?;

        Ok(())
    }
}
