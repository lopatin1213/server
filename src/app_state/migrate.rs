use deadpool_postgres::Pool;
use log::info;

use super::core::AppState;

impl AppState {
    // ---- init ----
    pub async fn init_db(pool: &Pool) -> Result<(), String> {
        let client = pool
            .get()
            .await
            .map_err(|e| format!("Ошибка получения клиента из пула: {}", e))?;

        // Весь SQL переписан под Postgres:
        // SERIAL / BIGSERIAL для автоинкремента
        // TIMESTAMPTZ для времени
        // BOOLEAN для флагов
        let sql = r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                display_name TEXT,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                last_seen BIGINT DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                device_name TEXT,
                last_seen TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS messages (
                id BIGSERIAL PRIMARY KEY,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                content TEXT NOT NULL,
                sent_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                edited BOOLEAN DEFAULT false,
                reply_to_id BIGINT,
                read_at TIMESTAMPTZ,
                delete_at BIGINT
            );
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                creator_id TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member')),
                joined_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (group_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS group_messages (
                id BIGSERIAL PRIMARY KEY,
                group_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
                sender_id TEXT NOT NULL,
                content TEXT NOT NULL,
                sent_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                edited BOOLEAN DEFAULT false,
                reply_to_id BIGINT,
                first_read_at TIMESTAMPTZ,
                delete_at BIGINT
            );
            CREATE TABLE IF NOT EXISTS fcm_tokens (
                id BIGSERIAL PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                session_token TEXT REFERENCES sessions(token) ON DELETE CASCADE,
                token TEXT NOT NULL,
                device_name TEXT,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(token)
            );
            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                creator_id TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS channel_subscribers (
                channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL,
                subscribed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (channel_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS channel_messages (
                id BIGSERIAL PRIMARY KEY,
                channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
                sender_id TEXT NOT NULL,
                content TEXT NOT NULL,
                sent_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                edited BOOLEAN DEFAULT false,
                reply_to_id BIGINT,
                delete_at BIGINT
            );
            CREATE TABLE IF NOT EXISTS channel_message_views (
                channel_msg_id BIGINT NOT NULL REFERENCES channel_messages(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL,
                viewed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (channel_msg_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS hidden_messages (
                user_id TEXT NOT NULL,
                kind INTEGER NOT NULL,
                msg_id BIGINT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, kind, msg_id)
            );

            -- Индексы для быстрой работы
            CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
            CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
            CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_id);
            CREATE INDEX IF NOT EXISTS idx_channel_messages_channel ON channel_messages(channel_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_fcm_user ON fcm_tokens(user_id);
            CREATE INDEX IF NOT EXISTS idx_fcm_session ON fcm_tokens(session_token);
            CREATE INDEX IF NOT EXISTS idx_hidden_user ON hidden_messages(user_id);
        "#;

        // batch_execute выполняет несколько запросов разом
        client
            .batch_execute(sql)
            .await
            .map_err(|e| format!("Ошибка создания таблиц PG: {}", e))?;
        // Создаем системного пользователя, если его нет
        let _ = client
            .execute(
                "INSERT INTO users (id, username, phone, password_hash, display_name) \
             VALUES ('system', 'system', '0000000000', '*', 'VartChat System') \
             ON CONFLICT (id) DO NOTHING",
                &[],
            )
            .await;
        info!("База данных PostgreSQL успешно инициализирована.");

        Ok(())
    }
}
