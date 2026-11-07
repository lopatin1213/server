use deadpool_postgres::Pool;
use log::info;
use sha2::{Digest, Sha256};

use super::core::AppState;

impl AppState {
    // Переносим сюда функцию хэширования, она нужна и тут, и в user.rs
    pub fn compute_phone_hash(phone: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(phone.as_bytes());
        hasher.update(crate::constants::PEPPER.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub async fn init_db(pool: &Pool) -> Result<(), String> {
        let client = pool
            .get()
            .await
            .map_err(|e| format!("Ошибка получения клиента из пула: {}", e))?;

        let sql = r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                display_name TEXT,
                bio TEXT,
                phone_hash TEXT,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                last_seen BIGINT DEFAULT 0
            );
            -- Добавляем bio и phone_hash, если таблица уже существует
            ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
            ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_hash TEXT;
            CREATE INDEX IF NOT EXISTS idx_users_phone_hash ON users(phone_hash);

            CREATE TABLE IF NOT EXISTS user_settings (
                user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                hide_phone BOOLEAN DEFAULT false,
                last_seen_privacy SMALLINT DEFAULT 0
            );
            INSERT INTO user_settings (user_id) SELECT id FROM users ON CONFLICT DO NOTHING;

            CREATE TABLE IF NOT EXISTS user_contacts (
                owner_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                contact_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY (owner_id, contact_id)
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
            CREATE TABLE IF NOT EXISTS bans (
                id BIGSERIAL PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                reason TEXT NOT NULL,
                expires_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
            CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
            CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_id);
            CREATE INDEX IF NOT EXISTS idx_channel_messages_channel ON channel_messages(channel_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_fcm_user ON fcm_tokens(user_id);
            CREATE INDEX IF NOT EXISTS idx_fcm_session ON fcm_tokens(session_token);
            CREATE INDEX IF NOT EXISTS idx_hidden_user ON hidden_messages(user_id);
        "#;

        client
            .batch_execute(sql)
            .await
            .map_err(|e| format!("Ошибка создания таблиц PG: {}", e))?;

        let _ = client.execute("INSERT INTO users (id, username, phone, password_hash, display_name) VALUES ('system', 'system', '0000000000', '*', 'VartChat System') ON CONFLICT (id) DO NOTHING", &[]).await;
        let _ = client
            .execute(
                "INSERT INTO user_settings (user_id) VALUES ('system') ON CONFLICT DO NOTHING",
                &[],
            )
            .await;

        // ==================== V5: МИГРАЦИЯ ДАННЫХ ====================
        info!("Проверяем необходимость миграции phone_hash...");

        let rows = client
            .query(
                "SELECT id, phone FROM users WHERE phone_hash IS NULL AND phone != '0000000000'",
                &[],
            )
            .await
            .map_err(|e| format!("Ошибка выборки для миграции: {}", e))?;

        if !rows.is_empty() {
            info!(
                "Миграция: найдено {} пользователей без phone_hash. Заполняем...",
                rows.len()
            );

            for row in rows {
                let user_id: String = row.get(0);
                let phone: String = row.get(1);
                let hash = Self::compute_phone_hash(&phone);

                let _ = client
                    .execute(
                        "UPDATE users SET phone_hash = $1 WHERE id = $2",
                        &[&hash, &user_id],
                    )
                    .await
                    .map_err(|e| format!("Ошибка записи phone_hash: {}", e))?;
            }
            info!("Миграция: успешно заполнены хэши для всех пользователей.");
        } else {
            info!("Миграция: все пользователи уже имеют phone_hash.");
        }
        // ==========================================================

        info!("База данных PostgreSQL успешно инициализирована (с поддержкой V5).");
        Ok(())
    }
}
