// ============================================================
//  main.rs — Relay Server with E2EE, multi-device, FCM pushes
// ============================================================
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use jsonwebtoken::{encode, EncodingKey, Header};
use log::{error, info, warn, debug};
//use rand::rngs::OsRng as RandOsRng; // переименовали, чтобы не конфликтовало
use reqwest::Client;
use rusqlite::{params, Connection};
use serde::Serialize;
use serde_json::json;
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration as StdDuration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};

// Оставили только один OsRng, из aes_gcm::aead мы уже имеем OsRng,
// поэтому rand::rngs::OsRng переименовали в RandOsRng, но он не используется,
// можно убрать, но оставим для ясности.

// ==================== Константы ====================
const MSG_TYPE_USER: u8 = 0x01;
const MSG_TYPE_SYSTEM: u8 = 0x02;
const MSG_TYPE_COMMAND: u8 = 0x03;
const MSG_TYPE_AUTH: u8 = 0x04;

const MAX_MESSAGE_SIZE: usize = 64 * 1024; // 64 KB
const RATE_LIMIT_WINDOW: StdDuration = StdDuration::from_secs(1);
const RATE_LIMIT_MAX: usize = 10; // сообщений в секунду
const HISTORY_LIMIT: i64 = 100; // пагинация

// ==================== FCM ====================
/// Отправляет push-уведомление через Python-модуль fcm_helper
async fn send_fcm_push(
    fcm_token: &str,
    title: &str,
    body: &str,
    data: Option<serde_json::Value>,
) -> Result<(), String> {
    // Преобразуем data в HashMap<String, String> (если есть)
    let data_map: Option<HashMap<String, String>> = data.map(|v| {
        v.as_object()
            .unwrap_or(&serde_json::Map::new())
            .iter()
            .filter_map(|(k, v)| {
                if let Some(s) = v.as_str() {
                    Some((k.clone(), s.to_string()))
                } else {
                    // Если значение не строка, сериализуем в строку
                    Some((k.clone(), v.to_string()))
                }
            })
            .collect()
    });

    // Вызов Python-функции в блокирующем потоке
    let token = fcm_token.to_string();
    let title = title.to_string();
    let body = body.to_string();

    let result = tokio::task::spawn_blocking(move || -> Result<(), String> {
        // Инициализируем интерпретатор Python (PyO3 сделает это автоматически, но можно явно)
        Python::with_gil(|py| {
            // Импортируем наш модуль
            let helper = py.import("fcm_helper")
                .map_err(|e| format!("Не удалось импортировать fcm_helper: {}", e))?;
            let send_func = helper.getattr("send_fcm_push")
                .map_err(|e| format!("Не удалось найти send_fcm_push: {}", e))?;

            // Подготавливаем аргументы
            let args = (token, title, body, data_map);
            // Вызываем функцию
            let result: bool = send_func.call1(args)
                .map_err(|e| format!("Ошибка вызова send_fcm_push: {}", e))?
                .extract()
                .map_err(|e| format!("Ошибка извлечения результата: {}", e))?;

            if result {
                Ok(())
            } else {
                Err("FCM отправка вернула False".to_string())
            }
        })
    }).await
        .map_err(|e| format!("Ошибка выполнения Python-кода: {}", e))?
        .map_err(|e| format!("Ошибка FCM: {}", e))?;

    Ok(())
}

// ==================== Ключи сессии ====================
#[derive(Clone)]
struct SessionKeys {
    key: [u8; 32],
}

// ==================== Сессия ====================
struct Session {
    tx: mpsc::UnboundedSender<Message>,
    keys: SessionKeys,
    connected: bool,
    user_id: Option<String>,
    username: Option<String>,
    token: Option<String>,
    // Rate limiting
    last_msg_time: Instant,
    msg_count: usize,
}

impl Session {
    fn new(tx: mpsc::UnboundedSender<Message>, keys: SessionKeys) -> Self {
        Self {
            tx,
            keys,
            connected: true,
            user_id: None,
            username: None,
            token: None,
            last_msg_time: Instant::now(),
            msg_count: 0,
        }
    }

    fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        if now - self.last_msg_time > RATE_LIMIT_WINDOW {
            self.last_msg_time = now;
            self.msg_count = 1;
            true
        } else {
            self.msg_count += 1;
            if self.msg_count > RATE_LIMIT_MAX {
                false
            } else {
                true
            }
        }
    }
}

// ==================== Состояние приложения ====================
struct AppState {
    db: Arc<StdMutex<Connection>>,
    sessions: HashMap<String, Arc<Mutex<Session>>>,
    online_users: HashMap<String, Vec<String>>, // username -> список токенов
}

impl AppState {
    fn new(db: Connection) -> Self {
        Self {
            db: Arc::new(StdMutex::new(db)),
            sessions: HashMap::new(),
            online_users: HashMap::new(),
        }
    }

    // ---- Миграция (добавление sent_at и создание fcm_tokens) ----
    fn migrate_db(conn: &mut Connection) -> Result<(), String> {
        // ---- Проверяем messages ----
        let mut stmt = conn
            .prepare("PRAGMA table_info(messages)")
            .map_err(|e| e.to_string())?;
        let mut has_sent_at = false;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| e.to_string())?;
        for name in rows {
            if name.map_err(|e| e.to_string())? == "sent_at" {
                has_sent_at = true;
                break;
            }
        }
        if !has_sent_at {
            conn.execute(
                "ALTER TABLE messages ADD COLUMN sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                [],
            )
                .map_err(|e| e.to_string())?;
            info!("Добавлен столбец sent_at в таблицу messages");
        }

        // ---- Проверяем group_messages ----
        let mut stmt2 = conn
            .prepare("PRAGMA table_info(group_messages)")
            .map_err(|e| e.to_string())?;
        let mut has_sent_at2 = false;
        let rows2 = stmt2
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| e.to_string())?;
        for name in rows2 {
            if name.map_err(|e| e.to_string())? == "sent_at" {
                has_sent_at2 = true;
                break;
            }
        }
        if !has_sent_at2 {
            conn.execute(
                "ALTER TABLE group_messages ADD COLUMN sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                [],
            )
                .map_err(|e| e.to_string())?;
            info!("Добавлен столбец sent_at в таблицу group_messages");
        }

        // ---- Проверяем channel_messages ----
        let mut stmt3 = conn
            .prepare("PRAGMA table_info(channel_messages)")
            .map_err(|e| e.to_string())?;
        let mut has_sent_at3 = false;
        let rows3 = stmt3
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| e.to_string())?;
        for name in rows3 {
            if name.map_err(|e| e.to_string())? == "sent_at" {
                has_sent_at3 = true;
                break;
            }
        }
        if !has_sent_at3 {
            conn.execute(
                "ALTER TABLE channel_messages ADD COLUMN sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                [],
            )
                .map_err(|e| e.to_string())?;
            info!("Добавлен столбец sent_at в таблицу channel_messages");
        }

        // ---- Проверяем fcm_tokens (таблица) ----
        let mut stmt4 = conn
            .prepare("PRAGMA table_info(fcm_tokens)")
            .map_err(|e| e.to_string())?;
        let mut has_fcm = false;
        let rows4 = stmt4
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| e.to_string())?;
        for name in rows4 {
            if name.map_err(|e| e.to_string())? == "token" {
                has_fcm = true;
                break;
            }
        }
        if !has_fcm {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS fcm_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token TEXT NOT NULL,
                device_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, token)
            )",
                [],
            )
                .map_err(|e| e.to_string())?;
            info!("Создана таблица fcm_tokens");
        }

        // ---- Индексы (добавляем для производительности) ----
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_username)",
            [],
        )
            .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_username)",
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

        Ok(())
    }

    fn init_db(conn: &mut Connection) -> Result<(), String> {
        let sql = r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                display_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                device_name TEXT,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender_username TEXT NOT NULL,
                recipient_username TEXT NOT NULL,
                content TEXT NOT NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                creator_username TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
                username TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member')),
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (group_id, username)
            );
            CREATE TABLE IF NOT EXISTS group_messages (
                id TEXT PRIMARY KEY,
                group_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
                sender_username TEXT NOT NULL,
                content TEXT NOT NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                creator_username TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS channel_subscribers (
                channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
                username TEXT NOT NULL,
                subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (channel_id, username)
            );
            CREATE TABLE IF NOT EXISTS channel_messages (
                id TEXT PRIMARY KEY,
                channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
                sender_username TEXT NOT NULL,
                content TEXT NOT NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        "#;
        conn.execute_batch(sql)
            .map_err(|e| format!("Ошибка создания таблиц: {}", e))?;

        // Создаём fcm_tokens и индексы отдельно (если ещё нет)
        Self::migrate_db(conn)?;

        // Индексы (уже есть в migrate, но добавим для надёжности)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_username)",
            [],
        )
            .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_username)",
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

        Ok(())
    }

    // ==================== Методы работы с БД ====================

    // ---- Users ----
    fn register_user(
        conn: &mut Connection,
        username: &str,
        phone: &str,
        password: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
    ) -> Result<String, String> {
        let password_hash = hash(password, DEFAULT_COST).map_err(|e| format!("Ошибка хеширования: {}", e))?;
        let user_id = Uuid::new_v4().to_string();
        let display_name = match (first_name, last_name) {
            (Some(f), Some(l)) => format!("{} {}", f, l),
            (Some(f), None) => f.to_string(),
            _ => username.to_string(),
        };
        let first_name_str = first_name.unwrap_or("");
        let last_name_str = last_name.unwrap_or("");
        conn.execute(
            "INSERT INTO users (id, username, phone, password_hash, first_name, last_name, display_name) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![user_id, username, phone, password_hash, first_name_str, last_name_str, display_name],
        ).map_err(|e| format!("Ошибка регистрации: {}", e))?;
        Ok(user_id)
    }

    fn login_user_by_phone(conn: &mut Connection, phone: &str, password: &str) -> Result<String, String> {
        let mut stmt = conn
            .prepare("SELECT id, password_hash FROM users WHERE phone = ?")
            .map_err(|e| format!("Ошибка запроса: {}", e))?;
        let mut rows = stmt.query([phone]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let user_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            let hash: String = row.get(1).map_err(|e| format!("Ошибка чтения hash: {}", e))?;
            if verify(password, &hash).map_err(|e| format!("Ошибка проверки пароля: {}", e))? {
                return Ok(user_id);
            }
        }
        Err("Неверный телефон или пароль".to_string())
    }

    fn create_session(conn: &mut Connection, user_id: &str, device_name: &str) -> Result<String, String> {
        let token = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO sessions (token, user_id, device_name, last_seen) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            params![token, user_id, device_name],
        ).map_err(|e| format!("Ошибка создания сессии: {}", e))?;
        Ok(token)
    }

    fn check_session(conn: &mut Connection, token: &str) -> Result<(String, String), String> {
        let mut stmt = conn
            .prepare("SELECT user_id, username FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.token = ?")
            .map_err(|e| format!("Ошибка подготовки: {}", e))?;
        let mut rows = stmt.query([token]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let user_id: String = row.get(0).map_err(|e| format!("Ошибка чтения user_id: {}", e))?;
            let username: String = row.get(1).map_err(|e| format!("Ошибка чтения username: {}", e))?;
            conn.execute("UPDATE sessions SET last_seen = CURRENT_TIMESTAMP WHERE token = ?", [token])
                .map_err(|e| format!("Ошибка обновления last_seen: {}", e))?;
            Ok((user_id, username))
        } else {
            Err("Недействительный токен".to_string())
        }
    }

    fn delete_session(conn: &mut Connection, token: &str) -> Result<(), String> {
        conn.execute("DELETE FROM sessions WHERE token = ?", [token])
            .map_err(|e| format!("Ошибка удаления сессии: {}", e))?;
        Ok(())
    }

    fn user_exists_by_username(conn: &mut Connection, username: &str) -> Result<bool, String> {
        let mut stmt = conn
            .prepare("SELECT 1 FROM users WHERE username = ?")
            .map_err(|e| format!("Ошибка запроса: {}", e))?;
        let mut rows = stmt.query([username]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        Ok(rows.next().map_err(|e| format!("Ошибка чтения: {}", e))?.is_some())
    }

    // ---- Сохранение FCM-токена ----
    fn save_fcm_token(conn: &mut Connection, user_id: &str, token: &str, device_name: &str) -> Result<(), String> {
        conn.execute(
            "INSERT OR REPLACE INTO fcm_tokens (user_id, token, device_name) VALUES (?, ?, ?)",
            params![user_id, token, device_name],
        ).map_err(|e| format!("Ошибка сохранения FCM-токена: {}", e))?;
        Ok(())
    }

    fn get_fcm_tokens_for_user(conn: &mut Connection, username: &str) -> Result<Vec<String>, String> {
        let mut stmt = conn
            .prepare("SELECT token FROM fcm_tokens WHERE user_id = (SELECT id FROM users WHERE username = ?)")
            .map_err(|e| format!("Ошибка запроса FCM: {}", e))?;
        let mut rows = stmt.query([username]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        let mut tokens = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let token: String = row.get(0).map_err(|e| format!("Ошибка чтения токена: {}", e))?;
            tokens.push(token);
        }
        Ok(tokens)
    }

    // ---- Сообщения с пагинацией ----
    fn store_message(conn: &mut Connection, sender: &str, recipient: &str, content: &str, timestamp: i64) -> Result<(), String> {
        let msg_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO messages (id, sender_username, recipient_username, content, sent_at) VALUES (?, ?, ?, ?, datetime(?/1000, 'unixepoch'))",
            params![msg_id, sender, recipient, content, &timestamp],
        ).map_err(|e| format!("Ошибка сохранения сообщения: {}", e))?;
        Ok(())
    }

    fn get_user_messages(
        conn: &mut Connection,
        username: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<(String, String, String, i64)>, String> {
        let mut stmt = conn.prepare(
            "SELECT sender_username, recipient_username, content, strftime('%s', sent_at) * 1000
             FROM messages
             WHERE sender_username = ? OR recipient_username = ?
             ORDER BY sent_at ASC
             LIMIT ? OFFSET ?"
        ).map_err(|e| format!("Ошибка подготовки: {}", e))?;
        let mut rows = stmt.query(params![username, username, limit, offset])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let sender: String = row.get(0).map_err(|e| format!("Ошибка чтения sender: {}", e))?;
            let recipient: String = row.get(1).map_err(|e| format!("Ошибка чтения recipient: {}", e))?;
            let content: String = row.get(2).map_err(|e| format!("Ошибка чтения content: {}", e))?;
            let timestamp: i64 = row.get(3).map_err(|e| format!("Ошибка чтения timestamp: {}", e))?;
            result.push((sender, recipient, content, timestamp));
        }
        Ok(result)
    }

    // ---- Группы с пагинацией ----
    fn create_group(conn: &mut Connection, name: &str, creator: &str) -> Result<(), String> {
        let group_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO groups (id, name, creator_username) VALUES (?, ?, ?)",
            params![group_id, name, creator],
        ).map_err(|e| format!("Ошибка создания группы: {}", e))?;
        conn.execute(
            "INSERT INTO group_members (group_id, username, role) VALUES (?, ?, 'owner')",
            params![group_id, creator],
        ).map_err(|e| format!("Ошибка добавления создателя в группу: {}", e))?;
        Ok(())
    }

    fn join_group(conn: &mut Connection, group_name: &str, username: &str) -> Result<(), String> {
        let mut stmt = conn.prepare("SELECT id FROM groups WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса группы: {}", e))?;
        let mut rows = stmt.query([group_name]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let group_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            conn.execute(
                "INSERT OR IGNORE INTO group_members (group_id, username, role) VALUES (?, ?, 'member')",
                params![group_id, username],
            ).map_err(|e| format!("Ошибка присоединения к группе: {}", e))?;
            Ok(())
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    fn leave_group(conn: &mut Connection, group_name: &str, username: &str) -> Result<(), String> {
        let mut stmt = conn.prepare("SELECT id FROM groups WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса группы: {}", e))?;
        let mut rows = stmt.query([group_name]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let group_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            conn.execute(
                "DELETE FROM group_members WHERE group_id = ? AND username = ?",
                params![group_id, username],
            ).map_err(|e| format!("Ошибка выхода из группы: {}", e))?;
            Ok(())
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    fn get_group_members(conn: &mut Connection, group_name: &str) -> Result<Vec<String>, String> {
        let mut stmt = conn.prepare(
            "SELECT gm.username FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE g.name = ?"
        ).map_err(|e| format!("Ошибка запроса участников: {}", e))?;
        let mut rows = stmt.query([group_name]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        let mut members = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let username: String = row.get(0).map_err(|e| format!("Ошибка чтения username: {}", e))?;
            members.push(username);
        }
        Ok(members)
    }

    fn store_group_message(conn: &mut Connection, group_name: &str, sender: &str, content: &str, timestamp: i64) -> Result<(), String> {
        let mut stmt = conn.prepare("SELECT id FROM groups WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса группы: {}", e))?;
        let mut rows = stmt.query([group_name]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let group_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            let msg_id = Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO group_messages (id, group_id, sender_username, content, sent_at) VALUES (?, ?, ?, ?, datetime(?/1000, 'unixepoch'))",
                params![msg_id, group_id, sender, content, &timestamp],
            ).map_err(|e| format!("Ошибка сохранения группового сообщения: {}", e))?;
            Ok(())
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    fn get_group_messages(
        conn: &mut Connection,
        group_name: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<(String, String, i64)>, String> {
        let mut stmt = conn.prepare(
            "SELECT gm.sender_username, gm.content, strftime('%s', gm.sent_at) * 1000
             FROM group_messages gm JOIN groups g ON gm.group_id = g.id
             WHERE g.name = ?
             ORDER BY gm.sent_at ASC
             LIMIT ? OFFSET ?"
        ).map_err(|e| format!("Ошибка подготовки: {}", e))?;
        let mut rows = stmt.query(params![group_name, limit, offset])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let sender: String = row.get(0).map_err(|e| format!("Ошибка чтения sender: {}", e))?;
            let content: String = row.get(1).map_err(|e| format!("Ошибка чтения content: {}", e))?;
            let timestamp: i64 = row.get(2).map_err(|e| format!("Ошибка чтения timestamp: {}", e))?;
            result.push((sender, content, timestamp));
        }
        Ok(result)
    }

    // ---- Каналы с пагинацией ----
    fn create_channel(conn: &mut Connection, name: &str, creator: &str) -> Result<(), String> {
        let channel_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO channels (id, name, creator_username) VALUES (?, ?, ?)",
            params![channel_id, name, creator],
        ).map_err(|e| format!("Ошибка создания канала: {}", e))?;
        conn.execute(
            "INSERT INTO channel_subscribers (channel_id, username) VALUES (?, ?)",
            params![channel_id, creator],
        ).map_err(|e| format!("Ошибка подписки создателя: {}", e))?;
        Ok(())
    }

    fn subscribe_channel(conn: &mut Connection, channel_name: &str, username: &str) -> Result<(), String> {
        let mut stmt = conn.prepare("SELECT id FROM channels WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса канала: {}", e))?;
        let mut rows = stmt.query([channel_name]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let channel_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            conn.execute(
                "INSERT OR IGNORE INTO channel_subscribers (channel_id, username) VALUES (?, ?)",
                params![channel_id, username],
            ).map_err(|e| format!("Ошибка подписки: {}", e))?;
            Ok(())
        } else {
            Err("Канал не найден".to_string())
        }
    }

    fn unsubscribe_channel(conn: &mut Connection, channel_name: &str, username: &str) -> Result<(), String> {
        let mut stmt = conn.prepare("SELECT id FROM channels WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса канала: {}", e))?;
        let mut rows = stmt.query([channel_name]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let channel_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            conn.execute(
                "DELETE FROM channel_subscribers WHERE channel_id = ? AND username = ?",
                params![channel_id, username],
            ).map_err(|e| format!("Ошибка отписки: {}", e))?;
            Ok(())
        } else {
            Err("Канал не найден".to_string())
        }
    }

    fn get_channel_subscribers(conn: &mut Connection, channel_name: &str) -> Result<Vec<String>, String> {
        let mut stmt = conn.prepare(
            "SELECT cs.username FROM channel_subscribers cs JOIN channels c ON cs.channel_id = c.id WHERE c.name = ?"
        ).map_err(|e| format!("Ошибка запроса подписчиков: {}", e))?;
        let mut rows = stmt.query([channel_name]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        let mut subscribers = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let username: String = row.get(0).map_err(|e| format!("Ошибка чтения username: {}", e))?;
            subscribers.push(username);
        }
        Ok(subscribers)
    }

    fn store_channel_message(conn: &mut Connection, channel_name: &str, sender: &str, content: &str, timestamp: i64) -> Result<(), String> {
        let mut stmt = conn.prepare("SELECT id FROM channels WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса канала: {}", e))?;
        let mut rows = stmt.query([channel_name]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let channel_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            let msg_id = Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO channel_messages (id, channel_id, sender_username, content, sent_at) VALUES (?, ?, ?, ?, datetime(?/1000, 'unixepoch'))",
                params![msg_id, channel_id, sender, content, &timestamp],
            ).map_err(|e| format!("Ошибка сохранения сообщения канала: {}", e))?;
            Ok(())
        } else {
            Err("Канал не найден".to_string())
        }
    }

    fn get_channel_messages(
        conn: &mut Connection,
        channel_name: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<(String, String, i64)>, String> {
        let mut stmt = conn.prepare(
            "SELECT cm.sender_username, cm.content, strftime('%s', cm.sent_at) * 1000
             FROM channel_messages cm JOIN channels c ON cm.channel_id = c.id
             WHERE c.name = ?
             ORDER BY cm.sent_at ASC
             LIMIT ? OFFSET ?"
        ).map_err(|e| format!("Ошибка подготовки: {}", e))?;
        let mut rows = stmt.query(params![channel_name, limit, offset])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let sender: String = row.get(0).map_err(|e| format!("Ошибка чтения sender: {}", e))?;
            let content: String = row.get(1).map_err(|e| format!("Ошибка чтения content: {}", e))?;
            let timestamp: i64 = row.get(2).map_err(|e| format!("Ошибка чтения timestamp: {}", e))?;
            result.push((sender, content, timestamp));
        }
        Ok(result)
    }

    // ---- Профиль ----
    fn get_profile(conn: &mut Connection, username: &str) -> Result<(String, String, String, String, String), String> {
        let mut stmt = conn.prepare("SELECT username, phone, first_name, last_name, display_name FROM users WHERE username = ?")
            .map_err(|e| format!("Ошибка подготовки запроса: {}", e))?;
        let mut rows = stmt.query([username]).map_err(|e| format!("Ошибка выполнения запроса: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения результата: {}", e))? {
            let username: String = row.get(0).map_err(|e| format!("Ошибка чтения username: {}", e))?;
            let phone: String = row.get(1).map_err(|e| format!("Ошибка чтения phone: {}", e))?;
            let first_name: String = row.get(2).map_err(|e| format!("Ошибка чтения first_name: {}", e))?;
            let last_name: String = row.get(3).map_err(|e| format!("Ошибка чтения last_name: {}", e))?;
            let display_name: String = row.get(4).map_err(|e| format!("Ошибка чтения display_name: {}", e))?;
            Ok((username, phone, first_name, last_name, display_name))
        } else {
            Err("Пользователь не найден".to_string())
        }
    }

    fn set_name(conn: &mut Connection, username: &str, first_name: &str, last_name: &str) -> Result<(), String> {
        let display_name = if last_name.is_empty() {
            first_name.to_string()
        } else {
            format!("{} {}", first_name, last_name)
        };
        conn.execute(
            "UPDATE users SET first_name = ?, last_name = ?, display_name = ? WHERE username = ?",
            params![first_name, last_name, display_name, username],
        ).map_err(|e| format!("Ошибка обновления имени: {}", e))?;
        Ok(())
    }

    fn set_display_name(conn: &mut Connection, username: &str, display_name: &str) -> Result<(), String> {
        conn.execute(
            "UPDATE users SET display_name = ? WHERE username = ?",
            params![display_name, username],
        ).map_err(|e| format!("Ошибка обновления отображаемого имени: {}", e))?;
        Ok(())
    }

    fn set_username(conn: &mut Connection, old_username: &str, new_username: &str) -> Result<(), String> {
        let mut stmt = conn.prepare("SELECT 1 FROM users WHERE username = ?")
            .map_err(|e| format!("Ошибка подготовки запроса: {}", e))?;
        let mut rows = stmt.query([new_username]).map_err(|e| format!("Ошибка выполнения запроса: {}", e))?;
        if rows.next().map_err(|e| format!("Ошибка чтения: {}", e))?.is_some() {
            return Err("Username уже занят".to_string());
        }
        let mut stmt2 = conn.prepare("SELECT 1 FROM users WHERE username = ?")
            .map_err(|e| format!("Ошибка подготовки запроса: {}", e))?;
        let mut rows2 = stmt2.query([old_username]).map_err(|e| format!("Ошибка выполнения запроса: {}", e))?;
        if rows2.next().map_err(|e| format!("Ошибка чтения: {}", e))?.is_none() {
            return Err("Пользователь не найден".to_string());
        }
        conn.execute(
            "UPDATE users SET username = ? WHERE username = ?",
            params![new_username, old_username],
        ).map_err(|e| format!("Ошибка обновления username: {}", e))?;
        Ok(())
    }
}

// ==================== Handshake ====================
async fn ws_handshake(stream: &mut tokio_tungstenite::WebSocketStream<TcpStream>) -> Result<SessionKeys, String> {
    info!("Handshake: ожидание первого сообщения");
    let msg = stream
        .next()
        .await
        .ok_or("No message received")?
        .map_err(|e| format!("WebSocket error: {}", e))?;
    let data = match msg {
        Message::Binary(d) => d,
        Message::Text(t) => {
            warn!("Handshake: получен текст вместо бинарных данных: {}", t);
            return Err("Expected binary".to_string());
        }
        _ => return Err("Expected binary".to_string()),
    };
    if data.len() != 32 {
        return Err(format!("Invalid public key length: {}", data.len()));
    }
    let client_key: [u8; 32] = data
        .to_vec()
        .try_into()
        .map_err(|_| "Invalid key array")?;
    info!("Handshake: получен публичный ключ клиента");

    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    stream
        .send(Message::Binary(public.as_bytes().to_vec().into()))
        .await
        .map_err(|e| format!("Failed to send public key: {}", e))?;
    info!("Handshake: отправлен публичный ключ сервера");

    let peer_public = PublicKey::from(client_key);
    let shared = secret.diffie_hellman(&peer_public);
    let shared_bytes = shared.to_bytes();

    let hk = Hkdf::<Sha256>::new(None, &shared_bytes);
    let mut derived = [0u8; 32];
    hk.expand(b"relay-server", &mut derived)
        .map_err(|e| format!("HKDF error: {}", e))?;
    let key = derived;
    info!("Handshake: успешно завершён");
    debug!("Handshake: ключ сессии = {}", hex::encode(&key)); // <-- добавить
    Ok(SessionKeys { key })
}

// ==================== Вспомогательные функции отправки ====================
async fn send_system_message(tx: &mpsc::UnboundedSender<Message>, text: &str) -> Result<(), String> {
    let bytes = text.as_bytes();
    let mut data = Vec::with_capacity(1 + 4 + bytes.len());
    data.push(MSG_TYPE_SYSTEM);
    data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(bytes);
    tx.send(Message::Binary(data.into()))
        .map_err(|e| format!("send error: {}", e))
}

async fn send_encrypted_message(
    tx: &mpsc::UnboundedSender<Message>,
    keys: &SessionKeys,
    sender_id: &str,
    recipient_id: &str,
    plaintext: &[u8],
    timestamp: i64,
) -> Result<(), String> {
    if plaintext.len() > MAX_MESSAGE_SIZE {
        return Err("Message too large".to_string());
    }
    let key = Key::<Aes256Gcm>::from_slice(&keys.key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("encryption error: {}", e))?;

    let mut data = Vec::new();
    data.push(MSG_TYPE_USER);
    let sender_bytes = sender_id.as_bytes();
    data.extend_from_slice(&(sender_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(sender_bytes);
    let recipient_bytes = recipient_id.as_bytes();
    data.extend_from_slice(&(recipient_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(recipient_bytes);
    data.extend_from_slice(&nonce); // 12 байт
    data.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    data.extend_from_slice(&encrypted);
    data.extend_from_slice(&timestamp.to_be_bytes());

    tx.send(Message::Binary(data.into()))
        .map_err(|e| format!("send error: {}", e))
}

async fn broadcast_system_message(state: &Arc<Mutex<AppState>>, message: &str, exclude_username: Option<&str>) {
    let state_guard = state.lock().await;
    for (_, session) in &state_guard.sessions {
        let (connected, tx, username) = {
            let guard = session.lock().await;
            (
                guard.connected,
                guard.tx.clone(),
                guard.username.clone(),
            )
        };
        if connected {
            if let Some(uname) = username {
                if Some(uname.as_str()) == exclude_username {
                    continue;
                }
            }
            let _ = send_system_message(&tx, message).await;
        }
    }
}

// ==================== Обработчик клиента ====================
async fn handle_client(stream: TcpStream, state: Arc<Mutex<AppState>>) {
    let start_time = Instant::now();
    info!("Принято TCP-соединение от {:?}", stream.peer_addr().ok());

    let ws_result = accept_async(stream).await;
    let mut ws_stream = match ws_result {
        Ok(ws) => {
            info!("WebSocket-соединение успешно установлено");
            ws
        }
        Err(e) => {
            error!("WebSocket accept error: {}", e);
            return;
        }
    };

    let keys = match ws_handshake(&mut ws_stream).await {
        Ok(k) => k,
        Err(e) => {
            error!("Handshake error: {}", e);
            return;
        }
    };

    let (mut sink, mut stream) = ws_stream.split();

    let (tx, mut rx) = mpsc::unbounded_channel();
    let session = Arc::new(Mutex::new(Session::new(tx.clone(), keys.clone())));
    let temp_id = Uuid::new_v4().to_string();

    {
        let mut state_guard = state.lock().await;
        state_guard.sessions.insert(temp_id.clone(), session.clone());
        info!("Временная сессия создана: {}", temp_id);
    }

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = sink.send(msg).await {
                error!("Ошибка отправки: {}", e);
                break;
            }
        }
        info!("Задача отправки завершена");
    });

    // ---- Аутентификация ----
    let auth_data = match stream.next().await {
        Some(Ok(Message::Binary(data))) => data,
        Some(Ok(_)) => {
            error!("Ожидался бинарный пакет аутентификации, получен другой тип сообщения");
            let _ = send_task.await;
            return;
        }
        Some(Err(e)) => {
            error!("Ошибка чтения аутентификации: {}", e);
            let _ = send_task.await;
            return;
        }
        None => {
            error!("Соединение закрыто до аутентификации");
            let _ = send_task.await;
            return;
        }
    };

    if auth_data.is_empty() || auth_data[0] != MSG_TYPE_AUTH {
        error!("Ожидался MSG_TYPE_AUTH, получено {:?}", auth_data.first());
        let _ = send_task.await;
        return;
    }

    let auth_str = String::from_utf8(auth_data[5..].to_vec()).unwrap_or_default();
    info!("Auth string: {}", auth_str);
    let parts: Vec<&str> = auth_str.split('|').collect();
    if parts.len() < 3 {
        error!("Неверный формат аутентификации");
        let _ = send_task.await;
        return;
    }

    let command = parts[0];
    let phone = parts[1].trim().to_string();
    let password = parts[2].trim().to_string();

    // Извлекаем FCM-токен, если есть (последний параметр)
    let fcm_token = if parts.len() > 4 {
        Some(parts[parts.len() - 1].trim().to_string())
    } else {
        None
    };

    // ---- Обработка аутентификации ----
    let auth_result = match command {
        "token" => {
            if parts.len() < 3 {
                error!("Неверный формат token");
                let _ = send_task.await;
                return;
            }
            let token = parts[1].trim();
            let device_name = if parts.len() > 3 {
                parts[2].trim().to_string()
            } else {
                "unknown".to_string()
            };

            let db = state.lock().await.db.clone();
            let token_str = token.to_string();
            let result = tokio::task::spawn_blocking(move || {
                let mut conn = db.lock().unwrap();
                AppState::check_session(&mut conn, &token_str)
            })
                .await
                .unwrap();

            match result {
                Ok((user_id, username)) => {
                    info!("Восстановлена сессия: user_id={}, username={}", user_id, username);
                    let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                    let _ = send_system_message(&tx, &msg).await;

                    // Сохраняем FCM-токен
                    if let Some(fcm) = fcm_token {
                        let db = state.lock().await.db.clone();
                        let uid = user_id.clone();
                        let fcm_tok = fcm.clone();
                        let dev = device_name.clone();
                        tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            let _ = AppState::save_fcm_token(&mut conn, &uid, &fcm_tok, &dev);
                        })
                            .await
                            .unwrap();
                    }

                    // Обновляем сессию
                    {
                        let mut guard = session.lock().await;
                        guard.user_id = Some(user_id.clone());
                        guard.username = Some(username.clone());
                        guard.token = Some(token.to_string());
                    }
                    {
                        let mut state_guard = state.lock().await;
                        state_guard.sessions.remove(&temp_id);
                        state_guard.sessions.insert(token.to_string(), session.clone());
                        state_guard
                            .online_users
                            .entry(username.clone())
                            .or_insert_with(Vec::new)
                            .push(token.to_string());
                    }
                    let msg = format!("[Система] Пользователь {} подключился", username);
                    broadcast_system_message(&state, &msg, Some(&username)).await;
                    Ok((user_id, username))
                }
                Err(e) => {
                    error!("Ошибка восстановления сессии: {}", e);
                    let _ = send_system_message(&tx, &format!("[Система] Ошибка: {}", e)).await;
                    Err(())
                }
            }
        }
        "login" => {
            let device_name = if parts.len() > 4 {
                parts[3].trim().to_string()
            } else {
                "unknown".to_string()
            };

            let db = state.lock().await.db.clone();
            let ph = phone.clone();
            let pwd = password.clone();
            let result = tokio::task::spawn_blocking(move || {
                let mut conn = db.lock().unwrap();
                AppState::login_user_by_phone(&mut conn, &ph, &pwd)
            })
                .await
                .unwrap();

            match result {
                Ok(user_id) => {
                    info!("Аутентификация успешна для user_id={}", user_id);
                    // Получаем username
                    let db3 = state.lock().await.db.clone();
                    let uid = user_id.clone();
                    let username_from_db = tokio::task::spawn_blocking(move || {
                        let mut conn = db3.lock().unwrap();
                        let mut stmt = conn
                            .prepare("SELECT username FROM users WHERE id = ?")
                            .map_err(|e| e.to_string())?;
                        let mut rows = stmt.query([&uid]).map_err(|e| e.to_string())?;
                        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
                            let username: String = row.get(0).map_err(|e| e.to_string())?;
                            Ok(username)
                        } else {
                            Err("Пользователь не найден".to_string())
                        }
                    })
                        .await
                        .unwrap();
                    let username = match username_from_db {
                        Ok(uname) => uname,
                        Err(_) => phone.clone(),
                    };

                    // Создаём сессию
                    let db2 = state.lock().await.db.clone();
                    let uid2 = user_id.clone();
                    let dev = device_name.clone();
                    let token_result = tokio::task::spawn_blocking(move || {
                        let mut conn = db2.lock().unwrap();
                        AppState::create_session(&mut conn, &uid2, &dev)
                    })
                        .await
                        .unwrap();

                    match token_result {
                        Ok(token) => {
                            info!("Сессия создана, токен: {}", token);
                            let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                            let _ = send_system_message(&tx, &msg).await;

                            // Сохраняем FCM-токен
                            if let Some(fcm) = fcm_token {
                                let db = state.lock().await.db.clone();
                                let uid = user_id.clone();
                                let fcm_tok = fcm.clone();
                                let dev = device_name.clone();
                                tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    let _ = AppState::save_fcm_token(&mut conn, &uid, &fcm_tok, &dev);
                                })
                                    .await
                                    .unwrap();
                            }

                            {
                                let mut guard = session.lock().await;
                                guard.user_id = Some(user_id.clone());
                                guard.username = Some(username.clone());
                                guard.token = Some(token.clone());
                            }
                            {
                                let mut state_guard = state.lock().await;
                                state_guard.sessions.remove(&temp_id);
                                state_guard.sessions.insert(token.clone(), session.clone());
                                state_guard
                                    .online_users
                                    .entry(username.clone())
                                    .or_insert_with(Vec::new)
                                    .push(token.clone());
                            }
                            let msg = format!("[Система] Пользователь {} подключился", username);
                            broadcast_system_message(&state, &msg, Some(&username)).await;
                            Ok((user_id, username))
                        }
                        Err(e) => {
                            error!("Ошибка создания сессии: {}", e);
                            let _ = send_system_message(&tx, &format!("[Система] Ошибка создания сессии: {}", e))
                                .await;
                            Err(())
                        }
                    }
                }
                Err(e) => {
                    error!("Ошибка логина: {}", e);
                    let _ = send_system_message(&tx, &format!("[Система] Ошибка: {}", e)).await;
                    Err(())
                }
            }
        }
        "register" => {
            let first_name = if parts.len() > 3 { Some(parts[3].trim()) } else { None };
            let last_name = if parts.len() > 4 { Some(parts[4].trim()) } else { None };
            let username = if parts.len() > 5 && !parts[5].trim().is_empty() {
                parts[5].trim().to_string()
            } else {
                phone.clone()
            };
            let device_name = if parts.len() > 6 {
                parts[6].trim().to_string()
            } else {
                "unknown".to_string()
            };
            // FCM-токен будет в parts[7] если есть

            let db = state.lock().await.db.clone();
            let ph = phone.clone();
            let pwd = password.clone();
            let uname = username.clone();
            let fn_opt = first_name.map(|s| s.to_string());
            let ln_opt = last_name.map(|s| s.to_string());

            let result = tokio::task::spawn_blocking(move || {
                let mut conn = db.lock().unwrap();
                AppState::register_user(
                    &mut conn,
                    &uname,
                    &ph,
                    &pwd,
                    fn_opt.as_deref(),
                    ln_opt.as_deref(),
                )
            })
                .await
                .unwrap();

            match result {
                Ok(user_id) => {
                    info!("Регистрация успешна для user_id={}", user_id);
                    let db2 = state.lock().await.db.clone();
                    let uid = user_id.clone();
                    let dev = device_name.clone();
                    let token_result = tokio::task::spawn_blocking(move || {
                        let mut conn = db2.lock().unwrap();
                        AppState::create_session(&mut conn, &uid, &dev)
                    })
                        .await
                        .unwrap();

                    match token_result {
                        Ok(token) => {
                            info!("Сессия создана, токен: {}", token);
                            let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                            let _ = send_system_message(&tx, &msg).await;

                            if let Some(fcm) = fcm_token {
                                let db = state.lock().await.db.clone();
                                let uid = user_id.clone();
                                let fcm_tok = fcm.clone();
                                let dev = device_name.clone();
                                tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    let _ = AppState::save_fcm_token(&mut conn, &uid, &fcm_tok, &dev);
                                })
                                    .await
                                    .unwrap();
                            }

                            {
                                let mut guard = session.lock().await;
                                guard.user_id = Some(user_id.clone());
                                guard.username = Some(username.clone());
                                guard.token = Some(token.clone());
                            }
                            {
                                let mut state_guard = state.lock().await;
                                state_guard.sessions.remove(&temp_id);
                                state_guard.sessions.insert(token.clone(), session.clone());
                                state_guard
                                    .online_users
                                    .entry(username.clone())
                                    .or_insert_with(Vec::new)
                                    .push(token.clone());
                            }
                            let msg = format!("[Система] Пользователь {} подключился", username);
                            broadcast_system_message(&state, &msg, Some(&username)).await;
                            Ok((user_id, username))
                        }
                        Err(e) => {
                            error!("Ошибка создания сессии: {}", e);
                            let _ = send_system_message(&tx, &format!("[Система] Ошибка создания сессии: {}", e))
                                .await;
                            Err(())
                        }
                    }
                }
                Err(e) => {
                    error!("Ошибка регистрации: {}", e);
                    let _ = send_system_message(&tx, &format!("[Система] Ошибка: {}", e)).await;
                    Err(())
                }
            }
        }
        _ => {
            error!("Неизвестная команда: {}", command);
            let _ = send_system_message(&tx, &format!("[Система] Ошибка: Неизвестная команда {}", command)).await;
            Err(())
        }
    };

    // Если аутентификация не удалась – завершаем
    let (my_user_id, my_username) = match auth_result {
        Ok((uid, uname)) => (uid, uname),
        Err(_) => {
            let _ = send_task.await;
            return;
        }
    };

    // ---- Загрузка истории (первая страница, limit=100, offset=0) ----
    let username_clone = my_username.clone();
    if !username_clone.is_empty() {
        // Личные сообщения
        let db = state.lock().await.db.clone();
        let uname = username_clone.clone();
        let history = tokio::task::spawn_blocking(move || {
            let mut conn = db.lock().unwrap();
            AppState::get_user_messages(&mut conn, &uname, HISTORY_LIMIT, 0)
        })
            .await
            .unwrap();

        if let Ok(msgs) = history {
            let tx = {
                let guard = session.lock().await;
                guard.tx.clone()
            };
            let keys = {
                let guard = session.lock().await;
                guard.keys.clone()
            };
            info!("Загружено {} личных сообщений", msgs.len());
            for (sender, recipient, content, timestamp) in msgs {
                let _ = send_encrypted_message(&tx, &keys, &sender, &recipient, content.as_bytes(), timestamp).await;
            }
        }

        // Групповые сообщения
        let db2 = state.lock().await.db.clone();
        let uname2 = username_clone.clone();
        let groups_history = tokio::task::spawn_blocking(move || {
            let mut conn = db2.lock().unwrap();
            let mut group_names: Vec<String> = Vec::new();
            {
                let mut stmt = conn
                    .prepare("SELECT g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.username = ?")
                    .map_err(|e| e.to_string())?;
                let mut rows = stmt.query([&uname2]).map_err(|e| e.to_string())?;
                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                    let name: String = row.get(0).map_err(|e| e.to_string())?;
                    group_names.push(name);
                }
            }
            let mut all_msgs = Vec::new();
            for gname in &group_names {
                let msgs = AppState::get_group_messages(&mut conn, gname, HISTORY_LIMIT, 0)?;
                for (sender, content, timestamp) in msgs {
                    all_msgs.push((sender, content, gname.clone(), timestamp));
                }
            }
            Ok::<_, String>(all_msgs)
        })
            .await
            .unwrap();

        if let Ok(msgs) = groups_history {
            let tx = {
                let guard = session.lock().await;
                guard.tx.clone()
            };
            let keys = {
                let guard = session.lock().await;
                guard.keys.clone()
            };
            info!("Загружено {} групповых сообщений", msgs.len());
            for (sender, content, gname, timestamp) in msgs {
                let recipient = format!("#{}", gname);
                let _ = send_encrypted_message(&tx, &keys, &sender, &recipient, content.as_bytes(), timestamp).await;
            }
        }

        // Канальные сообщения
        let db3 = state.lock().await.db.clone();
        let uname3 = username_clone.clone();
        let channels_history = tokio::task::spawn_blocking(move || {
            let mut conn = db3.lock().unwrap();
            let mut channel_names: Vec<String> = Vec::new();
            {
                let mut stmt = conn
                    .prepare("SELECT c.name FROM channels c JOIN channel_subscribers cs ON c.id = cs.channel_id WHERE cs.username = ?")
                    .map_err(|e| e.to_string())?;
                let mut rows = stmt.query([&uname3]).map_err(|e| e.to_string())?;
                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                    let name: String = row.get(0).map_err(|e| e.to_string())?;
                    channel_names.push(name);
                }
            }
            let mut all_msgs = Vec::new();
            for ch_name in &channel_names {
                let msgs = AppState::get_channel_messages(&mut conn, ch_name, HISTORY_LIMIT, 0)?;
                for (sender, content, timestamp) in msgs {
                    all_msgs.push((sender, content, ch_name.clone(), timestamp));
                }
            }
            Ok::<_, String>(all_msgs)
        })
            .await
            .unwrap();

        if let Ok(msgs) = channels_history {
            let tx = {
                let guard = session.lock().await;
                guard.tx.clone()
            };
            let keys = {
                let guard = session.lock().await;
                guard.keys.clone()
            };
            info!("Загружено {} канальных сообщений", msgs.len());
            for (sender, content, ch_name, timestamp) in msgs {
                let recipient = format!("&{}", ch_name);
                let _ = send_encrypted_message(&tx, &keys, &sender, &recipient, content.as_bytes(), timestamp).await;
            }
        }
    }

    // ---- Основной цикл обработки сообщений ----
    info!("Начало основного цикла для {}", my_username);
    loop {
        // Проверяем, не закрыто ли соединение
        if !session.lock().await.connected {
            break;
        }

        let msg = match stream.next().await {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => {
                error!("Ошибка чтения: {}", e);
                break;
            }
            None => break,
        };

        if let Message::Binary(data) = msg {
            if data.is_empty() {
                continue;
            }

            // Rate limiting
            {
                let mut guard = session.lock().await;
                if !guard.check_rate_limit() {
                    let _ = send_system_message(&guard.tx, "[Система] Слишком много сообщений, подождите").await;
                    continue;
                }
            }

            let msg_type = data[0];
            let rest = &data[1..];

            match msg_type {
                MSG_TYPE_USER => {
                    let mut offset = 0;
                    let sender_len = u32::from_be_bytes(rest[offset..offset+4].try_into().unwrap()) as usize;
                    offset += 4;
                    let sender = String::from_utf8(rest[offset..offset+sender_len].to_vec()).unwrap_or_default();
                    offset += sender_len;

                    let recipient_len = u32::from_be_bytes(rest[offset..offset+4].try_into().unwrap()) as usize;
                    offset += 4;
                    let recipient = String::from_utf8(rest[offset..offset+recipient_len].to_vec()).unwrap_or_default();
                    offset += recipient_len;

                    // Читаем nonce (12 байт)
                    let nonce = &rest[offset..offset+12];
                    info!("nonce (hex) = {}", hex::encode(nonce));
                    offset += 12;

                    let msg_len = u32::from_be_bytes(rest[offset..offset+4].try_into().unwrap()) as usize;
                    info!("encrypted len = {}", msg_len-12);
                    offset += 4;
                    debug!("{}", rest.len()-offset);
                    debug!("offset: {:#?}, next 4 bytes: {:#?}", offset, hex::encode(&rest[offset..offset+4]));
                    let encrypted = &rest[offset..offset+msg_len];
                    info!("encrypted (hex) = {}", hex::encode(encrypted));
                    offset += msg_len;

                    // timestamp
                    let timestamp = if rest.len() >= offset + 8 {
                        i64::from_be_bytes(rest[offset..offset+8].try_into().unwrap())
                    } else {
                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
                    };

                    // Расшифровка
                    let key = &keys.key;
                    info!("Ключ для расшифровки (hex) = {}", hex::encode(key));

                    use aes_gcm::aead::{Aead, KeyInit};
                    let cipher = aes_gcm::Aes256Gcm::new(Key::<aes_gcm::Aes256Gcm>::from_slice(key));
                    let nonce = aes_gcm::Nonce::from_slice(nonce); // ← убедитесь, что Nonce из 12 байт

                    let plaintext = match cipher.decrypt(nonce, encrypted) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Ошибка расшифровки: {}", e);
                            // Дополнительная диагностика
                            error!("Ключ: {}", hex::encode(key));
                            error!("Nonce: {}", hex::encode(nonce));
                            error!("Зашифровано: {}", hex::encode(encrypted));
                            continue;
                        }
                    };
                    let content = String::from_utf8_lossy(&plaintext).to_string();
                    info!("Сообщение от {} для {}: {}", sender, recipient, content);

                    // ---- Обработка команд ----
                    if content.starts_with('/') {
                        let cmd_parts: Vec<&str> = content.split_whitespace().collect();
                        if cmd_parts.is_empty() {
                            continue;
                        }
                        let cmd = cmd_parts[0];
                        let args = &cmd_parts[1..];
                        let response = match cmd {
                            "/creategroup" => {
                                if args.is_empty() {
                                    "[Система] Использование: /creategroup <название>".to_string()
                                } else {
                                    let group_name = args.join(" ");
                                    let db = state.lock().await.db.clone();
                                    let uname = my_username.clone();
                                    let gname = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::create_group(&mut conn, &gname, &uname)
                                    })
                                        .await
                                        .unwrap();
                                    match result {
                                        Ok(_) => format!("[Система] Группа {} создана", group_name),
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            "/joingroup" => {
                                if args.is_empty() {
                                    "[Система] Использование: /joingroup <название>".to_string()
                                } else {
                                    let group_name = args.join(" ");
                                    let db = state.lock().await.db.clone();
                                    let uname = my_username.clone();
                                    let gname = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::join_group(&mut conn, &gname, &uname)
                                    })
                                        .await
                                        .unwrap();
                                    match result {
                                        Ok(_) => format!("[Система] Вы присоединились к группе {}", group_name),
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            "/leavegroup" => {
                                if args.is_empty() {
                                    "[Система] Использование: /leavegroup <название>".to_string()
                                } else {
                                    let group_name = args.join(" ");
                                    let db = state.lock().await.db.clone();
                                    let uname = my_username.clone();
                                    let gname = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::leave_group(&mut conn, &gname, &uname)
                                    })
                                        .await
                                        .unwrap();
                                    match result {
                                        Ok(_) => format!("[Система] Вы покинули группу {}", group_name),
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            "/groupmembers" => {
                                if args.is_empty() {
                                    "[Система] Использование: /groupmembers <название>".to_string()
                                } else {
                                    let group_name = args.join(" ");
                                    let db = state.lock().await.db.clone();
                                    let gname = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::get_group_members(&mut conn, &gname)
                                    })
                                        .await
                                        .unwrap();
                                    match result {
                                        Ok(members) => {
                                            if members.is_empty() {
                                                format!("[Система] В группе {} нет участников", group_name)
                                            } else {
                                                format!("[Система] Участники группы {}: {}", group_name, members.join(", "))
                                            }
                                        }
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            "/listgroups" => {
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    let mut stmt = conn
                                        .prepare("SELECT g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.username = ?")
                                        .map_err(|e| e.to_string())?;
                                    let mut rows = stmt.query([&uname]).map_err(|e| e.to_string())?;
                                    let mut groups = Vec::new();
                                    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                                        let name: String = row.get(0).map_err(|e| e.to_string())?;
                                        groups.push(name);
                                    }
                                    Ok::<_, String>(groups)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(groups) => {
                                        if groups.is_empty() {
                                            "[Система] Вы не состоите ни в одной группе".to_string()
                                        } else {
                                            format!("[Система] Ваши группы: {}", groups.join(", "))
                                        }
                                    }
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                            "/createchannel" => {
                                if args.is_empty() {
                                    "[Система] Использование: /createchannel <название>".to_string()
                                } else {
                                    let channel_name = args.join(" ");
                                    let db = state.lock().await.db.clone();
                                    let uname = my_username.clone();
                                    let ch = channel_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::create_channel(&mut conn, &ch, &uname)
                                    })
                                        .await
                                        .unwrap();
                                    match result {
                                        Ok(_) => format!("[Система] Канал {} создан", channel_name),
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            "/subscribe" => {
                                if args.is_empty() {
                                    "[Система] Использование: /subscribe <название>".to_string()
                                } else {
                                    let channel_name = args.join(" ");
                                    let db = state.lock().await.db.clone();
                                    let uname = my_username.clone();
                                    let ch = channel_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::subscribe_channel(&mut conn, &ch, &uname)
                                    })
                                        .await
                                        .unwrap();
                                    match result {
                                        Ok(_) => format!("[Система] Вы подписались на канал {}", channel_name),
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            "/unsubscribe" => {
                                if args.is_empty() {
                                    "[Система] Использование: /unsubscribe <название>".to_string()
                                } else {
                                    let channel_name = args.join(" ");
                                    let db = state.lock().await.db.clone();
                                    let uname = my_username.clone();
                                    let ch = channel_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::unsubscribe_channel(&mut conn, &ch, &uname)
                                    })
                                        .await
                                        .unwrap();
                                    match result {
                                        Ok(_) => format!("[Система] Вы отписались от канала {}", channel_name),
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            "/channels" => {
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    let mut stmt = conn
                                        .prepare("SELECT c.name, c.creator_username FROM channels c JOIN channel_subscribers cs ON c.id = cs.channel_id WHERE cs.username = ?")
                                        .map_err(|e| e.to_string())?;
                                    let mut rows = stmt.query([&uname]).map_err(|e| e.to_string())?;
                                    let mut channels = Vec::new();
                                    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                                        let name: String = row.get(0).map_err(|e| e.to_string())?;
                                        let creator: String = row.get(1).map_err(|e| e.to_string())?;
                                        channels.push(format!("{}|{}", name, creator));
                                    }
                                    Ok::<_, String>(channels)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(channels) => {
                                        if channels.is_empty() {
                                            "[Система] Вы не подписаны ни на один канал".to_string()
                                        } else {
                                            format!("[Система] Ваши каналы: {}", channels.join(", "))
                                        }
                                    }
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                            "/listusers" => {
                                let db = state.lock().await.db.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    let mut stmt = conn
                                        .prepare("SELECT username, first_name, last_name FROM users ORDER BY username")
                                        .map_err(|e| e.to_string())?;
                                    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
                                    let mut users = Vec::new();
                                    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                                        let username: String = row.get(0).map_err(|e| e.to_string())?;
                                        let first_name: Option<String> = row.get(1).ok();
                                        let last_name: Option<String> = row.get(2).ok();
                                        let display_name = match (first_name, last_name) {
                                            (Some(f), Some(l)) => format!("{} {}", f, l),
                                            (Some(f), None) => f,
                                            _ => username.clone(),
                                        };
                                        users.push(format!("{}|{}", username, display_name));
                                    }
                                    Ok::<_, String>(users)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(users) => {
                                        if users.is_empty() {
                                            "[Система] Нет зарегистрированных пользователей".to_string()
                                        } else {
                                            format!("[Система] Пользователи: {}", users.join(", "))
                                        }
                                    }
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                            "/profile" => {
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::get_profile(&mut conn, &uname)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok((username, phone, first_name, last_name, display_name)) => {
                                        format!("[Система] Профиль: username={}, phone={}, name={} {}, display_name={}",
                                                username, phone, first_name, last_name, display_name)
                                    }
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                            "/setname" => {
                                if args.len() < 1 {
                                    "[Система] Использование: /setname <имя> [фамилия]".to_string()
                                } else {
                                    let first_name = args[0];
                                    let last_name = if args.len() > 1 { args[1..].join(" ") } else { "".to_string() };
                                    let db = state.lock().await.db.clone();
                                    let uname = my_username.clone();
                                    let fn_ = first_name.to_string();
                                    let ln_ = last_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::set_name(&mut conn, &uname, &fn_, &ln_)
                                    })
                                        .await
                                        .unwrap();
                                    match result {
                                        Ok(_) => format!("[Система] Имя обновлено: {} {}", first_name, last_name),
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            "/setdisplayname" => {
                                if args.is_empty() {
                                    "[Система] Использование: /setdisplayname <отображаемое имя>".to_string()
                                } else {
                                    let display_name = args.join(" ");
                                    let db = state.lock().await.db.clone();
                                    let uname = my_username.clone();
                                    let dn = display_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::set_display_name(&mut conn, &uname, &dn)
                                    })
                                        .await
                                        .unwrap();
                                    match result {
                                        Ok(_) => format!("[Система] Отображаемое имя обновлено: {}", display_name),
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            "/setusername" => {
                                if args.is_empty() {
                                    "[Система] Использование: /setusername <новый_username>".to_string()
                                } else {
                                    let new_username = args[0];
                                    let db = state.lock().await.db.clone();
                                    let uname = my_username.clone();
                                    let nu = new_username.to_string();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::set_username(&mut conn, &uname, &nu)
                                    })
                                        .await
                                        .unwrap();
                                    match result {
                                        Ok(_) => {
                                            // Обновляем username в сессии
                                            let mut guard = session.lock().await;
                                            guard.username = Some(new_username.to_string());
                                            format!("[Система] Username изменён на {}", new_username)
                                        }
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            _ => format!("[Система] Неизвестная команда: {}", cmd),
                        };
                        let _ = send_system_message(&tx, &response).await;
                        continue;
                    }

                    // ---- Личное сообщение ----
                    if !recipient.starts_with('#') && !recipient.starts_with('&') {
                        // Проверяем существование получателя
                        let db = state.lock().await.db.clone();
                        let target_clone = recipient.clone();
                        let exists = tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            AppState::user_exists_by_username(&mut conn, &target_clone)
                        })
                            .await
                            .unwrap()
                            .unwrap_or(false);

                        if !exists {
                            let _ = send_system_message(&tx, &format!("[Система] Пользователь {} не найден", recipient)).await;
                            continue;
                        }

                        // Сохраняем в БД
                        let db = state.lock().await.db.clone();
                        let sender = my_username.clone();
                        let recipient_clone = recipient.clone();
                        let content_clone = content.clone();
                        let ts = timestamp;
                        tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            let _ = AppState::store_message(&mut conn, &sender, &recipient_clone, &content_clone, ts);
                        })
                            .await
                            .unwrap();

                        // Отправка эха себе
                        let _ = send_encrypted_message(&tx, &keys, &my_username, &recipient, &plaintext, timestamp).await;

                            // Отправка получателю, если онлайн
                            let target_online = {
                                let state_guard = state.lock().await;
                                state_guard.online_users.contains_key(&recipient)
                            };


                            let target_tokens = {
                                let state_guard = state.lock().await;
                                state_guard
                                    .online_users
                                    .get(&recipient)
                                    .cloned()
                                    .unwrap_or_default()
                            };
                            for tok in target_tokens {
                                let target_session = {
                                    let state_guard = state.lock().await;
                                    state_guard.sessions.get(&tok).cloned()
                                };
                                if let Some(ts) = target_session {
                                    let (target_tx, target_keys) = {
                                        let guard = ts.lock().await;
                                        (guard.tx.clone(), guard.keys.clone())
                                    };
                                    let _ = send_encrypted_message(
                                        &target_tx,
                                        &target_keys,
                                        &my_username,
                                        &recipient,
                                        &plaintext,
                                        timestamp,
                                    )
                                        .await;
                                }
                            }

                        // Отправляем FCM push
                            let db = state.lock().await.db.clone();
                            let target_user = recipient.clone();
                            let fcm_tokens = tokio::task::spawn_blocking(move || {
                                let mut conn = db.lock().unwrap();
                                AppState::get_fcm_tokens_for_user(&mut conn, &target_user)
                            })
                                .await
                                .unwrap()
                                .unwrap_or_default();

                            for fcm_tok in fcm_tokens {
                                let title = format!("Новое сообщение от {}", my_username);
                                let body = content.chars().take(100).collect::<String>();
                                let data_payload = json!({
                                    "sender": my_username,
                                    "type": "private",
                                });

                                if let Err(e) = send_fcm_push(&fcm_tok, &title, &body, Some(data_payload)).await {
                                    error!("Не удалось отправить push для токена {}: {}", fcm_tok, e);
                                }
                            }

                        continue;
                    }

                    // ---- Групповое сообщение (#) ----
                    if recipient.starts_with('#') {
                        let group_name = recipient.trim_start_matches('#');
                        // Проверяем членство
                        let db = state.lock().await.db.clone();
                        let uname = my_username.clone();
                        let gname = group_name.to_string();
                        let is_member = tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            let mut stmt = conn
                                .prepare("SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE g.name = ? AND gm.username = ?")
                                .map_err(|e| format!("Ошибка запроса: {}", e))?;
                            let mut rows = stmt.query(params![gname, uname]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
                            Ok::<_, String>(rows.next().map_err(|e| format!("Ошибка чтения: {}", e))?.is_some())
                        })
                            .await
                            .unwrap()
                            .unwrap_or(false);

                        if !is_member {
                            let _ = send_system_message(&tx, "[Система] Вы не состоите в этой группе").await;
                            continue;
                        }

                        // Сохраняем
                        let db = state.lock().await.db.clone();
                        let sender = my_username.clone();
                        let recip_group = group_name.to_string();
                        let cnt = content.clone();
                        let ts = timestamp;
                        tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            let _ = AppState::store_group_message(&mut conn, &recip_group, &sender, &cnt, ts);
                        })
                            .await
                            .unwrap();

                        // Получаем участников
                        let db = state.lock().await.db.clone();
                        let gname = group_name.to_string();
                        let members = tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            AppState::get_group_members(&mut conn, &gname)
                        })
                            .await
                            .unwrap()
                            .unwrap_or_default();

                        // Отправляем эхо себе
                        let recip_with_hash = format!("#{}", group_name);
                        let _ = send_encrypted_message(&tx, &keys, &my_username, &recip_with_hash, &plaintext, timestamp).await;

                        // Отправка всем участникам (кроме себя)
                        for member in members {
                            if member == my_username {
                                continue;
                            }
                            let target_online = {
                                let state_guard = state.lock().await;
                                state_guard.online_users.contains_key(&member)
                            };
                            if target_online {
                                let target_tokens = {
                                    let state_guard = state.lock().await;
                                    state_guard
                                        .online_users
                                        .get(&member)
                                        .cloned()
                                        .unwrap_or_default()
                                };
                                for tok in target_tokens {
                                    let target_session = {
                                        let state_guard = state.lock().await;
                                        state_guard.sessions.get(&tok).cloned()
                                    };
                                    if let Some(ts) = target_session {
                                        let (target_tx, target_keys) = {
                                            let guard = ts.lock().await;
                                            (guard.tx.clone(), guard.keys.clone())
                                        };
                                        let _ = send_encrypted_message(
                                            &target_tx,
                                            &target_keys,
                                            &my_username,
                                            &recip_with_hash,
                                            &plaintext,
                                            timestamp,
                                        )
                                            .await;
                                    }
                                }
                            } else {
                                // Отправляем FCM push
                                let db = state.lock().await.db.clone();
                                let target_user = member.clone();
                                let fcm_tokens = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::get_fcm_tokens_for_user(&mut conn, &target_user)
                                })
                                    .await
                                    .unwrap()
                                    .unwrap_or_default();

                                for fcm_tok in fcm_tokens {
                                    let title = format!("Новое сообщение в группе {}", group_name);
                                    let body = format!("{}: {}", my_username, content.chars().take(100).collect::<String>());
                                    let data_payload = json!({
                                        "sender": my_username,
                                        "group": group_name,
                                        "type": "group",
                                    });
                                    let _ = send_fcm_push(&fcm_tok, &title, &body, Some(data_payload)).await;
                                }
                            }
                        }
                        continue;
                    }

                    // ---- Канальное сообщение (&) ----
                    if recipient.starts_with('&') {
                        let channel_name = recipient.trim_start_matches('&');
                        // Проверяем подписку
                        let db = state.lock().await.db.clone();
                        let uname = my_username.clone();
                        let ch = channel_name.to_string();
                        let is_subscribed = tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            let mut stmt = conn
                                .prepare("SELECT 1 FROM channel_subscribers cs JOIN channels c ON cs.channel_id = c.id WHERE c.name = ? AND cs.username = ?")
                                .map_err(|e| format!("Ошибка запроса: {}", e))?;
                            let mut rows = stmt.query(params![ch, uname]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
                            Ok::<_, String>(rows.next().map_err(|e| format!("Ошибка чтения: {}", e))?.is_some())
                        })
                            .await
                            .unwrap()
                            .unwrap_or(false);

                        if !is_subscribed {
                            let _ = send_system_message(&tx, "[Система] Вы не подписаны на этот канал").await;
                            continue;
                        }

                        // Проверяем владельца
                        let is_owner = {
                            let db = state.lock().await.db.clone();
                            let ch = channel_name.to_string();
                            let uname = my_username.clone();
                            tokio::task::spawn_blocking(move || {
                                let mut conn = db.lock().unwrap();
                                let mut stmt = conn
                                    .prepare("SELECT 1 FROM channels WHERE name = ? AND creator_username = ?")
                                    .map_err(|e| e.to_string())?;
                                let mut rows = stmt.query(params![ch, uname]).map_err(|e| e.to_string())?;
                                Ok::<_, String>(rows.next().map_err(|e| e.to_string())?.is_some())
                            })
                                .await
                                .unwrap()
                                .unwrap_or(false)
                        };

                        if !is_owner {
                            let _ = send_system_message(&tx, "[Система] Только владелец канала может отправлять сообщения").await;
                            continue;
                        }

                        // Сохраняем
                        let db = state.lock().await.db.clone();
                        let sender = my_username.clone();
                        let ch_name = channel_name.to_string();
                        let cnt = content.clone();
                        let ts = timestamp;
                        tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            let _ = AppState::store_channel_message(&mut conn, &ch_name, &sender, &cnt, ts);
                        })
                            .await
                            .unwrap();

                        // Получаем подписчиков
                        let db = state.lock().await.db.clone();
                        let ch_name2 = channel_name.to_string();
                        let subscribers = tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            AppState::get_channel_subscribers(&mut conn, &ch_name2)
                        })
                            .await
                            .unwrap()
                            .unwrap_or_default();

                        let recip_with_amp = format!("&{}", channel_name);
                        let _ = send_encrypted_message(&tx, &keys, &my_username, &recip_with_amp, &plaintext, timestamp).await;

                        for subscriber in subscribers {
                            if subscriber == my_username {
                                continue;
                            }
                            let target_online = {
                                let state_guard = state.lock().await;
                                state_guard.online_users.contains_key(&subscriber)
                            };
                            if target_online {
                                let target_tokens = {
                                    let state_guard = state.lock().await;
                                    state_guard
                                        .online_users
                                        .get(&subscriber)
                                        .cloned()
                                        .unwrap_or_default()
                                };
                                for tok in target_tokens {
                                    let target_session = {
                                        let state_guard = state.lock().await;
                                        state_guard.sessions.get(&tok).cloned()
                                    };
                                    if let Some(ts) = target_session {
                                        let (target_tx, target_keys) = {
                                            let guard = ts.lock().await;
                                            (guard.tx.clone(), guard.keys.clone())
                                        };
                                        let _ = send_encrypted_message(
                                            &target_tx,
                                            &target_keys,
                                            &my_username,
                                            &recip_with_amp,
                                            &plaintext,
                                            timestamp,
                                        )
                                            .await;
                                    }
                                }
                            } else {
                                // FCM push для подписчиков
                                let db = state.lock().await.db.clone();
                                let target_user = subscriber.clone();
                                let fcm_tokens = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::get_fcm_tokens_for_user(&mut conn, &target_user)
                                })
                                    .await
                                    .unwrap()
                                    .unwrap_or_default();

                                for fcm_tok in fcm_tokens {
                                    let title = format!("Новое сообщение в канале {}", channel_name);
                                    let body = format!("{}: {}", my_username, content.chars().take(100).collect::<String>());
                                    let data_payload = json!({
                                        "sender": my_username,
                                        "channel": channel_name,
                                        "type": "channel",
                                    });
                                    let _ = send_fcm_push(&fcm_tok, &title, &body, Some(data_payload)).await;
                                }
                            }
                        }
                        continue;
                    }

                    // Если ничего не подошло – игнорируем
                    warn!("Неизвестный тип получателя: {}", recipient);
                }

                MSG_TYPE_COMMAND => {
                    // Обработка команд, отправленных через отдельный тип
                    let cmd = String::from_utf8(rest[4..].to_vec()).unwrap_or_default();
                    info!("Получена команда через MSG_TYPE_COMMAND: {}", cmd);
                    let cmd_parts: Vec<&str> = cmd.split_whitespace().collect();
                    if cmd_parts.is_empty() {
                        continue;
                    }
                    debug!("{:#?}", cmd_parts);

                    let cmd_name = cmd_parts[0];
                    let args = &cmd_parts[1..];
                    let response = match cmd_name {
                        "/creategroup" => {
                            if args.is_empty() {
                                "[Система] Использование: /creategroup <название>".to_string()
                            } else {
                                let group_name = args.join(" ");
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let gname = group_name.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::create_group(&mut conn, &gname, &uname)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(_) => format!("[Система] Группа {} создана", group_name),
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                        }
                        "/joingroup" => {
                            if args.is_empty() {
                                "[Система] Использование: /joingroup <название>".to_string()
                            } else {
                                let group_name = args.join(" ");
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let gname = group_name.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::join_group(&mut conn, &gname, &uname)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(_) => format!("[Система] Вы присоединились к группе {}", group_name),
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                        }
                        "/leavegroup" => {
                            if args.is_empty() {
                                "[Система] Использование: /leavegroup <название>".to_string()
                            } else {
                                let group_name = args.join(" ");
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let gname = group_name.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::leave_group(&mut conn, &gname, &uname)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(_) => format!("[Система] Вы покинули группу {}", group_name),
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                        }
                        "/groupmembers" => {
                            if args.is_empty() {
                                "[Система] Использование: /groupmembers <название>".to_string()
                            } else {
                                let group_name = args.join(" ");
                                let db = state.lock().await.db.clone();
                                let gname = group_name.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::get_group_members(&mut conn, &gname)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(members) => {
                                        if members.is_empty() {
                                            format!("[Система] В группе {} нет участников", group_name)
                                        } else {
                                            format!("[Система] Участники группы {}: {}", group_name, members.join(", "))
                                        }
                                    }
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                        }
                        "/listgroups" => {
                            let db = state.lock().await.db.clone();
                            let uname = my_username.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                let mut conn = db.lock().unwrap();
                                let mut stmt = conn
                                    .prepare("SELECT g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.username = ?")
                                    .map_err(|e| e.to_string())?;
                                let mut rows = stmt.query([&uname]).map_err(|e| e.to_string())?;
                                let mut groups = Vec::new();
                                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                                    let name: String = row.get(0).map_err(|e| e.to_string())?;
                                    groups.push(name);
                                }
                                Ok::<_, String>(groups)
                            })
                                .await
                                .unwrap();
                            match result {
                                Ok(groups) => {
                                    if groups.is_empty() {
                                        "[Система] Вы не состоите ни в одной группе".to_string()
                                    } else {
                                        format!("[Система] Ваши группы: {}", groups.join(", "))
                                    }
                                }
                                Err(e) => format!("[Система] Ошибка: {}", e),
                            }
                        }
                        "/createchannel" => {
                            if args.is_empty() {
                                "[Система] Использование: /createchannel <название>".to_string()
                            } else {
                                let channel_name = args.join(" ");
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let ch = channel_name.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::create_channel(&mut conn, &ch, &uname)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(_) => format!("[Система] Канал {} создан", channel_name),
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                        }
                        "/subscribe" => {
                            if args.is_empty() {
                                "[Система] Использование: /subscribe <название>".to_string()
                            } else {
                                let channel_name = args.join(" ");
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let ch = channel_name.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::subscribe_channel(&mut conn, &ch, &uname)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(_) => format!("[Система] Вы подписались на канал {}", channel_name),
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                        }
                        "/unsubscribe" => {
                            if args.is_empty() {
                                "[Система] Использование: /unsubscribe <название>".to_string()
                            } else {
                                let channel_name = args.join(" ");
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let ch = channel_name.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::unsubscribe_channel(&mut conn, &ch, &uname)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(_) => format!("[Система] Вы отписались от канала {}", channel_name),
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                        }
                        "/channels" => {
                            let db = state.lock().await.db.clone();
                            let uname = my_username.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                let mut conn = db.lock().unwrap();
                                let mut stmt = conn
                                    .prepare("SELECT c.name, c.creator_username FROM channels c JOIN channel_subscribers cs ON c.id = cs.channel_id WHERE cs.username = ?")
                                    .map_err(|e| e.to_string())?;
                                let mut rows = stmt.query([&uname]).map_err(|e| e.to_string())?;
                                let mut channels = Vec::new();
                                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                                    let name: String = row.get(0).map_err(|e| e.to_string())?;
                                    let creator: String = row.get(1).map_err(|e| e.to_string())?;
                                    channels.push(format!("{}|{}", name, creator));
                                }
                                Ok::<_, String>(channels)
                            })
                                .await
                                .unwrap();
                            match result {
                                Ok(channels) => {
                                    if channels.is_empty() {
                                        "[Система] Вы не подписаны ни на один канал".to_string()
                                    } else {
                                        format!("[Система] Ваши каналы: {}", channels.join(", "))
                                    }
                                }
                                Err(e) => format!("[Система] Ошибка: {}", e),
                            }
                        }
                        "/listusers" => {
                            let db = state.lock().await.db.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                let mut conn = db.lock().unwrap();
                                let mut stmt = conn
                                    .prepare("SELECT username, first_name, last_name FROM users ORDER BY username")
                                    .map_err(|e| e.to_string())?;
                                let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
                                let mut users = Vec::new();
                                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                                    let username: String = row.get(0).map_err(|e| e.to_string())?;
                                    let first_name: Option<String> = row.get(1).ok();
                                    let last_name: Option<String> = row.get(2).ok();
                                    let display_name = match (first_name, last_name) {
                                        (Some(f), Some(l)) => format!("{} {}", f, l),
                                        (Some(f), None) => f,
                                        _ => username.clone(),
                                    };
                                    users.push(format!("{}|{}", username, display_name));
                                }
                                Ok::<_, String>(users)
                            })
                                .await
                                .unwrap();
                            match result {
                                Ok(users) => {
                                    if users.is_empty() {
                                        "[Система] Нет зарегистрированных пользователей".to_string()
                                    } else {
                                        format!("[Система] Пользователи: {}", users.join(", "))
                                    }
                                }
                                Err(e) => format!("[Система] Ошибка: {}", e),
                            }
                        }
                        "/profile" => {
                            let db = state.lock().await.db.clone();
                            let uname = my_username.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                let mut conn = db.lock().unwrap();
                                AppState::get_profile(&mut conn, &uname)
                            })
                                .await
                                .unwrap();
                            match result {
                                Ok((username, phone, first_name, last_name, display_name)) => {
                                    format!("[Система] Профиль: username={}, phone={}, name={} {}, display_name={}",
                                            username, phone, first_name, last_name, display_name)
                                }
                                Err(e) => format!("[Система] Ошибка: {}", e),
                            }
                        }
                        "/setname" => {
                            if args.len() < 1 {
                                "[Система] Использование: /setname <имя> [фамилия]".to_string()
                            } else {
                                let first_name = args[0];
                                let last_name = if args.len() > 1 { args[1..].join(" ") } else { "".to_string() };
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let fn_ = first_name.to_string();
                                let ln_ = last_name.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::set_name(&mut conn, &uname, &fn_, &ln_)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(_) => format!("[Система] Имя обновлено: {} {}", first_name, last_name),
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                        }
                        "/setdisplayname" => {
                            if args.is_empty() {
                                "[Система] Использование: /setdisplayname <отображаемое имя>".to_string()
                            } else {
                                let display_name = args.join(" ");
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let dn = display_name.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::set_display_name(&mut conn, &uname, &dn)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(_) => format!("[Система] Отображаемое имя обновлено: {}", display_name),
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                        }
                        "/setusername" => {
                            if args.is_empty() {
                                "[Система] Использование: /setusername <новый_username>".to_string()
                            } else {
                                let new_username = args[0];
                                let db = state.lock().await.db.clone();
                                let uname = my_username.clone();
                                let nu = new_username.to_string();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::set_username(&mut conn, &uname, &nu)
                                })
                                    .await
                                    .unwrap();
                                match result {
                                    Ok(_) => {
                                        // Обновляем username в сессии
                                        let mut guard = session.lock().await;
                                        guard.username = Some(new_username.to_string());
                                        format!("[Система] Username изменён на {}", new_username)
                                    }
                                    Err(e) => format!("[Система] Ошибка: {}", e),
                                }
                            }
                        }
                        _ => format!("[Система] Неизвестная команда: {}", cmd),
                    };
                    let _ = send_system_message(&tx, &response).await;

                }

                _ => {
                    warn!("Неизвестный тип сообщения: {}", msg_type);
                }
            }
        } else {
            // Небинарное сообщение – игнорируем
            warn!("Получено небинарное сообщение, игнорируем");
        }
    }

    // ---- Закрытие сессии ----
    {
        let username = {
            let guard = session.lock().await;
            guard.username.clone().unwrap_or_default()
        };
        let token = {
            let guard = session.lock().await;
            guard.token.clone().unwrap_or_default()
        };
        let mut state_guard = state.lock().await;
        if !username.is_empty() {
            if let Some(tokens) = state_guard.online_users.get_mut(&username) {
                tokens.retain(|t| t != &token);
                if tokens.is_empty() {
                    state_guard.online_users.remove(&username);
                }
            }
        }
        if !token.is_empty() {
            state_guard.sessions.remove(&token);
        }
        let msg = format!("[Система] Пользователь {} отключился", username);
        drop(state_guard);
        broadcast_system_message(&state, &msg, Some(&username)).await;
    }

    info!("Клиент {} отключён, время сессии: {:?}", my_username, start_time.elapsed());
    let _ = send_task.await;
}

// ==================== Функция запуска сервера ====================
async fn run_server(listener: TcpListener, state: Arc<Mutex<AppState>>) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state_clone = state.clone();
        tokio::spawn(async move {
            handle_client(stream, state_clone).await;
        });
    }
}

// ==================== Точка входа ====================
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let ip = env::var("IP").unwrap_or_else(|_| "::".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8100".to_string());
    let addr = format!("[{}]:{}", ip, port);
    let listener = TcpListener::bind(&addr).await?;
    info!("WebSocket сервер запущен на {}", addr);

    let db_path = "data.db";
    let db = Connection::open(db_path)?;
    let mut db = db;
    AppState::init_db(&mut db)?;
    let state = Arc::new(Mutex::new(AppState::new(db)));

    // Graceful shutdown
    let ctrl_c = tokio::signal::ctrl_c();
    let terminate = async {
        #[cfg(unix)]
        {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install signal handler")
                .recv()
                .await;
        }
        #[cfg(not(unix))]
        std::future::pending::<()>().await;
    };

    tokio::select! {
        _ = run_server(listener, state) => {},
        _ = ctrl_c => {
            info!("Получен сигнал Ctrl+C, завершаем работу...");
        },
        _ = terminate => {
            info!("Получен сигнал завершения, завершаем работу...");
        },
    }

    Ok(())
}