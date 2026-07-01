use x25519_dalek::{EphemeralSecret, PublicKey};
use rand::rngs::OsRng;
use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{KeyIvInit, block_padding::Pkcs7};
use aes::cipher::{BlockEncryptMut, BlockDecryptMut};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use rusqlite::{Connection, params};
use uuid::Uuid;
use bcrypt::{hash, verify, DEFAULT_COST};
use tokio::sync::mpsc;
use std::time::Instant;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const MSG_TYPE_USER: u8 = 0x01;
const MSG_TYPE_SYSTEM: u8 = 0x02;
const MSG_TYPE_COMMAND: u8 = 0x03;
const MSG_TYPE_AUTH: u8 = 0x04;

#[derive(Clone)]
struct SessionKeys {
    key: Vec<u8>,
    iv: Vec<u8>,
}

struct Session {
    tx: mpsc::UnboundedSender<Message>,
    keys: SessionKeys,
    connected: bool,
    user_id: Option<String>,
    username: Option<String>,
    token: Option<String>,
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
        }
    }
}

struct AppState {
    db: Arc<StdMutex<Connection>>,
    sessions: HashMap<String, Arc<Mutex<Session>>>,
    online_users: HashMap<String, String>,
}

impl AppState {
    fn new(db: Connection) -> Self {
        Self {
            db: Arc::new(StdMutex::new(db)),
            sessions: HashMap::new(),
            online_users: HashMap::new(),
        }
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
        Ok(())
    }

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
        let mut stmt = conn.prepare("SELECT id, password_hash FROM users WHERE phone = ?")
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
        let mut stmt = conn.prepare("SELECT user_id, username FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.token = ?")
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

    fn user_exists_by_username(conn: &mut Connection, username: &str) -> Result<bool, String> {
        let mut stmt = conn.prepare("SELECT 1 FROM users WHERE username = ?")
            .map_err(|e| format!("Ошибка запроса: {}", e))?;
        let mut rows = stmt.query([username]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        Ok(rows.next().map_err(|e| format!("Ошибка чтения: {}", e))?.is_some())
    }

    // ---- Messages ----
    fn store_message(conn: &mut Connection, sender: &str, recipient: &str, content: &str) -> Result<(), String> {
        let msg_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO messages (id, sender_username, recipient_username, content) VALUES (?, ?, ?, ?)",
            params![msg_id, sender, recipient, content],
        ).map_err(|e| format!("Ошибка сохранения сообщения: {}", e))?;
        Ok(())
    }

    fn get_user_messages(conn: &mut Connection, username: &str, limit: i64) -> Result<Vec<(String, String, String)>, String> {
        let mut stmt = conn.prepare(
            "SELECT sender_username, recipient_username, content FROM messages WHERE sender_username = ? OR recipient_username = ? ORDER BY sent_at ASC LIMIT ?"
        ).map_err(|e| format!("Ошибка подготовки: {}", e))?;
        let mut rows = stmt.query(params![username, username, limit]).map_err(|e| format!("Ошибка запроса: {}", e))?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let sender: String = row.get(0).map_err(|e| format!("Ошибка чтения sender: {}", e))?;
            let recipient: String = row.get(1).map_err(|e| format!("Ошибка чтения recipient: {}", e))?;
            let content: String = row.get(2).map_err(|e| format!("Ошибка чтения content: {}", e))?;
            result.push((sender, recipient, content));
        }
        Ok(result)
    }

    // ---- Groups ----
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

    fn store_group_message(conn: &mut Connection, group_name: &str, sender: &str, content: &str) -> Result<(), String> {
        let mut stmt = conn.prepare("SELECT id FROM groups WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса группы: {}", e))?;
        let mut rows = stmt.query([group_name]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let group_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            let msg_id = Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO group_messages (id, group_id, sender_username, content) VALUES (?, ?, ?, ?)",
                params![msg_id, group_id, sender, content],
            ).map_err(|e| format!("Ошибка сохранения группового сообщения: {}", e))?;
            Ok(())
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    fn get_group_messages(conn: &mut Connection, group_name: &str, limit: i64) -> Result<Vec<(String, String)>, String> {
        let mut stmt = conn.prepare(
            "SELECT gm.sender_username, gm.content FROM group_messages gm JOIN groups g ON gm.group_id = g.id WHERE g.name = ? ORDER BY gm.sent_at ASC LIMIT ?"
        ).map_err(|e| format!("Ошибка подготовки: {}", e))?;
        let mut rows = stmt.query(params![group_name, limit]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let sender: String = row.get(0).map_err(|e| format!("Ошибка чтения sender: {}", e))?;
            let content: String = row.get(1).map_err(|e| format!("Ошибка чтения content: {}", e))?;
            result.push((sender, content));
        }
        Ok(result)
    }

    // ---- Channels ----
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

    fn store_channel_message(conn: &mut Connection, channel_name: &str, sender: &str, content: &str) -> Result<(), String> {
        let mut stmt = conn.prepare("SELECT id FROM channels WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса канала: {}", e))?;
        let mut rows = stmt.query([channel_name]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let channel_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            let msg_id = Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO channel_messages (id, channel_id, sender_username, content) VALUES (?, ?, ?, ?)",
                params![msg_id, channel_id, sender, content],
            ).map_err(|e| format!("Ошибка сохранения сообщения канала: {}", e))?;
            Ok(())
        } else {
            Err("Канал не найден".to_string())
        }
    }

    fn get_channel_messages(conn: &mut Connection, channel_name: &str, limit: i64) -> Result<Vec<(String, String)>, String> {
        let mut stmt = conn.prepare(
            "SELECT cm.sender_username, cm.content FROM channel_messages cm JOIN channels c ON cm.channel_id = c.id WHERE c.name = ? ORDER BY cm.sent_at ASC LIMIT ?"
        ).map_err(|e| format!("Ошибка подготовки: {}", e))?;
        let mut rows = stmt.query(params![channel_name, limit]).map_err(|e| format!("Ошибка выполнения: {}", e))?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let sender: String = row.get(0).map_err(|e| format!("Ошибка чтения sender: {}", e))?;
            let content: String = row.get(1).map_err(|e| format!("Ошибка чтения content: {}", e))?;
            result.push((sender, content));
        }
        Ok(result)
    }

    // ---- Profile ----
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

// ---- WebSocket Handshake ----
async fn ws_handshake(stream: &mut tokio_tungstenite::WebSocketStream<TcpStream>) -> Result<SessionKeys, String> {
    println!("[Сервер] Handshake: ожидание первого сообщения");
    let msg = stream.next().await
        .ok_or("No message received")?
        .map_err(|e| format!("WebSocket error: {}", e))?;
    println!("[Сервер] Handshake: получено сообщение, тип={:?}", msg);

    let data = match msg {
        Message::Binary(d) => {
            println!("[Сервер] Handshake: бинарные данные, длина={}", d.len());
            d
        },
        Message::Text(t) => {
            println!("[Сервер] Handshake: текстовое сообщение: {}", t);
            return Err("Expected binary".to_string());
        },
        _ => return Err("Expected binary".to_string()),
    };
    if data.len() != 32 {
        return Err(format!("Invalid public key length: {}", data.len()));
    }
    let client_key: [u8; 32] = data.to_vec().try_into().map_err(|_| "Invalid key array")?;
    println!("[Сервер] Handshake: получен публичный ключ клиента");

    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    stream.send(Message::Binary(public.as_bytes().to_vec().into()))
        .await
        .map_err(|e| format!("Failed to send public key: {}", e))?;
    println!("[Сервер] Handshake: отправлен публичный ключ сервера");

    let peer_public = PublicKey::from(client_key);
    let shared = secret.diffie_hellman(&peer_public);
    let shared_bytes = shared.to_bytes();

    let hk = Hkdf::<Sha256>::new(None, &shared_bytes);
    let mut derived = [0u8; 48];
    hk.expand(b"relay-server", &mut derived).map_err(|e| e.to_string())?;
    let key = derived[..32].to_vec();
    let iv = derived[32..].to_vec();
    println!("[Сервер] Handshake: успешно завершён");
    Ok(SessionKeys { key, iv })
}

// ---- Отправка системных сообщений ----
async fn send_system_message(
    tx: &mpsc::UnboundedSender<Message>,
    text: &str,
) -> Result<(), String> {
    let bytes = text.as_bytes();
    let mut data = Vec::with_capacity(1 + 4 + bytes.len());
    data.push(MSG_TYPE_SYSTEM);
    data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(bytes);
    tx.send(Message::Binary(data.into())).map_err(|e| e.to_string())
}

// ---- Отправка зашифрованного сообщения ----
async fn send_encrypted_message(
    tx: &mpsc::UnboundedSender<Message>,
    keys: &SessionKeys,
    sender_id: &str,
    recipient_id: &str,
    plaintext: &[u8],
) -> Result<(), String> {
    let cipher_enc = Aes256CbcEnc::new(keys.key.as_slice().into(), keys.iv.as_slice().into());
    let mut buffer = vec![0u8; plaintext.len() + 16];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    let encrypted = cipher_enc
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|e| format!("encryption error: {}", e))?;

    let mut data = Vec::new();
    data.push(MSG_TYPE_USER);
    let sender_bytes = sender_id.as_bytes();
    data.extend_from_slice(&(sender_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(sender_bytes);
    let recipient_bytes = recipient_id.as_bytes();
    data.extend_from_slice(&(recipient_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(recipient_bytes);
    data.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    data.extend_from_slice(&encrypted);
    tx.send(Message::Binary(data.into())).map_err(|e| e.to_string())
}

// ---- Broadcast системных сообщений ----
async fn broadcast_system_message(
    state: &Arc<Mutex<AppState>>,
    message: &str,
    exclude_id: Option<&str>,
) {
    let state_guard = state.lock().await;
    let sessions = &state_guard.sessions;
    for (_, session) in sessions {
        let (connected, tx, username) = {
            let guard = session.lock().await;
            (guard.connected, guard.tx.clone(), guard.username.clone())
        };
        if connected {
            if let Some(uname) = username {
                if Some(uname.as_str()) == exclude_id {
                    continue;
                }
            }
            let _ = send_system_message(&tx, message).await;
        }
    }
}

// ---- Обработчик клиента ----
async fn handle_client(
    stream: TcpStream,
    state: Arc<Mutex<AppState>>,
) {
    let start_time = Instant::now();
    println!("[Сервер] Принято TCP-соединение от {:?}", stream.peer_addr().ok());

    let ws_result = accept_async(stream).await;
    let mut ws_stream = match ws_result {
        Ok(ws) => {
            println!("[Сервер] WebSocket-соединение успешно установлено");
            ws
        },
        Err(e) => {
            eprintln!("[Сервер] WebSocket accept error: {}", e);
            return;
        }
    };

    let keys = match ws_handshake(&mut ws_stream).await {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[Сервер] Handshake error: {}", e);
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
        println!("[Сервер] Временная сессия создана: {}", temp_id);
    }

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = sink.send(msg).await {
                eprintln!("[Сервер] Ошибка отправки: {}", e);
                break;
            }
        }
        println!("[Сервер] Задача отправки завершена");
    });

    async fn read_binary_message(stream: &mut futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<TcpStream>>) -> Result<Vec<u8>, String> {
        let msg = stream.next().await
            .ok_or("Connection closed")?
            .map_err(|e| format!("WebSocket error: {}", e))?;
        match msg {
            Message::Binary(data) => {
                println!("[Сервер] Получено бинарное сообщение, длина={}", data.len());
                Ok(data.to_vec())
            },
            Message::Text(t) => {
                println!("[Сервер] Получено текстовое сообщение: {}", t);
                Err("Expected binary".to_string())
            },
            _ => Err("Unexpected message type".to_string()),
        }
    }

    // ------ Аутентификация ------
    let data = match read_binary_message(&mut stream).await {
        Ok(d) => {
            println!("[Сервер] Первый пакет аутентификации, длина={}", d.len());
            d
        },
        Err(e) => {
            eprintln!("[Сервер] Ошибка чтения аутентификации: {}", e);
            let _ = send_task.await;
            return;
        }
    };
    if data.is_empty() || data[0] != MSG_TYPE_AUTH {
        eprintln!("[Сервер] Ожидался MSG_TYPE_AUTH, получено {:?}", data.first());
        let _ = send_task.await;
        return;
    }
    println!("[Сервер] Получен пакет аутентификации");

    let auth_str = String::from_utf8(data[1..].to_vec()).unwrap_or_default();
    println!("[Сервер] Auth string: {}", auth_str);
    let parts: Vec<&str> = auth_str.split('|').collect();
    if parts.len() < 3 {
        eprintln!("[Сервер] Неверный формат аутентификации");
        let _ = send_task.await;
        return;
    }
    let command = parts[0];
    let phone = parts[1].trim().to_string();
    let password = parts[2].trim().to_string();
    println!("[Сервер] Команда: {}, телефон: {}", command, phone);

    // Парсим в зависимости от команды
    if command == "token" {
        // Формат: token|токен|устройство
        if parts.len() < 2 {
            eprintln!("[Сервер] Неверный формат token");
            let _ = send_task.await;
            return;
        }
        let token = parts[1].trim();
        let device_name = if parts.len() > 2 { parts[2].trim().to_string() } else { "unknown".to_string() };
        let db = state.lock().await.db.clone();
        let token_str = token.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = db.lock().unwrap();
            AppState::check_session(&mut conn, &token_str)
        }).await.unwrap();

        match result {
            Ok((user_id, username_db)) => {
                println!("[Сервер] Восстановлена сессия: user_id={}, username={}", user_id, username_db);
                let msg = format!("Успех|{}|{}|{}", user_id, token, username_db);
                let _ = send_system_message(&tx, &msg).await;

                {
                    let mut guard = session.lock().await;
                    guard.user_id = Some(user_id.clone());
                    guard.username = Some(username_db.clone());
                    guard.token = Some(token.to_string());
                }
                {
                    let mut state_guard = state.lock().await;
                    state_guard.sessions.remove(&temp_id);
                    state_guard.sessions.insert(token.to_string(), session.clone());
                    state_guard.online_users.insert(username_db.clone(), user_id.clone());
                }
                let msg = format!("[Система] Пользователь {} подключился", username_db);
                broadcast_system_message(&state, &msg, Some(&username_db)).await;
            }
            Err(e) => {
                eprintln!("[Сервер] Ошибка восстановления сессии: {}", e);
                let _ = send_system_message(&tx, &format!("[Система] Ошибка: {}", e)).await;
                let _ = send_task.await;
                return;
            }
        }
    } else if command == "login" {
        // Формат: login|телефон|пароль|устройство (опционально)
        let device_name = if parts.len() > 3 { parts[3].trim().to_string() } else { "unknown".to_string() };
        let db = state.lock().await.db.clone();
        let ph = phone.clone();
        let pwd = password.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = db.lock().unwrap();
            AppState::login_user_by_phone(&mut conn, &ph, &pwd)
        }).await.unwrap();

        match result {
            Ok(user_id) => {
                println!("[Сервер] Аутентификация успешна для user_id={}", user_id);
                // Получаем username из БД
                let db3 = state.lock().await.db.clone();
                let uid = user_id.clone();
                let username_from_db = tokio::task::spawn_blocking(move || {
                    let mut conn = db3.lock().unwrap();
                    let mut stmt = conn.prepare("SELECT username FROM users WHERE id = ?")
                        .map_err(|e| e.to_string())?;
                    let mut rows = stmt.query([&uid]).map_err(|e| e.to_string())?;
                    if let Some(row) = rows.next().map_err(|e| e.to_string())? {
                        let username: String = row.get(0).map_err(|e| e.to_string())?;
                        Ok(username)
                    } else {
                        Err("Пользователь не найден".to_string())
                    }
                }).await.unwrap();
                let username = match username_from_db {
                    Ok(uname) => uname,
                    Err(_) => phone.clone()
                };

                let db2 = state.lock().await.db.clone();
                let uid2 = user_id.clone();
                let dev = device_name.clone();
                let token_result = tokio::task::spawn_blocking(move || {
                    let mut conn = db2.lock().unwrap();
                    AppState::create_session(&mut conn, &uid2, &dev)
                }).await.unwrap();

                match token_result {
                    Ok(token) => {
                        println!("[Сервер] Сессия создана, токен: {}", token);
                        let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                        let _ = send_system_message(&tx, &msg).await;

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
                            state_guard.online_users.insert(username.clone(), user_id.clone());
                        }
                        let msg = format!("[Система] Пользователь {} подключился", username);
                        broadcast_system_message(&state, &msg, Some(&username)).await;
                    }
                    Err(e) => {
                        eprintln!("[Сервер] Ошибка создания сессии: {}", e);
                        let _ = send_system_message(&tx, &format!("[Система] Ошибка создания сессии: {}", e)).await;
                        let _ = send_task.await;
                        return;
                    }
                }
            }
            Err(e) => {
                eprintln!("[Сервер] Ошибка логина: {}", e);
                let _ = send_system_message(&tx, &format!("[Система] Ошибка: {}", e)).await;
                let _ = send_task.await;
                return;
            }
        }
    } else if command == "register" {
        // Формат: register|телефон|пароль|имя|фамилия|username|устройство
        // Минимум: register|телефон|пароль|имя|фамилия|username|устройство (7 полей)
        // Если username не указан, используем телефон
        let first_name = if parts.len() > 3 { Some(parts[3].trim()) } else { None };
        let last_name = if parts.len() > 4 { Some(parts[4].trim()) } else { None };
        let username = if parts.len() > 5 && !parts[5].trim().is_empty() {
            parts[5].trim().to_string()
        } else {
            phone.clone()
        };
        let device_name = if parts.len() > 6 { parts[6].trim().to_string() } else { "unknown".to_string() };

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
        }).await.unwrap();

        match result {
            Ok(user_id) => {
                println!("[Сервер] Регистрация успешна для user_id={}", user_id);
                // Создаём сессию
                let db2 = state.lock().await.db.clone();
                let uid = user_id.clone();
                let dev = device_name.clone();
                let token_result = tokio::task::spawn_blocking(move || {
                    let mut conn = db2.lock().unwrap();
                    AppState::create_session(&mut conn, &uid, &dev)
                }).await.unwrap();

                match token_result {
                    Ok(token) => {
                        println!("[Сервер] Сессия создана, токен: {}", token);
                        let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                        let _ = send_system_message(&tx, &msg).await;

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
                            state_guard.online_users.insert(username.clone(), user_id.clone());
                        }
                        let msg = format!("[Система] Пользователь {} подключился", username);
                        broadcast_system_message(&state, &msg, Some(&username)).await;
                    }
                    Err(e) => {
                        eprintln!("[Сервер] Ошибка создания сессии: {}", e);
                        let _ = send_system_message(&tx, &format!("[Система] Ошибка создания сессии: {}", e)).await;
                        let _ = send_task.await;
                        return;
                    }
                }
            }
            Err(e) => {
                eprintln!("[Сервер] Ошибка регистрации: {}", e);
                let _ = send_system_message(&tx, &format!("[Система] Ошибка: {}", e)).await;
                let _ = send_task.await;
                return;
            }
        }
    } else {
        eprintln!("[Сервер] Неизвестная команда: {}", command);
        let _ = send_system_message(&tx, &format!("[Система] Ошибка: Неизвестная команда {}", command)).await;
        let _ = send_task.await;
        return;
    }

    // ------ Загрузка истории ------
    let username_clone = {
        let guard = session.lock().await;
        guard.username.clone().unwrap_or_default()
    };
    if !username_clone.is_empty() {
        let db = state.lock().await.db.clone();
        let uname = username_clone.clone();
        let history = tokio::task::spawn_blocking(move || {
            let mut conn = db.lock().unwrap();
            AppState::get_user_messages(&mut conn, &uname, 50)
        }).await.unwrap();

        if let Ok(msgs) = history {
            let tx = {
                let guard = session.lock().await;
                guard.tx.clone()
            };
            let keys = {
                let guard = session.lock().await;
                guard.keys.clone()
            };
            println!("[Сервер] Загружено {} личных сообщений", msgs.len());
            for (sender, recipient, content) in msgs {
                let _ = send_encrypted_message(&tx, &keys, &sender, &recipient, content.as_bytes()).await;
            }

        }
    }

    // ------ Основной цикл ------
    println!("[Сервер] Начало основного цикла обработки для {}", username_clone);
    loop {
        let msg = match stream.next().await {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => {
                eprintln!("[Сервер] Ошибка чтения: {}", e);
                break;
            }
            None => break,
        };
        if let Message::Binary(data) = msg {
            if data.is_empty() {
                continue;
            }
            let msg_type = data[0];
            let rest = &data[1..];
            match msg_type {
                MSG_TYPE_USER => {
                    let mut offset = 0;
                    let target_len = u32::from_be_bytes(rest[offset..offset+4].try_into().unwrap()) as usize;
                    offset += 4;
                    let target = String::from_utf8(rest[offset..offset+target_len].to_vec()).unwrap_or_default();
                    offset += target_len;
                    let msg_len = u32::from_be_bytes(rest[offset..offset+4].try_into().unwrap()) as usize;
                    offset += 4;
                    let encrypted = &rest[offset..offset+msg_len];

                    let keys = {
                        let guard = session.lock().await;
                        guard.keys.clone()
                    };
                    let cipher_dec = Aes256CbcDec::new(keys.key.as_slice().into(), keys.iv.as_slice().into());
                    let mut decrypted = encrypted.to_vec();
                    let plaintext = match cipher_dec.decrypt_padded_mut::<Pkcs7>(&mut decrypted) {
                        Ok(p) => p.to_vec(),
                        Err(e) => {
                            eprintln!("[Сервер] Ошибка расшифровки: {}", e);
                            continue;
                        }
                    };
                    let content = String::from_utf8_lossy(&plaintext).to_string();
                    let my_username = {
                        let guard = session.lock().await;
                        guard.username.clone().unwrap_or_default()
                    };
                    println!("[Сервер] Сообщение от {} для {}: {}", my_username, target, content);
                    // Здесь будет логика обработки (эхо для примера)
                    let tx = {
                        let guard = session.lock().await;
                        guard.tx.clone()
                    };
                    let _ = send_encrypted_message(&tx, &keys, &my_username, &target, &plaintext).await;
                }
                MSG_TYPE_COMMAND => {
                    let cmd = String::from_utf8(rest.to_vec()).unwrap_or_default();
                    println!("[Сервер] Получена команда: {}", cmd);
                    let tx = {
                        let guard = session.lock().await;
                        guard.tx.clone()
                    };
                    let _ = send_system_message(&tx, &format!("[Система] Команда {} получена", cmd)).await;
                }
                _ => {}
            }
        } else {
            println!("[Сервер] Получено небинарное сообщение, игнорируем");
        }
    }

    // Закрытие
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
            state_guard.online_users.remove(&username);
        }
        if !token.is_empty() {
            state_guard.sessions.remove(&token);
        }
        let msg = format!("[Система] Пользователь {} отключился", username);
        drop(state_guard);
        broadcast_system_message(&state, &msg, Some(&username)).await;
    }
    println!("[Сервер] Клиент {} отключён, время сессии: {:?}", username_clone, start_time.elapsed());
    let _ = send_task.await;
}

// ---- Точка входа ----
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_path = "data.db";
    let db = Connection::open(db_path)?;
    let mut db = db;
    AppState::init_db(&mut db)?;

    let state = Arc::new(Mutex::new(AppState::new(db)));

    let addr = "[::]:8100";
    let listener = TcpListener::bind(&addr).await?;
    println!("[Сервер] WebSocket сервер запущен на {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let state_clone = state.clone();
        tokio::spawn(async move {
            handle_client(stream, state_clone).await;
        });
    }
}