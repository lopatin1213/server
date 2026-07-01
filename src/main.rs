use x25519_dalek::{EphemeralSecret, PublicKey};
use rand::rngs::OsRng;
use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{KeyIvInit, block_padding::Pkcs7, BlockDecryptMut};
use aes::cipher::BlockEncryptMut;
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::io;
use std::sync::Mutex as StdMutex;
use rusqlite::{Connection, params};
use uuid::Uuid;
use bcrypt::{hash, verify, DEFAULT_COST};
use tokio::signal;
use tokio::time;
use std::time::Duration;

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
    read: Option<OwnedReadHalf>,
    write: Option<Arc<Mutex<OwnedWriteHalf>>>,
    keys: SessionKeys,
    connected: bool,
    user_id: Option<String>,
    username: Option<String>,
    token: Option<String>,
}

impl Session {
    fn new(read: OwnedReadHalf, write: Arc<Mutex<OwnedWriteHalf>>, keys: SessionKeys) -> Self {
        Self {
            read: Some(read),
            write: Some(write),
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
    online_users: HashMap<String, String>, // username -> user_id
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

// ---- Handshake ----
async fn handshake(
    mut stream: TcpStream,
) -> (SessionKeys, OwnedReadHalf, OwnedWriteHalf) {
    println!("[Сервер] Handshake: начат");
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    stream.write_all(public.as_bytes()).await.unwrap();
    println!("[Сервер] Handshake: отправлен публичный ключ");

    let mut peer_buf = [0u8; 32];
    stream.read_exact(&mut peer_buf).await.unwrap();
    println!("[Сервер] Handshake: получен публичный ключ клиента");
    let peer_public = PublicKey::from(peer_buf);
    let shared = secret.diffie_hellman(&peer_public);
    let shared_bytes = shared.to_bytes();

    let hk = Hkdf::<Sha256>::new(None, &shared_bytes);
    let mut derived = [0u8; 48];
    hk.expand(b"relay-server", &mut derived).expect("HKDF expand failed");
    let key = derived[..32].to_vec();
    let iv = derived[32..].to_vec();
    let keys = SessionKeys { key, iv };

    let (read, write) = stream.into_split();
    println!("[Сервер] Handshake: завершён");
    (keys, read, write)
}

// ---- Функции отправки ----
async fn send_system_message_to_client(
    write: &Arc<Mutex<OwnedWriteHalf>>,
    text: &str,
) -> io::Result<()> {
    let write_guard = time::timeout(Duration::from_secs(2), write.lock()).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "lock timeout"))?;
    let mut write_guard = write_guard;
    write_guard.write_all(&[MSG_TYPE_SYSTEM]).await?;
    let bytes = text.as_bytes();
    write_guard.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    write_guard.write_all(bytes).await?;
    write_guard.flush().await?;
    Ok(())
}

async fn send_encrypted_to_client_with_sender_recipient(
    write: &Arc<Mutex<OwnedWriteHalf>>,
    sender_id: &str,
    recipient_id: &str,
    encrypted: &[u8],
) -> io::Result<()> {
    let write_guard = time::timeout(Duration::from_secs(2), write.lock()).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "lock timeout"))?;
    let mut write_guard = write_guard;
    write_guard.write_all(&[MSG_TYPE_USER]).await?;
    let sender_bytes = sender_id.as_bytes();
    write_guard.write_all(&(sender_bytes.len() as u32).to_be_bytes()).await?;
    write_guard.write_all(sender_bytes).await?;
    let recipient_bytes = recipient_id.as_bytes();
    write_guard.write_all(&(recipient_bytes.len() as u32).to_be_bytes()).await?;
    write_guard.write_all(recipient_bytes).await?;
    write_guard.write_all(&(encrypted.len() as u32).to_be_bytes()).await?;
    write_guard.write_all(encrypted).await?;
    write_guard.flush().await?;
    Ok(())
}

async fn send_user_message_to_client(
    write: &Arc<Mutex<OwnedWriteHalf>>,
    keys: &SessionKeys,
    sender_id: &str,
    recipient_id: &str,
    plaintext: &[u8],
) -> io::Result<()> {
    let cipher_enc = Aes256CbcEnc::new(keys.key.as_slice().into(), keys.iv.as_slice().into());
    let mut buffer = vec![0u8; plaintext.len() + 16];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    let encrypted = cipher_enc
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encryption error: {}", e)))?;
    send_encrypted_to_client_with_sender_recipient(write, sender_id, recipient_id, &encrypted).await
}

async fn broadcast_system_message(
    state: &Arc<Mutex<AppState>>,
    message: &str,
    exclude_id: Option<&str>,
) {
    let state_guard = state.lock().await;
    let sessions = &state_guard.sessions;
    for (_, session) in sessions {
        let (connected, write, username) = {
            let guard = session.lock().await;
            (guard.connected, guard.write.clone(), guard.username.clone())
        };
        if connected {
            if let Some(w) = write {
                if let Some(uname) = username {
                    if Some(uname.as_str()) == exclude_id {
                        continue;
                    }
                }
                let _ = send_system_message_to_client(&w, message).await;
            }
        }
    }
}

// ---- Обработчик клиента ----
async fn handle_client(
    stream: TcpStream,
    state: Arc<Mutex<AppState>>,
) {
    println!("[Сервер] Принято соединение");

    let (keys, read, write) = handshake(stream).await;
    let write = Arc::new(Mutex::new(write));
    let session = Arc::new(Mutex::new(Session::new(read, write, keys)));
    let temp_id = Uuid::new_v4().to_string();

    {
        let mut state_guard = state.lock().await;
        state_guard.sessions.insert(temp_id.clone(), session.clone());
    }
    println!("[Сервер] Временная сессия создана, ожидаем аутентификацию");

    // --- Аутентификация ---
    let auth_result: Option<(Arc<Mutex<Session>>, String, String, String, OwnedReadHalf)> = 'auth: {
        let mut read = {
            let mut guard = session.lock().await;
            guard.read.take().expect("read half missing")
        };

        let mut type_byte = [0u8; 1];
        if let Err(e) = read.read_exact(&mut type_byte).await {
            eprintln!("[Сервер] Ошибка чтения типа аутентификации: {}", e);
            return;
        }
        if type_byte[0] != MSG_TYPE_AUTH {
            eprintln!("[Сервер] Ожидался MSG_TYPE_AUTH, получено {}", type_byte[0]);
            return;
        }
        println!("[Сервер] Получен пакет аутентификации");

        let mut len_buf = [0u8; 4];
        if let Err(e) = read.read_exact(&mut len_buf).await {
            eprintln!("[Сервер] Ошибка чтения длины аутентификации: {}", e);
            return;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        if let Err(e) = read.read_exact(&mut data).await {
            eprintln!("[Сервер] Ошибка чтения данных аутентификации: {}", e);
            return;
        }
        let auth_str = String::from_utf8(data).unwrap_or_default();
        let parts: Vec<&str> = auth_str.split('|').collect();
        if parts.len() < 3 {
            eprintln!("[Сервер] Неверный формат аутентификации: ожидается команда|телефон|пароль [|устройство], получено {:?}", parts);
            return;
        }
        let command = parts[0];

        // Если команда "token" – восстановление сессии
        if command == "token" {
            if parts.len() < 2 {
                eprintln!("[Сервер] Неверный формат token команды");
                return;
            }
            let token = parts[1].trim();
            let db = state.lock().await.db.clone();
            let token_str = token.to_string();
            let result = tokio::task::spawn_blocking(move || {
                let mut conn = db.lock().unwrap();
                AppState::check_session(&mut conn, &token_str)
            }).await.unwrap();
            match result {
                Ok((user_id, username_db)) => {
                    println!("[Сервер] Восстановление сессии по токену, user_id={}, username={}", user_id, username_db);
                    let write = {
                        let guard = session.lock().await;
                        guard.write.clone().unwrap()
                    };
                    let msg = format!("Успех|{}|{}|{}", user_id, token, username_db);
                    let mut w = write.lock().await;
                    let _ = w.write_all(&[MSG_TYPE_SYSTEM]).await;
                    let _ = w.write_all(&(msg.len() as u32).to_be_bytes()).await;
                    let _ = w.write_all(msg.as_bytes()).await;
                    let _ = w.flush().await;
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
                    break 'auth Some((session.clone(), user_id, username_db, token.to_string(), read));
                }
                Err(e) => {
                    eprintln!("[Сервер] Ошибка восстановления сессии: {}", e);
                    let write = {
                        let guard = session.lock().await;
                        guard.write.clone().unwrap()
                    };
                    let _ = send_system_message_to_client(&write, &format!("[Система] Ошибка: {}", e)).await;
                    return;
                }
            }
        }

        // Обычный логин/регистрация
        let phone = parts[1].trim().to_string();
        let password = parts[2].trim().to_string();
        let device_name = if parts.len() > 3 { parts[3].trim().to_string() } else { "unknown".to_string() };
        let mut username = String::new();
        let mut first_name = None;
        let mut last_name = None;
        if command == "register" {
            if parts.len() >= 7 {
                first_name = Some(parts[3].trim());
                last_name = Some(parts[4].trim());
                username = parts[5].trim().to_string();
            } else if parts.len() >= 6 {
                first_name = Some(parts[3].trim());
                last_name = Some(parts[4].trim());
                username = phone.clone();
            } else {
                username = phone.clone();
            }
        }

        println!("[Сервер] Аутентификация: команда={}, телефон={}", command, phone);

        let db = state.lock().await.db.clone();
        let cmd = command.to_string();
        let ph = phone.clone();
        let pwd = password.clone();
        let dev = device_name.clone();
        let reg_username = username.clone();
        let reg_first_name = first_name.map(|s| s.to_string());
        let reg_last_name = last_name.map(|s| s.to_string());

        let reg_username_for_closure = reg_username.clone();
        let reg_first_name_for_closure = reg_first_name.clone();
        let reg_last_name_for_closure = reg_last_name.clone();

        let result = tokio::task::spawn_blocking(move || {
            let mut conn = db.lock().unwrap();
            match cmd.as_str() {
                "register" => {
                    let username = if reg_username_for_closure.is_empty() { ph.clone() } else { reg_username_for_closure };
                    let first_name_ref = reg_first_name_for_closure.as_deref();
                    let last_name_ref = reg_last_name_for_closure.as_deref();
                    AppState::register_user(&mut conn, &username, &ph, &pwd, first_name_ref, last_name_ref)
                }
                "login" => AppState::login_user_by_phone(&mut conn, &ph, &pwd),
                _ => Err("Неизвестная команда".to_string()),
            }
        }).await.unwrap();

        match result {
            Ok(user_id) => {
                println!("[Сервер] Аутентификация успешна для user_id={}", user_id);
                let username = if command == "register" && !reg_username.is_empty() {
                    reg_username
                } else if command == "login" {
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
                    match username_from_db {
                        Ok(uname) => uname,
                        Err(_) => phone
                    }
                } else {
                    phone
                };

                let db2 = state.lock().await.db.clone();
                let uid = user_id.clone();
                let dev2 = dev.clone();
                let token_result = tokio::task::spawn_blocking(move || {
                    let mut conn = db2.lock().unwrap();
                    AppState::create_session(&mut conn, &uid, &dev2)
                }).await.unwrap();

                match token_result {
                    Ok(token) => {
                        println!("[Сервер] Сессия создана, токен: {}", token);
                        {
                            let mut guard = session.lock().await;
                            guard.user_id = Some(user_id.clone());
                            guard.username = Some(username.clone());
                            guard.token = Some(token.clone());
                        }
                        let write = {
                            let guard = session.lock().await;
                            guard.write.clone().unwrap()
                        };
                        let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                        let mut w = write.lock().await;
                        if let Err(e) = w.write_all(&[MSG_TYPE_SYSTEM]).await {
                            eprintln!("[Сервер] Ошибка записи типа: {}", e);
                        } else if let Err(e) = w.write_all(&(msg.len() as u32).to_be_bytes()).await {
                            eprintln!("[Сервер] Ошибка записи длины: {}", e);
                        } else if let Err(e) = w.write_all(msg.as_bytes()).await {
                            eprintln!("[Сервер] Ошибка записи данных: {}", e);
                        } else if let Err(e) = w.flush().await {
                            eprintln!("[Сервер] Ошибка flush: {}", e);
                        } else {
                            println!("[Сервер] Токен успешно отправлен: {}", token);
                        }
                        {
                            let mut state_guard = state.lock().await;
                            state_guard.sessions.remove(&temp_id);
                            state_guard.sessions.insert(token.clone(), session.clone());
                            state_guard.online_users.insert(username.clone(), user_id.clone());
                        }
                        let msg = format!("[Система] Пользователь {} подключился", username);
                        broadcast_system_message(&state, &msg, Some(&username)).await;
                        break 'auth Some((session.clone(), user_id, username, token, read));
                    }
                    Err(e) => {
                        eprintln!("[Сервер] Ошибка создания сессии: {}", e);
                        let write = {
                            let guard = session.lock().await;
                            guard.write.clone().unwrap()
                        };
                        let _ = send_system_message_to_client(&write, &format!("[Система] Ошибка создания сессии: {}", e)).await;
                        return;
                    }
                }
            }
            Err(e) => {
                eprintln!("[Сервер] Ошибка аутентификации: {}", e);
                let write = {
                    let guard = session.lock().await;
                    guard.write.clone().unwrap()
                };
                let _ = send_system_message_to_client(&write, &format!("[Система] Ошибка: {}", e)).await;
                return;
            }
        }
    };

    if let Some((session_arc, user_id, username, token, read)) = auth_result {
        // Восстанавливаем read в сессии
        {
            let mut guard = session_arc.lock().await;
            guard.read = Some(read);
        }

        println!("[Сервер] Клиент {} ({}) аутентифицирован, токен {}", username, user_id, token);
        println!("[Сервер] Загружаем историю для {}", username);

        // ---- Загрузка истории личных сообщений ----
        let db = state.lock().await.db.clone();
        let uname = username.clone();
        let history = tokio::task::spawn_blocking(move || {
            let mut conn = db.lock().unwrap();
            AppState::get_user_messages(&mut conn, &uname, 50)
        }).await.unwrap();

        if let Ok(msgs) = history {
            println!("[Сервер] Найдено {} личных сообщений", msgs.len());
            let write = {
                let guard = session_arc.lock().await;
                guard.write.clone().unwrap()
            };
            let keys = {
                let guard = session_arc.lock().await;
                guard.keys.clone()
            };
            for (sender, recipient, content) in msgs {
                let _ = send_user_message_to_client(&write, &keys, &sender, &recipient, content.as_bytes()).await;
            }
        }

        // ---- Загрузка истории групповых сообщений ----
        let db = state.lock().await.db.clone();
        let uname2 = username.clone();
        let groups_history = tokio::task::spawn_blocking(move || {
            let mut conn = db.lock().unwrap();
            let group_names = {
                let mut stmt = conn.prepare(
                    "SELECT g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.username = ?"
                ).map_err(|e| e.to_string())?;
                let mut rows = stmt.query([&uname2]).map_err(|e| e.to_string())?;
                let mut names = Vec::new();
                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                    let name: String = row.get(0).map_err(|e| e.to_string())?;
                    names.push(name);
                }
                names
            };
            let mut all_msgs = Vec::new();
            for gname in group_names {
                let msgs = AppState::get_group_messages(&mut conn, &gname, 50)?;
                for (sender, content) in msgs {
                    all_msgs.push((sender, content, gname.clone()));
                }
            }
            Ok::<_, String>(all_msgs)
        }).await.unwrap();

        if let Ok(msgs) = groups_history {
            let write = {
                let guard = session_arc.lock().await;
                guard.write.clone().unwrap()
            };
            let keys = {
                let guard = session_arc.lock().await;
                guard.keys.clone()
            };
            for (sender, content, gname) in msgs {
                let recipient = format!("#{}", gname);
                let _ = send_user_message_to_client(&write, &keys, &sender, &recipient, content.as_bytes()).await;
            }
        }

        // ---- Загрузка истории каналов ----
        let db = state.lock().await.db.clone();
        let uname3 = username.clone();
        let channels_history = tokio::task::spawn_blocking(move || {
            let mut conn = db.lock().unwrap();
            let channel_names = {
                let mut stmt = conn.prepare(
                    "SELECT c.name FROM channels c JOIN channel_subscribers cs ON c.id = cs.channel_id WHERE cs.username = ?"
                ).map_err(|e| e.to_string())?;
                let mut rows = stmt.query([&uname3]).map_err(|e| e.to_string())?;
                let mut names = Vec::new();
                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                    let name: String = row.get(0).map_err(|e| e.to_string())?;
                    names.push(name);
                }
                names
            };
            let mut all_msgs = Vec::new();
            for ch_name in channel_names {
                let msgs = AppState::get_channel_messages(&mut conn, &ch_name, 50)?;
                for (sender, content) in msgs {
                    all_msgs.push((sender, content, ch_name.clone()));
                }
            }
            Ok::<_, String>(all_msgs)
        }).await.unwrap();

        if let Ok(msgs) = channels_history {
            let write = {
                let guard = session_arc.lock().await;
                guard.write.clone().unwrap()
            };
            let keys = {
                let guard = session_arc.lock().await;
                guard.keys.clone()
            };
            for (sender, content, ch_name) in msgs {
                let recipient = format!("&{}", ch_name);
                let _ = send_user_message_to_client(&write, &keys, &sender, &recipient, content.as_bytes()).await;
            }
        }

        // ---- Список онлайн-пользователей ----
        let user_list = {
            let state_guard = state.lock().await;
            let users: Vec<String> = state_guard.online_users.keys().cloned().collect();
            users
        };
        if !user_list.is_empty() {
            let write = {
                let guard = session_arc.lock().await;
                guard.write.clone().unwrap()
            };
            let msg = format!("[Система] Онлайн: {}", user_list.join(", "));
            let _ = send_system_message_to_client(&write, &msg).await;
        }

        // ---- Основной цикл ----
        loop {
            let mut read = {
                let mut guard = session_arc.lock().await;
                guard.read.take().expect("read half missing")
            };
            let keys = {
                let guard = session_arc.lock().await;
                guard.keys.clone()
            };
            let my_username = username.clone();

            let mut type_byte = [0u8; 1];
            if let Err(e) = read.read_exact(&mut type_byte).await {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    println!("[Сервер] Клиент {} отключился (EOF)", my_username);
                } else {
                    eprintln!("[Сервер] Ошибка чтения типа от {}: {}", my_username, e);
                }
                {
                    let mut state_guard = state.lock().await;
                    state_guard.online_users.remove(&my_username);
                    state_guard.sessions.remove(&token);
                }
                let msg = format!("[Система] Пользователь {} отключился", my_username);
                broadcast_system_message(&state, &msg, Some(&my_username)).await;
                {
                    let mut guard = session_arc.lock().await;
                    guard.read = Some(read);
                }
                return;
            }

            match type_byte[0] {
                MSG_TYPE_USER => {
                    let mut len_buf = [0u8; 4];
                    if let Err(e) = read.read_exact(&mut len_buf).await {
                        eprintln!("[Сервер] Ошибка чтения длины ID получателя: {}", e);
                        let mut guard = session_arc.lock().await;
                        guard.read = Some(read);
                        continue;
                    }
                    let target_len = u32::from_be_bytes(len_buf) as usize;
                    let mut target_bytes = vec![0u8; target_len];
                    if let Err(e) = read.read_exact(&mut target_bytes).await {
                        eprintln!("[Сервер] Ошибка чтения ID получателя: {}", e);
                        let mut guard = session_arc.lock().await;
                        guard.read = Some(read);
                        continue;
                    }
                    let target = String::from_utf8(target_bytes).unwrap_or_default();

                    let mut msg_len_buf = [0u8; 4];
                    if let Err(e) = read.read_exact(&mut msg_len_buf).await {
                        eprintln!("[Сервер] Ошибка чтения длины сообщения: {}", e);
                        let mut guard = session_arc.lock().await;
                        guard.read = Some(read);
                        continue;
                    }
                    let msg_len = u32::from_be_bytes(msg_len_buf) as usize;
                    let mut encrypted = vec![0u8; msg_len];
                    if let Err(e) = read.read_exact(&mut encrypted).await {
                        eprintln!("[Сервер] Ошибка чтения сообщения: {}", e);
                        let mut guard = session_arc.lock().await;
                        guard.read = Some(read);
                        continue;
                    }

                    let cipher_dec = Aes256CbcDec::new(keys.key.as_slice().into(), keys.iv.as_slice().into());
                    let plaintext = match cipher_dec.decrypt_padded_mut::<Pkcs7>(&mut encrypted) {
                        Ok(data) => data.to_vec(),
                        Err(e) => {
                            eprintln!("[Сервер] Ошибка расшифровки: {}", e);
                            let mut guard = session_arc.lock().await;
                            guard.read = Some(read);
                            continue;
                        }
                    };
                    let content = String::from_utf8_lossy(&plaintext).to_string();
                    println!("[Сервер] Получено сообщение от {} для {}: {}", my_username, target, content);

                    // ---- Команды из текста (для чата с собой) ----
                    if content.starts_with('/') {
                        let cmd_parts: Vec<&str> = content.split_whitespace().collect();
                        if cmd_parts.is_empty() {
                            let mut guard = session_arc.lock().await;
                            guard.read = Some(read);
                            continue;
                        }
                        let cmd = cmd_parts[0];
                        let args = &cmd_parts[1..];
                        let write = {
                            let guard = session_arc.lock().await;
                            guard.write.clone().unwrap()
                        };
                        let response = match cmd {
                            "/creategroup" => {
                                if args.is_empty() {
                                    "[Система] Использование: /creategroup <название>".to_string()
                                } else {
                                    let group_name = args.join(" ");
                                    let db = state.lock().await.db.clone();
                                    let uname_clone = my_username.clone();
                                    let gname_clone = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::create_group(&mut conn, &gname_clone, &uname_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let gname_clone = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::join_group(&mut conn, &gname_clone, &uname_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let gname_clone = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::leave_group(&mut conn, &gname_clone, &uname_clone)
                                    }).await.unwrap();
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
                                    let gname_clone = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::get_group_members(&mut conn, &gname_clone)
                                    }).await.unwrap();
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
                                let uname_clone = my_username.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    let mut stmt = conn.prepare(
                                        "SELECT g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.username = ?"
                                    ).map_err(|e| e.to_string())?;
                                    let mut rows = stmt.query([&uname_clone]).map_err(|e| e.to_string())?;
                                    let mut groups = Vec::new();
                                    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                                        let name: String = row.get(0).map_err(|e| e.to_string())?;
                                        groups.push(name);
                                    }
                                    Ok::<_, String>(groups)
                                }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let ch_name = channel_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::create_channel(&mut conn, &ch_name, &uname_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let ch_name = channel_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::subscribe_channel(&mut conn, &ch_name, &uname_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let ch_name = channel_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::unsubscribe_channel(&mut conn, &ch_name, &uname_clone)
                                    }).await.unwrap();
                                    match result {
                                        Ok(_) => format!("[Система] Вы отписались от канала {}", channel_name),
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            "/channels" => {
                                let db = state.lock().await.db.clone();
                                let uname_clone = my_username.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    let mut stmt = conn.prepare(
                                        "SELECT c.name, c.creator_username FROM channels c JOIN channel_subscribers cs ON c.id = cs.channel_id WHERE cs.username = ?"
                                    ).map_err(|e| e.to_string())?;
                                    let mut rows = stmt.query([&uname_clone]).map_err(|e| e.to_string())?;
                                    let mut channels = Vec::new();
                                    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                                        let name: String = row.get(0).map_err(|e| e.to_string())?;
                                        let creator: String = row.get(1).map_err(|e| e.to_string())?;
                                        channels.push(format!("{}|{}", name, creator));
                                    }
                                    Ok::<_, String>(channels)
                                }).await.unwrap();
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
                                    let mut stmt = conn.prepare(
                                        "SELECT username, first_name, last_name FROM users ORDER BY username"
                                    ).map_err(|e| e.to_string())?;
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
                                }).await.unwrap();
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
                                let uname_clone = my_username.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::get_profile(&mut conn, &uname_clone)
                                }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let fn_clone = first_name.to_string();
                                    let ln_clone = last_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::set_name(&mut conn, &uname_clone, &fn_clone, &ln_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let dn_clone = display_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::set_display_name(&mut conn, &uname_clone, &dn_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let nu_clone = new_username.to_string();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::set_username(&mut conn, &uname_clone, &nu_clone)
                                    }).await.unwrap();
                                    match result {
                                        Ok(_) => {
                                            {
                                                let mut guard = session_arc.lock().await;
                                                guard.username = Some(new_username.to_string());
                                            }
                                            format!("[Система] Username изменён на {}", new_username)
                                        }
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            _ => format!("[Система] Неизвестная команда: {}", content),
                        };
                        let _ = send_system_message_to_client(&write, &response).await;
                        let mut guard = session_arc.lock().await;
                        guard.read = Some(read);
                        continue;
                    }

                    // ---- Групповое сообщение (#) ----
                    if target.starts_with('#') {
                        let group_name = target.trim_start_matches('#');
                        let db = state.lock().await.db.clone();
                        let uname_clone = my_username.clone();
                        let gname_clone = group_name.to_string();
                        let is_member = tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            let mut stmt = conn.prepare(
                                "SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE g.name = ? AND gm.username = ?"
                            ).map_err(|e| format!("Ошибка запроса: {}", e))?;
                            let mut rows = stmt.query(params![gname_clone, uname_clone])
                                .map_err(|e| format!("Ошибка выполнения: {}", e))?;
                            Ok::<_, String>(rows.next().map_err(|e| format!("Ошибка чтения: {}", e))?.is_some())
                        }).await.unwrap().unwrap_or(false);

                        if !is_member {
                            let write = {
                                let guard = session_arc.lock().await;
                                guard.write.clone().unwrap()
                            };
                            let _ = send_system_message_to_client(&write, "[Система] Вы не состоите в этой группе").await;
                            let mut guard = session_arc.lock().await;
                            guard.read = Some(read);
                            continue;
                        }

                        let db = state.lock().await.db.clone();
                        let sender = my_username.clone();
                        let recipient_group = group_name.to_string();
                        let cnt = content.clone();
                        tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            let _ = AppState::store_group_message(&mut conn, &recipient_group, &sender, &cnt);
                        }).await.unwrap();

                        let db = state.lock().await.db.clone();
                        let gname = group_name.to_string();
                        let members = tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            AppState::get_group_members(&mut conn, &gname)
                        }).await.unwrap().unwrap_or_default();

                        let recipient_group_with_hash = format!("#{}", group_name);
                        let write = {
                            let guard = session_arc.lock().await;
                            guard.write.clone().unwrap()
                        };

                        for member in members {
                            if member == my_username {
                                continue;
                            }
                            let target_online = {
                                let state_guard = state.lock().await;
                                state_guard.online_users.contains_key(&member)
                            };
                            if target_online {
                                let target_token = {
                                    let state_guard = state.lock().await;
                                    let mut found = None;
                                    for (tok, sess) in &state_guard.sessions {
                                        let guard = sess.lock().await;
                                        if let Some(uname) = &guard.username {
                                            if uname == &member {
                                                found = Some(tok.clone());
                                                break;
                                            }
                                        }
                                    }
                                    found
                                };
                                if let Some(tok) = target_token {
                                    let target_session = {
                                        let state_guard = state.lock().await;
                                        state_guard.sessions.get(&tok).cloned()
                                    };
                                    if let Some(ts) = target_session {
                                        let (target_write, target_keys) = {
                                            let guard = ts.lock().await;
                                            (guard.write.clone().unwrap(), guard.keys.clone())
                                        };
                                        let _ = send_user_message_to_client(&target_write, &target_keys, &my_username, &recipient_group_with_hash, content.as_bytes()).await;
                                    }
                                }
                            } else {
                                println!("[Сервер] Групповое сообщение для {} сохранено в БД", member);
                            }
                        }

                        let _ = send_user_message_to_client(&write, &keys, &my_username, &recipient_group_with_hash, content.as_bytes()).await;
                    }
                    // ---- Канальное сообщение (&) ----
                    else if target.starts_with('&') {
                        let channel_name = target.trim_start_matches('&');
                        let db = state.lock().await.db.clone();
                        let uname_clone = my_username.clone();
                        let ch_name = channel_name.to_string();
                        let is_subscribed = tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            let mut stmt = conn.prepare(
                                "SELECT 1 FROM channel_subscribers cs JOIN channels c ON cs.channel_id = c.id WHERE c.name = ? AND cs.username = ?"
                            ).map_err(|e| format!("Ошибка запроса: {}", e))?;
                            let mut rows = stmt.query(params![ch_name, uname_clone])
                                .map_err(|e| format!("Ошибка выполнения: {}", e))?;
                            Ok::<_, String>(rows.next().map_err(|e| format!("Ошибка чтения: {}", e))?.is_some())
                        }).await.unwrap().unwrap_or(false);

                        if !is_subscribed {
                            let write = {
                                let guard = session_arc.lock().await;
                                guard.write.clone().unwrap()
                            };
                            let _ = send_system_message_to_client(&write, "[Система] Вы не подписаны на этот канал").await;
                            let mut guard = session_arc.lock().await;
                            guard.read = Some(read);
                            continue;
                        }

                        // ---- Проверка владельца ----
                        let is_owner = {
                            let db = state.lock().await.db.clone();
                            let ch_name = channel_name.to_string();
                            let uname = my_username.clone();
                            tokio::task::spawn_blocking(move || {
                                let mut conn = db.lock().unwrap();
                                let mut stmt = conn.prepare(
                                    "SELECT 1 FROM channels WHERE name = ? AND creator_username = ?"
                                ).map_err(|e| e.to_string())?;
                                let mut rows = stmt.query(params![ch_name, uname])
                                    .map_err(|e| e.to_string())?;
                                Ok::<_, String>(rows.next().map_err(|e| e.to_string())?.is_some())
                            }).await.unwrap().unwrap_or(false)
                        };

                        if !is_owner {
                            let write = { let guard = session_arc.lock().await; guard.write.clone().unwrap() };
                            let _ = send_system_message_to_client(&write, "[Система] Только владелец канала может отправлять сообщения").await;
                            let mut guard = session_arc.lock().await;
                            guard.read = Some(read);
                            continue;
                        }
                        // ------------------------------------------------

                        let db = state.lock().await.db.clone();
                        let sender = my_username.clone();
                        let channel_name_clone = channel_name.to_string();
                        let cnt = content.clone();
                        tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            let _ = AppState::store_channel_message(&mut conn, &channel_name_clone, &sender, &cnt);
                        }).await.unwrap();

                        let db = state.lock().await.db.clone();
                        let ch_name2 = channel_name.to_string();
                        let subscribers = tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            AppState::get_channel_subscribers(&mut conn, &ch_name2)
                        }).await.unwrap().unwrap_or_default();

                        let recipient_channel = format!("&{}", channel_name);
                        let write = {
                            let guard = session_arc.lock().await;
                            guard.write.clone().unwrap()
                        };

                        for subscriber in subscribers {
                            if subscriber == my_username {
                                continue;
                            }
                            let target_online = {
                                let state_guard = state.lock().await;
                                state_guard.online_users.contains_key(&subscriber)
                            };
                            if target_online {
                                let target_token = {
                                    let state_guard = state.lock().await;
                                    let mut found = None;
                                    for (tok, sess) in &state_guard.sessions {
                                        let guard = sess.lock().await;
                                        if let Some(uname) = &guard.username {
                                            if uname == &subscriber {
                                                found = Some(tok.clone());
                                                break;
                                            }
                                        }
                                    }
                                    found
                                };
                                if let Some(tok) = target_token {
                                    let target_session = {
                                        let state_guard = state.lock().await;
                                        state_guard.sessions.get(&tok).cloned()
                                    };
                                    if let Some(ts) = target_session {
                                        let (target_write, target_keys) = {
                                            let guard = ts.lock().await;
                                            (guard.write.clone().unwrap(), guard.keys.clone())
                                        };
                                        let _ = send_user_message_to_client(&target_write, &target_keys, &my_username, &recipient_channel, content.as_bytes()).await;
                                    }
                                }
                            } else {
                                println!("[Сервер] Сообщение в канал {} для {} сохранено в БД", channel_name, subscriber);
                            }
                        }

                        let _ = send_user_message_to_client(&write, &keys, &my_username, &recipient_channel, content.as_bytes()).await;
                    }
                    // ---- Личное сообщение ----
                    else {
                        let db = state.lock().await.db.clone();
                        let target_clone = target.clone();
                        let exists = tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            AppState::user_exists_by_username(&mut conn, &target_clone)
                        }).await.unwrap().unwrap_or(false);

                        if !exists {
                            let write = {
                                let guard = session_arc.lock().await;
                                guard.write.clone().unwrap()
                            };
                            let _ = send_system_message_to_client(&write, &format!("[Система] Пользователь {} не найден", target)).await;
                            let mut guard = session_arc.lock().await;
                            guard.read = Some(read);
                            continue;
                        }

                        let db = state.lock().await.db.clone();
                        let sender = my_username.clone();
                        let recipient = target.clone();
                        let cnt = content.clone();
                        tokio::task::spawn_blocking(move || {
                            let mut conn = db.lock().unwrap();
                            let _ = AppState::store_message(&mut conn, &sender, &recipient, &cnt);
                        }).await.unwrap();

                        let target_online = {
                            let state_guard = state.lock().await;
                            state_guard.online_users.contains_key(&target)
                        };

                        // Отправляем получателю, если он не равен отправителю
                        if target != my_username && target_online {
                            let target_tokens = {
                                let state_guard = state.lock().await;
                                let mut tokens = Vec::new();
                                for (tok, sess) in &state_guard.sessions {
                                    let guard = sess.lock().await;
                                    if let Some(uname) = &guard.username {
                                        if uname == &target {
                                            tokens.push(tok.clone());
                                        }
                                    }
                                }
                                tokens
                            };

                            if !target_tokens.is_empty() {
                                for tok in target_tokens {
                                    let target_session = {
                                        let state_guard = state.lock().await;
                                        state_guard.sessions.get(&tok).cloned()
                                    };
                                    if let Some(ts) = target_session {
                                        let (target_write, target_keys) = {
                                            let guard = ts.lock().await;
                                            (guard.write.clone().unwrap(), guard.keys.clone())
                                        };
                                        if let Err(e) = send_user_message_to_client(&target_write, &target_keys, &my_username, &target, &plaintext).await {
                                            eprintln!("[Сервер] Ошибка отправки сообщения {}: {}", target, e);
                                        } else {
                                            println!("[Сервер] Сообщение отправлено получателю {} (сессия {})", target, tok);
                                        }
                                    }
                                }
                            } else {
                                println!("[Сервер] Сообщение сохранено в offline для {}", target);
                            }
                        } else if target == my_username {
                            println!("[Сервер] Сообщение отправлено самому себе, получатель не вызывается");
                        } else {
                            println!("[Сервер] Сообщение сохранено в offline для {}", target);
                        }

                        // Отправка обратно отправителю (эхо)
                        let write = {
                            let guard = session_arc.lock().await;
                            guard.write.clone().unwrap()
                        };
                        let _ = send_user_message_to_client(&write, &keys, &my_username, &target, &plaintext).await;
                    }

                    let mut guard = session_arc.lock().await;
                    guard.read = Some(read);
                }

                MSG_TYPE_COMMAND => {
                    let mut len_buf = [0u8; 4];
                    if let Err(e) = read.read_exact(&mut len_buf).await {
                        eprintln!("[Сервер] Ошибка чтения длины команды: {}", e);
                        let mut guard = session_arc.lock().await;
                        guard.read = Some(read);
                        continue;
                    }
                    let cmd_len = u32::from_be_bytes(len_buf) as usize;
                    let mut cmd_bytes = vec![0u8; cmd_len];
                    if let Err(e) = read.read_exact(&mut cmd_bytes).await {
                        eprintln!("[Сервер] Ошибка чтения команды: {}", e);
                        let mut guard = session_arc.lock().await;
                        guard.read = Some(read);
                        continue;
                    }
                    let cmd = String::from_utf8(cmd_bytes).unwrap_or_default();
                    println!("[Сервер] Получена команда через MSG_TYPE_COMMAND: {}", cmd);

                    let cmd_parts: Vec<&str> = cmd.split_whitespace().collect();
                    if !cmd_parts.is_empty() {
                        let cmd_name = cmd_parts[0];
                        let args = &cmd_parts[1..];
                        let write = {
                            let guard = session_arc.lock().await;
                            guard.write.clone().unwrap()
                        };
                        let response = match cmd_name {
                            "/creategroup" => {
                                if args.is_empty() {
                                    "[Система] Использование: /creategroup <название>".to_string()
                                } else {
                                    let group_name = args.join(" ");
                                    let db = state.lock().await.db.clone();
                                    let uname_clone = my_username.clone();
                                    let gname_clone = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::create_group(&mut conn, &gname_clone, &uname_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let gname_clone = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::join_group(&mut conn, &gname_clone, &uname_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let gname_clone = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::leave_group(&mut conn, &gname_clone, &uname_clone)
                                    }).await.unwrap();
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
                                    let gname_clone = group_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::get_group_members(&mut conn, &gname_clone)
                                    }).await.unwrap();
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
                                let uname_clone = my_username.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    let mut stmt = conn.prepare(
                                        "SELECT g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.username = ?"
                                    ).map_err(|e| e.to_string())?;
                                    let mut rows = stmt.query([&uname_clone]).map_err(|e| e.to_string())?;
                                    let mut groups = Vec::new();
                                    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                                        let name: String = row.get(0).map_err(|e| e.to_string())?;
                                        groups.push(name);
                                    }
                                    Ok::<_, String>(groups)
                                }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let ch_name = channel_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::create_channel(&mut conn, &ch_name, &uname_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let ch_name = channel_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::subscribe_channel(&mut conn, &ch_name, &uname_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let ch_name = channel_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::unsubscribe_channel(&mut conn, &ch_name, &uname_clone)
                                    }).await.unwrap();
                                    match result {
                                        Ok(_) => format!("[Система] Вы отписались от канала {}", channel_name),
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            "/channels" => {
                                let db = state.lock().await.db.clone();
                                let uname_clone = my_username.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    let mut stmt = conn.prepare(
                                        "SELECT c.name, c.creator_username FROM channels c JOIN channel_subscribers cs ON c.id = cs.channel_id WHERE cs.username = ?"
                                    ).map_err(|e| e.to_string())?;
                                    let mut rows = stmt.query([&uname_clone]).map_err(|e| e.to_string())?;
                                    let mut channels = Vec::new();
                                    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                                        let name: String = row.get(0).map_err(|e| e.to_string())?;
                                        let creator: String = row.get(1).map_err(|e| e.to_string())?;
                                        channels.push(format!("{}|{}", name, creator));
                                    }
                                    Ok::<_, String>(channels)
                                }).await.unwrap();
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
                                    let mut stmt = conn.prepare(
                                        "SELECT username, first_name, last_name FROM users ORDER BY username"
                                    ).map_err(|e| e.to_string())?;
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
                                }).await.unwrap();
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
                                let uname_clone = my_username.clone();
                                let result = tokio::task::spawn_blocking(move || {
                                    let mut conn = db.lock().unwrap();
                                    AppState::get_profile(&mut conn, &uname_clone)
                                }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let fn_clone = first_name.to_string();
                                    let ln_clone = last_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::set_name(&mut conn, &uname_clone, &fn_clone, &ln_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let dn_clone = display_name.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::set_display_name(&mut conn, &uname_clone, &dn_clone)
                                    }).await.unwrap();
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
                                    let uname_clone = my_username.clone();
                                    let nu_clone = new_username.to_string();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut conn = db.lock().unwrap();
                                        AppState::set_username(&mut conn, &uname_clone, &nu_clone)
                                    }).await.unwrap();
                                    match result {
                                        Ok(_) => {
                                            {
                                                let mut guard = session_arc.lock().await;
                                                guard.username = Some(new_username.to_string());
                                            }
                                            format!("[Система] Username изменён на {}", new_username)
                                        }
                                        Err(e) => format!("[Система] Ошибка: {}", e),
                                    }
                                }
                            }
                            _ => format!("[Система] Неизвестная команда: {}", cmd),
                        };
                        let _ = send_system_message_to_client(&write, &response).await;
                    }

                    let mut guard = session_arc.lock().await;
                    guard.read = Some(read);
                }

                _ => {
                    eprintln!("[Сервер] {} отправил неизвестный тип {}", my_username, type_byte[0]);
                    let mut guard = session_arc.lock().await;
                    guard.read = Some(read);
                }
            }
        }
    }
}

// ---- Обработчик сигнала ----
async fn handle_shutdown(_state: Arc<Mutex<AppState>>) {
    signal::ctrl_c().await.unwrap();
    println!("\n[Сервер] Получен сигнал завершения. Завершаем работу.");
    std::process::exit(0);
}

// ---- Точка входа ----
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_path = "data.db";
    let db = Connection::open(db_path)?;
    let mut db = db;
    AppState::init_db(&mut db)?;

    let state = Arc::new(Mutex::new(AppState::new(db)));

    let state_clone = state.clone();
    tokio::spawn(async move {
        handle_shutdown(state_clone).await;
    });

    use std::env;

    let ip = env::var("IP").unwrap_or_else(|_| "::".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8100".to_string());
    let addr = format!("[{}]:{}", ip, port);
    let listener = TcpListener::bind(&addr).await?;
    println!("[Сервер] Запущен на 0.0.0.0:8080 с БД и аутентификацией.");

    loop {
        let (stream, _) = listener.accept().await?;
        let state_clone = state.clone();
        tokio::spawn(async move {
            handle_client(stream, state_clone).await;
        });
    }
}