use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;

use crate::constants::*;

// ==================== Ключи сессии ====================
#[derive(Clone)]
pub struct SessionKeys {
    pub key: [u8; 32],
}

// ==================== Поля сообщения для отправки ====================
#[derive(Clone, Copy, Debug)]
pub struct MsgFields {
    pub timestamp: i64,
    pub msg_id: i64,
    pub reply_to_id: i64,
    pub flag_me: bool,
    pub flag_any: bool,
    pub views: Option<u32>,
}

// ==================== Сессия ====================
pub struct Session {
    pub tx: mpsc::UnboundedSender<Message>,
    pub keys: SessionKeys,
    pub connected: bool,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub token: Option<String>,
    pub last_msg_time: Instant,
    pub msg_count: usize,
}

impl Session {
    pub fn new(tx: mpsc::UnboundedSender<Message>, keys: SessionKeys) -> Self {
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

    pub fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        if now - self.last_msg_time > RATE_LIMIT_WINDOW {
            self.last_msg_time = now;
            self.msg_count = 1;
            true
        } else {
            self.msg_count += 1;
            self.msg_count <= RATE_LIMIT_MAX
        }
    }
}

// ==================== DbState ====================
pub struct DbState {
    pub conn: rusqlite::Connection,
    pub username_to_id: HashMap<String, String>,
    pub id_to_username: HashMap<String, String>,
}

impl DbState {
    pub fn resolve_username(&mut self, id: &str) -> String {
        if let Some(name) = self.id_to_username.get(id) {
            return name.clone();
        }
        let r: Result<String, _> =
            self.conn
                .query_row("SELECT username FROM users WHERE id = ?", [id], |row| {
                    row.get(0)
                });
        match r {
            Ok(name) => {
                self.id_to_username.insert(id.to_string(), name.clone());
                self.username_to_id.insert(name.clone(), id.to_string());
                name
            }
            Err(_) => DELETED_LABEL.to_string(),
        }
    }

    pub fn resolve_id(&mut self, username: &str) -> Option<String> {
        if let Some(id) = self.username_to_id.get(username) {
            return Some(id.clone());
        }
        let r: Result<String, _> = self.conn.query_row(
            "SELECT id FROM users WHERE username = ?",
            [username],
            |row| row.get(0),
        );
        match r {
            Ok(id) => {
                self.username_to_id.insert(username.to_string(), id.clone());
                self.id_to_username.insert(id.clone(), username.to_string());
                Some(id)
            }
            Err(_) => None,
        }
    }
}

// ==================== AppState ====================
pub struct AppState {
    pub db: Arc<StdMutex<DbState>>,
    pub sessions: HashMap<String, Arc<Mutex<Session>>>,
    pub online_users: HashMap<String, Vec<String>>,
}

impl AppState {
    pub fn new(db: DbState) -> Self {
        Self {
            db: Arc::new(StdMutex::new(db)),
            sessions: HashMap::new(),
            online_users: HashMap::new(),
        }
    }
}
