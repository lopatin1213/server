use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Instant;
use tokio::sync::mpsc;
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
    pub edited: bool,
}

// ==================== Сессия (без Mutex!) ====================
pub struct Session {
    pub tx: mpsc::UnboundedSender<Message>,
    pub keys: SessionKeys,
    pub connected: AtomicBool,
    pub user_id: OnceLock<String>,
    pub username: OnceLock<String>,
    pub token: OnceLock<String>,
    pub last_msg_time: StdMutex<Instant>, // Маленький лок только для времени
    pub msg_count: AtomicUsize,
}

impl Session {
    pub fn new(tx: mpsc::UnboundedSender<Message>, keys: SessionKeys) -> Self {
        Self {
            tx,
            keys,
            connected: AtomicBool::new(true),
            user_id: OnceLock::new(),
            username: OnceLock::new(),
            token: OnceLock::new(),
            last_msg_time: StdMutex::new(Instant::now()),
            msg_count: AtomicUsize::new(0),
        }
    }

    pub fn check_rate_limit(&self) -> bool {
        let now = Instant::now();
        let mut last = self.last_msg_time.lock().unwrap();
        if now.duration_since(*last) > RATE_LIMIT_WINDOW {
            *last = now;
            self.msg_count.store(1, Ordering::Relaxed);
            true
        } else {
            let count = self.msg_count.fetch_add(1, Ordering::Relaxed) + 1;
            count <= RATE_LIMIT_MAX
        }
    }
}

// ==================== DbState (не трогаем, пока SQLite) ====================
pub struct DbState {
    pub conn: rusqlite::Connection,
    pub username_to_id: std::collections::HashMap<String, String>,
    pub id_to_username: std::collections::HashMap<String, String>,
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

// ==================== AppState (DashMap) ====================
pub struct AppState {
    pub db: Arc<StdMutex<DbState>>,
    pub sessions: DashMap<String, Arc<Session>>,
    pub online_users: DashMap<String, Vec<String>>,
}

impl AppState {
    pub fn new(db: DbState) -> Self {
        Self {
            db: Arc::new(StdMutex::new(db)),
            sessions: DashMap::new(),
            online_users: DashMap::new(),
        }
    }
}
