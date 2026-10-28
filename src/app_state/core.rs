use dashmap::DashMap;
use deadpool_postgres::Pool;
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

// ==================== AppState (Postgres Pool + DashMap) ====================
pub struct AppState {
    pub db: Pool,
    pub sessions: DashMap<String, Arc<Session>>,
    pub online_users: DashMap<String, Vec<String>>,
    // Кэши для быстрого поиска без запросов в БД
    pub username_to_id: DashMap<String, String>,
    pub id_to_username: DashMap<String, String>,
}

impl AppState {
    pub fn new(db: Pool) -> Self {
        Self {
            db,
            sessions: DashMap::new(),
            online_users: DashMap::new(),
            username_to_id: DashMap::new(),
            id_to_username: DashMap::new(),
        }
    }

    // Асинхронный аналог старого метода из DbState
    pub async fn resolve_username(&self, id: &str) -> String {
        // 1. Пытаемся найти в кэше
        if let Some(name) = self.id_to_username.get(id) {
            return name.clone();
        }

        // 2. Если нет — идем в базу
        match self.db.get().await {
            Ok(client) => {
                match client
                    .query_opt("SELECT username FROM users WHERE id = $1", &[&id])
                    .await
                {
                    Ok(Some(row)) => {
                        let name: String = row.get(0);
                        // Обновляем кэш
                        self.id_to_username.insert(id.to_string(), name.clone());
                        self.username_to_id.insert(name.clone(), id.to_string());
                        name
                    }
                    _ => DELETED_LABEL.to_string(), // Если юзер удален или ошибка
                }
            }
            Err(_) => DELETED_LABEL.to_string(), // Если нет коннекта к БД
        }
    }

    // Асинхронный аналог старого метода из DbState
    pub async fn resolve_id(&self, username: &str) -> Option<String> {
        // 1. Пытаемся найти в кэше
        if let Some(id) = self.username_to_id.get(username) {
            return Some(id.clone());
        }

        // 2. Если нет — идем в базу
        match self.db.get().await {
            Ok(client) => {
                match client
                    .query_opt("SELECT id FROM users WHERE username = $1", &[&username])
                    .await
                {
                    Ok(Some(row)) => {
                        let id: String = row.get(0);
                        // Обновляем кэш
                        self.username_to_id.insert(username.to_string(), id.clone());
                        self.id_to_username.insert(id.clone(), username.to_string());
                        Some(id)
                    }
                    _ => None,
                }
            }
            Err(_) => None,
        }
    }
}
