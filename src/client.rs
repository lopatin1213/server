use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use log::{debug, error, info, warn};
use rusqlite::params;
use serde_json::json;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::app_state::{AppState, MsgFields, Session, SessionKeys};
use crate::constants::*;
use crate::fcm::send_fcm_push_and_cleanup;

// ==================== Handshake ====================
pub async fn ws_handshake(
    stream: &mut tokio_tungstenite::WebSocketStream<TcpStream>,
) -> Result<SessionKeys, String> {
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
    let client_key: [u8; 32] = data.to_vec().try_into().map_err(|_| "Invalid key array")?;
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
    Ok(SessionKeys { key })
}

// ==================== Хелперы для отправки ====================
pub async fn send_system_message(
    tx: &mpsc::UnboundedSender<Message>,
    text: &str,
) -> Result<(), String> {
    let bytes = text.as_bytes();
    let mut data = Vec::with_capacity(1 + 4 + bytes.len());
    data.push(MSG_TYPE_SYSTEM);
    data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(bytes);
    tx.send(Message::Binary(data.into()))
        .map_err(|e| format!("send error: {}", e))
}

pub fn build_delete_packet(msg_id: i64, kind: u8, dtype: u8) -> Vec<u8> {
    if dtype == MSG_DELETE_FOR_ALL {
        let mut data = Vec::with_capacity(10);
        data.push(MSG_TYPE_DELETE);
        data.extend_from_slice(&msg_id.to_be_bytes());
        data.push(kind);
        data
    } else {
        let mut data = Vec::with_capacity(11);
        data.push(MSG_TYPE_DELETE);
        data.extend_from_slice(&msg_id.to_be_bytes());
        data.push(kind);
        data.push(dtype);
        data
    }
}

pub fn build_read_packet(items: &[(u8, i64)]) -> Vec<u8> {
    let mut data = Vec::with_capacity(3 + items.len() * 9);
    data.push(MSG_TYPE_READ);
    let count = items.len() as u16;
    data.extend_from_slice(&count.to_be_bytes());
    for (kind, msg_id) in items {
        data.push(*kind);
        data.extend_from_slice(&msg_id.to_be_bytes());
    }
    data
}

pub async fn send_encrypted_message(
    tx: &mpsc::UnboundedSender<Message>,
    keys: &SessionKeys,
    sender_name: &str,
    recipient_name: &str,
    plaintext: &[u8],
    fields: MsgFields,
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
    let sender_bytes = sender_name.as_bytes();
    data.extend_from_slice(&(sender_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(sender_bytes);
    let recipient_bytes = recipient_name.as_bytes();
    data.extend_from_slice(&(recipient_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(recipient_bytes);
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    data.extend_from_slice(&encrypted);
    data.extend_from_slice(&fields.timestamp.to_be_bytes());
    data.extend_from_slice(&fields.msg_id.to_be_bytes());
    data.extend_from_slice(&fields.reply_to_id.to_be_bytes());
    data.push(if fields.flag_me { 1 } else { 0 });
    data.push(if fields.flag_any { 1 } else { 0 });
    if let Some(v) = fields.views {
        data.extend_from_slice(&v.to_be_bytes());
    }
    tx.send(Message::Binary(data.into()))
        .map_err(|e| format!("send error: {}", e))
}

// ==================== История ====================
pub async fn send_chat_history(
    tx: &mpsc::UnboundedSender<Message>,
    keys: &SessionKeys,
    my_user_id: &str,
    chat: &str,
    before_id: Option<i64>,
    limit: i64,
    state: &Arc<Mutex<AppState>>,
) {
    let cursor = before_id.unwrap_or(i64::MAX);
    let db = state.lock().await.db.clone();
    let me = my_user_id.to_string();
    let chat_owned = chat.to_string();

    type HistRow = (
        i64,
        String,
        String,
        String,
        i64,
        Option<i64>,
        bool,
        bool,
        Option<u32>,
    );

    let result: Result<Vec<HistRow>, String> = tokio::task::spawn_blocking(move || {
        let mut st = db.lock().unwrap();

        let raw: Vec<HistRow> = if chat_owned.starts_with('#') {
            let gname = chat_owned.trim_start_matches('#').to_string();
            let rows: Vec<(i64, String, String, i64, Option<i64>, Option<String>)> = {
                let mut stmt = st
                    .conn
                    .prepare(
                        "SELECT gm.id, gm.sender_id, gm.content,
                            strftime('%s', gm.sent_at) * 1000, gm.reply_to_id, gm.first_read_at
                     FROM group_messages gm
                     JOIN groups g ON gm.group_id = g.id
                     LEFT JOIN hidden_messages h
                            ON h.kind = 2 AND h.msg_id = gm.id AND h.user_id = ?1
                     WHERE g.name = ?2 AND gm.id < ?3 AND h.msg_id IS NULL
                     ORDER BY gm.id DESC LIMIT ?4",
                    )
                    .map_err(|e| e.to_string())?;
                let iter = stmt
                    .query_map(params![me, gname, cursor, limit], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<i64>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                        ))
                    })
                    .map_err(|e| e.to_string())?;
                let mut v = Vec::new();
                for r in iter {
                    v.push(r.map_err(|e| e.to_string())?);
                }
                v
            };
            let mut out = Vec::with_capacity(rows.len());
            for (id, sender_id, content, ts, reply_id, first_read_at) in rows {
                let sender = st.resolve_username(&sender_id);
                let is_sender = sender_id == me;
                let flag_me = is_sender;
                let flag_any = first_read_at.is_some();
                out.push((
                    id,
                    sender,
                    chat_owned.clone(),
                    content,
                    ts,
                    reply_id,
                    flag_me,
                    flag_any,
                    None,
                ));
            }
            out
        } else if chat_owned.starts_with('&') {
            let cname = chat_owned.trim_start_matches('&').to_string();
            let rows: Vec<(i64, String, String, i64, Option<i64>, i64)> = {
                let mut stmt = st
                    .conn
                    .prepare(
                        "SELECT cm.id, cm.sender_id, cm.content,
                            strftime('%s', cm.sent_at) * 1000, cm.reply_to_id,
                            (SELECT COUNT(*) FROM channel_message_views v
                             WHERE v.channel_msg_id = cm.id)
                     FROM channel_messages cm
                     JOIN channels c ON cm.channel_id = c.id
                     LEFT JOIN hidden_messages h
                            ON h.kind = 3 AND h.msg_id = cm.id AND h.user_id = ?1
                     WHERE c.name = ?2 AND cm.id < ?3 AND h.msg_id IS NULL
                     ORDER BY cm.id DESC LIMIT ?4",
                    )
                    .map_err(|e| e.to_string())?;
                let iter = stmt
                    .query_map(params![me, cname, cursor, limit], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<i64>>(4)?,
                            row.get::<_, i64>(5).unwrap_or(0),
                        ))
                    })
                    .map_err(|e| e.to_string())?;
                let mut v = Vec::new();
                for r in iter {
                    v.push(r.map_err(|e| e.to_string())?);
                }
                v
            };
            let mut out = Vec::with_capacity(rows.len());
            for (id, sender_id, content, ts, reply_id, views) in rows {
                let sender = st.resolve_username(&sender_id);
                let v = views as u32;
                out.push((
                    id,
                    sender,
                    chat_owned.clone(),
                    content,
                    ts,
                    reply_id,
                    true,
                    v > 0,
                    Some(v),
                ));
            }
            out
        } else {
            let peer_id = match st.resolve_id(&chat_owned) {
                Some(id) => id,
                None => return Ok(Vec::new()),
            };
            let rows: Vec<(
                i64,
                String,
                String,
                String,
                i64,
                Option<i64>,
                Option<String>,
            )> = {
                let mut stmt = st
                    .conn
                    .prepare(
                        "SELECT m.id, m.sender_id, m.recipient_id, m.content,
                            strftime('%s', m.sent_at) * 1000, m.reply_to_id, m.read_at
                     FROM messages m
                     LEFT JOIN hidden_messages h
                            ON h.kind = 1 AND h.msg_id = m.id AND h.user_id = ?1
                     WHERE ((m.sender_id = ?1 AND m.recipient_id = ?2) OR
                            (m.sender_id = ?2 AND m.recipient_id = ?1))
                       AND m.id < ?3 AND h.msg_id IS NULL
                     ORDER BY m.id DESC LIMIT ?4",
                    )
                    .map_err(|e| e.to_string())?;
                let iter = stmt
                    .query_map(params![me, peer_id, cursor, limit], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, Option<i64>>(5)?,
                            row.get::<_, Option<String>>(6)?,
                        ))
                    })
                    .map_err(|e| e.to_string())?;
                let mut v = Vec::new();
                for r in iter {
                    v.push(r.map_err(|e| e.to_string())?);
                }
                v
            };
            let mut out = Vec::with_capacity(rows.len());
            for (id, sender_id, recipient_id, content, ts, reply_id, read_at) in rows {
                let sender = st.resolve_username(&sender_id);
                let recipient = st.resolve_username(&recipient_id);
                let is_sender = sender_id == me;
                let read_flag = read_at.is_some();
                let flag_me = if is_sender { true } else { read_flag };
                let flag_any = if is_sender { read_flag } else { true };
                out.push((
                    id, sender, recipient, content, ts, reply_id, flag_me, flag_any, None,
                ));
            }
            out
        };

        let mut v = raw;
        v.reverse();
        Ok(v)
    })
    .await
    .unwrap_or_else(|e| Err(format!("join: {}", e)));

    let msgs = match result {
        Ok(v) => v,
        Err(e) => {
            let _ = send_system_message(tx, &format!("[Система] Ошибка истории: {}", e)).await;
            let _ = send_system_message(tx, &format!("[Система] history_done|{}|0", chat)).await;
            return;
        }
    };

    let count = msgs.len();
    info!("История {}: отдано {} сообщений", chat, count);
    for (msg_id, sender, recipient, content, ts, reply_id, flag_me, flag_any, views) in msgs {
        let _ = send_encrypted_message(
            tx,
            keys,
            &sender,
            &recipient,
            content.as_bytes(),
            MsgFields {
                timestamp: ts,
                msg_id,
                reply_to_id: reply_id.unwrap_or(0),
                flag_me,
                flag_any,
                views,
            },
        )
        .await;
    }

    let _ = send_system_message(tx, &format!("[Система] history_done|{}|{}", chat, count)).await;
}

pub async fn send_messages_by_ids(
    tx: &mpsc::UnboundedSender<Message>,
    keys: &SessionKeys,
    my_user_id: &str,
    kind: u8,
    ids: Vec<i64>,
    state: &Arc<Mutex<AppState>>,
) {
    if ids.is_empty() {
        return;
    }
    let requested = ids.len();
    let db = state.lock().await.db.clone();
    let me = my_user_id.to_string();

    let result = tokio::task::spawn_blocking(move || {
        let mut st = db.lock().unwrap();
        AppState::get_messages_by_ids(&mut st, kind, &ids, &me)
    })
    .await
    .unwrap_or_else(|e| Err(format!("join: {}", e)));

    let msgs = match result {
        Ok(v) => v,
        Err(e) => {
            warn!("/getmsg ошибка: {}", e);
            return;
        }
    };

    info!(
        "/getmsg kind={} запрошено={} найдено={}",
        kind,
        requested,
        msgs.len()
    );
    for (msg_id, sender, recipient, content, ts, reply_id, flag_me, flag_any, views) in msgs {
        let _ = send_encrypted_message(
            tx,
            keys,
            &sender,
            &recipient,
            content.as_bytes(),
            MsgFields {
                timestamp: ts,
                msg_id,
                reply_to_id: reply_id.unwrap_or(0),
                flag_me,
                flag_any,
                views,
            },
        )
        .await;
    }
}

pub async fn resolve_display_name(
    state: &Arc<Mutex<AppState>>,
    user_id: &str,
    fallback: &str,
) -> String {
    let db = state.lock().await.db.clone();
    let uid = user_id.to_string();
    let fb = fallback.to_string();
    tokio::task::spawn_blocking(move || {
        let mut st = db.lock().unwrap();
        let raw = match AppState::get_display_name(&mut st.conn, &uid) {
            Ok(name) => name,
            _ => String::new(),
        };
        let trimmed = raw.trim();
        let result = if trimmed.is_empty() {
            fb.clone()
        } else {
            trimmed.to_string()
        };
        debug!(
            "resolve_display_name: user_id={}, raw=[{}], fallback={}, result={}",
            uid, raw, fb, result
        );
        result
    })
    .await
    .unwrap()
}

pub async fn broadcast_system_message(
    state: &Arc<Mutex<AppState>>,
    message: &str,
    exclude_username: Option<&str>,
) {
    let state_guard = state.lock().await;
    for (_, session) in &state_guard.sessions {
        let (connected, tx, username) = {
            let guard = session.lock().await;
            (guard.connected, guard.tx.clone(), guard.username.clone())
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

// ==================== process_command ====================
pub async fn process_command(
    cmd: &str,
    my_user_id: &str,
    my_username: &str,
    state: &Arc<Mutex<AppState>>,
    session: &Arc<Mutex<Session>>,
) -> String {
    let cmd_parts: Vec<&str> = cmd.split_whitespace().collect();
    if cmd_parts.is_empty() {
        return String::new();
    }
    debug!("process_command: {:#?}", cmd_parts);

    let cmd_name = cmd_parts[0];
    let args = &cmd_parts[1..];

    match cmd_name {
        "/creategroup" => {
            if args.is_empty() {
                "[Система] Использование: /creategroup <название>".to_string()
            } else {
                let group_name = args.join(" ");
                let db = state.lock().await.db.clone();
                let uid = my_user_id.to_string();
                let gname = group_name.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    AppState::create_group(&mut st.conn, &gname, &uid)
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
                let uid = my_user_id.to_string();
                let gname = group_name.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    AppState::join_group(&mut st.conn, &gname, &uid)
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
                let uid = my_user_id.to_string();
                let gname = group_name.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    AppState::leave_group(&mut st.conn, &gname, &uid)
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
                    let mut st = db.lock().unwrap();
                    let ids = AppState::get_group_members(&mut st.conn, &gname)?;
                    let names: Vec<String> = ids.iter().map(|id| st.resolve_username(id)).collect();
                    Ok::<_, String>(names)
                })
                .await
                .unwrap();
                match result {
                    Ok(members) => {
                        if members.is_empty() {
                            format!("[Система] В группе {} нет участников", group_name)
                        } else {
                            format!(
                                "[Система] Участники группы {}: {}",
                                group_name,
                                members.join(", ")
                            )
                        }
                    }
                    Err(e) => format!("[Система] Ошибка: {}", e),
                }
            }
        }
        "/listgroups" => {
            let db = state.lock().await.db.clone();
            let result = tokio::task::spawn_blocking(move || {
                let mut st = db.lock().unwrap();
                let mut stmt = st
                    .conn
                    .prepare("SELECT name, creator_id FROM groups ORDER BY name")
                    .map_err(|e| e.to_string())?;
                let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
                let mut groups = Vec::new();
                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                    let name: String = row.get(0).map_err(|e| e.to_string())?;
                    let creator_id: String = row.get(1).map_err(|e| e.to_string())?;
                    groups.push((name, creator_id));
                }
                drop(rows);
                drop(stmt);
                let out: Vec<String> = groups
                    .into_iter()
                    .map(|(name, cid)| format!("{}|{}", name, st.resolve_username(&cid)))
                    .collect();
                Ok::<_, String>(out)
            })
            .await
            .unwrap();
            match result {
                Ok(groups) => {
                    if groups.is_empty() {
                        "[Система] Нет ни одной группы".to_string()
                    } else {
                        format!(
                            "[Система] Все группы ({}): {}",
                            groups.len(),
                            groups.join(", ")
                        )
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
                let uid = my_user_id.to_string();
                let ch = channel_name.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    AppState::create_channel(&mut st.conn, &ch, &uid)
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
                let uid = my_user_id.to_string();
                let ch = channel_name.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    AppState::subscribe_channel(&mut st.conn, &ch, &uid)
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
                let uid = my_user_id.to_string();
                let ch = channel_name.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    AppState::unsubscribe_channel(&mut st.conn, &ch, &uid)
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
            let uid = my_user_id.to_string();
            let result = tokio::task::spawn_blocking(move || {
                let mut st = db.lock().unwrap();
                let mut stmt = st
                    .conn
                    .prepare(
                        "SELECT c.name, c.creator_id,
                                (SELECT 1 FROM channel_subscribers cs
                                 WHERE cs.channel_id = c.id AND cs.user_id = ?) AS subscribed
                         FROM channels c
                         ORDER BY c.name",
                    )
                    .map_err(|e| e.to_string())?;
                let mut rows = stmt.query([&uid]).map_err(|e| e.to_string())?;
                let mut raw = Vec::new();
                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                    let name: String = row.get(0).map_err(|e| e.to_string())?;
                    let creator_id: String = row.get(1).map_err(|e| e.to_string())?;
                    let subscribed: Option<i64> = row.get(2).ok();
                    raw.push((name, creator_id, subscribed.is_some()));
                }
                drop(rows);
                drop(stmt);
                let out: Vec<String> = raw
                    .into_iter()
                    .map(|(name, cid, sub)| {
                        format!(
                            "{}|{}|{}",
                            name,
                            st.resolve_username(&cid),
                            if sub { "1" } else { "0" }
                        )
                    })
                    .collect();
                Ok::<_, String>(out)
            })
            .await
            .unwrap();
            match result {
                Ok(channels) => {
                    if channels.is_empty() {
                        "[Система] Нет ни одного канала".to_string()
                    } else {
                        format!(
                            "[Система] Все каналы ({}): {}",
                            channels.len(),
                            channels.join(", ")
                        )
                    }
                }
                Err(e) => format!("[Система] Ошибка: {}", e),
            }
        }
        "/listusers" => {
            let db = state.lock().await.db.clone();
            let result = tokio::task::spawn_blocking(move || {
                let st = db.lock().unwrap();
                let mut stmt = st.conn
                    .prepare("SELECT phone, username, display_name, last_seen FROM users ORDER BY username")
                    .map_err(|e| e.to_string())?;
                let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
                let mut users = Vec::new();
                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                    let phone: String = row.get(0).map_err(|e| e.to_string())?;
                    let username: String = row.get(1).map_err(|e| e.to_string())?;
                    let display_name: String = row.get(2).unwrap_or_default();
                    let last_seen: i64 = row.get(3).unwrap_or(0);
                    users.push(format!("{}|{}|{}|{}", phone, username, display_name, last_seen));
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
        "/onlineusers" => {
            let state_guard = state.lock().await;
            let mut users: Vec<String> = state_guard.online_users.keys().cloned().collect();
            drop(state_guard);
            users.sort();
            if users.is_empty() {
                "[Система] Нет пользователей онлайн".to_string()
            } else {
                format!(
                    "[Система] Пользователей онлайн ({}): {}",
                    users.len(),
                    users.join(", ")
                )
            }
        }
        "/profile" => {
            let db = state.lock().await.db.clone();
            let uid = my_user_id.to_string();
            let result = tokio::task::spawn_blocking(move || {
                let mut st = db.lock().unwrap();
                AppState::get_profile(&mut st.conn, &uid)
            })
            .await
            .unwrap();
            match result {
                Ok((username, phone, first_name, last_name, display_name)) => {
                    format!(
                        "[Система] Профиль: username={}, phone={}, name={} {}, display_name={}",
                        username, phone, first_name, last_name, display_name
                    )
                }
                Err(e) => format!("[Система] Ошибка: {}", e),
            }
        }
        "/setname" => {
            if args.is_empty() {
                "[Система] Использование: /setname <имя> [фамилия]".to_string()
            } else {
                let first_name = args[0];
                let last_name = if args.len() > 1 {
                    args[1..].join(" ")
                } else {
                    "".to_string()
                };
                let db = state.lock().await.db.clone();
                let uid = my_user_id.to_string();
                let fn_ = first_name.to_string();
                let ln_ = last_name.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    AppState::set_name(&mut st.conn, &uid, &fn_, &ln_)
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
                let uid = my_user_id.to_string();
                let dn = display_name.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    AppState::set_display_name(&mut st.conn, &uid, &dn)
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
                let new_username = args[0].to_string();
                let db = state.lock().await.db.clone();
                let uid = my_user_id.to_string();
                let nu = new_username.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    AppState::set_username(&mut st, &uid, &nu)
                })
                .await
                .unwrap();
                match result {
                    Ok(_old) => {
                        let mut guard = session.lock().await;
                        guard.username = Some(new_username.clone());
                        let _ = my_username;
                        format!("[Система] Username изменён на {}", new_username)
                    }
                    Err(e) => format!("[Система] Ошибка: {}", e),
                }
            }
        }
        _ => format!("[Система] Неизвестная команда: {}", cmd),
    }
}

// ==================== handle_client ====================
pub async fn handle_client(stream: TcpStream, state: Arc<Mutex<AppState>>) {
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
        state_guard
            .sessions
            .insert(temp_id.clone(), session.clone());
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

    let tx_ping = tx.clone();
    let ping_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(PING_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            if tx_ping.send(Message::Ping(Vec::new().into())).is_err() {
                break;
            }
        }
    });

    // ---- Аутентификация ----
    let auth_data = match stream.next().await {
        Some(Ok(Message::Binary(data))) => data,
        Some(Ok(_)) => {
            error!("Ожидался бинарный пакет аутентификации");
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

    let fcm_token = if parts.len() > 4 {
        Some(parts[parts.len() - 1].trim().to_string())
    } else {
        None
    };

    let auth_result = match command {
        "token" => {
            let token = parts[1].trim();
            let device_name = if parts.len() > 3 {
                parts[2].trim().to_string()
            } else {
                "unknown".to_string()
            };

            let db = state.lock().await.db.clone();
            let token_str = token.to_string();
            let result = tokio::task::spawn_blocking(move || {
                let mut st = db.lock().unwrap();
                AppState::check_session(&mut st.conn, &token_str)
            })
            .await
            .unwrap();

            match result {
                Ok((user_id, username)) => {
                    let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                    let _ = send_system_message(&tx, &msg).await;

                    if let Some(fcm) = fcm_token {
                        let db = state.lock().await.db.clone();
                        let uid = user_id.clone();
                        let session_tok = token.to_string();
                        let fcm_tok = fcm.clone();
                        let dev = device_name.clone();
                        tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            let _ = AppState::save_fcm_token(
                                &mut st.conn,
                                &uid,
                                &session_tok,
                                &fcm_tok,
                                &dev,
                            );
                        })
                        .await
                        .unwrap();
                    }

                    {
                        let mut guard = session.lock().await;
                        guard.user_id = Some(user_id.clone());
                        guard.username = Some(username.clone());
                        guard.token = Some(token.to_string());
                    }
                    {
                        let mut state_guard = state.lock().await;
                        state_guard.sessions.remove(&temp_id);
                        state_guard
                            .sessions
                            .insert(token.to_string(), session.clone());
                        state_guard
                            .online_users
                            .entry(username.clone())
                            .or_insert_with(Vec::new)
                            .push(token.to_string());
                    }

                    {
                        let db_ls = state.lock().await.db.clone();
                        let uid_ls = user_id.clone();
                        tokio::task::spawn_blocking(move || {
                            let mut st = db_ls.lock().unwrap();
                            let _ = AppState::update_last_seen(&mut st.conn, &uid_ls);
                        })
                        .await
                        .unwrap();
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
                let mut st = db.lock().unwrap();
                AppState::login_user_by_phone(&mut st.conn, &ph, &pwd)
            })
            .await
            .unwrap();

            match result {
                Ok(user_id) => {
                    let db3 = state.lock().await.db.clone();
                    let uid = user_id.clone();
                    let username_from_db = tokio::task::spawn_blocking(move || {
                        let st = db3.lock().unwrap();
                        let mut stmt = st
                            .conn
                            .prepare("SELECT username FROM users WHERE id = ?")
                            .map_err(|e| e.to_string())?;
                        let mut rows = stmt.query([&uid]).map_err(|e| e.to_string())?;
                        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
                            Ok(row.get::<_, String>(0).map_err(|e| e.to_string())?)
                        } else {
                            Err("Пользователь не найден".to_string())
                        }
                    })
                    .await
                    .unwrap();
                    let username = username_from_db.unwrap_or_else(|_| phone.clone());

                    let db2 = state.lock().await.db.clone();
                    let uid2 = user_id.clone();
                    let dev = device_name.clone();
                    let token_result = tokio::task::spawn_blocking(move || {
                        let mut st = db2.lock().unwrap();
                        AppState::create_session(&mut st.conn, &uid2, &dev)
                    })
                    .await
                    .unwrap();

                    match token_result {
                        Ok(token) => {
                            let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                            let _ = send_system_message(&tx, &msg).await;

                            if let Some(fcm) = fcm_token {
                                let db = state.lock().await.db.clone();
                                let uid = user_id.clone();
                                let session_tok = token.clone();
                                let fcm_tok = fcm.clone();
                                let dev = device_name.clone();
                                tokio::task::spawn_blocking(move || {
                                    let mut st = db.lock().unwrap();
                                    let _ = AppState::save_fcm_token(
                                        &mut st.conn,
                                        &uid,
                                        &session_tok,
                                        &fcm_tok,
                                        &dev,
                                    );
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

                            {
                                let db_ls = state.lock().await.db.clone();
                                let uid_ls = user_id.clone();
                                tokio::task::spawn_blocking(move || {
                                    let mut st = db_ls.lock().unwrap();
                                    let _ = AppState::update_last_seen(&mut st.conn, &uid_ls);
                                })
                                .await
                                .unwrap();
                            }

                            let msg = format!("[Система] Пользователь {} подключился", username);
                            broadcast_system_message(&state, &msg, Some(&username)).await;
                            Ok((user_id, username))
                        }
                        Err(e) => {
                            error!("Ошибка создания сессии: {}", e);
                            let _ = send_system_message(
                                &tx,
                                &format!("[Система] Ошибка создания сессии: {}", e),
                            )
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
            let first_name = if parts.len() > 3 {
                Some(parts[3].trim())
            } else {
                None
            };
            let last_name = if parts.len() > 4 {
                Some(parts[4].trim())
            } else {
                None
            };
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

            let db = state.lock().await.db.clone();
            let ph = phone.clone();
            let pwd = password.clone();
            let uname = username.clone();
            let fn_opt = first_name.map(|s| s.to_string());
            let ln_opt = last_name.map(|s| s.to_string());

            let result = tokio::task::spawn_blocking(move || {
                let mut st = db.lock().unwrap();
                AppState::register_user(
                    &mut st,
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
                    let db2 = state.lock().await.db.clone();
                    let uid = user_id.clone();
                    let dev = device_name.clone();
                    let token_result = tokio::task::spawn_blocking(move || {
                        let mut st = db2.lock().unwrap();
                        AppState::create_session(&mut st.conn, &uid, &dev)
                    })
                    .await
                    .unwrap();

                    match token_result {
                        Ok(token) => {
                            let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                            let _ = send_system_message(&tx, &msg).await;

                            if let Some(fcm) = fcm_token {
                                let db = state.lock().await.db.clone();
                                let uid = user_id.clone();
                                let session_tok = token.clone();
                                let fcm_tok = fcm.clone();
                                let dev = device_name.clone();
                                tokio::task::spawn_blocking(move || {
                                    let mut st = db.lock().unwrap();
                                    let _ = AppState::save_fcm_token(
                                        &mut st.conn,
                                        &uid,
                                        &session_tok,
                                        &fcm_tok,
                                        &dev,
                                    );
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

                            {
                                let db_ls = state.lock().await.db.clone();
                                let uid_ls = user_id.clone();
                                tokio::task::spawn_blocking(move || {
                                    let mut st = db_ls.lock().unwrap();
                                    let _ = AppState::update_last_seen(&mut st.conn, &uid_ls);
                                })
                                .await
                                .unwrap();
                            }

                            let msg = format!("[Система] Пользователь {} подключился", username);
                            broadcast_system_message(&state, &msg, Some(&username)).await;
                            Ok((user_id, username))
                        }
                        Err(e) => {
                            error!("Ошибка создания сессии: {}", e);
                            let _ = send_system_message(
                                &tx,
                                &format!("[Система] Ошибка создания сессии: {}", e),
                            )
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
            let _ = send_system_message(
                &tx,
                &format!("[Система] Ошибка: Неизвестная команда {}", command),
            )
            .await;
            Err(())
        }
    };

    let (my_user_id, my_username) = match auth_result {
        Ok((uid, uname)) => (uid, uname),
        Err(_) => {
            let _ = send_task.await;
            return;
        }
    };

    // ---- Загрузка истории при логине ----
    if !my_user_id.is_empty() {
        let tx_h = tx.clone();
        let keys_h = keys.clone();
        let uid_h = my_user_id.clone();
        let state_h = state.clone();

        // Личные
        let db = state_h.lock().await.db.clone();
        let uid = uid_h.clone();
        let personal = tokio::task::spawn_blocking(move || {
            let mut st = db.lock().unwrap();
            AppState::get_recent_personal(&mut st.conn, &uid, LOGIN_PER_CHAT)
        })
        .await
        .unwrap();
        if let Ok(msgs) = personal {
            let count = msgs.len();
            for (msg_id, sender_id, recipient_id, content, ts, reply_id, flag_me, flag_any) in msgs
            {
                let db = state_h.lock().await.db.clone();
                let sid = sender_id.clone();
                let rid = recipient_id.clone();
                let (sender, recipient) = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    (st.resolve_username(&sid), st.resolve_username(&rid))
                })
                .await
                .unwrap();
                let _ = send_encrypted_message(
                    &tx_h,
                    &keys_h,
                    &sender,
                    &recipient,
                    content.as_bytes(),
                    MsgFields {
                        timestamp: ts,
                        msg_id,
                        reply_to_id: reply_id.unwrap_or(0),
                        flag_me,
                        flag_any,
                        views: None,
                    },
                )
                .await;
            }
            info!("Логин: {} последних личных ({} шт)", LOGIN_PER_CHAT, count);
        }

        // Группы
        let db = state_h.lock().await.db.clone();
        let uid = uid_h.clone();
        let groups = tokio::task::spawn_blocking(move || {
            let mut st = db.lock().unwrap();
            AppState::get_recent_groups(&mut st.conn, &uid, LOGIN_PER_CHAT)
        })
        .await
        .unwrap();
        if let Ok(msgs) = groups {
            let count = msgs.len();
            for (msg_id, gname, sender_id, content, ts, reply_id, flag_me, flag_any) in msgs {
                let db = state_h.lock().await.db.clone();
                let sid = sender_id.clone();
                let sender = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    st.resolve_username(&sid)
                })
                .await
                .unwrap();
                let recipient = format!("#{}", gname);
                let _ = send_encrypted_message(
                    &tx_h,
                    &keys_h,
                    &sender,
                    &recipient,
                    content.as_bytes(),
                    MsgFields {
                        timestamp: ts,
                        msg_id,
                        reply_to_id: reply_id.unwrap_or(0),
                        flag_me,
                        flag_any,
                        views: None,
                    },
                )
                .await;
            }
            info!(
                "Логин: {} последних групповых ({} шт)",
                LOGIN_PER_CHAT, count
            );
        }

        // Каналы
        let db = state_h.lock().await.db.clone();
        let uid = uid_h.clone();
        let channels = tokio::task::spawn_blocking(move || {
            let mut st = db.lock().unwrap();
            AppState::get_recent_channels(&mut st.conn, &uid, LOGIN_PER_CHAT)
        })
        .await
        .unwrap();
        if let Ok(msgs) = channels {
            let count = msgs.len();
            for (msg_id, cname, sender_id, content, ts, reply_id, flag_me, flag_any, views) in msgs
            {
                let db = state_h.lock().await.db.clone();
                let sid = sender_id.clone();
                let sender = tokio::task::spawn_blocking(move || {
                    let mut st = db.lock().unwrap();
                    st.resolve_username(&sid)
                })
                .await
                .unwrap();
                let recipient = format!("&{}", cname);
                let _ = send_encrypted_message(
                    &tx_h,
                    &keys_h,
                    &sender,
                    &recipient,
                    content.as_bytes(),
                    MsgFields {
                        timestamp: ts,
                        msg_id,
                        reply_to_id: reply_id.unwrap_or(0),
                        flag_me,
                        flag_any,
                        views: Some(views),
                    },
                )
                .await;
            }
            info!(
                "Логин: {} последних канальных ({} шт)",
                LOGIN_PER_CHAT, count
            );
        }
    }

    // ---- Основной цикл ----
    info!("Начало основного цикла для {}", my_username);
    loop {
        if !session.lock().await.connected {
            break;
        }

        let msg = match tokio::time::timeout(PONG_TIMEOUT, stream.next()).await {
            Ok(Some(Ok(msg))) => msg,
            Ok(Some(Err(e))) => {
                error!("Ошибка чтения: {}", e);
                break;
            }
            Ok(None) => break,
            Err(_) => {
                error!("Таймаут: нет активности от клиента, отключаем");
                break;
            }
        };

        if let Message::Binary(data) = msg {
            if data.is_empty() {
                continue;
            }

            {
                let mut guard = session.lock().await;
                if !guard.check_rate_limit() {
                    let _ = send_system_message(
                        &guard.tx,
                        "[Система] Слишком много сообщений, подождите",
                    )
                    .await;
                    continue;
                }
            }

            let msg_type = data[0];
            let rest = &data[1..];

            match msg_type {
                MSG_TYPE_USER => {
                    let mut offset = 0;
                    let sender_len =
                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;
                    offset += 4;
                    offset += sender_len;

                    let recipient_len =
                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;
                    offset += 4;
                    let recipient_name =
                        String::from_utf8(rest[offset..offset + recipient_len].to_vec())
                            .unwrap_or_default();
                    offset += recipient_len;

                    let nonce = &rest[offset..offset + 12];
                    offset += 12;

                    let msg_len =
                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;
                    offset += 4;
                    let encrypted = &rest[offset..offset + msg_len];
                    offset += msg_len;

                    let (timestamp, _client_msg_id, reply_to_id) = if rest.len() >= offset + 24 {
                        let ts = i64::from_be_bytes(rest[offset..offset + 8].try_into().unwrap());
                        let id =
                            i64::from_be_bytes(rest[offset + 8..offset + 16].try_into().unwrap());
                        let rt =
                            i64::from_be_bytes(rest[offset + 16..offset + 24].try_into().unwrap());
                        (ts, id, rt)
                    } else if rest.len() >= offset + 16 {
                        let ts = i64::from_be_bytes(rest[offset..offset + 8].try_into().unwrap());
                        let id =
                            i64::from_be_bytes(rest[offset + 8..offset + 16].try_into().unwrap());
                        (ts, id, 0)
                    } else if rest.len() >= offset + 8 {
                        let ts = i64::from_be_bytes(rest[offset..offset + 8].try_into().unwrap());
                        (ts, 0, 0)
                    } else {
                        (
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as i64,
                            0,
                            0,
                        )
                    };

                    let reply_opt: Option<i64> = if reply_to_id == 0 {
                        None
                    } else {
                        Some(reply_to_id)
                    };

                    let key = &keys.key;
                    let cipher =
                        aes_gcm::Aes256Gcm::new(Key::<aes_gcm::Aes256Gcm>::from_slice(key));
                    let nonce = aes_gcm::Nonce::from_slice(nonce);

                    let plaintext = match cipher.decrypt(nonce, encrypted) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Ошибка расшифровки: {}", e);
                            continue;
                        }
                    };
                    let content = String::from_utf8_lossy(&plaintext).to_string();
                    debug!(
                        "Сообщение от user_id={} для {}: {}",
                        my_user_id, recipient_name, content
                    );

                    // Временный канал команд через MSG_TYPE_USER.
                    if content.starts_with('/') {
                        if content.starts_with("/history") {
                            let parts: Vec<&str> = content.split_whitespace().collect();
                            if parts.len() < 2 {
                                let _ = send_system_message(
                                    &tx,
                                    "[Система] Использование: /history <chat> [<before_id>]",
                                )
                                .await;
                            } else {
                                let chat = parts[1];
                                let before_id: Option<i64> = if parts.len() > 2 {
                                    parts[2].parse().ok()
                                } else {
                                    None
                                };
                                send_chat_history(
                                    &tx,
                                    &keys,
                                    &my_user_id,
                                    chat,
                                    before_id,
                                    HISTORY_PAGE_SIZE,
                                    &state,
                                )
                                .await;
                            }
                            continue;
                        }
                        if content.starts_with("/getmsg") {
                            let parts: Vec<&str> = content.split_whitespace().collect();
                            if parts.len() < 3 {
                                let _ = send_system_message(
                                    &tx,
                                    "[Система] Использование: /getmsg <kind> <id1> [<id2> ...]",
                                )
                                .await;
                            } else {
                                let kind: u8 = parts[1].parse().unwrap_or(0);
                                let ids: Vec<i64> =
                                    parts[2..].iter().filter_map(|s| s.parse().ok()).collect();
                                send_messages_by_ids(&tx, &keys, &my_user_id, kind, ids, &state)
                                    .await;
                            }
                            continue;
                        }
                        let response =
                            process_command(&content, &my_user_id, &my_username, &state, &session)
                                .await;
                        if !response.is_empty() {
                            let _ = send_system_message(&tx, &response).await;
                        }
                        continue;
                    }

                    // ---- Личное ----
                    if !recipient_name.starts_with('#') && !recipient_name.starts_with('&') {
                        let db = state.lock().await.db.clone();
                        let target_name = recipient_name.clone();
                        let recipient_id_opt = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            st.resolve_id(&target_name)
                        })
                        .await
                        .unwrap();

                        let recipient_id = match recipient_id_opt {
                            Some(id) => id,
                            None => {
                                let _ = send_system_message(
                                    &tx,
                                    &format!("[Система] Пользователь {} не найден", recipient_name),
                                )
                                .await;
                                continue;
                            }
                        };

                        let db = state.lock().await.db.clone();
                        let sender_id = my_user_id.clone();
                        let rec_id = recipient_id.clone();
                        let content_clone = content.clone();
                        let ts = timestamp;
                        let reply_for_store = reply_opt;
                        let stored_id: i64 = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::store_message(
                                &mut st.conn,
                                &sender_id,
                                &rec_id,
                                &content_clone,
                                ts,
                                reply_for_store,
                            )
                        })
                        .await
                        .unwrap()
                        .unwrap_or(0);

                        let _ = send_encrypted_message(
                            &tx,
                            &keys,
                            &my_username,
                            &recipient_name,
                            &plaintext,
                            MsgFields {
                                timestamp,
                                msg_id: stored_id,
                                reply_to_id,
                                flag_me: true,
                                flag_any: false,
                                views: None,
                            },
                        )
                        .await;

                        if recipient_id != my_user_id {
                            let target_tokens = {
                                let state_guard = state.lock().await;
                                state_guard
                                    .online_users
                                    .get(&recipient_name)
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
                                        &recipient_name,
                                        &plaintext,
                                        MsgFields {
                                            timestamp,
                                            msg_id: stored_id,
                                            reply_to_id,
                                            flag_me: false,
                                            flag_any: false,
                                            views: None,
                                        },
                                    )
                                    .await;
                                }
                            }

                            let db = state.lock().await.db.clone();
                            let rec_id_clone = recipient_id.clone();
                            let fcm_tokens = tokio::task::spawn_blocking(move || {
                                let mut st = db.lock().unwrap();
                                AppState::get_fcm_tokens_for_user(&mut st.conn, &rec_id_clone)
                            })
                            .await
                            .unwrap()
                            .unwrap_or_default();

                            let sender_display_name =
                                resolve_display_name(&state, &my_user_id, &my_username).await;
                            let db_fcm = state.lock().await.db.clone();
                            for fcm_tok in fcm_tokens {
                                let title = format!("{}", sender_display_name);
                                let body = content.chars().take(100).collect::<String>();
                                let data_payload = json!({
                                    "sender": sender_display_name,
                                    "type": "private",
                                });
                                let db_clone = db_fcm.clone();
                                tokio::spawn(async move {
                                    send_fcm_push_and_cleanup(
                                        db_clone,
                                        &fcm_tok,
                                        &title,
                                        &body,
                                        Some(data_payload),
                                    )
                                    .await;
                                });
                            }
                        }

                        continue;
                    }

                    // ---- Группа ----
                    if recipient_name.starts_with('#') {
                        let group_name = recipient_name.trim_start_matches('#').to_string();

                        let db = state.lock().await.db.clone();
                        let uid = my_user_id.clone();
                        let gname = group_name.clone();
                        let is_member = tokio::task::spawn_blocking(move || {
                            let st = db.lock().unwrap();
                            let mut stmt = st.conn
                                .prepare("SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE g.name = ? AND gm.user_id = ?")
                                .map_err(|e| format!("Ошибка запроса: {}", e))?;
                            let mut rows = stmt.query(params![gname, uid]).map_err(|e| format!("Ошибка: {}", e))?;
                            Ok::<_, String>(rows.next().map_err(|e| format!("Ошибка: {}", e))?.is_some())
                        })
                            .await
                            .unwrap()
                            .unwrap_or(false);

                        if !is_member {
                            let _ =
                                send_system_message(&tx, "[Система] Вы не состоите в этой группе")
                                    .await;
                            continue;
                        }

                        let db = state.lock().await.db.clone();
                        let sender_id = my_user_id.clone();
                        let gname = group_name.clone();
                        let cnt = content.clone();
                        let ts = timestamp;
                        let reply_for_store = reply_opt;
                        let stored_id: i64 = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::store_group_message(
                                &mut st.conn,
                                &gname,
                                &sender_id,
                                &cnt,
                                ts,
                                reply_for_store,
                            )
                        })
                        .await
                        .unwrap()
                        .unwrap_or(0);

                        let db = state.lock().await.db.clone();
                        let gname = group_name.clone();
                        let members = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::get_group_members(&mut st.conn, &gname)
                        })
                        .await
                        .unwrap()
                        .unwrap_or_default();

                        let recip_with_hash = format!("#{}", group_name);
                        let _ = send_encrypted_message(
                            &tx,
                            &keys,
                            &my_username,
                            &recip_with_hash,
                            &plaintext,
                            MsgFields {
                                timestamp,
                                msg_id: stored_id,
                                reply_to_id,
                                flag_me: true,
                                flag_any: false,
                                views: None,
                            },
                        )
                        .await;

                        for member_id in members {
                            if member_id == my_user_id {
                                continue;
                            }
                            let db = state.lock().await.db.clone();
                            let mid = member_id.clone();
                            let member_name_opt = tokio::task::spawn_blocking(move || {
                                let mut st = db.lock().unwrap();
                                let name = st.resolve_username(&mid);
                                if name == DELETED_LABEL {
                                    None
                                } else {
                                    Some(name)
                                }
                            })
                            .await
                            .unwrap();

                            let member_name = match member_name_opt {
                                Some(n) => n,
                                None => continue,
                            };

                            let target_online = {
                                let state_guard = state.lock().await;
                                state_guard.online_users.contains_key(&member_name)
                            };
                            if target_online {
                                let target_tokens = {
                                    let state_guard = state.lock().await;
                                    state_guard
                                        .online_users
                                        .get(&member_name)
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
                                            MsgFields {
                                                timestamp,
                                                msg_id: stored_id,
                                                reply_to_id,
                                                flag_me: false,
                                                flag_any: false,
                                                views: None,
                                            },
                                        )
                                        .await;
                                    }
                                }
                            } else {
                                let db = state.lock().await.db.clone();
                                let mid2 = member_id.clone();
                                let fcm_tokens = tokio::task::spawn_blocking(move || {
                                    let mut st = db.lock().unwrap();
                                    AppState::get_fcm_tokens_for_user(&mut st.conn, &mid2)
                                })
                                .await
                                .unwrap()
                                .unwrap_or_default();

                                let sender_display_name =
                                    resolve_display_name(&state, &my_user_id, &my_username).await;
                                let db_fcm = state.lock().await.db.clone();
                                for fcm_tok in fcm_tokens {
                                    let title = format!("Новое сообщение в группе {}", group_name);
                                    let body = format!(
                                        "{}: {}",
                                        sender_display_name,
                                        content.chars().take(100).collect::<String>()
                                    );
                                    let data_payload = json!({
                                        "sender": sender_display_name,
                                        "group": group_name,
                                        "type": "group",
                                    });
                                    let db_clone = db_fcm.clone();
                                    tokio::spawn(async move {
                                        send_fcm_push_and_cleanup(
                                            db_clone,
                                            &fcm_tok,
                                            &title,
                                            &body,
                                            Some(data_payload),
                                        )
                                        .await;
                                    });
                                }
                            }
                        }
                        continue;
                    }

                    // ---- Канал ----
                    if recipient_name.starts_with('&') {
                        let channel_name = recipient_name.trim_start_matches('&').to_string();

                        let db = state.lock().await.db.clone();
                        let uid = my_user_id.clone();
                        let ch = channel_name.clone();
                        let is_subscribed = tokio::task::spawn_blocking(move || {
                            let st = db.lock().unwrap();
                            let mut stmt = st.conn
                                .prepare("SELECT 1 FROM channel_subscribers cs JOIN channels c ON cs.channel_id = c.id WHERE c.name = ? AND cs.user_id = ?")
                                .map_err(|e| format!("Ошибка: {}", e))?;
                            let mut rows = stmt.query(params![ch, uid]).map_err(|e| format!("Ошибка: {}", e))?;
                            Ok::<_, String>(rows.next().map_err(|e| format!("Ошибка: {}", e))?.is_some())
                        })
                            .await
                            .unwrap()
                            .unwrap_or(false);

                        if !is_subscribed {
                            let _ =
                                send_system_message(&tx, "[Система] Вы не подписаны на этот канал")
                                    .await;
                            continue;
                        }

                        let is_owner = {
                            let db = state.lock().await.db.clone();
                            let ch = channel_name.clone();
                            let uid = my_user_id.clone();
                            tokio::task::spawn_blocking(move || {
                                let st = db.lock().unwrap();
                                let mut stmt = st
                                    .conn
                                    .prepare(
                                        "SELECT 1 FROM channels WHERE name = ? AND creator_id = ?",
                                    )
                                    .map_err(|e| e.to_string())?;
                                let mut rows =
                                    stmt.query(params![ch, uid]).map_err(|e| e.to_string())?;
                                Ok::<_, String>(rows.next().map_err(|e| e.to_string())?.is_some())
                            })
                            .await
                            .unwrap()
                            .unwrap_or(false)
                        };

                        if !is_owner {
                            let _ = send_system_message(
                                &tx,
                                "[Система] Только владелец канала может отправлять сообщения",
                            )
                            .await;
                            continue;
                        }

                        let db = state.lock().await.db.clone();
                        let sender_id = my_user_id.clone();
                        let ch_name = channel_name.clone();
                        let cnt = content.clone();
                        let ts = timestamp;
                        let reply_for_store = reply_opt;
                        let stored_id: i64 = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::store_channel_message(
                                &mut st.conn,
                                &ch_name,
                                &sender_id,
                                &cnt,
                                ts,
                                reply_for_store,
                            )
                        })
                        .await
                        .unwrap()
                        .unwrap_or(0);

                        let db = state.lock().await.db.clone();
                        let ch_name2 = channel_name.clone();
                        let subscribers = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::get_channel_subscribers(&mut st.conn, &ch_name2)
                        })
                        .await
                        .unwrap()
                        .unwrap_or_default();

                        let recip_with_amp = format!("&{}", channel_name);
                        let _ = send_encrypted_message(
                            &tx,
                            &keys,
                            &my_username,
                            &recip_with_amp,
                            &plaintext,
                            MsgFields {
                                timestamp,
                                msg_id: stored_id,
                                reply_to_id,
                                flag_me: true,
                                flag_any: false,
                                views: Some(0),
                            },
                        )
                        .await;

                        for sub_id in subscribers {
                            if sub_id == my_user_id {
                                continue;
                            }
                            let db = state.lock().await.db.clone();
                            let sid = sub_id.clone();
                            let sub_name_opt = tokio::task::spawn_blocking(move || {
                                let mut st = db.lock().unwrap();
                                let name = st.resolve_username(&sid);
                                if name == DELETED_LABEL {
                                    None
                                } else {
                                    Some(name)
                                }
                            })
                            .await
                            .unwrap();

                            let sub_name = match sub_name_opt {
                                Some(n) => n,
                                None => continue,
                            };

                            let target_online = {
                                let state_guard = state.lock().await;
                                state_guard.online_users.contains_key(&sub_name)
                            };
                            if target_online {
                                let target_tokens = {
                                    let state_guard = state.lock().await;
                                    state_guard
                                        .online_users
                                        .get(&sub_name)
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
                                            MsgFields {
                                                timestamp,
                                                msg_id: stored_id,
                                                reply_to_id,
                                                flag_me: true,
                                                flag_any: false,
                                                views: Some(0),
                                            },
                                        )
                                        .await;
                                    }
                                }
                            } else {
                                let db = state.lock().await.db.clone();
                                let sid2 = sub_id.clone();
                                let fcm_tokens = tokio::task::spawn_blocking(move || {
                                    let mut st = db.lock().unwrap();
                                    AppState::get_fcm_tokens_for_user(&mut st.conn, &sid2)
                                })
                                .await
                                .unwrap()
                                .unwrap_or_default();

                                let sender_display_name =
                                    resolve_display_name(&state, &my_user_id, &my_username).await;
                                let db_fcm = state.lock().await.db.clone();
                                for fcm_tok in fcm_tokens {
                                    let title =
                                        format!("Новое сообщение в канале {}", channel_name);
                                    let body = content.chars().take(100).collect::<String>();
                                    let data_payload = json!({
                                        "sender": sender_display_name,
                                        "channel": channel_name,
                                        "type": "channel",
                                    });
                                    let db_clone = db_fcm.clone();
                                    tokio::spawn(async move {
                                        send_fcm_push_and_cleanup(
                                            db_clone,
                                            &fcm_tok,
                                            &title,
                                            &body,
                                            Some(data_payload),
                                        )
                                        .await;
                                    });
                                }
                            }
                        }
                        continue;
                    }

                    warn!("Неизвестный тип получателя: {}", recipient_name);
                }

                MSG_TYPE_READ => {
                    if rest.len() < 2 {
                        warn!("0x07: мало данных");
                        continue;
                    }
                    let count = u16::from_be_bytes(rest[0..2].try_into().unwrap()) as usize;
                    if rest.len() < 2 + count * 9 {
                        warn!("0x07: не хватает данных");
                        continue;
                    }

                    let mut personal_ids: Vec<i64> = Vec::new();
                    let mut group_ids: Vec<i64> = Vec::new();
                    let mut channel_ids: Vec<i64> = Vec::new();
                    for i in 0..count {
                        let off = 2 + i * 9;
                        let kind = rest[off];
                        let msg_id = i64::from_be_bytes(rest[off + 1..off + 9].try_into().unwrap());
                        match kind {
                            MSG_KIND_PERSONAL => personal_ids.push(msg_id),
                            MSG_KIND_GROUP => group_ids.push(msg_id),
                            MSG_KIND_CHANNEL => channel_ids.push(msg_id),
                            _ => {}
                        }
                    }
                    info!(
                        "0x07 от {}: p={}, g={}, c={}",
                        my_username,
                        personal_ids.len(),
                        group_ids.len(),
                        channel_ids.len()
                    );

                    // --- Личные ---
                    if !personal_ids.is_empty() {
                        let db = state.lock().await.db.clone();
                        let me = my_user_id.clone();
                        let ids = personal_ids.clone();
                        let by_author = tokio::task::spawn_blocking(move || {
                            let st = db.lock().unwrap();
                            let mut map: HashMap<String, Vec<i64>> = HashMap::new();
                            for msg_id in ids {
                                let row: Option<(String, String)> = st
                                    .conn
                                    .query_row(
                                        "SELECT sender_id, recipient_id FROM messages WHERE id = ?",
                                        [msg_id],
                                        |row| Ok((row.get(0)?, row.get(1)?)),
                                    )
                                    .ok();
                                if let Some((sender_id, recipient_id)) = row {
                                    if recipient_id == me {
                                        let _ = st.conn.execute(
                                            "UPDATE messages SET read_at = CURRENT_TIMESTAMP WHERE id = ? AND read_at IS NULL",
                                            [msg_id],
                                        );
                                        map.entry(sender_id).or_default().push(msg_id);
                                    }
                                }
                            }
                            map
                        })
                            .await
                            .unwrap();

                        for (author_id, ids) in by_author {
                            if author_id == my_user_id {
                                continue;
                            }
                            let author_name = {
                                let db = state.lock().await.db.clone();
                                let aid = author_id.clone();
                                tokio::task::spawn_blocking(move || {
                                    let mut st = db.lock().unwrap();
                                    st.resolve_username(&aid)
                                })
                                .await
                                .unwrap()
                            };
                            let tokens = {
                                let g = state.lock().await;
                                g.online_users
                                    .get(&author_name)
                                    .cloned()
                                    .unwrap_or_default()
                            };
                            let items: Vec<(u8, i64)> =
                                ids.iter().map(|id| (MSG_KIND_PERSONAL, *id)).collect();
                            let pkt = build_read_packet(&items);
                            for tok in tokens {
                                let sess = {
                                    let g = state.lock().await;
                                    g.sessions.get(&tok).cloned()
                                };
                                if let Some(s) = sess {
                                    let ttx = s.lock().await.tx.clone();
                                    let _ = ttx.send(Message::Binary(pkt.clone().into()));
                                }
                            }
                        }
                    }

                    // --- Группы ---
                    if !group_ids.is_empty() {
                        let db = state.lock().await.db.clone();
                        let me = my_user_id.clone();
                        let ids = group_ids.clone();
                        let by_group = tokio::task::spawn_blocking(move || {
                            let st = db.lock().unwrap();
                            let mut map: HashMap<String, Vec<i64>> = HashMap::new();
                            for msg_id in ids {
                                let gid: Option<String> = st
                                    .conn
                                    .query_row(
                                        "SELECT group_id FROM group_messages WHERE id = ?",
                                        [msg_id],
                                        |row| row.get(0),
                                    )
                                    .ok();
                                if let Some(gid) = gid {
                                    let _ = st.conn.execute(
                                        "UPDATE group_messages SET first_read_at = CURRENT_TIMESTAMP WHERE id = ? AND first_read_at IS NULL",
                                        [msg_id],
                                    );
                                    map.entry(gid).or_default().push(msg_id);
                                }
                            }
                            let _ = me;
                            map
                        })
                            .await
                            .unwrap();

                        for (group_id, ids) in by_group {
                            let db = state.lock().await.db.clone();
                            let gid = group_id.clone();
                            let members = tokio::task::spawn_blocking(move || {
                                let st = db.lock().unwrap();
                                let mut stmt = st
                                    .conn
                                    .prepare("SELECT user_id FROM group_members WHERE group_id = ?")
                                    .map_err(|e| e.to_string())?;
                                let iter = stmt
                                    .query_map([&gid], |row| row.get::<_, String>(0))
                                    .map_err(|e| e.to_string())?;
                                let mut v = Vec::new();
                                for r in iter {
                                    v.push(r.map_err(|e| e.to_string())?);
                                }
                                Ok::<_, String>(v)
                            })
                            .await
                            .unwrap()
                            .unwrap_or_default();

                            let items: Vec<(u8, i64)> =
                                ids.iter().map(|id| (MSG_KIND_GROUP, *id)).collect();
                            let pkt = build_read_packet(&items);

                            for mid in members {
                                if mid == my_user_id {
                                    continue;
                                }
                                let name = {
                                    let db = state.lock().await.db.clone();
                                    let m = mid.clone();
                                    tokio::task::spawn_blocking(move || {
                                        let mut st = db.lock().unwrap();
                                        st.resolve_username(&m)
                                    })
                                    .await
                                    .unwrap()
                                };
                                let tokens = {
                                    let g = state.lock().await;
                                    g.online_users.get(&name).cloned().unwrap_or_default()
                                };
                                for tok in tokens {
                                    let sess = {
                                        let g = state.lock().await;
                                        g.sessions.get(&tok).cloned()
                                    };
                                    if let Some(s) = sess {
                                        let ttx = s.lock().await.tx.clone();
                                        let _ = ttx.send(Message::Binary(pkt.clone().into()));
                                    }
                                }
                            }
                        }
                    }

                    // --- Каналы ---
                    if !channel_ids.is_empty() {
                        let db = state.lock().await.db.clone();
                        let me = my_user_id.clone();
                        let ids = channel_ids.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            let st = db.lock().unwrap();
                            for msg_id in ids {
                                let _ = st.conn.execute(
                                    "INSERT OR IGNORE INTO channel_message_views (channel_msg_id, user_id) VALUES (?, ?)",
                                    params![msg_id, me],
                                );
                            }
                        })
                            .await;
                    }
                }

                MSG_TYPE_DELETE => {
                    if rest.len() < 9 {
                        warn!("MSG_TYPE_DELETE: мало данных");
                        continue;
                    }
                    let msg_id = i64::from_be_bytes(rest[0..8].try_into().unwrap());
                    let kind = rest[8];
                    let dtype = if rest.len() >= 10 { rest[9] } else { 0 };

                    if dtype == MSG_DELETE_FOR_ME {
                        let db = state.lock().await.db.clone();
                        let uid = my_user_id.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::hide_message(&mut st.conn, &uid, kind, msg_id)
                        })
                        .await
                        .unwrap();
                        if let Err(e) = result {
                            let _ = send_system_message(
                                &tx,
                                &format!("[Система] Ошибка скрытия: {}", e),
                            )
                            .await;
                        } else {
                            info!(
                                "Сообщение kind={} id={} скрыто у {}",
                                kind, msg_id, my_username
                            );
                        }
                        continue;
                    }

                    match kind {
                        MSG_KIND_PERSONAL => {
                            let db = state.lock().await.db.clone();
                            let lookup = tokio::task::spawn_blocking(move || {
                                let mut st = db.lock().unwrap();
                                AppState::lookup_personal_message(&mut st.conn, msg_id)
                            })
                            .await
                            .unwrap();

                            match lookup {
                                Ok(Some((sender_id, recipient_id))) => {
                                    if sender_id != my_user_id {
                                        let _ = send_system_message(
                                            &tx,
                                            "[Система] Удалять у всех можно только свои сообщения",
                                        )
                                        .await;
                                        continue;
                                    }
                                    let db = state.lock().await.db.clone();
                                    let del = tokio::task::spawn_blocking(move || {
                                        let mut st = db.lock().unwrap();
                                        AppState::delete_message(&mut st.conn, msg_id)
                                    })
                                    .await
                                    .unwrap();
                                    if let Err(e) = del {
                                        let _ = send_system_message(
                                            &tx,
                                            &format!("[Система] Ошибка удаления: {}", e),
                                        )
                                        .await;
                                        continue;
                                    }

                                    let pkt = build_delete_packet(msg_id, kind, MSG_DELETE_FOR_ALL);
                                    let _ = tx.send(Message::Binary(pkt.clone().into()));

                                    if recipient_id != my_user_id {
                                        let db = state.lock().await.db.clone();
                                        let rid = recipient_id.clone();
                                        let rec_name_opt = tokio::task::spawn_blocking(move || {
                                            let mut st = db.lock().unwrap();
                                            let name = st.resolve_username(&rid);
                                            if name == DELETED_LABEL {
                                                None
                                            } else {
                                                Some(name)
                                            }
                                        })
                                        .await
                                        .unwrap();

                                        if let Some(rec_name) = rec_name_opt {
                                            let tokens = {
                                                let g = state.lock().await;
                                                g.online_users
                                                    .get(&rec_name)
                                                    .cloned()
                                                    .unwrap_or_default()
                                            };
                                            for tok in tokens {
                                                let target = {
                                                    let g = state.lock().await;
                                                    g.sessions.get(&tok).cloned()
                                                };
                                                if let Some(ts) = target {
                                                    let ttx = { ts.lock().await.tx.clone() };
                                                    let _ = ttx
                                                        .send(Message::Binary(pkt.clone().into()));
                                                }
                                            }
                                        }
                                    }
                                    info!("Личное сообщение id={} удалено у всех", msg_id);
                                }
                                Ok(None) => {
                                    let _ =
                                        send_system_message(&tx, "[Система] Сообщение не найдено")
                                            .await;
                                }
                                Err(e) => {
                                    let _ =
                                        send_system_message(&tx, &format!("[Система] {}", e)).await;
                                }
                            }
                        }

                        MSG_KIND_GROUP => {
                            let _ = send_system_message(
                                &tx,
                                "[Система] Удаление у всех в группах пока не поддерживается",
                            )
                            .await;
                        }

                        MSG_KIND_CHANNEL => {
                            let db = state.lock().await.db.clone();
                            let lookup = tokio::task::spawn_blocking(move || {
                                let mut st = db.lock().unwrap();
                                AppState::lookup_channel_message(&mut st.conn, msg_id)
                            })
                            .await
                            .unwrap();

                            match lookup {
                                Ok(Some((channel_name, creator_id, _sender_id))) => {
                                    if creator_id != my_user_id {
                                        let _ = send_system_message(&tx, "[Система] Только владелец канала может удалять сообщения").await;
                                        continue;
                                    }
                                    let db = state.lock().await.db.clone();
                                    let del = tokio::task::spawn_blocking(move || {
                                        let mut st = db.lock().unwrap();
                                        AppState::delete_channel_message(&mut st.conn, msg_id)
                                    })
                                    .await
                                    .unwrap();
                                    if let Err(e) = del {
                                        let _ = send_system_message(
                                            &tx,
                                            &format!("[Система] Ошибка удаления: {}", e),
                                        )
                                        .await;
                                        continue;
                                    }

                                    let db = state.lock().await.db.clone();
                                    let ch = channel_name.clone();
                                    let subs_ids = tokio::task::spawn_blocking(move || {
                                        let mut st = db.lock().unwrap();
                                        AppState::get_channel_subscribers(&mut st.conn, &ch)
                                    })
                                    .await
                                    .unwrap()
                                    .unwrap_or_default();

                                    let pkt = build_delete_packet(msg_id, kind, MSG_DELETE_FOR_ALL);

                                    let mut tokens: Vec<String> = Vec::new();
                                    {
                                        let g = state.lock().await;
                                        for (tok, sess) in &g.sessions {
                                            let uid = {
                                                let guard = sess.lock().await;
                                                guard.user_id.clone()
                                            };
                                            if let Some(uid) = uid {
                                                if subs_ids.contains(&uid) {
                                                    tokens.push(tok.clone());
                                                }
                                            }
                                        }
                                    }

                                    for tok in tokens {
                                        let target = {
                                            let g = state.lock().await;
                                            g.sessions.get(&tok).cloned()
                                        };
                                        if let Some(ts) = target {
                                            let ttx = { ts.lock().await.tx.clone() };
                                            let _ = ttx.send(Message::Binary(pkt.clone().into()));
                                        }
                                    }
                                    info!(
                                        "Сообщение канала {} id={} удалено у всех",
                                        channel_name, msg_id
                                    );
                                }
                                Ok(None) => {
                                    let _ =
                                        send_system_message(&tx, "[Система] Сообщение не найдено")
                                            .await;
                                }
                                Err(e) => {
                                    let _ =
                                        send_system_message(&tx, &format!("[Система] {}", e)).await;
                                }
                            }
                        }

                        _ => {
                            let _ = send_system_message(&tx, "[Система] Неизвестный kind удаления")
                                .await;
                        }
                    }
                }

                MSG_TYPE_LOGOUT => {
                    if rest.len() < 4 {
                        warn!("MSG_TYPE_LOGOUT: слишком короткий пакет");
                        continue;
                    }
                    let token_len = u32::from_be_bytes(rest[0..4].try_into().unwrap()) as usize;
                    if rest.len() < 4 + token_len {
                        warn!("MSG_TYPE_LOGOUT: не хватает данных");
                        continue;
                    }
                    let token =
                        String::from_utf8(rest[4..4 + token_len].to_vec()).unwrap_or_default();
                    info!("Logout: token={}", token);

                    if token.is_empty() {
                        let _ = send_system_message(&tx, "[Система] Пустой токен").await;
                        continue;
                    }

                    let db = state.lock().await.db.clone();
                    let tok = token.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        let mut st = db.lock().unwrap();
                        AppState::delete_session(&mut st.conn, &tok)
                    })
                    .await
                    .unwrap();

                    match result {
                        Ok(_) => {
                            {
                                let mut state_guard = state.lock().await;
                                state_guard.sessions.remove(&token);
                                let uname = my_username.clone();
                                if let Some(tokens) = state_guard.online_users.get_mut(&uname) {
                                    tokens.retain(|t| t != &token);
                                    if tokens.is_empty() {
                                        state_guard.online_users.remove(&uname);
                                    }
                                }
                            }
                            {
                                let mut guard = session.lock().await;
                                guard.connected = false;
                            }
                            let _ = send_system_message(&tx, "[Система] Вы вышли из системы").await;
                            info!("Сессия {} завершена по logout", token);
                        }
                        Err(e) => {
                            let _ = send_system_message(
                                &tx,
                                &format!("[Система] Ошибка logout: {}", e),
                            )
                            .await;
                        }
                    }
                }

                MSG_TYPE_COMMAND => {
                    let cmd = String::from_utf8(rest[4..].to_vec()).unwrap_or_default();
                    info!("Получена команда через MSG_TYPE_COMMAND: {}", cmd);

                    if cmd.starts_with("/history") {
                        let parts: Vec<&str> = cmd.split_whitespace().collect();
                        if parts.len() < 2 {
                            let _ = send_system_message(
                                &tx,
                                "[Система] Использование: /history <chat> [<before_id>]",
                            )
                            .await;
                        } else {
                            let chat = parts[1];
                            let before_id: Option<i64> = if parts.len() > 2 {
                                parts[2].parse().ok()
                            } else {
                                None
                            };
                            send_chat_history(
                                &tx,
                                &keys,
                                &my_user_id,
                                chat,
                                before_id,
                                HISTORY_PAGE_SIZE,
                                &state,
                            )
                            .await;
                        }
                        continue;
                    }

                    if cmd.starts_with("/getmsg") {
                        let parts: Vec<&str> = cmd.split_whitespace().collect();
                        if parts.len() < 3 {
                            let _ = send_system_message(
                                &tx,
                                "[Система] Использование: /getmsg <kind> <id1> [<id2> ...]",
                            )
                            .await;
                        } else {
                            let kind: u8 = parts[1].parse().unwrap_or(0);
                            let ids: Vec<i64> =
                                parts[2..].iter().filter_map(|s| s.parse().ok()).collect();
                            send_messages_by_ids(&tx, &keys, &my_user_id, kind, ids, &state).await;
                        }
                        continue;
                    }

                    let response =
                        process_command(&cmd, &my_user_id, &my_username, &state, &session).await;
                    if !response.is_empty() {
                        let _ = send_system_message(&tx, &response).await;
                    }
                }

                _ => {
                    warn!("Неизвестный тип сообщения: {}", msg_type);
                }
            }
        } else if let Message::Pong(_) = msg {
        } else if let Message::Ping(_) = msg {
        } else if let Message::Close(_) = msg {
            info!("Клиент прислал Close");
            break;
        } else {
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

        if !my_user_id.is_empty() {
            let db_ls = state.lock().await.db.clone();
            let uid_ls = my_user_id.clone();
            tokio::task::spawn_blocking(move || {
                let mut st = db_ls.lock().unwrap();
                let _ = AppState::update_last_seen(&mut st.conn, &uid_ls);
            })
            .await
            .unwrap();
        }

        broadcast_system_message(&state, &msg, Some(&username)).await;
    }

    info!(
        "Клиент {} отключён, время сессии: {:?}",
        my_username,
        start_time.elapsed()
    );
    ping_task.abort();
    let _ = send_task.await;
}
