use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use log::{info, warn};
use rusqlite::params;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;

use crate::app_state::{AppState, MsgFields, SessionKeys};
use crate::constants::*;

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

/// C→S и S→C 0x05 (удаление целого чата/группы/канала):
/// [0x05][0 i64 BE][kind u8][type u8][name_len u32 BE][name utf8]
pub fn build_delete_chat_packet(kind: u8, name: &str, dtype: u8) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let total_len = 1 + 8 + 1 + 1 + 4 + name_bytes.len();
    let mut data = Vec::with_capacity(total_len);
    data.push(MSG_TYPE_DELETE);
    data.extend_from_slice(&0i64.to_be_bytes()); // msg_id = 0
    data.push(kind);
    data.push(dtype);
    data.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(name_bytes);
    data
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
    client_msg_id: Option<i64>, // <--- ДОБАВЛЕНО
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
    let views_val: u32 = fields.views.unwrap_or(0);
    data.extend_from_slice(&views_val.to_be_bytes());
    data.push(if fields.edited { 1 } else { 0 });

    // ДОБАВЛЕНО: Сериализация client_msg_id (0, если это не ACK)
    data.extend_from_slice(&client_msg_id.unwrap_or(0).to_be_bytes());

    tx.send(Message::Binary(data.into()))
        .map_err(|e| format!("send error: {}", e))
}
pub async fn send_to_all_my_sessions(
    state: &Arc<AppState>, // <-- Без Mutex
    my_username: &str,
    recipient_name: &str,
    plaintext: &[u8],
    fields: MsgFields,
    client_msg_id: Option<i64>,
) {
    let tokens = {
        state
            .online_users
            .get(my_username)
            .map(|r| r.clone())
            .unwrap_or_default()
    };
    for tok in tokens {
        let sess = state.sessions.get(&tok).map(|r| r.clone());
        if let Some(s) = sess {
            let _ = send_encrypted_message(
                &s.tx,
                &s.keys,
                my_username,
                recipient_name,
                plaintext,
                fields,
                client_msg_id,
            )
            .await;
        }
    }
}

pub async fn send_to_user_sessions(
    state: &Arc<AppState>, // <-- Без Mutex
    username: &str,
    packet: Vec<u8>,
) {
    let tokens = {
        state
            .online_users
            .get(username)
            .map(|r| r.clone())
            .unwrap_or_default()
    };
    for tok in tokens {
        let sess = state.sessions.get(&tok).map(|r| r.clone());
        if let Some(s) = sess {
            let _ = s.tx.send(Message::Binary(packet.clone().into()));
        }
    }
}

pub async fn broadcast_system_message(
    state: &Arc<AppState>, // <-- Без Mutex
    message: &str,
    exclude_username: Option<&str>,
) {
    for entry in state.sessions.iter() {
        let session = entry.value();
        let connected = session.connected.load(std::sync::atomic::Ordering::Relaxed);
        if connected {
            if let Some(uname) = session.username.get() {
                if Some(uname.as_str()) == exclude_username {
                    continue;
                }
            }
            let _ = send_system_message(&session.tx, message).await;
        }
    }
}

pub async fn send_chat_history(
    tx: &mpsc::UnboundedSender<Message>,
    keys: &SessionKeys,
    my_user_id: &str,
    chat: &str,
    before_id: Option<i64>,
    limit: i64,
    state: &Arc<AppState>, // <-- Без Mutex
) {
    let db = state.db.clone(); // <-- Берем только db

    let cursor = before_id.unwrap_or(i64::MAX);

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
        bool,
    );

    let result: Result<Vec<HistRow>, String> = tokio::task::spawn_blocking(move || {
        let mut st = db.lock().unwrap();

        let raw: Vec<HistRow> = if chat_owned.starts_with('#') {
            let gname = chat_owned.trim_start_matches('#').to_string();
            let rows: Vec<(i64, String, String, i64, Option<i64>, Option<String>, i64)> = {
                let mut stmt = st.conn.prepare(
                    "SELECT gm.id, gm.sender_id, gm.content,
                            strftime('%s', gm.sent_at) * 1000, gm.reply_to_id, gm.first_read_at,
                            COALESCE(gm.edited, 0)
                     FROM group_messages gm
                     JOIN groups g ON gm.group_id = g.id
                     LEFT JOIN hidden_messages h ON h.kind = 2 AND h.msg_id = gm.id AND h.user_id = ?1
                     WHERE g.name = ?2 AND gm.id < ?3 AND h.msg_id IS NULL
                     ORDER BY gm.id DESC LIMIT ?4",
                ).map_err(|e| e.to_string())?;
                let iter = stmt.query_map(params![me, gname, cursor, limit], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?, row.get::<_, Option<i64>>(4)?, row.get::<_, Option<String>>(5)?, row.get::<_, i64>(6).unwrap_or(0)))
                }).map_err(|e| e.to_string())?;
                let mut v = Vec::new();
                for r in iter { v.push(r.map_err(|e| e.to_string())?); }
                v
            };
            let mut out = Vec::with_capacity(rows.len());
            for (id, sender_id, content, ts, reply_id, first_read_at, edited) in rows {
                let sender = st.resolve_username(&sender_id);
                let is_sender = sender_id == me;
                out.push((id, sender, chat_owned.clone(), content, ts, reply_id, is_sender, first_read_at.is_some(), None, edited != 0));
            }
            out
        } else if chat_owned.starts_with('&') {
            let cname = chat_owned.trim_start_matches('&').to_string();
            let rows: Vec<(i64, String, String, i64, Option<i64>, i64, i64)> = {
                let mut stmt = st.conn.prepare(
                    "SELECT cm.id, cm.sender_id, cm.content,
                            strftime('%s', cm.sent_at) * 1000, cm.reply_to_id,
                            (SELECT COUNT(*) FROM channel_message_views v WHERE v.channel_msg_id = cm.id),
                            COALESCE(cm.edited, 0)
                     FROM channel_messages cm
                     JOIN channels c ON cm.channel_id = c.id
                     LEFT JOIN hidden_messages h ON h.kind = 3 AND h.msg_id = cm.id AND h.user_id = ?1
                     WHERE c.name = ?2 AND cm.id < ?3 AND h.msg_id IS NULL
                     ORDER BY cm.id DESC LIMIT ?4",
                ).map_err(|e| e.to_string())?;
                let iter = stmt.query_map(params![me, cname, cursor, limit], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?, row.get::<_, Option<i64>>(4)?, row.get::<_, i64>(5).unwrap_or(0), row.get::<_, i64>(6).unwrap_or(0)))
                }).map_err(|e| e.to_string())?;
                let mut v = Vec::new();
                for r in iter { v.push(r.map_err(|e| e.to_string())?); }
                v
            };
            let mut out = Vec::with_capacity(rows.len());
            for (id, sender_id, content, ts, reply_id, views, edited) in rows {
                let sender = st.resolve_username(&sender_id);
                let v = views as u32;
                out.push((id, sender, chat_owned.clone(), content, ts, reply_id, true, v > 0, Some(v), edited != 0));
            }
            out
        } else {
            let peer_id = match st.resolve_id(&chat_owned) {
                Some(id) => id,
                None => return Ok(Vec::new()),
            };
            let rows: Vec<(i64, String, String, String, i64, Option<i64>, Option<String>, i64)> = {
                let mut stmt = st.conn.prepare(
                    "SELECT m.id, m.sender_id, m.recipient_id, m.content,
                            strftime('%s', m.sent_at) * 1000, m.reply_to_id, m.read_at,
                            COALESCE(m.edited, 0)
                     FROM messages m
                     LEFT JOIN hidden_messages h ON h.kind = 1 AND h.msg_id = m.id AND h.user_id = ?1
                     WHERE ((m.sender_id = ?1 AND m.recipient_id = ?2) OR (m.sender_id = ?2 AND m.recipient_id = ?1))
                       AND m.id < ?3 AND h.msg_id IS NULL
                     ORDER BY m.id DESC LIMIT ?4",
                ).map_err(|e| e.to_string())?;
                let iter = stmt.query_map(params![me, peer_id, cursor, limit], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, i64>(4)?, row.get::<_, Option<i64>>(5)?, row.get::<_, Option<String>>(6)?, row.get::<_, i64>(7).unwrap_or(0)))
                }).map_err(|e| e.to_string())?;
                let mut v = Vec::new();
                for r in iter { v.push(r.map_err(|e| e.to_string())?); }
                v
            };
            let mut out = Vec::with_capacity(rows.len());
            for (id, sender_id, recipient_id, content, ts, reply_id, read_at, edited) in rows {
                let sender = st.resolve_username(&sender_id);
                let recipient = st.resolve_username(&recipient_id);
                let is_sender = sender_id == me;
                let read_flag = read_at.is_some();
                let flag_me = if is_sender { true } else { read_flag };
                let flag_any = if is_sender { read_flag } else { true };
                out.push((id, sender, recipient, content, ts, reply_id, flag_me, flag_any, None, edited != 0));
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
    for (msg_id, sender, recipient, content, ts, reply_id, flag_me, flag_any, views, edited) in msgs
    {
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
                edited,
            },
            None, // <--- ДОБАВИТЬ СЮДА
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
    state: &Arc<AppState>, // <-- Без Mutex
) {
    if ids.is_empty() {
        return;
    }
    let requested = ids.len();
    let db = state.db.clone();
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
    for (msg_id, sender, recipient, content, ts, reply_id, flag_me, flag_any, views, edited) in msgs
    {
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
                edited,
            },
            None, // <--- ДОБАВИТЬ СЮДА
        )
        .await;
    }
}
