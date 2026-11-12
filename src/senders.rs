use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use log::{info, warn};
use std::sync::Arc;
use tokio::sync::mpsc;
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
    tx.send(Message::Binary(data))
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

pub fn build_delete_chat_packet(kind: u8, name: &str, dtype: u8) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let total_len = 1 + 8 + 1 + 1 + 4 + name_bytes.len();
    let mut data = Vec::with_capacity(total_len);
    data.push(MSG_TYPE_DELETE);
    data.extend_from_slice(&0i64.to_be_bytes());
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

pub fn build_reaction_packet(
    msg_id: i64,
    kind: u8,
    symbol: &str,
    count: u32,
    who: &str,
) -> Vec<u8> {
    let sym_bytes = symbol.as_bytes();
    let who_bytes = who.as_bytes();
    let mut data = Vec::with_capacity(1 + 8 + 1 + 4 + sym_bytes.len() + 4 + 4 + who_bytes.len());
    data.push(MSG_TYPE_REACTION);
    data.extend_from_slice(&msg_id.to_be_bytes());
    data.push(kind);
    data.extend_from_slice(&(sym_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(sym_bytes);
    data.extend_from_slice(&count.to_be_bytes());
    data.extend_from_slice(&(who_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(who_bytes);
    data
}

pub fn build_invalidate_cache_packet() -> Vec<u8> {
    vec![MSG_TYPE_INVALIDATE_CACHE]
}

pub async fn send_encrypted_message(
    tx: &mpsc::UnboundedSender<Message>,
    keys: &SessionKeys,
    sender_name: &str,
    recipient_name: &str,
    plaintext: &[u8],
    fields: MsgFields,
    client_msg_id: Option<i64>,
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

    data.extend_from_slice(&client_msg_id.unwrap_or(0).to_be_bytes());

    tx.send(Message::Binary(data))
        .map_err(|e| format!("send error: {}", e))
}

pub async fn send_to_all_my_sessions(
    state: &Arc<AppState>,
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

pub async fn send_to_user_sessions(state: &Arc<AppState>, username: &str, packet: Vec<u8>) {
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
            let _ = s.tx.send(Message::Binary(packet.clone()));
        }
    }
}

pub async fn broadcast_system_message(
    state: &Arc<AppState>,
    message: &str,
    exclude_username: Option<&str>,
) {
    for entry in state.sessions.iter() {
        let session = entry.value();
        let connected = session.connected.load(std::sync::atomic::Ordering::Relaxed);
        if connected {
            if let Some(uname) = session.username.get()
                && Some(uname.as_str()) == exclude_username
            {
                continue;
            }
            let _ = send_system_message(&session.tx, message).await;
        }
    }
}

pub async fn broadcast_invalidate_cache(state: &Arc<AppState>, exclude_username: Option<&str>) {
    let pkt = build_invalidate_cache_packet();
    for entry in state.sessions.iter() {
        let session = entry.value();
        let connected = session.connected.load(std::sync::atomic::Ordering::Relaxed);
        if connected {
            if let Some(uname) = session.username.get()
                && Some(uname.as_str()) == exclude_username
            {
                continue;
            }
            let _ = session.tx.send(Message::Binary(pkt.clone()));
        }
    }
}

pub async fn push_login_history(
    tx: &mpsc::UnboundedSender<Message>,
    keys: &SessionKeys,
    my_user_id: &str,
    state: &Arc<AppState>,
) {
    if my_user_id.is_empty() {
        return;
    }
    let tx_h = tx.clone();
    let keys_h = keys.clone();
    let uid_h = my_user_id.to_string();
    let state_h = state.clone();

    let personal = state_h.get_recent_personal(&uid_h, LOGIN_PER_CHAT).await;
    if let Ok(msgs) = personal {
        let msg_ids: Vec<i64> = msgs.iter().map(|m| m.0).collect();
        let reactions = state_h
            .get_reactions_for_messages(MSG_KIND_PERSONAL, &msg_ids)
            .await
            .unwrap_or_default();
        for (msg_id, sender_id, recipient_id, content, ts, reply_id, flag_me, flag_any, edited) in
            msgs
        {
            let sender = state_h.resolve_username(&sender_id).await;
            let recipient = state_h.resolve_username(&recipient_id).await;
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
                    edited,
                },
                None,
            )
            .await;
            if let Some(msg_reacts) = reactions.get(&msg_id) {
                for (emoji, users) in msg_reacts {
                    let count = users.len() as u32;
                    let who = users.join(",");
                    let pkt = build_reaction_packet(msg_id, MSG_KIND_PERSONAL, emoji, count, &who);
                    let _ = tx_h.send(Message::Binary(pkt));
                }
            }
        }
    }

    let groups = state_h.get_recent_groups(&uid_h, LOGIN_PER_CHAT).await;
    if let Ok(msgs) = groups {
        let msg_ids: Vec<i64> = msgs.iter().map(|m| m.0).collect();
        let reactions = state_h
            .get_reactions_for_messages(MSG_KIND_GROUP, &msg_ids)
            .await
            .unwrap_or_default();
        for (msg_id, gname, sender_id, content, ts, reply_id, flag_me, flag_any, edited) in msgs {
            let sender = state_h.resolve_username(&sender_id).await;
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
                    edited,
                },
                None,
            )
            .await;
            if let Some(msg_reacts) = reactions.get(&msg_id) {
                for (emoji, users) in msg_reacts {
                    let count = users.len() as u32;
                    let who = users.join(",");
                    let pkt = build_reaction_packet(msg_id, MSG_KIND_GROUP, emoji, count, &who);
                    let _ = tx_h.send(Message::Binary(pkt));
                }
            }
        }
    }

    let channels = state_h.get_recent_channels(&uid_h, LOGIN_PER_CHAT).await;
    if let Ok(msgs) = channels {
        let msg_ids: Vec<i64> = msgs.iter().map(|m| m.0).collect();
        let reactions = state_h
            .get_reactions_for_messages(MSG_KIND_CHANNEL, &msg_ids)
            .await
            .unwrap_or_default();
        for (msg_id, cname, sender_id, content, ts, reply_id, flag_me, flag_any, views, edited) in
            msgs
        {
            let sender = state_h.resolve_username(&sender_id).await;
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
                    edited,
                },
                None,
            )
            .await;
            if let Some(msg_reacts) = reactions.get(&msg_id) {
                for (emoji, users) in msg_reacts {
                    let count = users.len() as u32;
                    let who = users.join(",");
                    let pkt = build_reaction_packet(msg_id, MSG_KIND_CHANNEL, emoji, count, &who);
                    let _ = tx_h.send(Message::Binary(pkt));
                }
            }
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
    state: &Arc<AppState>,
) {
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

    let client = match state.db.get().await {
        Ok(c) => c,
        Err(e) => {
            let _ = send_system_message(tx, &format!("[Система] Ошибка пула БД: {}", e)).await;
            return;
        }
    };

    let raw: Vec<HistRow> = if chat_owned.starts_with('#') {
        let gname = chat_owned.trim_start_matches('#').to_string();
        let query = client.prepare_cached(
            "SELECT gm.id, gm.sender_id, gm.content,
                    (EXTRACT(EPOCH FROM gm.sent_at) * 1000)::bigint, gm.reply_to_id, gm.first_read_at,
                    gm.edited
             FROM group_messages gm
             JOIN groups g ON gm.group_id = g.id
             LEFT JOIN hidden_messages h ON h.kind = 2 AND h.msg_id = gm.id AND h.user_id = $1
             WHERE g.name = $2 AND gm.id < $3 AND h.msg_id IS NULL
             ORDER BY gm.id DESC LIMIT $4"
        ).await.unwrap();

        let rows = client
            .query(&query, &[&me, &gname, &cursor, &limit])
            .await
            .unwrap_or_default();

        rows.into_iter()
            .map(|row| {
                let id: i64 = row.get(0);
                let sender_id: String = row.get(1);
                let content: String = row.get(2);
                let ts: i64 = row.get(3);
                let reply_id: Option<i64> = row.get(4);
                let first_read_at: Option<chrono::DateTime<chrono::Utc>> = row.get(5);
                let edited: bool = row.get(6);
                (
                    id,
                    sender_id,
                    chat_owned.clone(),
                    content,
                    ts,
                    reply_id,
                    first_read_at.is_some(),
                    false,
                    None,
                    edited,
                )
            })
            .collect()
    } else if chat_owned.starts_with('&') {
        let cname = chat_owned.trim_start_matches('&').to_string();
        let query = client
            .prepare_cached(
                "SELECT cm.id, cm.sender_id, cm.content,
                    (EXTRACT(EPOCH FROM cm.sent_at) * 1000)::bigint, cm.reply_to_id,
                    (SELECT COUNT(*) FROM channel_message_views v WHERE v.channel_msg_id = cm.id),
                    cm.edited
             FROM channel_messages cm
             JOIN channels c ON cm.channel_id = c.id
             LEFT JOIN hidden_messages h ON h.kind = 3 AND h.msg_id = cm.id AND h.user_id = $1
             WHERE c.name = $2 AND cm.id < $3 AND h.msg_id IS NULL
             ORDER BY cm.id DESC LIMIT $4",
            )
            .await
            .unwrap();

        let rows = client
            .query(&query, &[&me, &cname, &cursor, &limit])
            .await
            .unwrap_or_default();

        rows.into_iter()
            .map(|row| {
                let id: i64 = row.get(0);
                let sender_id: String = row.get(1);
                let content: String = row.get(2);
                let ts: i64 = row.get(3);
                let reply_id: Option<i64> = row.get(4);
                let views: i64 = row.get(5);
                let edited: bool = row.get(6);
                let v = views as u32;
                (
                    id,
                    sender_id,
                    chat_owned.clone(),
                    content,
                    ts,
                    reply_id,
                    true,
                    v > 0,
                    Some(v),
                    edited,
                )
            })
            .collect()
    } else {
        let peer_id_opt = state.resolve_id(&chat_owned).await;
        let peer_id = match peer_id_opt {
            Some(id) => id,
            None => return,
        };
        let query = client.prepare_cached(
            "SELECT m.id, m.sender_id, m.content,
                    (EXTRACT(EPOCH FROM m.sent_at) * 1000)::bigint, m.reply_to_id, m.read_at,
                    m.edited
             FROM messages m
             LEFT JOIN hidden_messages h ON h.kind = 1 AND h.msg_id = m.id AND h.user_id = $1
             WHERE ((m.sender_id = $1 AND m.recipient_id = $2) OR (m.sender_id = $2 AND m.recipient_id = $1))
               AND m.id < $3 AND h.msg_id IS NULL
             ORDER BY m.id DESC LIMIT $4"
        ).await.unwrap();

        let rows = client
            .query(&query, &[&me, &peer_id, &cursor, &limit])
            .await
            .unwrap_or_default();

        rows.into_iter()
            .map(|row| {
                let id: i64 = row.get(0);
                let sender_id: String = row.get(1);
                let content: String = row.get(2);
                let ts: i64 = row.get(3);
                let reply_id: Option<i64> = row.get(4);
                let read_at: Option<chrono::DateTime<chrono::Utc>> = row.get(5);
                let edited: bool = row.get(6);

                let is_sender = sender_id == me;
                let read_flag = read_at.is_some();
                let flag_me = if is_sender { true } else { read_flag };
                let flag_any = if is_sender { read_flag } else { true };

                (
                    id,
                    sender_id,
                    chat_owned.clone(),
                    content,
                    ts,
                    reply_id,
                    flag_me,
                    flag_any,
                    None,
                    edited,
                )
            })
            .collect()
    };

    let mut msgs = raw;
    msgs.reverse();

    let count = msgs.len();
    info!("История {}: отдано {} сообщений", chat, count);

    let kind = if chat_owned.starts_with('#') {
        MSG_KIND_GROUP
    } else if chat_owned.starts_with('&') {
        MSG_KIND_CHANNEL
    } else {
        MSG_KIND_PERSONAL
    };

    let msg_ids: Vec<i64> = msgs.iter().map(|m| m.0).collect();
    let reactions = state
        .get_reactions_for_messages(kind, &msg_ids)
        .await
        .unwrap_or_default();

    for (msg_id, sender_id, recipient, content, ts, reply_id, flag_me, flag_any, views, edited) in
        msgs
    {
        let sender_name = state.resolve_username(&sender_id).await;

        let _ = send_encrypted_message(
            tx,
            keys,
            &sender_name,
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
            None,
        )
        .await;

        if let Some(msg_reacts) = reactions.get(&msg_id) {
            for (emoji, users) in msg_reacts {
                let count = users.len() as u32;
                let who = users.join(",");
                let pkt = build_reaction_packet(msg_id, kind, emoji, count, &who);
                let _ = tx.send(Message::Binary(pkt));
            }
        }
    }

    let _ = send_system_message(tx, &format!("[Система] history_done|{}|{}", chat, count)).await;
}

pub async fn send_messages_by_ids(
    tx: &mpsc::UnboundedSender<Message>,
    keys: &SessionKeys,
    my_user_id: &str,
    kind: u8,
    ids: Vec<i64>,
    state: &Arc<AppState>,
) {
    if ids.is_empty() {
        return;
    }
    let requested = ids.len();
    let me = my_user_id.to_string();

    let result = state.get_messages_by_ids(kind, &ids, &me).await;

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

    let reactions = state
        .get_reactions_for_messages(kind, &ids)
        .await
        .unwrap_or_default();

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
            None,
        )
        .await;

        if let Some(msg_reacts) = reactions.get(&msg_id) {
            for (emoji, users) in msg_reacts {
                let count = users.len() as u32;
                let who = users.join(",");
                let pkt = build_reaction_packet(msg_id, kind, emoji, count, &who);
                let _ = tx.send(Message::Binary(pkt));
            }
        }
    }
}

use serde_json::json;

pub async fn send_system_notification(state: &Arc<AppState>, target_user_id: &str, text: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let msg_id = match state
        .store_message("system", target_user_id, text, now, None)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            log::error!("Ошибка сохранения системного уведомления: {}", e);
            return;
        }
    };

    let target_name = state.resolve_username(target_user_id).await;
    if target_name == DELETED_LABEL {
        return;
    }

    let tokens = state
        .online_users
        .get(&target_name)
        .map(|r| r.clone())
        .unwrap_or_default();
    let is_online = !tokens.is_empty();

    if is_online {
        for tok in tokens {
            let sess = state.sessions.get(&tok).map(|r| r.clone());
            if let Some(s) = sess {
                let _ = send_encrypted_message(
                    &s.tx,
                    &s.keys,
                    "system",
                    &target_name,
                    text.as_bytes(),
                    MsgFields {
                        timestamp: now,
                        msg_id,
                        reply_to_id: 0,
                        flag_me: false,
                        flag_any: false,
                        views: None,
                        edited: false,
                    },
                    None,
                )
                .await;
            }
        }
    }

    if !is_online {
        let fcm_tokens = state
            .get_fcm_tokens_for_user(target_user_id)
            .await
            .unwrap_or_default();
        for fcm_tok in fcm_tokens {
            let title = "VartChat System".to_string();
            let body = text.chars().take(150).collect::<String>();
            let data_payload =
                json!({ "chatKey": "system", "kind": "system", "sender": "VartChat System" });
            let state_fcm = state.clone();
            tokio::spawn(async move {
                crate::fcm::send_fcm_push_and_cleanup(
                    state_fcm,
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
