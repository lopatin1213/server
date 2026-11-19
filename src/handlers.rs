use aes_gcm::{
    Key,
    aead::{Aead, KeyInit},
};
use log::{error, info, warn};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_tungstenite::tungstenite::Message;

use crate::app_state::{MsgFields, Session};
use crate::client::{resolve_display_name, Ctx};
use crate::constants::*;
use crate::senders::{
    broadcast_system_message, send_chat_history, send_encrypted_message, send_messages_by_ids,
    send_system_message, send_to_all_my_sessions,
};
use crate::fcm::send_fcm_push_and_cleanup;

impl Ctx {
pub async fn handle_user(&self, data: &[u8]) {
    let rest = &data[1..];

                    if rest.len() < 4 + 4 + 12 + 4 + 24 {

                        warn!("0x01: мало данных");

                        return;

                    }

                    let mut offset = 0;

                    let sender_len =

                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;

                    offset += 4;

                    if rest.len() < offset + sender_len {

                        return;

                    }

                    let _sender_name =

                        String::from_utf8_lossy(&rest[offset..offset + sender_len]).to_string();

                    offset += sender_len;

                    let recipient_len =

                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;

                    offset += 4;

                    if rest.len() < offset + recipient_len {

                        return;

                    }

                    let recipient_name =

                        String::from_utf8_lossy(&rest[offset..offset + recipient_len]).to_string();

                    offset += recipient_len;

                    let nonce = &rest[offset..offset + 12];

                    offset += 12;

                    let msg_len =

                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;

                    offset += 4;

                    if rest.len() < offset + msg_len {

                        return;

                    }

                    let encrypted = &rest[offset..offset + msg_len];

                    offset += msg_len;



                    let (timestamp, client_msg_id, reply_to_id) = if rest.len() >= offset + 24 {

                        let ts = i64::from_be_bytes(rest[offset..offset + 8].try_into().unwrap());

                        let id =

                            i64::from_be_bytes(rest[offset + 8..offset + 16].try_into().unwrap());

                        let rt =

                            i64::from_be_bytes(rest[offset + 16..offset + 24].try_into().unwrap());

                        (ts, id, rt)

                    } else {

                        let now = SystemTime::now()

                            .duration_since(UNIX_EPOCH)

                            .unwrap()

                            .as_millis() as i64;

                        (now, 0, 0)

                    };

                    let reply_opt = (reply_to_id != 0).then_some(reply_to_id);



                    let cipher =

                        aes_gcm::Aes256Gcm::new(Key::<aes_gcm::Aes256Gcm>::from_slice(&self.keys.key));

                    let nonce = aes_gcm::Nonce::from_slice(nonce);

                    let plaintext = match cipher.decrypt(nonce, encrypted) {

                        Ok(p) => p,

                        Err(e) => {

                            error!("0x01: ошибка расшифровки: {}", e);

                            return;

                        }

                    };

                    let content = String::from_utf8_lossy(&plaintext).to_string();



                    if content.starts_with('/') {

                        if content.starts_with("/history") {

                            let parts: Vec<&str> = content.split_whitespace().collect();

                            if parts.len() < 2 {

                                let _ = send_system_message(

                                    &self.tx,

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

                                    &self.tx,

                                    &self.keys,

                                    &self.my_user_id,

                                    chat,

                                    before_id,

                                    HISTORY_PAGE_SIZE,

                                    &self.state,

                                )

                                .await;

                            }

                            return;

                        }

                        if content.starts_with("/getmsg") {

                            let parts: Vec<&str> = content.split_whitespace().collect();

                            if parts.len() < 3 {

                                let _ = send_system_message(

                                    &self.tx,

                                    "[Система] Использование: /getmsg <kind> <id1> [<id2> ...]",

                                )

                                .await;

                            } else {

                                let kind: u8 = parts[1].parse().unwrap_or(0);

                                let ids: Vec<i64> =

                                    parts[2..].iter().filter_map(|s| s.parse().ok()).collect();

                                send_messages_by_ids(&self.tx, &self.keys, &self.my_user_id, kind, ids, &self.state)

                                    .await;

                            }

                            return;

                        }

                        let response =

                            self.process_command(&content)

                                .await;

                        if !response.is_empty() {

                            let _ = send_system_message(&self.tx, &response).await;

                        }

                        return;

                    }



                    if !recipient_name.starts_with(['#', '&']) {

                        let recipient_id_opt = self.state.resolve_id(&recipient_name).await;

                        let recipient_id = match recipient_id_opt {

                            Some(id) => id,

                            None => {

                                let _ = send_system_message(

                                    &self.tx,

                                    &format!("[Система] Пользователь {} не найден", recipient_name),

                                )

                                .await;

                                let pkt = crate::senders::build_invalidate_cache_packet();

                                let _ = self.tx.send(Message::Binary(pkt));

                                return;

                            }

                        };



                        let stored_id = match self.state

                            .store_message(

                                &self.my_user_id,

                                &recipient_id,

                                &content,

                                timestamp,

                                reply_opt,

                            )

                            .await

                        {

                            Ok(id) => id,

                            Err(e) => {

                                error!("ОШИБКА сохранения сообщения в БД: {}", e);

                                return;

                            }

                        };



                        send_to_all_my_sessions(

                            &self.state,

                            &self.my_username,

                            &recipient_name,

                            &plaintext,

                            MsgFields {

                                timestamp,

                                msg_id: stored_id,

                                reply_to_id,

                                flag_me: true,

                                flag_any: false,

                                views: None,

                                edited: false,

                            },

                            Some(client_msg_id),

                        )

                        .await;



                        if self.is_background {

                            let _ = send_encrypted_message(

                                &self.tx,

                                &self.keys,

                                &self.my_username,

                                &recipient_name,

                                &plaintext,

                                MsgFields {

                                    timestamp,

                                    msg_id: stored_id,

                                    reply_to_id,

                                    flag_me: true,

                                    flag_any: false,

                                    views: None,

                                    edited: false,

                                },

                                Some(client_msg_id),

                            )

                            .await;

                        }



                        if recipient_id != self.my_user_id {

                            let target_tokens = {

                                self.state

                                    .online_users

                                    .get(&recipient_name)

                                    .map(|r| r.clone())

                                    .unwrap_or_default()

                            };

                            for tok in target_tokens {

                                let target_session = self.state.sessions.get(&tok).map(|r| r.clone());

                                if let Some(ts) = target_session {

                                    let _ = send_encrypted_message(

                                        &ts.tx,

                                        &ts.keys,

                                        &self.my_username,

                                        &recipient_name,

                                        &plaintext,

                                        MsgFields {

                                            timestamp,

                                            msg_id: stored_id,

                                            reply_to_id,

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



                            let fcm_tokens = self.state

                                .get_fcm_tokens_for_user(&recipient_id)

                                .await

                                .unwrap_or_default();

                            let sender_display_name =

                                resolve_display_name(&self.state, &self.my_user_id, &self.my_username).await;



                            for fcm_tok in fcm_tokens {

                                let title = sender_display_name.to_string();

                                let body = content.chars().take(100).collect::<String>();

                                let data_payload = json!({ "sender": sender_display_name, "sender_username": self.my_username, "chatKey": self.my_username, "type": "private", "kind": "personal", "msg_id": stored_id.to_string() });

                                let state_fcm = self.state.clone();

                                tokio::spawn(async move {

                                    send_fcm_push_and_cleanup(

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

                        return;

                    }



                    if recipient_name.starts_with('#') {

                        let group_name = recipient_name.trim_start_matches('#').to_string();

                        let is_member = {

                            match self.state.db.get().await {

                                Ok(client) => client.query_opt("SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE g.name = $1 AND gm.user_id = $2", &[&group_name, &self.my_user_id]).await.map(|opt| opt.is_some()).unwrap_or(false),

                                Err(_) => false

                            }

                        };

                        if !is_member {

                            let _ =

                                send_system_message(&self.tx, "[Система] Вы не состоите в этой группе")

                                    .await;

                            return;

                        }



                        let stored_id = match self.state

                            .store_group_message(

                                &group_name,

                                &self.my_user_id,

                                &content,

                                timestamp,

                                reply_opt,

                            )

                            .await

                        {

                            Ok(id) => id,

                            Err(e) => {

                                error!("ОШИБКА сохранения группового сообщения в БД: {}", e);

                                return;

                            }

                        };



                        let members = self.state

                            .get_group_members(&group_name)

                            .await

                            .unwrap_or_default();

                        let recip_with_hash = format!("#{}", group_name);



                        send_to_all_my_sessions(

                            &self.state,

                            &self.my_username,

                            &recip_with_hash,

                            &plaintext,

                            MsgFields {

                                timestamp,

                                msg_id: stored_id,

                                reply_to_id,

                                flag_me: true,

                                flag_any: false,

                                views: None,

                                edited: false,

                            },

                            Some(client_msg_id),

                        )

                        .await;



                        if self.is_background {

                            let _ = send_encrypted_message(

                                &self.tx,

                                &self.keys,

                                &self.my_username,

                                &recip_with_hash,

                                &plaintext,

                                MsgFields {

                                    timestamp,

                                    msg_id: stored_id,

                                    reply_to_id,

                                    flag_me: true,

                                    flag_any: false,

                                    views: None,

                                    edited: false,

                                },

                                Some(client_msg_id),

                            )

                            .await;

                        }



                        for member_id in members {

                            if member_id == self.my_user_id {

                                continue;

                            }

                            let member_name = self.state.resolve_username(&member_id).await;

                            if member_name == DELETED_LABEL {

                                continue;

                            }



                            let target_online = self.state.online_users.contains_key(&member_name);

                            if target_online {

                                let target_tokens = {

                                    self.state

                                        .online_users

                                        .get(&member_name)

                                        .map(|r| r.clone())

                                        .unwrap_or_default()

                                };

                                for tok in target_tokens {

                                    let target_session =

                                        self.state.sessions.get(&tok).map(|r| r.clone());

                                    if let Some(ts) = target_session {

                                        let _ = send_encrypted_message(

                                            &ts.tx,

                                            &ts.keys,

                                            &self.my_username,

                                            &recip_with_hash,

                                            &plaintext,

                                            MsgFields {

                                                timestamp,

                                                msg_id: stored_id,

                                                reply_to_id,

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

                            } else {

                                let fcm_tokens = self.state

                                    .get_fcm_tokens_for_user(&member_id)

                                    .await

                                    .unwrap_or_default();

                                let sender_display_name =

                                    resolve_display_name(&self.state, &self.my_user_id, &self.my_username).await;

                                for fcm_tok in fcm_tokens {

                                    let title = format!("Новое сообщение в группе {}", group_name);

                                    let body = format!(

                                        "{}: {}",

                                        sender_display_name,

                                        content.chars().take(100).collect::<String>()

                                    );

                                    let data_payload = json!({ "sender": sender_display_name, "group": group_name, "chatKey": format!("#{}", group_name), "type": "group", "kind": "group", "msg_id": stored_id.to_string() });

                                    let state_fcm = self.state.clone();

                                    tokio::spawn(async move {

                                        send_fcm_push_and_cleanup(

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

                        return;

                    }



                    if recipient_name.starts_with('&') {

                        let channel_name = recipient_name.trim_start_matches('&').to_string();

                        let is_owner = {

                            match self.state.db.get().await {

                                Ok(client) => client.query_opt("SELECT 1 FROM channels WHERE name = $1 AND creator_id = $2", &[&channel_name, &self.my_user_id]).await.map(|opt| opt.is_some()).unwrap_or(false),

                                Err(_) => false

                            }

                        };

                        if !is_owner {

                            let _ = send_system_message(

                                &self.tx,

                                "[Система] Только владелец канала может отправлять сообщения",

                            )

                            .await;

                            return;

                        }



                        let stored_id = match self.state

                            .store_channel_message(

                                &channel_name,

                                &self.my_user_id,

                                &content,

                                timestamp,

                                reply_opt,

                            )

                            .await

                        {

                            Ok(id) => id,

                            Err(e) => {

                                error!("ОШИБКА сохранения сообщения канала в БД: {}", e);

                                return;

                            }

                        };



                        let subscribers = self.state

                            .get_channel_subscribers(&channel_name)

                            .await

                            .unwrap_or_default();

                        let recip_with_amp = format!("&{}", channel_name);



                        send_to_all_my_sessions(

                            &self.state,

                            &self.my_username,

                            &recip_with_amp,

                            &plaintext,

                            MsgFields {

                                timestamp,

                                msg_id: stored_id,

                                reply_to_id,

                                flag_me: true,

                                flag_any: false,

                                views: Some(0),

                                edited: false,

                            },

                            Some(client_msg_id),

                        )

                        .await;



                        for sub_id in subscribers {

                            if sub_id == self.my_user_id {

                                continue;

                            }

                            let sub_name = self.state.resolve_username(&sub_id).await;

                            if sub_name == DELETED_LABEL {

                                continue;

                            }



                            let target_online = self.state.online_users.contains_key(&sub_name);

                            if target_online {

                                let target_tokens = {

                                    self.state

                                        .online_users

                                        .get(&sub_name)

                                        .map(|r| r.clone())

                                        .unwrap_or_default()

                                };

                                for tok in target_tokens {

                                    let target_session =

                                        self.state.sessions.get(&tok).map(|r| r.clone());

                                    if let Some(ts) = target_session {

                                        let _ = send_encrypted_message(

                                            &ts.tx,

                                            &ts.keys,

                                            &self.my_username,

                                            &recip_with_amp,

                                            &plaintext,

                                            MsgFields {

                                                timestamp,

                                                msg_id: stored_id,

                                                reply_to_id,

                                                flag_me: true,

                                                flag_any: false,

                                                views: Some(0),

                                                edited: false,

                                            },

                                            None,

                                        )

                                        .await;

                                    }

                                }

                            } else {

                                let fcm_tokens = self.state

                                    .get_fcm_tokens_for_user(&sub_id)

                                    .await

                                    .unwrap_or_default();

                                let sender_display_name =

                                    resolve_display_name(&self.state, &self.my_user_id, &self.my_username).await;

                                for fcm_tok in fcm_tokens {

                                    let title =

                                        format!("Новое сообщение в канале {}", channel_name);

                                    let body = content.chars().take(100).collect::<String>();

                                    let data_payload = json!({ "sender": sender_display_name, "channel": channel_name, "chatKey": format!("&{}", channel_name), "type": "channel", "kind": "channel", "msg_id": stored_id.to_string() });

                                    let state_fcm = self.state.clone();

                                    tokio::spawn(async move {

                                        send_fcm_push_and_cleanup(

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

                        return;

                    }

}

pub async fn handle_edit(&self, data: &[u8]) {
    let rest = &data[1..];

                    if rest.len() < 8 + 1 + 12 + 4 {

                        warn!("0x08: мало данных");

                        return;

                    }

                    let mut offset = 0usize;

                    let msg_id = i64::from_be_bytes(rest[offset..offset + 8].try_into().unwrap());

                    offset += 8;

                    let kind = rest[offset];

                    offset += 1;

                    let nonce_bytes = &rest[offset..offset + 12];

                    offset += 12;

                    let enc_len =

                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;

                    offset += 4;

                    if rest.len() < offset + enc_len {

                        return;

                    }

                    let encrypted = &rest[offset..offset + enc_len];



                    let cipher =

                        aes_gcm::Aes256Gcm::new(Key::<aes_gcm::Aes256Gcm>::from_slice(&self.keys.key));

                    let nonce_ref = aes_gcm::Nonce::from_slice(nonce_bytes);

                    let plaintext = match cipher.decrypt(nonce_ref, encrypted) {

                        Ok(p) => p,

                        Err(e) => {

                            error!("0x08: ошибка расшифровки: {}", e);

                            return;

                        }

                    };

                    let new_text = String::from_utf8_lossy(&plaintext).to_string();



                    match kind {

                        MSG_KIND_PERSONAL => {

                            let lookup = self.state.lookup_personal_message(msg_id).await;

                            let (sender_id, recipient_id) = match lookup {

                                Ok(Some(v)) => v,

                                Ok(None) => {

                                    let _ =

                                        send_system_message(&self.tx, "[Система] Сообщение не найдено")

                                            .await;

                                    return;

                                }

                                Err(e) => {

                                    let _ =

                                        send_system_message(&self.tx, &format!("[Система] {}", e)).await;

                                    return;

                                }

                            };



                            if sender_id != self.my_user_id {

                                let _ = send_system_message(

                                    &self.tx,

                                    "[Система] Редактировать можно только свои сообщения",

                                )

                                .await;

                                return;

                            }



                            let (ts, reply_opt, read_flag) = {

                                match self.state.db.get().await {

                                    Ok(client) => {

                                        match client.query_opt("SELECT (EXTRACT(EPOCH FROM sent_at) * 1000)::bigint, reply_to_id, read_at FROM messages WHERE id = $1", &[&msg_id]).await {

                                            Ok(Some(row)) => {

                                                let ts: i64 = row.get(0);

                                                let rt: Option<i64> = row.get(1);

                                                let ra: Option<chrono::DateTime<chrono::Utc>> = row.get(2);

                                                (ts, rt, ra.is_some())

                                            }

                                            _ => (0, None, false),

                                        }

                                    }

                                    Err(_) => (0, None, false),

                                }

                            };



                            let _ = self.state

                                .update_personal_message_content(msg_id, &new_text)

                                .await;



                            let reply_id = reply_opt.unwrap_or(0);

                            let (s_name, r_name) = (

                                self.state.resolve_username(&sender_id).await,

                                self.state.resolve_username(&recipient_id).await,

                            );



                            send_to_all_my_sessions(

                                &self.state,

                                &self.my_username,

                                &r_name,

                                new_text.as_bytes(),

                                MsgFields {

                                    timestamp: ts,

                                    msg_id,

                                    reply_to_id: reply_id,

                                    flag_me: true,

                                    flag_any: read_flag,

                                    views: None,

                                    edited: true,

                                },

                                None,

                            )

                            .await;



                            if recipient_id != self.my_user_id {

                                let hidden = {

                                    match self.state.db.get().await {

                                        Ok(client) => client.query_opt("SELECT 1 FROM hidden_messages WHERE user_id = $1 AND kind = 1 AND msg_id = $2", &[&recipient_id, &msg_id]).await.map(|opt| opt.is_some()).unwrap_or(false),

                                        Err(_) => false

                                    }

                                };

                                if !hidden {

                                    let tokens = {

                                        self.state

                                            .online_users

                                            .get(&r_name)

                                            .map(|r| r.clone())

                                            .unwrap_or_default()

                                    };

                                    for tok in tokens {

                                        let sess = self.state.sessions.get(&tok).map(|r| r.clone());

                                        if let Some(s) = sess {

                                            let _ = send_encrypted_message(

                                                &s.tx,

                                                &s.keys,

                                                &s_name,

                                                &r_name,

                                                new_text.as_bytes(),

                                                MsgFields {

                                                    timestamp: ts,

                                                    msg_id,

                                                    reply_to_id: reply_id,

                                                    flag_me: read_flag,

                                                    flag_any: true,

                                                    views: None,

                                                    edited: true,

                                                },

                                                None,

                                            )

                                            .await;

                                        }

                                    }

                                }

                            }

                        }

                        MSG_KIND_GROUP => {

                            let mut sender_id_opt = None;

                            let mut ts = 0;

                            let mut reply_id = 0;

                            let mut flag_any = false;

                            let mut gname = String::new();



                            if let Ok(client) = self.state.db.get().await

                                && let Ok(Some(row)) = client.query_opt("SELECT gm.sender_id, (EXTRACT(EPOCH FROM gm.sent_at) * 1000)::bigint, gm.reply_to_id, gm.first_read_at, g.name FROM group_messages gm JOIN groups g ON gm.group_id = g.id WHERE gm.id = $1", &[&msg_id]).await {

                                sender_id_opt = Some(row.get::<_, String>(0));

                                ts = row.get(1);

                                reply_id = row.get::<_, Option<i64>>(2).unwrap_or(0);

                                flag_any = row.get::<_, Option<chrono::DateTime<chrono::Utc>>>(3).is_some();

                                gname = row.get(4);

                            }



                            let sender_id = match sender_id_opt {

                                Some(v) => v,

                                None => {

                                    let _ =

                                        send_system_message(&self.tx, "[Система] Сообщение не найдено")

                                            .await;

                                    return;

                                }

                            };



                            if sender_id != self.my_user_id {

                                let _ = send_system_message(

                                    &self.tx,

                                    "[Система] Редактировать можно только свои сообщения",

                                )

                                .await;

                                return;

                            }



                            let _ = self.state.update_group_message_content(msg_id, &new_text).await;

                            let recip_with_hash = format!("#{}", gname);



                            send_to_all_my_sessions(

                                &self.state,

                                &self.my_username,

                                &recip_with_hash,

                                new_text.as_bytes(),

                                MsgFields {

                                    timestamp: ts,

                                    msg_id,

                                    reply_to_id: reply_id,

                                    flag_me: true,

                                    flag_any,

                                    views: None,

                                    edited: true,

                                },

                                None,

                            )

                            .await;



                            let members = self.state.get_group_members(&gname).await.unwrap_or_default();

                            for member_id in members {

                                if member_id == self.my_user_id {

                                    continue;

                                }

                                let hidden = {

                                    match self.state.db.get().await {

                                        Ok(client) => client.query_opt("SELECT 1 FROM hidden_messages WHERE user_id = $1 AND kind = 2 AND msg_id = $2", &[&member_id, &msg_id]).await.map(|opt| opt.is_some()).unwrap_or(false),

                                        Err(_) => false

                                    }

                                };

                                if hidden {

                                    continue;

                                }



                                let member_name = self.state.resolve_username(&member_id).await;

                                if member_name == DELETED_LABEL {

                                    continue;

                                }



                                let tokens = {

                                    self.state

                                        .online_users

                                        .get(&member_name)

                                        .map(|r| r.clone())

                                        .unwrap_or_default()

                                };

                                for tok in tokens {

                                    let sess = self.state.sessions.get(&tok).map(|r| r.clone());

                                    if let Some(s) = sess {

                                        let _ = send_encrypted_message(

                                            &s.tx,

                                            &s.keys,

                                            &self.my_username,

                                            &recip_with_hash,

                                            new_text.as_bytes(),

                                            MsgFields {

                                                timestamp: ts,

                                                msg_id,

                                                reply_to_id: reply_id,

                                                flag_me: false,

                                                flag_any,

                                                views: None,

                                                edited: true,

                                            },

                                            None,

                                        )

                                        .await;

                                    }

                                }

                            }

                            info!("Групповое сообщение id={} отредактировано", msg_id);

                        }

                        MSG_KIND_CHANNEL => {

                            let lookup = self.state.lookup_channel_message(msg_id).await;

                            let (cname, creator_id, _sender_id) = match lookup {

                                Ok(Some(v)) => v,

                                Ok(None) => {

                                    let _ =

                                        send_system_message(&self.tx, "[Система] Сообщение не найдено")

                                            .await;

                                    return;

                                }

                                Err(e) => {

                                    let _ =

                                        send_system_message(&self.tx, &format!("[Система] {}", e)).await;

                                    return;

                                }

                            };



                            if creator_id != self.my_user_id {

                                let _ = send_system_message(&self.tx, "[Система] Только владелец канала может редактировать сообщения").await;

                                return;

                            }



                            let (ts, reply_id, views_u) = {

                                match self.state.db.get().await {

                                    Ok(client) => {

                                        match client.query_opt("SELECT (EXTRACT(EPOCH FROM sent_at) * 1000)::bigint, reply_to_id, (SELECT COUNT(*) FROM channel_message_views v WHERE v.channel_msg_id = cm.id) FROM channel_messages cm WHERE cm.id = $1", &[&msg_id]).await {

                                            Ok(Some(row)) => {

                                                let t: i64 = row.get(0);

                                                let r: i64 = row.get::<_, Option<i64>>(1).unwrap_or(0);

                                                let v: i64 = row.get(2);

                                                (t, r, v as u32)

                                            }

                                            _ => (0, 0, 0),

                                        }

                                    }

                                    Err(_) => (0, 0, 0),

                                }

                            };



                            let _ = self.state

                                .update_channel_message_content(msg_id, &new_text)

                                .await;

                            let recip_with_amp = format!("&{}", cname);



                            send_to_all_my_sessions(

                                &self.state,

                                &self.my_username,

                                &recip_with_amp,

                                new_text.as_bytes(),

                                MsgFields {

                                    timestamp: ts,

                                    msg_id,

                                    reply_to_id: reply_id,

                                    flag_me: true,

                                    flag_any: views_u > 0,

                                    views: Some(views_u),

                                    edited: true,

                                },

                                None,

                            )

                            .await;



                            let subscribers = self.state

                                .get_channel_subscribers(&cname)

                                .await

                                .unwrap_or_default();

                            for sub_id in subscribers {

                                if sub_id == self.my_user_id {

                                    continue;

                                }

                                let hidden = {

                                    match self.state.db.get().await {

                                        Ok(client) => client.query_opt("SELECT 1 FROM hidden_messages WHERE user_id = $1 AND kind = 3 AND msg_id = $2", &[&sub_id, &msg_id]).await.map(|opt| opt.is_some()).unwrap_or(false),

                                        Err(_) => false

                                    }

                                };

                                if hidden {

                                    continue;

                                }



                                let sub_name = self.state.resolve_username(&sub_id).await;

                                if sub_name == DELETED_LABEL {

                                    continue;

                                }



                                let tokens = {

                                    self.state

                                        .online_users

                                        .get(&sub_name)

                                        .map(|r| r.clone())

                                        .unwrap_or_default()

                                };

                                for tok in tokens {

                                    let sess = self.state.sessions.get(&tok).map(|r| r.clone());

                                    if let Some(s) = sess {

                                        let _ = send_encrypted_message(

                                            &s.tx,

                                            &s.keys,

                                            &self.my_username,

                                            &recip_with_amp,

                                            new_text.as_bytes(),

                                            MsgFields {

                                                timestamp: ts,

                                                msg_id,

                                                reply_to_id: reply_id,

                                                flag_me: true,

                                                flag_any: views_u > 0,

                                                views: Some(views_u),

                                                edited: true,

                                            },

                                            None,

                                        )

                                        .await;

                                    }

                                }

                            }

                            info!("Сообщение канала {} id={} отредактировано", cname, msg_id);

                        }

                        _ => {

                            warn!("0x08: неизвестный kind={}", kind);

                        }

                    }

}

pub async fn handle_read(&self, data: &[u8]) {
    let rest = &data[1..];

                    if rest.len() < 2 {

                        return;

                    }

                    let count = u16::from_be_bytes(rest[0..2].try_into().unwrap()) as usize;

                    if rest.len() < 2 + count * 9 {

                        return;

                    }



                    let mut personal_ids = Vec::new();

                    let mut group_ids = Vec::new();

                    let mut channel_ids = Vec::new();

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

                        self.my_username,

                        personal_ids.len(),

                        group_ids.len(),

                        channel_ids.len()

                    );



                    if !personal_ids.is_empty()

                        && let Ok(client) = self.state.db.get().await

                    {

                        let rows = client.query("SELECT id, sender_id FROM messages WHERE id = ANY($1) AND recipient_id = $2", &[&personal_ids, &self.my_user_id]).await.unwrap_or_default();

                        let mut by_author: std::collections::HashMap<String, Vec<i64>> =

                            std::collections::HashMap::new();

                        for row in rows {

                            let id: i64 = row.get(0);

                            let sender_id: String = row.get(1);

                            by_author.entry(sender_id).or_default().push(id);

                        }



                        let _ = client.execute("UPDATE messages SET read_at = CURRENT_TIMESTAMP WHERE id = ANY($1) AND read_at IS NULL", &[&personal_ids]).await;



                        for (author_id, ids) in by_author {

                            if author_id == self.my_user_id {

                                continue;

                            }

                            let author_name = self.state.resolve_username(&author_id).await;

                            let tokens = {

                                self.state

                                    .online_users

                                    .get(&author_name)

                                    .map(|r| r.clone())

                                    .unwrap_or_default()

                            };

                            let items: Vec<(u8, i64)> =

                                ids.iter().map(|id| (MSG_KIND_PERSONAL, *id)).collect();

                            let pkt = crate::senders::build_read_packet(&items);



                            for tok in tokens {

                                let sess = self.state.sessions.get(&tok).map(|r| r.clone());

                                if let Some(s) = sess {

                                    let _ = s.tx.send(Message::Binary(pkt.clone()));

                                }

                            }

                        }

                    }



                    if !group_ids.is_empty()

                        && let Ok(client) = self.state.db.get().await

                    {

                        let rows = client

                            .query(

                                "SELECT id, group_id FROM group_messages WHERE id = ANY($1)",

                                &[&group_ids],

                            )

                            .await

                            .unwrap_or_default();

                        let mut by_group: std::collections::HashMap<String, Vec<i64>> =

                            std::collections::HashMap::new();

                        for row in rows {

                            let id: i64 = row.get(0);

                            let group_id: String = row.get(1);

                            by_group.entry(group_id).or_default().push(id);

                        }



                        let _ = client.execute("UPDATE group_messages SET first_read_at = CURRENT_TIMESTAMP WHERE id = ANY($1) AND first_read_at IS NULL", &[&group_ids]).await;



                        for (group_id, ids) in by_group {

                            let members = match client

                                .query(

                                    "SELECT user_id FROM group_members WHERE group_id = $1",

                                    &[&group_id],

                                )

                                .await

                            {

                                Ok(rows) => rows

                                    .into_iter()

                                    .map(|r| r.get::<_, String>(0))

                                    .collect::<Vec<String>>(),

                                Err(_) => Vec::new(),

                            };



                            let items: Vec<(u8, i64)> =

                                ids.iter().map(|id| (MSG_KIND_GROUP, *id)).collect();

                            let pkt = crate::senders::build_read_packet(&items);



                            for mid in members {

                                if mid == self.my_user_id {

                                    continue;

                                }

                                let name = self.state.resolve_username(&mid).await;

                                let tokens = {

                                    self.state

                                        .online_users

                                        .get(&name)

                                        .map(|r| r.clone())

                                        .unwrap_or_default()

                                };

                                for tok in tokens {

                                    let sess = self.state.sessions.get(&tok).map(|r| r.clone());

                                    if let Some(s) = sess {

                                        let _ = s.tx.send(Message::Binary(pkt.clone()));

                                    }

                                }

                            }

                        }

                    }



                    if !channel_ids.is_empty()

                        && let Ok(client) = self.state.db.get().await

                    {

                        let _ = client.execute("INSERT INTO channel_message_views (channel_msg_id, user_id) SELECT unnest($1::bigint[]), $2 ON CONFLICT DO NOTHING", &[&channel_ids, &self.my_user_id]).await;

                    }

}

pub async fn handle_delete(&self, data: &[u8]) {
    let rest = &data[1..];

                    if rest.len() < 9 {

                        warn!("0x05: мало данных");

                        return;

                    }

                    let msg_id = i64::from_be_bytes(rest[0..8].try_into().unwrap());

                    let kind = rest[8];



                    if msg_id == 0 {

                        if rest.len() < 9 + 1 + 4 {

                            warn!("0x05 (чат): мало данных");

                            return;

                        }

                        let dtype = rest[9];

                        let name_len =

                            u32::from_be_bytes(rest[10..14].try_into().unwrap()) as usize;

                        if rest.len() < 14 + name_len {

                            return;

                        }

                        let name = String::from_utf8_lossy(&rest[14..14 + name_len]).to_string();



                        info!(

                            "0x05: Удаление чата kind={} name={} type={}",

                            kind, name, dtype

                        );



                        match kind {

                            MSG_KIND_PERSONAL => {

                                let peer_id_opt = self.state.resolve_id(&name).await;

                                if let Some(peer_id) = peer_id_opt {

                                    if dtype == MSG_DELETE_FOR_ME {

                                        let _ =

                                            self.state.hide_personal_chat(&self.my_user_id, &peer_id).await;

                                    } else {

                                        let _ =

                                            self.state.delete_personal_chat(&self.my_user_id, &peer_id).await;

                                        let pkt = crate::senders::build_delete_chat_packet(

                                            kind, &name, 0,

                                        );

                                        crate::senders::send_to_user_sessions(

                                            &self.state,

                                            &self.my_username,

                                            pkt.clone(),

                                        )

                                        .await;

                                        crate::senders::send_to_user_sessions(&self.state, &name, pkt)

                                            .await;

                                    }

                                }

                            }

                            MSG_KIND_GROUP => {

                                if dtype == MSG_DELETE_FOR_ME {

                                    let _ = self.state.leave_group(&name, &self.my_user_id).await;

                                } else {

                                    let members =

                                        self.state.get_group_members(&name).await.unwrap_or_default();

                                    let del_res = self.state.delete_group(&name, &self.my_user_id).await;

                                    match del_res {

                                        Ok(true) => {

                                            let pkt = crate::senders::build_delete_chat_packet(

                                                kind, &name, 0,

                                            );

                                            for m_id in members {

                                                let m_name = self.state.resolve_username(&m_id).await;

                                                crate::senders::send_to_user_sessions(

                                                    &self.state,

                                                    &m_name,

                                                    pkt.clone(),

                                                )

                                                .await;

                                            }

                                        }

                                        Ok(false) => {

                                            let _ = send_system_message(

                                                &self.tx,

                                                "[Система] Только владелец может удалить группу",

                                            )

                                            .await;

                                        }

                                        Err(e) => {

                                            let _ = send_system_message(

                                                &self.tx,

                                                &format!("[Система] Ошибка удаления: {}", e),

                                            )

                                            .await;

                                        }

                                    }

                                }

                            }

                            MSG_KIND_CHANNEL => {

                                if dtype == MSG_DELETE_FOR_ME {

                                    let _ = self.state.unsubscribe_channel(&name, &self.my_user_id).await;

                                } else {

                                    let subs = self.state

                                        .get_channel_subscribers(&name)

                                        .await

                                        .unwrap_or_default();

                                    let del_res = self.state.delete_channel(&name, &self.my_user_id).await;

                                    match del_res {

                                        Ok(true) => {

                                            let pkt = crate::senders::build_delete_chat_packet(

                                                kind, &name, 0,

                                            );

                                            for sub_id in subs {

                                                let s_name = self.state.resolve_username(&sub_id).await;

                                                crate::senders::send_to_user_sessions(

                                                    &self.state,

                                                    &s_name,

                                                    pkt.clone(),

                                                )

                                                .await;

                                            }

                                        }

                                        Ok(false) => {

                                            let _ = send_system_message(

                                                &self.tx,

                                                "[Система] Только владелец может удалить канал",

                                            )

                                            .await;

                                        }

                                        Err(e) => {

                                            let _ = send_system_message(

                                                &self.tx,

                                                &format!("[Система] Ошибка удаления: {}", e),

                                            )

                                            .await;

                                        }

                                    }

                                }

                            }

                            _ => {}

                        }

                        return;

                    }



                    let dtype = if rest.len() >= 10 { rest[9] } else { 0 };

                    if dtype == MSG_DELETE_FOR_ME {

                        let result = self.state.hide_message(&self.my_user_id, kind, msg_id).await;

                        if let Err(e) = result {

                            let _ = send_system_message(

                                &self.tx,

                                &format!("[Система] Ошибка скрытия: {}", e),

                            )

                            .await;

                        }

                        return;

                    }



                    match kind {

                        MSG_KIND_PERSONAL => {

                            let lookup = self.state.lookup_personal_message(msg_id).await;

                            match lookup {

                                Ok(Some((sender_id, recipient_id))) => {

                                    if sender_id != self.my_user_id {

                                        let _ = send_system_message(

                                            &self.tx,

                                            "[Система] Удалять у всех можно только свои сообщения",

                                        )

                                        .await;

                                        return;

                                    }



                                    if recipient_id != self.my_user_id {

                                        let rec_name = self.state.resolve_username(&recipient_id).await;

                                        if rec_name != DELETED_LABEL {

                                            let is_online =

                                                self.state.online_users.contains_key(&rec_name);

                                            if !is_online {

                                                let fcm_tokens = self.state

                                                    .get_fcm_tokens_for_user(&recipient_id)

                                                    .await

                                                    .unwrap_or_default();

                                                let data_payload = json!({ "kind": "delete", "msg_id": msg_id.to_string() });

                                                for fcm_tok in fcm_tokens {

                                                    let state_fcm = self.state.clone();

                                                    let payload = data_payload.clone();

                                                    tokio::spawn(async move {

                                                        send_fcm_push_and_cleanup(

                                                            state_fcm,

                                                            &fcm_tok,

                                                            "",

                                                            "",

                                                            Some(payload),

                                                        )

                                                        .await;

                                                    });

                                                }

                                            }

                                        }

                                    }



                                    let del = self.state.delete_message(msg_id).await;

                                    if let Err(e) = del {

                                        let _ = send_system_message(

                                            &self.tx,

                                            &format!("[Система] Ошибка удаления: {}", e),

                                        )

                                        .await;

                                        return;

                                    }



                                    let pkt = crate::senders::build_delete_packet(

                                        msg_id,

                                        kind,

                                        MSG_DELETE_FOR_ALL,

                                    );

                                    let _ = self.tx.send(Message::Binary(pkt.clone()));



                                    if recipient_id != self.my_user_id {

                                        let rec_name = self.state.resolve_username(&recipient_id).await;

                                        if rec_name != DELETED_LABEL {

                                            let tokens = {

                                                self.state

                                                    .online_users

                                                    .get(&rec_name)

                                                    .map(|r| r.clone())

                                                    .unwrap_or_default()

                                            };

                                            for tok in tokens {

                                                let target =

                                                    self.state.sessions.get(&tok).map(|r| r.clone());

                                                if let Some(ts) = target {

                                                    let _ =

                                                        ts.tx.send(Message::Binary(pkt.clone()));

                                                }

                                            }

                                        }

                                    }

                                }

                                Ok(None) => {

                                    let _ =

                                        send_system_message(&self.tx, "[Система] Сообщение не найдено")

                                            .await;

                                }

                                Err(e) => {

                                    let _ =

                                        send_system_message(&self.tx, &format!("[Система] {}", e)).await;

                                }

                            }

                        }

                        MSG_KIND_GROUP => {

                            let _ = send_system_message(

                                &self.tx,

                                "[Система] Удаление у всех в группах пока не поддерживается",

                            )

                            .await;

                        }

                        MSG_KIND_CHANNEL => {

                            let lookup = self.state.lookup_channel_message(msg_id).await;

                            match lookup {

                                Ok(Some((channel_name, creator_id, _sender_id))) => {

                                    if creator_id != self.my_user_id {

                                        let _ = send_system_message(&self.tx, "[Система] Только владелец канала может удалять сообщения").await;

                                        return;

                                    }



                                    let del = self.state.delete_channel_message(msg_id).await;

                                    if let Err(e) = del {

                                        let _ = send_system_message(

                                            &self.tx,

                                            &format!("[Система] Ошибка удаления: {}", e),

                                        )

                                        .await;

                                        return;

                                    }



                                    let subs_ids = self.state

                                        .get_channel_subscribers(&channel_name)

                                        .await

                                        .unwrap_or_default();

                                    let pkt = crate::senders::build_delete_packet(

                                        msg_id,

                                        kind,

                                        MSG_DELETE_FOR_ALL,

                                    );



                                    let sessions: Vec<Arc<Session>> =

                                        self.state.sessions.iter().map(|r| r.value().clone()).collect();

                                    for s in sessions {

                                        if let Some(uid) = s.user_id.get()

                                            && subs_ids.contains(uid)

                                        {

                                            let _ = s.tx.send(Message::Binary(pkt.clone()));

                                        }

                                    }

                                }

                                Ok(None) => {

                                    let _ =

                                        send_system_message(&self.tx, "[Система] Сообщение не найдено")

                                            .await;

                                }

                                Err(e) => {

                                    let _ =

                                        send_system_message(&self.tx, &format!("[Система] {}", e)).await;

                                }

                            }

                        }

                        _ => {

                            let _ = send_system_message(&self.tx, "[Система] Неизвестный kind удаления")

                                .await;

                        }

                    }

}

pub async fn handle_logout(&self, data: &[u8]) {
    let rest = &data[1..];

                    if rest.len() < 12 + 4 {

                        return;

                    }

                    let nonce = &rest[0..12];

                    let enc_len = u32::from_be_bytes(rest[12..16].try_into().unwrap()) as usize;

                    if rest.len() < 16 + enc_len {

                        return;

                    }

                    let encrypted = &rest[16..16 + enc_len];



                    let cipher =

                        aes_gcm::Aes256Gcm::new(Key::<aes_gcm::Aes256Gcm>::from_slice(&self.keys.key));

                    let nonce_ref = aes_gcm::Nonce::from_slice(nonce);

                    let plaintext = match cipher.decrypt(nonce_ref, encrypted) {

                        Ok(p) => p,

                        Err(e) => {

                            error!("0x06: ошибка расшифровки: {}", e);

                            return;

                        }

                    };

                    let cmd_str = String::from_utf8_lossy(&plaintext).to_string();

                    let parts: Vec<&str> = cmd_str.split('|').collect();

                    if parts.len() < 2 {

                        return;

                    }



                    let token = parts[0].trim();

                    let ltype: u8 = parts[1].parse().unwrap_or(LOGOUT_TYPE_EXIT);

                    let password = if parts.len() > 2 { parts[2].trim() } else { "" };



                    if token.is_empty() {

                        return;

                    }



                    if ltype == LOGOUT_TYPE_DELETE_ACCOUNT {

                        info!("Logout: DELETE_ACCOUNT от user_id={}", self.my_user_id);



                        if password.is_empty() {

                            let _ = send_system_message(&self.tx, "[Система] Неверный пароль").await;

                            return;

                        }



                        let pwd_check = self.state.verify_password_for_user(&self.my_user_id, password).await;

                        match pwd_check {

                            Ok(true) => {}

                            Ok(false) => {

                                warn!("DELETE_ACCOUNT: неверный пароль для user_id={}", self.my_user_id);

                                let _ = send_system_message(&self.tx, "[Система] Неверный пароль").await;

                                return;

                            }

                            Err(e) => {

                                error!("DELETE_ACCOUNT: {}", e);

                                let _ = send_system_message(&self.tx, &format!("[Система] {}", e)).await;

                                return;

                            }

                        }



                        let result = self.state.soft_delete_account(&self.my_user_id).await;

                        let tokens_to_kill = match result {

                            Ok(v) => v,

                            Err(e) => {

                                error!("Ошибка удаления аккаунта: {}", e);

                                let _ = send_system_message(

                                    &self.tx,

                                    &format!("[Система] Ошибка удаления аккаунта: {}", e),

                                )

                                .await;

                                return;

                            }

                        };



                        info!(

                            "Аккаунт {} удалён, закрываю {} сессий",

                            self.my_username,

                            tokens_to_kill.len()

                        );



                        let reason = "Аккаунт удалён";

                        let rb = reason.as_bytes();

                        let mut pkt = Vec::with_capacity(1 + 4 + rb.len());

                        pkt.push(MSG_TYPE_LOGOUT);

                        pkt.extend_from_slice(&(rb.len() as u32).to_be_bytes());

                        pkt.extend_from_slice(rb);



                        for tok in &tokens_to_kill {

                            let sess = self.state.sessions.get(tok).map(|r| r.clone());

                            if let Some(s) = sess {

                                let _ = s.tx.send(Message::Binary(pkt.clone()));

                                let _ = s.tx.send(Message::Close(None));

                                s.connected.store(false, Ordering::Relaxed);

                            }

                        }



                        self.state.online_users.remove(&self.my_username);

                        for tok in &tokens_to_kill {

                            self.state.sessions.remove(tok);

                        }



                        let msg = format!("[Система] Пользователь {} удалил аккаунт", self.my_username);

                        broadcast_system_message(&self.state, &msg, Some(&self.my_username)).await;



                        self.session.connected.store(false, Ordering::Relaxed);

                        return;

                    }



                    info!("Logout: EXIT, token={}", token);



                    let is_owner = self.state

                        .verify_session_ownership(token, &self.my_user_id)

                        .await

                        .unwrap_or(false);

                    if !is_owner {

                        let _ = send_system_message(&self.tx, "[Система] Сессия не найдена").await;

                        return;

                    }



                    let is_current = token == self.session.token.get().map(|s| s.as_str()).unwrap_or("");

                    let result = self.state.delete_session(token).await;



                    match result {

                        Ok(_) => {

                            // Мгновенно убиваем сокет целевой сессии, если она онлайн

                            if !is_current {

                                if let Some(target_sess) = self.state.sessions.get(token).map(|r| r.clone()) {

                                    let reason = "[Система] Сессия завершена с другого устройства";

                                    let rb = reason.as_bytes();

                                    let mut pkt = Vec::with_capacity(1 + 4 + rb.len());

                                    pkt.push(MSG_TYPE_LOGOUT);

                                    pkt.extend_from_slice(&(rb.len() as u32).to_be_bytes());

                                    pkt.extend_from_slice(rb);



                                    let _ = target_sess.tx.send(Message::Binary(pkt));

                                    let _ = target_sess.tx.send(Message::Close(None));

                                    target_sess.connected.store(false, Ordering::Relaxed);

                                    info!("Сессия {} принудительно завершена (сокет закрыт).", token);

                                }

                            }



                            self.state.sessions.remove(token);



                            if !self.is_background {

                                let mut should_remove = false;

                                if let Some(mut tokens) = self.state.online_users.get_mut(&self.my_username) {

                                    tokens.retain(|t| t != token);

                                    if tokens.is_empty() {

                                        should_remove = true;

                                    }

                                }

                                if should_remove {

                                    self.state.online_users.remove(&self.my_username);

                                }



                                if is_current {

                                    let _ = self.state.update_last_seen(&self.my_user_id).await;

                                    let msg = format!(

                                        "[Система] Пользователь {} отключился",

                                        self.my_username

                                    );

                                    broadcast_system_message(&self.state, &msg, Some(&self.my_username))

                                        .await;

                                }

                            }



                            if is_current {

                                self.session.connected.store(false, Ordering::Relaxed);

                                let _ =

                                    send_system_message(&self.tx, "[Система] Вы вышли из системы").await;

                                info!("Сессия {} завершена по logout", token);

                            } else {

                                let _ = send_system_message(

                                    &self.tx,

                                    "[Система] Устройство успешно отключено",

                                )

                                .await;

                                info!(

                                    "Сессия {} принудительно завершена пользователем {}",

                                    token, self.my_username

                                );

                            }

                        }

                        Err(e) => {

                            let _ = send_system_message(

                                &self.tx,

                                &format!("[Система] Ошибка logout: {}", e),

                            )

                            .await;

                        }

                    }

}

pub async fn handle_command(&self, data: &[u8]) {
    let rest = &data[1..];

                    if rest.len() < 4 {

                        return;

                    }

                    let cmd = String::from_utf8_lossy(&rest[4..]).to_string();

                    info!("Получена команда через MSG_TYPE_COMMAND: {}", cmd);



                    if cmd.starts_with("/history") {

                        let parts: Vec<&str> = cmd.split_whitespace().collect();

                        if parts.len() < 2 {

                            let _ = send_system_message(

                                &self.tx,

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

                                &self.tx,

                                &self.keys,

                                &self.my_user_id,

                                chat,

                                before_id,

                                HISTORY_PAGE_SIZE,

                                &self.state,

                            )

                            .await;

                        }

                        return;

                    }



                    if cmd.starts_with("/getmsg") {

                        let parts: Vec<&str> = cmd.split_whitespace().collect();

                        if parts.len() < 3 {

                            let _ = send_system_message(

                                &self.tx,

                                "[Система] Использование: /getmsg <kind> <id1> [<id2> ...]",

                            )

                            .await;

                        } else {

                            let kind: u8 = parts[1].parse().unwrap_or(0);

                            let ids: Vec<i64> =

                                parts[2..].iter().filter_map(|s| s.parse().ok()).collect();

                            send_messages_by_ids(&self.tx, &self.keys, &self.my_user_id, kind, ids, &self.state).await;

                        }

                        return;

                    }



                    let response =

                        self.process_command(&cmd).await;

                    if !response.is_empty() {

                        let _ = send_system_message(&self.tx, &response).await;

                    }

}

pub async fn handle_typing(&self, data: &[u8]) {
    let rest = &data[1..];

                    info!("Получен пакет TYPING от {}", self.my_username);

                    if rest.len() < 1 + 4 + 4 {

                        return;

                    }

                    let kind = rest[0];

                    let mut offset = 1;



                    let sender_len =

                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;

                    offset += 4;

                    if rest.len() < offset + sender_len {

                        return;

                    }

                    let _sender_name =

                        String::from_utf8_lossy(&rest[offset..offset + sender_len]).to_string();

                    offset += sender_len;



                    let recipient_len =

                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;

                    offset += 4;

                    if rest.len() < offset + recipient_len {

                        return;

                    }

                    let recipient_name =

                        String::from_utf8_lossy(&rest[offset..offset + recipient_len]).to_string();



                    if kind == MSG_KIND_PERSONAL {

                        let target_tokens = {

                            self.state

                                .online_users

                                .get(&recipient_name)

                                .map(|r| r.clone())

                                .unwrap_or_default()

                        };

                        for tok in target_tokens {

                            let target_session = self.state.sessions.get(&tok).map(|r| r.clone());

                            if let Some(ts) = target_session {

                                let _ = ts.tx.send(Message::Binary(data.to_vec()));

                            }

                        }

                    } else if kind == MSG_KIND_GROUP {

                        let group_name = recipient_name.trim_start_matches('#').to_string();

                        let members = self.state

                            .get_group_members(&group_name)

                            .await

                            .unwrap_or_default();

                        for member_id in members {

                            if member_id == self.my_user_id {

                                continue;

                            }

                            let member_name = self.state.resolve_username(&member_id).await;

                            let tokens = self.state

                                .online_users

                                .get(&member_name)

                                .map(|r| r.clone())

                                .unwrap_or_default();

                            for tok in tokens {

                                let target_session = self.state.sessions.get(&tok).map(|r| r.clone());

                                if let Some(ts) = target_session {

                                    let _ = ts.tx.send(Message::Binary(data.to_vec()));

                                }

                            }

                        }

                    }

}

pub async fn handle_secure_command(&self, data: &[u8]) {
    let rest = &data[1..];

                    if rest.len() < 12 + 4 {

                        warn!("0x0A: мало данных");

                        return;

                    }

                    let nonce = &rest[0..12];

                    let enc_len = u32::from_be_bytes(rest[12..16].try_into().unwrap()) as usize;

                    if rest.len() < 16 + enc_len {

                        return;

                    }

                    let encrypted = &rest[16..16 + enc_len];



                    let cipher =

                        aes_gcm::Aes256Gcm::new(Key::<aes_gcm::Aes256Gcm>::from_slice(&self.keys.key));

                    let nonce_ref = aes_gcm::Nonce::from_slice(nonce);

                    let plaintext = match cipher.decrypt(nonce_ref, encrypted) {

                        Ok(p) => p,

                        Err(e) => {

                            error!("0x0A: ошибка расшифровки: {}", e);

                            return;

                        }

                    };

                    let cmd = String::from_utf8_lossy(&plaintext).to_string();



                    info!(

                        "Получена SECURE_COMMAND через 0x0A: {}",

                        cmd.split('|').next().unwrap_or("")

                    );



                    let response =

                        self.process_command(&cmd).await;

                    if !response.is_empty() {

                        let _ = send_system_message(&self.tx, &response).await;

                    }

}

pub async fn handle_reaction(&self, data: &[u8]) {
    let rest = &data[1..];

                    if rest.len() < 8 + 1 + 4 {

                        warn!("0x0B: мало данных");

                        return;

                    }

                    let mut offset = 0;

                    let msg_id = i64::from_be_bytes(rest[offset..offset + 8].try_into().unwrap());

                    offset += 8;

                    let kind = rest[offset];

                    offset += 1;

                    let sym_len = u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;

                    offset += 4;

                    if rest.len() < offset + sym_len {

                        return;

                    }

                    let symbol = String::from_utf8_lossy(&rest[offset..offset + sym_len]).to_string();



                    let _ = self.state.save_reaction(kind, msg_id, &self.my_user_id, &symbol).await;



                    let reactions = self.state.get_reactions_for_messages(kind, &[msg_id]).await.unwrap_or_default();



                    let mut target_users = Vec::new();

                    match kind {

                        MSG_KIND_PERSONAL => {

                            if let Ok(Some((sender_id, recipient_id))) = self.state.lookup_personal_message(msg_id).await {

                                target_users.push(sender_id.clone());

                                if recipient_id != sender_id {

                                    target_users.push(recipient_id);

                                }

                            }

                        }

                        MSG_KIND_GROUP => {

                            if let Ok(client) = self.state.db.get().await {

                                if let Ok(Some(row)) = client.query_opt("SELECT g.name FROM group_messages gm JOIN groups g ON gm.group_id = g.id WHERE gm.id = $1", &[&msg_id]).await {

                                    let gname: String = row.get(0);

                                    if let Ok(members) = self.state.get_group_members(&gname).await {

                                        target_users.extend(members);

                                    }

                                }

                            }

                        }

                        MSG_KIND_CHANNEL => {

                            if let Ok(client) = self.state.db.get().await {

                                if let Ok(Some(row)) = client.query_opt("SELECT c.name FROM channel_messages cm JOIN channels c ON cm.channel_id = c.id WHERE cm.id = $1", &[&msg_id]).await {

                                    let cname: String = row.get(0);

                                    if let Ok(subs) = self.state.get_channel_subscribers(&cname).await {

                                        target_users.extend(subs);

                                    }

                                }

                            }

                        }

                        _ => {}

                    }



                    let mut updated_symbols = std::collections::HashSet::new();



                    if let Some(msg_reacts) = reactions.get(&msg_id) {

                        for (emoji, users) in msg_reacts {

                            updated_symbols.insert(emoji.clone());

                            let count = users.len() as u32;

                            let who = users.join(",");

                            let pkt = crate::senders::build_reaction_packet(msg_id, kind, emoji, count, &who);

                            for uid in &target_users {

                                let uname = self.state.resolve_username(uid).await;

                                crate::senders::send_to_user_sessions(&self.state, &uname, pkt.clone()).await;

                            }

                        }

                    }

                    

                    if !updated_symbols.contains(&symbol) {

                        let pkt = crate::senders::build_reaction_packet(msg_id, kind, &symbol, 0, "");

                        for uid in &target_users {

                            let uname = self.state.resolve_username(&uid).await;

                            crate::senders::send_to_user_sessions(&self.state, &uname, pkt.clone()).await;

                        }

                    }

}
}
