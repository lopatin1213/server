use aes_gcm::{
    Key,
    aead::{Aead, KeyInit},
};
use futures_util::{SinkExt, StreamExt};
use log::{error, info, warn};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use uuid::Uuid;

use crate::app_state::{AppState, Session, SessionKeys};
use crate::constants::*;
use crate::handshake::ws_handshake;
use crate::senders::{broadcast_system_message, send_system_message, send_system_notification};

pub async fn resolve_display_name(state: &Arc<AppState>, user_id: &str, fallback: &str) -> String {
    let raw = state.get_display_name(user_id).await.unwrap_or_default();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

// ==================== Ctx: контекст соединения ====================
// Собирает всё, что нужно обработчикам одного WebSocket-соединения,
// чтобы не таскать 6 параметров через каждую функцию.
pub struct Ctx {
    pub state: Arc<AppState>,
    pub session: Arc<Session>,
    pub tx: mpsc::UnboundedSender<Message>,
    pub keys: SessionKeys,
    pub my_user_id: String,
    pub my_username: String,
    pub is_background: bool,
}

impl Ctx {
    pub fn new(
        state: Arc<AppState>,
        session: Arc<Session>,
        tx: mpsc::UnboundedSender<Message>,
        keys: SessionKeys,
        my_user_id: String,
        my_username: String,
        is_background: bool,
    ) -> Self {
        Self {
            state,
            session,
            tx,
            keys,
            my_user_id,
            my_username,
            is_background,
        }
    }

    // ==================== process_command ====================
    pub async fn process_command(&self, cmd: &str) -> String {
        let my_user_id = &self.my_user_id;
        let _my_username = &self.my_username;
        let state = &self.state;
        let session = &self.session;
        let cmd_parts: Vec<&str> = cmd.split_whitespace().collect();
    if cmd_parts.is_empty() {
        return String::new();
    }

    let cmd_name = cmd_parts[0];
    let args = &cmd_parts[1..];

    match cmd_name {
        "/creategroup" => {
            if args.is_empty() {
                "[Система] Использование: /creategroup <название>".to_string()
            } else {
                let group_name = args.join(" ");
                match state.create_group(&group_name, my_user_id).await {
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
                match state.join_group(&group_name, my_user_id).await {
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
                match state.leave_group(&group_name, my_user_id).await {
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
                match state.get_group_members(&group_name).await {
                    Ok(ids) => {
                        let mut names = Vec::new();
                        for id in ids {
                            names.push(state.resolve_username(&id).await);
                        }
                        if names.is_empty() {
                            format!("[Система] В группе {} нет участников", group_name)
                        } else {
                            format!(
                                "[Система] Участники группы {}: {}",
                                group_name,
                                names.join(", ")
                            )
                        }
                    }
                    Err(e) => format!("[Система] Ошибка: {}", e),
                }
            }
        }
        "/listgroups" => {
            let uid = my_user_id.to_string();
            let result: Result<Vec<String>, String> = async {
                let client = state.db.get().await.map_err(|e| e.to_string())?;
                let rows = client.query("SELECT g.name, g.creator_id, (SELECT 1 FROM group_members gm WHERE gm.group_id = g.id AND gm.user_id = $1) AS is_member FROM groups g ORDER BY g.name", &[&uid]).await.map_err(|e| e.to_string())?;
                let mut groups = Vec::new();
                for row in rows {
                    let name: String = row.get(0);
                    let creator_id: String = row.get(1);
                    let is_member: Option<i32> = row.get(2);
                    groups.push((name, creator_id, is_member.is_some()));
                }
                let mut out = Vec::new();
                for (name, cid, is_member) in groups {
                    let creator_name = state.resolve_username(&cid).await;
                    out.push(format!("{}|{}|{}", name, creator_name, if is_member { "1" } else { "0" }));
                }
                Ok(out)
            }.await;
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
                match state.create_channel(&channel_name, my_user_id).await {
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
                match state.subscribe_channel(&channel_name, my_user_id).await {
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
                match state.unsubscribe_channel(&channel_name, my_user_id).await {
                    Ok(_) => format!("[Система] Вы отписались от канала {}", channel_name),
                    Err(e) => format!("[Система] Ошибка: {}", e),
                }
            }
        }
        "/channels" => {
            let uid = my_user_id.to_string();
            let result: Result<Vec<String>, String> = async {
                let client = state.db.get().await.map_err(|e| e.to_string())?;
                let rows = client.query("SELECT c.name, c.creator_id, (SELECT 1 FROM channel_subscribers cs WHERE cs.channel_id = c.id AND cs.user_id = $1) AS subscribed FROM channels c ORDER BY c.name", &[&uid]).await.map_err(|e| e.to_string())?;
                let mut raw = Vec::new();
                for row in rows {
                    let name: String = row.get(0);
                    let creator_id: String = row.get(1);
                    let subscribed: Option<i32> = row.get(2);
                    raw.push((name, creator_id, subscribed.is_some()));
                }
                let mut out = Vec::new();
                for (name, cid, sub) in raw {
                    let creator_name = state.resolve_username(&cid).await;
                    out.push(format!("{}|{}|{}", name, creator_name, if sub { "1" } else { "0" }));
                }
                Ok(out)
            }.await;
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
            let uid = my_user_id.to_string();
            let result: Result<Vec<String>, String> = async {
                let client = state.db.get().await.map_err(|e| e.to_string())?;

                if args.is_empty() {
                    let rows = client.query("SELECT phone, username, COALESCE(display_name, ''), COALESCE(last_seen, 0) FROM users ORDER BY username", &[]).await.map_err(|e| e.to_string())?;
                    let mut users = Vec::new();
                    for row in rows { users.push(format!("{}|{}|{}|{}", row.get::<_, String>(0), row.get::<_, String>(1), row.get::<_, String>(2), row.get::<_, i64>(3))); }
                    Ok(users)
                } else if args[0] == "history" {
                    info!("Вызван с history");
                    let rows = client.query("SELECT DISTINCT u.phone, u.username, COALESCE(u.display_name, ''), COALESCE(u.last_seen, 0) FROM users u JOIN messages m ON (m.sender_id = u.id AND m.recipient_id = $1) OR (m.recipient_id = u.id AND m.sender_id = $1) WHERE u.id != $1", &[&uid]).await.map_err(|e| e.to_string())?;
                    let mut users = Vec::new();
                    for row in rows { users.push(format!("{}|{}|{}|{}", row.get::<_, String>(0), row.get::<_, String>(1), row.get::<_, String>(2), row.get::<_, i64>(3))); }
                    Ok(users)
                } else if args[0] == "contacts" {
                    state.get_contacts(&uid).await
                } else {
                    let mut hashes = Vec::new();
                    for arg in args {
                        for part in arg.split(',') {
                            if !part.trim().is_empty() { hashes.push(part.trim().to_string()); }
                        }
                    }
                    let _ = state.sync_contacts(&uid, &hashes).await;
                    state.get_contacts(&uid).await
                }
            }.await;

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
        "/add_contact" => {
            if args.is_empty() {
                "[Система] Использование: /add_contact <username>".to_string()
            } else {
                match state.add_contact(my_user_id, args[0]).await {
                    Ok(_) => format!("[Система] Пользователь {} добавлен в контакты", args[0]),
                    Err(e) => format!("[Система] Ошибка: {}", e),
                }
            }
        }
        "/onlineusers" => {
            let mut users: Vec<String> =
                state.online_users.iter().map(|r| r.key().clone()).collect();
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
            let target_username = if args.is_empty() {
                _my_username
            } else {
                args[0]
            };
            let target_id_opt = state.resolve_id(target_username).await;

            if let Some(target_id) = target_id_opt {
                let last_seen: i64 = match state.db.get().await {
                    Ok(client) => match client
                        .query_opt("SELECT last_seen FROM users WHERE id = $1", &[&target_id])
                        .await
                    {
                        Ok(Some(row)) => row.get(0),
                        _ => 0,
                    },
                    Err(_) => 0,
                };

                match state.get_profile(&target_id).await {
                    Ok((uname, phone, first_name, last_name, display_name, bio)) => {
                        let (hide_phone, privacy) = state
                            .get_user_settings(&target_id)
                            .await
                            .unwrap_or((false, 0));
                        let is_me = target_id == *my_user_id;

                        let show_phone = if hide_phone && !is_me {
                            "скрыт".to_string()
                        } else {
                            phone.clone()
                        };

                        let mut can_see_last_seen = is_me || privacy == 0;
                        if !can_see_last_seen && privacy == 1 {
                            let is_contact = match state.db.get().await {
                                Ok(client) => client.query_opt("SELECT 1 FROM user_contacts WHERE owner_id = $1 AND contact_id = $2", &[&my_user_id, &target_id]).await.map(|opt| opt.is_some()).unwrap_or(false),
                                Err(_) => false,
                            };
                            if is_contact {
                                can_see_last_seen = true;
                            }
                        }

                        let status = if can_see_last_seen {
                            let is_online = state.online_users.contains_key(&uname);
                            if is_online {
                                "онлайн".to_string()
                            } else {
                                "офлайн".to_string()
                            }
                        } else {
                            "скрыт".to_string()
                        };

                        format!(
                            "[Система] Профиль|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                            uname,
                            show_phone,
                            first_name,
                            last_name,
                            display_name,
                            bio,
                            status,
                            last_seen,
                            hide_phone,
                            privacy
                        )
                    }
                    Err(e) => format!("[Система] Ошибка: {}", e),
                }
            } else {
                format!("[Система] Пользователь {} не найден", target_username)
            }
        }
        "/update_profile" => {
            if args.is_empty() {
                "[Система] Использование: /update_profile <имя>|<фамилия>|<display_name>|<username>|<bio>".to_string()
            } else {
                let joined = args.join(" ");
                let parts: Vec<&str> = joined.split('|').collect();
                if parts.len() != 5 {
                    "[Система] Ошибка: передайте 5 параметров через |".to_string()
                } else {
                    let old_username = _my_username.to_string();
                    let new_username = parts[3].to_string();

                    match state
                        .update_profile(
                            my_user_id, parts[0], parts[1], parts[2], parts[3], parts[4],
                        )
                        .await
                    {
                        Ok(_) => {
                            if old_username != new_username {
                                crate::senders::broadcast_invalidate_cache(
                                    state,
                                    Some(&new_username),
                                )
                                .await;
                            }
                            "[Система] Профиль успешно обновлен".to_string()
                        }
                        Err(e) => format!("[Система] Ошибка: {}", e),
                    }
                }
            }
        }
        "/update_settings" => {
            if args.is_empty() {
                "[Система] Использование: /update_settings <hide_phone 0/1>|<last_seen_privacy 0/1/2>".to_string()
            } else {
                let parts: Vec<&str> = args[0].split('|').collect();
                if parts.len() != 2 {
                    "[Система] Ошибка: передайте два параметра через |".to_string()
                } else {
                    let hide_phone = parts[0] == "1";
                    let privacy = parts[1].parse::<i16>().unwrap_or(0);
                    match state
                        .update_user_settings(my_user_id, hide_phone, privacy)
                        .await
                    {
                        Ok(_) => "[Система] Настройки приватности обновлены".to_string(),
                        Err(e) => format!("[Система] Ошибка: {}", e),
                    }
                }
            }
        }
        "/change_password" => {
            if args.is_empty() {
                "[Система] Использование: /change_password <старый>|<новый>".to_string()
            } else {
                let parts: Vec<&str> = args[0].split('|').collect();
                if parts.len() != 2 {
                    "[Система] Ошибка: передайте старый и новый пароль через |".to_string()
                } else {
                    match state.verify_password_for_user(my_user_id, parts[0]).await {
                        Ok(true) => match state.update_password(my_user_id, parts[1]).await {
                            Ok(_) => "[Система] Пароль успешно изменен".to_string(),
                            Err(e) => format!("[Система] Ошибка: {}", e),
                        },
                        _ => "[Система] Неверный старый пароль".to_string(),
                    }
                }
            }
        }
        "/sessions" => match state.get_user_sessions(my_user_id).await {
            Ok(sessions) => {
                let current_token = session.token.get().map(|s| s.as_str()).unwrap_or("");
                let mut out = Vec::new();
                for (tok, dev, last_seen) in sessions {
                    let is_current = if tok == current_token { "1" } else { "0" };
                    out.push(format!("{}|{}|{}|{}", tok, dev, last_seen, is_current));
                }
                format!("[Система] Сессии: {}", out.join(", "))
            }
            Err(e) => format!("[Система] Ошибка: {}", e),
        },
        "/report" => {
            if args.len() < 3 {
                "[Система] Использование: /report <kind> <msg_id> <причина>".to_string()
            } else {
                let kind: u8 = args[0].parse().unwrap_or(1);
                let msg_id: i64 = args[1].parse().unwrap_or(0);
                let reason = args[2..].join(" ");
                let target_type = match kind {
                    MSG_KIND_PERSONAL => "message",
                    MSG_KIND_GROUP => "message",
                    MSG_KIND_CHANNEL => "message",
                    _ => "message",
                };
                let client = state.db.get().await;
                match client {
                    Ok(c) => {
                        let res = c.execute("INSERT INTO reports (reporter_id, target_id, target_type, reason) VALUES ($1, $2, $3, $4)", &[&my_user_id, &msg_id.to_string(), &target_type, &reason]).await;
                        match res {
                            Ok(_) => "[Система] Жалоба отправлена модераторам.".to_string(),
                            Err(e) => format!("[Система] Ошибка: {}", e),
                        }
                    }
                    Err(e) => format!("[Система] Ошибка БД: {}", e),
                }
            }
        }
        _ => format!("[Система] Неизвестная команда: {}", cmd),
    }
    }
}

// ==================== handle_client ====================
pub async fn handle_client(stream: TcpStream, state: Arc<AppState>) {
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

    let hs = match ws_handshake(&mut ws_stream).await {
        Ok(k) => k,
        Err(e) => {
            error!("Handshake error: {}", e);
            return;
        }
    };
    let keys = hs.keys;
    info!("Согласованная версия протокола: v{}", hs.agreed_version);

    let (mut sink, mut stream) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let session = Arc::new(Session::new(tx.clone(), keys.clone()));
    let temp_id = Uuid::new_v4().to_string();

    {
        state.sessions.insert(temp_id.clone(), session.clone());
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
            if tx_ping.send(Message::Ping(Vec::new())).is_err() {
                break;
            }
        }
    });

    // ---- Аутентификация ----
    let auth_data = match stream.next().await {
        Some(Ok(Message::Binary(data))) => data,
        Some(Ok(_)) => {
            error!("Ожидался бинарный пакет аутентификации");
            ping_task.abort();
            send_task.abort();
            state.sessions.remove(&temp_id);
            return;
        }
        Some(Err(e)) => {
            error!("Ошибка чтения аутентификации: {}", e);
            ping_task.abort();
            send_task.abort();
            state.sessions.remove(&temp_id);
            return;
        }
        None => {
            error!("Соединение закрыто до аутентификации");
            ping_task.abort();
            send_task.abort();
            state.sessions.remove(&temp_id);
            return;
        }
    };

    if auth_data.is_empty() || auth_data[0] != MSG_TYPE_AUTH {
        error!("Ожидался MSG_TYPE_AUTH, получено {:?}", auth_data.first());
        ping_task.abort();
        send_task.abort();
        state.sessions.remove(&temp_id);
        return;
    }

    if auth_data.len() < 1 + 12 + 4 {
        error!("AUTH: пакет слишком короткий для v3");
        ping_task.abort();
        send_task.abort();
        state.sessions.remove(&temp_id);
        return;
    }
    let nonce = &auth_data[1..13];
    let enc_len = u32::from_be_bytes(auth_data[13..17].try_into().unwrap()) as usize;
    if auth_data.len() < 17 + enc_len {
        error!("AUTH: не хватает данных enc");
        ping_task.abort();
        send_task.abort();
        state.sessions.remove(&temp_id);
        return;
    }
    let encrypted = &auth_data[17..17 + enc_len];

    let is_background = if auth_data.len() > 17 + enc_len {
        auth_data[17 + enc_len] == 1
    } else {
        false
    };

    let cipher = aes_gcm::Aes256Gcm::new(Key::<aes_gcm::Aes256Gcm>::from_slice(&keys.key));
    let nonce_ref = aes_gcm::Nonce::from_slice(nonce);
    let auth_str = match cipher.decrypt(nonce_ref, encrypted) {
        Ok(p) => String::from_utf8_lossy(&p).to_string(),
        Err(e) => {
            error!("AUTH: ошибка расшифровки: {}", e);
            ping_task.abort();
            send_task.abort();
            state.sessions.remove(&temp_id);
            return;
        }
    };

    let parts: Vec<&str> = auth_str.split('|').collect();
    if parts.is_empty() {
        error!("Неверный формат аутентификации");
        ping_task.abort();
        send_task.abort();
        state.sessions.remove(&temp_id);
        return;
    }
    let command = parts[0];

    let safe_log = match command {
        "login" => format!(
            "login|{}|***|{}|*** (BG: {})",
            parts.get(1).unwrap_or(&""),
            parts.get(3).unwrap_or(&""),
            is_background
        ),
        "register" => format!(
            "register|{}|***|{}|{}|{}|{}|*** (BG: {})",
            parts.get(1).unwrap_or(&""),
            parts.get(3).unwrap_or(&""),
            parts.get(4).unwrap_or(&""),
            parts.get(5).unwrap_or(&""),
            parts.get(6).unwrap_or(&""),
            is_background
        ),
        "token" => format!(
            "token|***|{}|*** (BG: {})",
            parts.get(2).unwrap_or(&""),
            is_background
        ),
        _ => "unknown".to_string(),
    };
    info!("Получен пакет AUTH: {}", safe_log);

    let auth_result = match command {
        "token" => {
            let token = parts.get(1).map(|s| s.trim()).unwrap_or("");
            let device_name = parts.get(2).map(|s| s.trim()).unwrap_or("unknown");
            let fcm_token = parts
                .get(3)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let result = state.check_session(token).await;

            match result {
                Ok((user_id, username)) => {
                    if let Ok(Some(reason)) = state.is_user_banned(&user_id).await {
                        let _ = send_system_message(
                            &tx,
                            &format!(
                                "[Система] Вы заблокированы модератором. Причина: {}",
                                reason
                            ),
                        )
                        .await;
                        let _ = tx.send(Message::Close(None));
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        ping_task.abort();
                        send_task.abort();
                        state.sessions.remove(&temp_id);
                        return;
                    }

                    let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                    let _ = send_system_message(&tx, &msg).await;

                    if let Some(fcm) = fcm_token {
                        let _ = state
                            .save_fcm_token(&user_id, token, &fcm, device_name)
                            .await;
                    }

                    session.user_id.set(user_id.clone()).ok();
                    session.username.set(username.clone()).ok();
                    session.token.set(token.to_string()).ok();

                    state.sessions.remove(&temp_id);
                    state.sessions.insert(token.to_string(), session.clone());

                    if !is_background {
                        state
                            .online_users
                            .entry(username.clone())
                            .or_default()
                            .push(token.to_string());
                        let _ = state.update_last_seen(&user_id).await;
                        let msg = format!("[Система] Пользователь {} подключился", username);
                        broadcast_system_message(&state, &msg, Some(&username)).await;
                    }
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
            let phone = parts.get(1).map(|s| s.trim()).unwrap_or("");
            let password = parts.get(2).map(|s| s.trim()).unwrap_or("");
            let device_name = parts.get(3).map(|s| s.trim()).unwrap_or("unknown");
            let fcm_token = parts
                .get(4)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let result = state.login_user_by_phone(phone, password).await;

            match result {
                Ok(user_id) => {
                    if let Ok(Some(reason)) = state.is_user_banned(&user_id).await {
                        let _ = send_system_message(
                            &tx,
                            &format!(
                                "[Система] Вы заблокированы модератором. Причина: {}",
                                reason
                            ),
                        )
                        .await;
                        let _ = tx.send(Message::Close(None));
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        ping_task.abort();
                        send_task.abort();
                        state.sessions.remove(&temp_id);
                        return;
                    }

                    let username = match state.get_profile(&user_id).await {
                        Ok((uname, _, _, _, _, _)) => uname,
                        Err(_) => phone.to_string(),
                    };

                    let token_result = state.create_session(&user_id, device_name).await;

                    match token_result {
                        Ok(token) => {
                            let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                            let _ = send_system_message(&tx, &msg).await;

                            if let Some(fcm) = fcm_token {
                                let _ = state
                                    .save_fcm_token(&user_id, &token, &fcm, device_name)
                                    .await;
                            }

                            session.user_id.set(user_id.clone()).ok();
                            session.username.set(username.clone()).ok();
                            session.token.set(token.clone()).ok();

                            state.sessions.remove(&temp_id);
                            state.sessions.insert(token.clone(), session.clone());

                            if !is_background {
                                state
                                    .online_users
                                    .entry(username.clone())
                                    .or_default()
                                    .push(token.clone());
                                let _ = state.update_last_seen(&user_id).await;
                                let msg =
                                    format!("[Система] Пользователь {} подключился", username);
                                broadcast_system_message(&state, &msg, Some(&username)).await;
                                let sys_msg = format!(
                                    "Вход в аккаунт с нового устройства: {}\n\n[Отключить это устройство](killsession:{})",
                                    device_name, token
                                );
                                send_system_notification(&state, &user_id, &sys_msg).await;
                            }
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
            let phone = parts.get(1).map(|s| s.trim()).unwrap_or("");
            let password = parts.get(2).map(|s| s.trim()).unwrap_or("");
            let first_name = parts.get(3).map(|s| s.trim()).filter(|s| !s.is_empty());
            let last_name = parts.get(4).map(|s| s.trim()).filter(|s| !s.is_empty());
            let username_opt = parts.get(5).map(|s| s.trim()).filter(|s| !s.is_empty());
            let device_name = parts.get(6).map(|s| s.trim()).unwrap_or("unknown");
            let fcm_token = parts
                .get(7)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let phone_hash = parts.get(8).map(|s| s.trim()).filter(|s| !s.is_empty());

            let username = username_opt.unwrap_or(phone).to_string();

            let result = state
                .register_user(
                    &username, phone, password, first_name, last_name, phone_hash,
                )
                .await;

            match result {
                Ok(user_id) => {
                    let token_result = state.create_session(&user_id, device_name).await;

                    match token_result {
                        Ok(token) => {
                            let msg = format!("Успех|{}|{}|{}", user_id, token, username);
                            let _ = send_system_message(&tx, &msg).await;

                            if let Some(fcm) = fcm_token {
                                let _ = state
                                    .save_fcm_token(&user_id, &token, &fcm, device_name)
                                    .await;
                            }

                            session.user_id.set(user_id.clone()).ok();
                            session.username.set(username.clone()).ok();
                            session.token.set(token.clone()).ok();

                            state.sessions.remove(&temp_id);
                            state.sessions.insert(token.clone(), session.clone());

                            if !is_background {
                                state
                                    .online_users
                                    .entry(username.clone())
                                    .or_default()
                                    .push(token.clone());
                                let _ = state.update_last_seen(&user_id).await;
                                let msg =
                                    format!("[Система] Пользователь {} подключился", username);
                                broadcast_system_message(&state, &msg, Some(&username)).await;
                                let sys_msg = "Добро пожаловать в **VartChat**! 👋\n\nСюда вам будут приходить системные уведомления от самого мессенджера.\n\n⚠️ **Важно:** Пожалуйста, сохраните свой пароль в надежном месте. На данный момент функция восстановления пароля пока недоступна.".to_string();
                                send_system_notification(&state, &user_id, &sys_msg).await;
                            }
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
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            ping_task.abort();
            send_task.abort();
            state.sessions.remove(&temp_id);
            return;
        }
    };

    // ---- Загрузка истории при логине ----
    if !my_user_id.is_empty() && !is_background {
        crate::senders::push_login_history(&tx, &keys, &my_user_id, &state).await;
    }

    let ctx = Ctx::new(state.clone(), session.clone(), tx.clone(), keys.clone(), my_user_id.clone(), my_username.clone(), is_background);

    // ---- Основной цикл ----
    info!("Начало основного цикла для {}", my_username);
    loop {
        if !session.connected.load(Ordering::Relaxed) {
            break;
        }

        // КРИТИЧЕСКАЯ ПРОВЕРКА БЕЗОПАСНОСТИ:
        // Если токена больше нет в state.sessions, значит сессию убили с другого устройства.
        if let Some(tok) = session.token.get() {
            if !state.sessions.contains_key(tok) {
                info!(
                    "Сессия {} была завершена с другого устройства. Отключаем.",
                    tok
                );
                let _ = send_system_message(&tx, "[Система] Сессия завершена с другого устройства")
                    .await;
                let _ = tx.send(Message::Close(None));
                break;
            }
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

            if !session.check_rate_limit() {
                let _ = send_system_message(
                    &session.tx,
                    "[Система] Слишком много сообщений, подождите",
                )
                .await;
                continue;
            }

            let msg_type = data[0];

            match msg_type {
                MSG_TYPE_USER => { ctx.handle_user(&data).await; }
                MSG_TYPE_EDIT => { ctx.handle_edit(&data).await; }
                MSG_TYPE_READ => { ctx.handle_read(&data).await; }
                MSG_TYPE_DELETE => { ctx.handle_delete(&data).await; }
                MSG_TYPE_LOGOUT => { ctx.handle_logout(&data).await; }
                MSG_TYPE_COMMAND => { ctx.handle_command(&data).await; }
                MSG_TYPE_TYPING => { ctx.handle_typing(&data).await; }
                MSG_TYPE_SECURE_COMMAND => { ctx.handle_secure_command(&data).await; }
                MSG_TYPE_REACTION => { ctx.handle_reaction(&data).await; }
                _ => { warn!("Неизвестный тип сообщения: {}", msg_type); }
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
        let username = session.username.get().cloned().unwrap_or_default();
        let token = session.token.get().cloned().unwrap_or_default();

        if !is_background {
            if !username.is_empty() {
                let mut should_remove = false;
                if let Some(mut tokens) = state.online_users.get_mut(&username) {
                    tokens.retain(|t| t != &token);
                    if tokens.is_empty() {
                        should_remove = true;
                    }
                }
                if should_remove {
                    state.online_users.remove(&username);
                }
            }
            let msg = format!("[Система] Пользователь {} отключился", username);
            if !my_user_id.is_empty() {
                let _ = state.update_last_seen(&my_user_id).await;
            }
            broadcast_system_message(&state, &msg, Some(&username)).await;
        }
        if !token.is_empty() {
            state.sessions.remove(&token);
        }
    }

    info!(
        "Клиент {} отключён, время сессии: {:?}",
        my_username,
        start_time.elapsed()
    );
    ping_task.abort();
    send_task.abort();
}
