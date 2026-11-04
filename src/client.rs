use aes_gcm::{
    Key,
    aead::{Aead, KeyInit},
};
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use uuid::Uuid;

use crate::app_state::{AppState, MsgFields, Session};
use crate::constants::*;
use crate::fcm::send_fcm_push_and_cleanup;
use crate::handshake::ws_handshake;
use crate::senders::{
    broadcast_system_message, build_delete_chat_packet, send_chat_history, send_encrypted_message,
    send_messages_by_ids, send_system_message, send_system_notification, send_to_all_my_sessions,
    send_to_user_sessions,
};

pub async fn resolve_display_name(state: &Arc<AppState>, user_id: &str, fallback: &str) -> String {
    let raw = state.get_display_name(user_id).await.unwrap_or_default();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

// ==================== process_command ====================
pub async fn process_command(
    cmd: &str,
    my_user_id: &str,
    _my_username: &str,
    state: &Arc<AppState>,
    session: &Arc<Session>,
) -> String {
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
                let rows = client.query(
                    "SELECT g.name, g.creator_id, (SELECT 1 FROM group_members gm WHERE gm.group_id = g.id AND gm.user_id = $1) AS is_member FROM groups g ORDER BY g.name",
                    &[&uid]
                ).await.map_err(|e| e.to_string())?;

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
                let rows = client.query(
                    "SELECT c.name, c.creator_id, (SELECT 1 FROM channel_subscribers cs WHERE cs.channel_id = c.id AND cs.user_id = $1) AS subscribed FROM channels c ORDER BY c.name",
                    &[&uid],
                ).await.map_err(|e| e.to_string())?;

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
            let is_phones = args.len() >= 2 && args[0] == "phones";
            let is_history = args.len() >= 1 && args[0] == "history";

            let result: Result<Vec<String>, String> = async {
                let client = state.db.get().await.map_err(|e| e.to_string())?;

                let query_str = if is_phones {
                    "SELECT u.id, u.phone, u.username, COALESCE(u.display_name, ''), COALESCE(u.last_seen, 0), COALESCE(s.hide_phone, false), COALESCE(s.last_seen_privacy, 0)::smallint
                     FROM users u LEFT JOIN user_settings s ON u.id = s.user_id
                     WHERE u.phone = ANY($1)"
                } else if is_history {
                    "SELECT DISTINCT u.id, u.phone, u.username, COALESCE(u.display_name, ''), COALESCE(u.last_seen, 0), COALESCE(s.hide_phone, false), COALESCE(s.last_seen_privacy, 0)::smallint
                     FROM users u
                     LEFT JOIN user_settings s ON u.id = s.user_id
                     JOIN messages m ON (m.sender_id = u.id AND m.recipient_id = $1) OR (m.recipient_id = u.id AND m.sender_id = $1)
                     WHERE u.id != $1"
                } else {
                    "SELECT u.id, u.phone, u.username, COALESCE(u.display_name, ''), COALESCE(u.last_seen, 0), COALESCE(s.hide_phone, false), COALESCE(s.last_seen_privacy, 0)::smallint
                     FROM users u LEFT JOIN user_settings s ON u.id = s.user_id"
                };

                let rows = if is_phones {
                    let phones = args[1..].join(" ");
                    let phone_list: Vec<&str> = phones.split(',').collect();
                    client.query(query_str, &[&phone_list]).await
                } else if is_history {
                    client.query(query_str, &[&uid]).await
                } else {
                    client.query(query_str, &[]).await
                }.map_err(|e| e.to_string())?;

                let mut users = Vec::new();
                for row in rows {
                    let target_id: String = row.get(0);
                    let mut phone: String = row.get(1);
                    let username: String = row.get(2);
                    let display_name: String = row.get(3);
                    let mut last_seen: i64 = row.get(4);
                    let hide_phone: bool = row.get(5);
                    let privacy: i16 = row.get(6); // Теперь тут точно i16 (SMALLINT)!

                    if hide_phone && target_id != uid {
                        phone = "".to_string();
                    }

                    let is_online = state.online_users.contains_key(&username);
                    if privacy == 2 && target_id != uid {
                        last_seen = 0;
                    } else if privacy == 1 && target_id != uid && !is_history {
                        last_seen = 0;
                    }
                    if is_online {
                        last_seen = 0;
                    }

                    users.push(format!("{}|{}|{}|{}", phone, username, display_name, last_seen));
                }
                Ok(users)
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
                let last_seen: i64 = {
                    match state.db.get().await {
                        Ok(client) => match client
                            .query_opt("SELECT last_seen FROM users WHERE id = $1", &[&target_id])
                            .await
                        {
                            Ok(Some(row)) => row.get(0),
                            _ => 0,
                        },
                        Err(_) => 0,
                    }
                };

                match state.get_profile(&target_id).await {
                    Ok((uname, phone, fname, lname, dname, bio)) => {
                        let (hide_phone, privacy) = state
                            .get_user_settings(&target_id)
                            .await
                            .unwrap_or((false, 0));
                        let is_me = target_id == my_user_id;

                        let show_phone = if hide_phone && !is_me {
                            "скрыт".to_string()
                        } else {
                            phone.clone()
                        };

                        let mut status = "скрыт".to_string();
                        if is_me || privacy == 0 {
                            let is_online = state.online_users.contains_key(&uname);
                            if is_online {
                                status = "онлайн".to_string();
                            } else {
                                status = "офлайн".to_string();
                            }
                        } else if privacy == 1 {
                            status = "офлайн".to_string();
                        }

                        format!(
                            "[Система] Профиль|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                            uname,
                            show_phone,
                            fname,
                            lname,
                            dname,
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
                    let fname = parts[0];
                    let lname = parts[1];
                    let dname = parts[2];
                    let uname = parts[3];
                    let bio = parts[4];

                    match state
                        .update_profile(my_user_id, fname, lname, dname, uname, bio)
                        .await
                    {
                        Ok(_) => "[Система] Профиль успешно обновлен".to_string(),
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
                    let old_pwd = parts[0];
                    let new_pwd = parts[1];

                    match state.verify_password_for_user(my_user_id, old_pwd).await {
                        Ok(true) => match state.update_password(my_user_id, new_pwd).await {
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
                        let res = c.execute(
                            "INSERT INTO reports (reporter_id, target_id, target_type, reason) VALUES ($1, $2, $3, $4)",
                            &[&my_user_id, &msg_id.to_string(), &target_type, &reason],
                        ).await;
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

    // Читаем флаг is_background (если он есть)
    let is_background = if auth_data.len() > 17 + enc_len {
        auth_data[17 + enc_len] == 1
    } else {
        false // Старый клиент
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

    // БЕЗОПАСНОЕ ЛОГИРОВАНИЕ
    let safe_log = match command {
        "login" => {
            let phone = parts.get(1).unwrap_or(&"");
            let device = parts.get(3).unwrap_or(&"");
            format!("login|{}|***|{}|*** (BG: {})", phone, device, is_background)
        }
        "register" => {
            let phone = parts.get(1).unwrap_or(&"");
            let fname = parts.get(3).unwrap_or(&"");
            let lname = parts.get(4).unwrap_or(&"");
            let uname = parts.get(5).unwrap_or(&"");
            let device = parts.get(6).unwrap_or(&"");
            format!(
                "register|{}|***|{}|{}|{}|{}|*** (BG: {})",
                phone, fname, lname, uname, device, is_background
            )
        }
        "token" => {
            let device = parts.get(2).unwrap_or(&"");
            format!("token|***|{}|*** (BG: {})", device, is_background)
        }
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
                    debug!("Проверяю, что человек не заблокирован");
                    if let Ok(Some(reason)) = state.is_user_banned(&user_id).await {
                        debug!("Он заблокирован!");
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

                    // ВАЖНО: Обновляем онлайн-статус только если это НЕ фон
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
                    debug!("Проверяю, что человек не заблокирован");
                    if let Ok(Some(reason)) = state.is_user_banned(&user_id).await {
                        debug!("Он заблокирован! Отправляю отказ");
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

                    // ИСПРАВЛЕНИЕ: get_profile теперь возвращает 6 элементов (добавили bio)
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

                            // ВАЖНО: Обновляем онлайн-статус только если это НЕ фон
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

                                // ВОТ ТУТ НУЖНО ВЕРНУТЬ ССЫЛКУ
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

            let username = username_opt.unwrap_or(phone).to_string();

            let result = state
                .register_user(&username, phone, password, first_name, last_name)
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

                            // ВАЖНО: Обновляем онлайн-статус только если это НЕ фон
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
                                let sys_msg = "Добро пожаловать в **VartChat**! 👋\n\n\
     Сюда вам будут приходить системные уведомления от самого мессенджера.\n\n\
     ⚠️ **Важно:** Пожалуйста, сохраните свой пароль в надежном месте. На данный момент функция восстановления пароля пока недоступна.".to_string();
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
        let tx_h = tx.clone();
        let keys_h = keys.clone();
        let uid_h = my_user_id.clone();
        let state_h = state.clone();

        // Личные
        let personal = state_h.get_recent_personal(&uid_h, LOGIN_PER_CHAT).await;
        if let Ok(msgs) = personal {
            let count = msgs.len();
            for (
                msg_id,
                sender_id,
                recipient_id,
                content,
                ts,
                reply_id,
                flag_me,
                flag_any,
                edited,
            ) in msgs
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
            }
            info!("Логин: {} последних личных ({} шт)", LOGIN_PER_CHAT, count);
        }

        // Группы
        let groups = state_h.get_recent_groups(&uid_h, LOGIN_PER_CHAT).await;
        if let Ok(msgs) = groups {
            let count = msgs.len();
            for (msg_id, gname, sender_id, content, ts, reply_id, flag_me, flag_any, edited) in msgs
            {
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
            }
            info!(
                "Логин: {} последних групповых ({} шт)",
                LOGIN_PER_CHAT, count
            );
        }

        // Каналы
        let channels = state_h.get_recent_channels(&uid_h, LOGIN_PER_CHAT).await;
        if let Ok(msgs) = channels {
            let count = msgs.len();
            for (
                msg_id,
                cname,
                sender_id,
                content,
                ts,
                reply_id,
                flag_me,
                flag_any,
                views,
                edited,
            ) in msgs
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
        if !session.connected.load(Ordering::Relaxed) {
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

            // Rate limit
            if !session.check_rate_limit() {
                let _ = send_system_message(
                    &session.tx,
                    "[Система] Слишком много сообщений, подождите",
                )
                .await;
                continue;
            }

            let msg_type = data[0];
            let rest = &data[1..];

            match msg_type {
                MSG_TYPE_USER => {
                    if rest.len() < 4 + 4 + 12 + 4 + 24 {
                        warn!("0x01: мало данных");
                        continue;
                    }
                    let mut offset = 0;
                    let sender_len =
                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;
                    offset += 4;
                    if rest.len() < offset + sender_len {
                        continue;
                    }
                    let _sender_name =
                        String::from_utf8_lossy(&rest[offset..offset + sender_len]).to_string();
                    offset += sender_len;

                    let recipient_len =
                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;
                    offset += 4;
                    if rest.len() < offset + recipient_len {
                        continue;
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
                        continue;
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
                        aes_gcm::Aes256Gcm::new(Key::<aes_gcm::Aes256Gcm>::from_slice(&keys.key));
                    let nonce = aes_gcm::Nonce::from_slice(nonce);
                    let plaintext = match cipher.decrypt(nonce, encrypted) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("0x01: ошибка расшифровки: {}", e);
                            continue;
                        }
                    };
                    let content = String::from_utf8_lossy(&plaintext).to_string();

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
                    if !recipient_name.starts_with(['#', '&']) {
                        let recipient_id_opt = state.resolve_id(&recipient_name).await;

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

                        let stored_id = match state
                            .store_message(
                                &my_user_id,
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
                                continue;
                            }
                        };

                        send_to_all_my_sessions(
                            &state,
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
                                edited: false,
                            },
                            Some(client_msg_id),
                        )
                        .await;

                        if is_background {
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
                                    edited: false,
                                },
                                Some(client_msg_id),
                            )
                            .await;
                        }

                        if recipient_id != my_user_id {
                            let target_tokens = {
                                state
                                    .online_users
                                    .get(&recipient_name)
                                    .map(|r| r.clone())
                                    .unwrap_or_default()
                            };
                            for tok in target_tokens {
                                let target_session = state.sessions.get(&tok).map(|r| r.clone());
                                if let Some(ts) = target_session {
                                    let _ = send_encrypted_message(
                                        &ts.tx,
                                        &ts.keys,
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
                                            edited: false,
                                        },
                                        None,
                                    )
                                    .await;
                                }
                            }

                            let fcm_tokens = state
                                .get_fcm_tokens_for_user(&recipient_id)
                                .await
                                .unwrap_or_default();

                            let sender_display_name =
                                resolve_display_name(&state, &my_user_id, &my_username).await;

                            for fcm_tok in fcm_tokens {
                                let title = sender_display_name.to_string();
                                let body = content.chars().take(100).collect::<String>();
                                let data_payload = json!({
                                    "sender": sender_display_name,
                                    "sender_username": my_username,
                                    "chatKey": my_username,
                                    "type": "private",
                                    "kind": "personal",
                                    "msg_id": stored_id.to_string()
                                });
                                let state_fcm = state.clone();
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
                        continue;
                    }

                    // ---- Группа ----
                    if recipient_name.starts_with('#') {
                        let group_name = recipient_name.trim_start_matches('#').to_string();

                        let is_member = {
                            match state.db.get().await {
                                Ok(client) => {
                                    client.query_opt(
                                        "SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE g.name = $1 AND gm.user_id = $2",
                                        &[&group_name, &my_user_id]
                                    ).await.map(|opt| opt.is_some()).unwrap_or(false)
                                }
                                Err(_) => false,
                            }
                        };

                        if !is_member {
                            let _ =
                                send_system_message(&tx, "[Система] Вы не состоите в этой группе")
                                    .await;
                            continue;
                        }

                        let stored_id = match state
                            .store_group_message(
                                &group_name,
                                &my_user_id,
                                &content,
                                timestamp,
                                reply_opt,
                            )
                            .await
                        {
                            Ok(id) => id,
                            Err(e) => {
                                error!("ОШИБКА сохранения группового сообщения в БД: {}", e);
                                continue;
                            }
                        };

                        let members = state
                            .get_group_members(&group_name)
                            .await
                            .unwrap_or_default();
                        let recip_with_hash = format!("#{}", group_name);

                        send_to_all_my_sessions(
                            &state,
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
                                edited: false,
                            },
                            Some(client_msg_id),
                        )
                        .await;

                        if is_background {
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
                                    edited: false,
                                },
                                Some(client_msg_id),
                            )
                            .await;
                        }

                        for member_id in members {
                            if member_id == my_user_id {
                                continue;
                            }

                            let member_name = state.resolve_username(&member_id).await;
                            if member_name == DELETED_LABEL {
                                continue;
                            }

                            let target_online = state.online_users.contains_key(&member_name);

                            if target_online {
                                let target_tokens = {
                                    state
                                        .online_users
                                        .get(&member_name)
                                        .map(|r| r.clone())
                                        .unwrap_or_default()
                                };
                                for tok in target_tokens {
                                    let target_session =
                                        state.sessions.get(&tok).map(|r| r.clone());
                                    if let Some(ts) = target_session {
                                        let _ = send_encrypted_message(
                                            &ts.tx,
                                            &ts.keys,
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
                                                edited: false,
                                            },
                                            None,
                                        )
                                        .await;
                                    }
                                }
                            } else {
                                let fcm_tokens = state
                                    .get_fcm_tokens_for_user(&member_id)
                                    .await
                                    .unwrap_or_default();

                                let sender_display_name =
                                    resolve_display_name(&state, &my_user_id, &my_username).await;

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
                                        "chatKey": format!("#{}", group_name),
                                        "type": "group",
                                        "kind": "group",
                                        "msg_id": stored_id.to_string()
                                    });
                                    let state_fcm = state.clone();
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
                        continue;
                    }

                    // ---- Канал ----
                    if recipient_name.starts_with('&') {
                        let channel_name = recipient_name.trim_start_matches('&').to_string();

                        let is_owner = {
                            match state.db.get().await {
                                Ok(client) => {
                                    client.query_opt(
                                        "SELECT 1 FROM channels WHERE name = $1 AND creator_id = $2",
                                        &[&channel_name, &my_user_id]
                                    ).await.map(|opt| opt.is_some()).unwrap_or(false)
                                }
                                Err(_) => false,
                            }
                        };

                        if !is_owner {
                            let _ = send_system_message(
                                &tx,
                                "[Система] Только владелец канала может отправлять сообщения",
                            )
                            .await;
                            continue;
                        }

                        let stored_id = match state
                            .store_channel_message(
                                &channel_name,
                                &my_user_id,
                                &content,
                                timestamp,
                                reply_opt,
                            )
                            .await
                        {
                            Ok(id) => id,
                            Err(e) => {
                                error!("ОШИБКА сохранения сообщения канала в БД: {}", e);
                                continue;
                            }
                        };

                        let subscribers = state
                            .get_channel_subscribers(&channel_name)
                            .await
                            .unwrap_or_default();
                        let recip_with_amp = format!("&{}", channel_name);

                        send_to_all_my_sessions(
                            &state,
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
                                edited: false,
                            },
                            Some(client_msg_id),
                        )
                        .await;

                        for sub_id in subscribers {
                            if sub_id == my_user_id {
                                continue;
                            }

                            let sub_name = state.resolve_username(&sub_id).await;
                            if sub_name == DELETED_LABEL {
                                continue;
                            }

                            let target_online = state.online_users.contains_key(&sub_name);

                            if target_online {
                                let target_tokens = {
                                    state
                                        .online_users
                                        .get(&sub_name)
                                        .map(|r| r.clone())
                                        .unwrap_or_default()
                                };
                                for tok in target_tokens {
                                    let target_session =
                                        state.sessions.get(&tok).map(|r| r.clone());
                                    if let Some(ts) = target_session {
                                        let _ = send_encrypted_message(
                                            &ts.tx,
                                            &ts.keys,
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
                                                edited: false,
                                            },
                                            None,
                                        )
                                        .await;
                                    }
                                }
                            } else {
                                let fcm_tokens = state
                                    .get_fcm_tokens_for_user(&sub_id)
                                    .await
                                    .unwrap_or_default();

                                let sender_display_name =
                                    resolve_display_name(&state, &my_user_id, &my_username).await;

                                for fcm_tok in fcm_tokens {
                                    let title =
                                        format!("Новое сообщение в канале {}", channel_name);
                                    let body = content.chars().take(100).collect::<String>();
                                    let data_payload = json!({
                                        "sender": sender_display_name,
                                        "channel": channel_name,
                                        "chatKey": format!("&{}", channel_name),
                                        "type": "channel",
                                        "kind": "channel",
                                        "msg_id": stored_id.to_string()
                                    });
                                    let state_fcm = state.clone();
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
                        continue;
                    }
                }

                MSG_TYPE_EDIT => {
                    if rest.len() < 8 + 1 + 12 + 4 {
                        warn!("0x08: мало данных");
                        continue;
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
                        continue;
                    }
                    let encrypted = &rest[offset..offset + enc_len];

                    let cipher =
                        aes_gcm::Aes256Gcm::new(Key::<aes_gcm::Aes256Gcm>::from_slice(&keys.key));
                    let nonce_ref = aes_gcm::Nonce::from_slice(nonce_bytes);
                    let plaintext = match cipher.decrypt(nonce_ref, encrypted) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("0x08: ошибка расшифровки: {}", e);
                            continue;
                        }
                    };
                    let new_text = String::from_utf8_lossy(&plaintext).to_string();

                    match kind {
                        MSG_KIND_PERSONAL => {
                            let lookup = state.lookup_personal_message(msg_id).await;
                            let (sender_id, recipient_id) = match lookup {
                                Ok(Some(v)) => v,
                                Ok(None) => {
                                    let _ =
                                        send_system_message(&tx, "[Система] Сообщение не найдено")
                                            .await;
                                    continue;
                                }
                                Err(e) => {
                                    let _ =
                                        send_system_message(&tx, &format!("[Система] {}", e)).await;
                                    continue;
                                }
                            };

                            if sender_id != my_user_id {
                                let _ = send_system_message(
                                    &tx,
                                    "[Система] Редактировать можно только свои сообщения",
                                )
                                .await;
                                continue;
                            }

                            let (ts, reply_opt, read_flag) = {
                                match state.db.get().await {
                                    Ok(client) => {
                                        match client.query_opt(
                                            "SELECT (EXTRACT(EPOCH FROM sent_at) * 1000)::bigint, reply_to_id, read_at FROM messages WHERE id = $1",
                                            &[&msg_id]
                                        ).await {
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

                            let _ = state
                                .update_personal_message_content(msg_id, &new_text)
                                .await;

                            let reply_id = reply_opt.unwrap_or(0);
                            let (s_name, r_name) = (
                                state.resolve_username(&sender_id).await,
                                state.resolve_username(&recipient_id).await,
                            );

                            send_to_all_my_sessions(
                                &state,
                                &my_username,
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

                            if recipient_id != my_user_id {
                                let hidden = {
                                    match state.db.get().await {
                                        Ok(client) => client.query_opt(
                                            "SELECT 1 FROM hidden_messages WHERE user_id = $1 AND kind = 1 AND msg_id = $2",
                                            &[&recipient_id, &msg_id]
                                        ).await.map(|opt| opt.is_some()).unwrap_or(false),
                                        Err(_) => false,
                                    }
                                };

                                if !hidden {
                                    let tokens = {
                                        state
                                            .online_users
                                            .get(&r_name)
                                            .map(|r| r.clone())
                                            .unwrap_or_default()
                                    };
                                    for tok in tokens {
                                        let sess = state.sessions.get(&tok).map(|r| r.clone());
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

                            if let Ok(client) = state.db.get().await
                                && let Ok(Some(row)) = client.query_opt(
                                "SELECT gm.sender_id, (EXTRACT(EPOCH FROM gm.sent_at) * 1000)::bigint, gm.reply_to_id, gm.first_read_at, g.name \
                                     FROM group_messages gm JOIN groups g ON gm.group_id = g.id WHERE gm.id = $1",
                                &[&msg_id]
                            ).await {
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
                                        send_system_message(&tx, "[Система] Сообщение не найдено")
                                            .await;
                                    continue;
                                }
                            };

                            if sender_id != my_user_id {
                                let _ = send_system_message(
                                    &tx,
                                    "[Система] Редактировать можно только свои сообщения",
                                )
                                .await;
                                continue;
                            }

                            let _ = state.update_group_message_content(msg_id, &new_text).await;

                            let recip_with_hash = format!("#{}", gname);

                            send_to_all_my_sessions(
                                &state,
                                &my_username,
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

                            let members = state.get_group_members(&gname).await.unwrap_or_default();

                            for member_id in members {
                                if member_id == my_user_id {
                                    continue;
                                }

                                let hidden = {
                                    match state.db.get().await {
                                        Ok(client) => client.query_opt(
                                            "SELECT 1 FROM hidden_messages WHERE user_id = $1 AND kind = 2 AND msg_id = $2",
                                            &[&member_id, &msg_id]
                                        ).await.map(|opt| opt.is_some()).unwrap_or(false),
                                        Err(_) => false,
                                    }
                                };
                                if hidden {
                                    continue;
                                }

                                let member_name = state.resolve_username(&member_id).await;
                                if member_name == DELETED_LABEL {
                                    continue;
                                }

                                let tokens = {
                                    state
                                        .online_users
                                        .get(&member_name)
                                        .map(|r| r.clone())
                                        .unwrap_or_default()
                                };
                                for tok in tokens {
                                    let sess = state.sessions.get(&tok).map(|r| r.clone());
                                    if let Some(s) = sess {
                                        let _ = send_encrypted_message(
                                            &s.tx,
                                            &s.keys,
                                            &my_username,
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
                            let lookup = state.lookup_channel_message(msg_id).await;
                            let (cname, creator_id, _sender_id) = match lookup {
                                Ok(Some(v)) => v,
                                Ok(None) => {
                                    let _ =
                                        send_system_message(&tx, "[Система] Сообщение не найдено")
                                            .await;
                                    continue;
                                }
                                Err(e) => {
                                    let _ =
                                        send_system_message(&tx, &format!("[Система] {}", e)).await;
                                    continue;
                                }
                            };

                            if creator_id != my_user_id {
                                let _ = send_system_message(&tx, "[Система] Только владелец канала может редактировать сообщения").await;
                                continue;
                            }

                            let (ts, reply_id, views_u) = {
                                match state.db.get().await {
                                    Ok(client) => {
                                        match client.query_opt(
                                            "SELECT (EXTRACT(EPOCH FROM sent_at) * 1000)::bigint, reply_to_id, \
                                                    (SELECT COUNT(*) FROM channel_message_views v WHERE v.channel_msg_id = cm.id) \
                                             FROM channel_messages cm WHERE cm.id = $1",
                                            &[&msg_id]
                                        ).await {
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

                            let _ = state
                                .update_channel_message_content(msg_id, &new_text)
                                .await;

                            let recip_with_amp = format!("&{}", cname);

                            send_to_all_my_sessions(
                                &state,
                                &my_username,
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

                            let subscribers = state
                                .get_channel_subscribers(&cname)
                                .await
                                .unwrap_or_default();

                            for sub_id in subscribers {
                                if sub_id == my_user_id {
                                    continue;
                                }

                                let hidden = {
                                    match state.db.get().await {
                                        Ok(client) => client.query_opt(
                                            "SELECT 1 FROM hidden_messages WHERE user_id = $1 AND kind = 3 AND msg_id = $2",
                                            &[&sub_id, &msg_id]
                                        ).await.map(|opt| opt.is_some()).unwrap_or(false),
                                        Err(_) => false,
                                    }
                                };
                                if hidden {
                                    continue;
                                }

                                let sub_name = state.resolve_username(&sub_id).await;
                                if sub_name == DELETED_LABEL {
                                    continue;
                                }

                                let tokens = {
                                    state
                                        .online_users
                                        .get(&sub_name)
                                        .map(|r| r.clone())
                                        .unwrap_or_default()
                                };
                                for tok in tokens {
                                    let sess = state.sessions.get(&tok).map(|r| r.clone());
                                    if let Some(s) = sess {
                                        let _ = send_encrypted_message(
                                            &s.tx,
                                            &s.keys,
                                            &my_username,
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

                MSG_TYPE_READ => {
                    if rest.len() < 2 {
                        continue;
                    }
                    let count = u16::from_be_bytes(rest[0..2].try_into().unwrap()) as usize;
                    if rest.len() < 2 + count * 9 {
                        continue;
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
                        my_username,
                        personal_ids.len(),
                        group_ids.len(),
                        channel_ids.len()
                    );

                    if !personal_ids.is_empty()
                        && let Ok(client) = state.db.get().await
                    {
                        let rows = client.query(
                            "SELECT id, sender_id FROM messages WHERE id = ANY($1) AND recipient_id = $2",
                            &[&personal_ids, &my_user_id]
                        ).await.unwrap_or_default();

                        let mut by_author: std::collections::HashMap<String, Vec<i64>> =
                            std::collections::HashMap::new();
                        for row in rows {
                            let id: i64 = row.get(0);
                            let sender_id: String = row.get(1);
                            by_author.entry(sender_id).or_default().push(id);
                        }

                        let _ = client.execute(
                            "UPDATE messages SET read_at = CURRENT_TIMESTAMP WHERE id = ANY($1) AND read_at IS NULL",
                            &[&personal_ids]
                        ).await;

                        for (author_id, ids) in by_author {
                            if author_id == my_user_id {
                                continue;
                            }
                            let author_name = state.resolve_username(&author_id).await;
                            let tokens = {
                                state
                                    .online_users
                                    .get(&author_name)
                                    .map(|r| r.clone())
                                    .unwrap_or_default()
                            };
                            let items: Vec<(u8, i64)> =
                                ids.iter().map(|id| (MSG_KIND_PERSONAL, *id)).collect();
                            let pkt = crate::senders::build_read_packet(&items);

                            for tok in tokens {
                                let sess = state.sessions.get(&tok).map(|r| r.clone());
                                if let Some(s) = sess {
                                    let _ = s.tx.send(Message::Binary(pkt.clone()));
                                }
                            }
                        }
                    }

                    if !group_ids.is_empty()
                        && let Ok(client) = state.db.get().await
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

                        let _ = client.execute(
                            "UPDATE group_messages SET first_read_at = CURRENT_TIMESTAMP WHERE id = ANY($1) AND first_read_at IS NULL",
                            &[&group_ids]
                        ).await;

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
                                if mid == my_user_id {
                                    continue;
                                }
                                let name = state.resolve_username(&mid).await;
                                let tokens = {
                                    state
                                        .online_users
                                        .get(&name)
                                        .map(|r| r.clone())
                                        .unwrap_or_default()
                                };
                                for tok in tokens {
                                    let sess = state.sessions.get(&tok).map(|r| r.clone());
                                    if let Some(s) = sess {
                                        let _ = s.tx.send(Message::Binary(pkt.clone()));
                                    }
                                }
                            }
                        }
                    }

                    if !channel_ids.is_empty()
                        && let Ok(client) = state.db.get().await
                    {
                        let _ = client.execute(
                            "INSERT INTO channel_message_views (channel_msg_id, user_id) SELECT unnest($1::bigint[]), $2 ON CONFLICT DO NOTHING",
                            &[&channel_ids, &my_user_id]
                        ).await;
                    }
                }

                MSG_TYPE_DELETE => {
                    if rest.len() < 9 {
                        warn!("0x05: мало данных");
                        continue;
                    }
                    let msg_id = i64::from_be_bytes(rest[0..8].try_into().unwrap());
                    let kind = rest[8];

                    if msg_id == 0 {
                        if rest.len() < 9 + 1 + 4 {
                            warn!("0x05 (чат): мало данных");
                            continue;
                        }
                        let dtype = rest[9];
                        let name_len =
                            u32::from_be_bytes(rest[10..14].try_into().unwrap()) as usize;
                        if rest.len() < 14 + name_len {
                            continue;
                        }
                        let name = String::from_utf8_lossy(&rest[14..14 + name_len]).to_string();

                        info!(
                            "0x05: Удаление чата kind={} name={} type={}",
                            kind, name, dtype
                        );

                        match kind {
                            MSG_KIND_PERSONAL => {
                                let peer_id_opt = state.resolve_id(&name).await;

                                if let Some(peer_id) = peer_id_opt {
                                    if dtype == MSG_DELETE_FOR_ME {
                                        let _ =
                                            state.hide_personal_chat(&my_user_id, &peer_id).await;
                                    } else {
                                        let _ =
                                            state.delete_personal_chat(&my_user_id, &peer_id).await;

                                        let pkt = build_delete_chat_packet(kind, &name, 0);
                                        send_to_user_sessions(&state, &my_username, pkt.clone())
                                            .await;
                                        send_to_user_sessions(&state, &name, pkt).await;
                                    }
                                }
                            }
                            MSG_KIND_GROUP => {
                                if dtype == MSG_DELETE_FOR_ME {
                                    let _ = state.leave_group(&name, &my_user_id).await;
                                } else {
                                    let members =
                                        state.get_group_members(&name).await.unwrap_or_default();

                                    let del_res = state.delete_group(&name, &my_user_id).await;

                                    match del_res {
                                        Ok(true) => {
                                            let pkt = build_delete_chat_packet(kind, &name, 0);
                                            for m_id in members {
                                                let m_name = state.resolve_username(&m_id).await;
                                                send_to_user_sessions(&state, &m_name, pkt.clone())
                                                    .await;
                                            }
                                        }
                                        Ok(false) => {
                                            let _ = send_system_message(
                                                &tx,
                                                "[Система] Только владелец может удалить группу",
                                            )
                                            .await;
                                        }
                                        Err(e) => {
                                            let _ = send_system_message(
                                                &tx,
                                                &format!("[Система] Ошибка удаления: {}", e),
                                            )
                                            .await;
                                        }
                                    }
                                }
                            }
                            MSG_KIND_CHANNEL => {
                                if dtype == MSG_DELETE_FOR_ME {
                                    let _ = state.unsubscribe_channel(&name, &my_user_id).await;
                                } else {
                                    let subs = state
                                        .get_channel_subscribers(&name)
                                        .await
                                        .unwrap_or_default();

                                    let del_res = state.delete_channel(&name, &my_user_id).await;

                                    match del_res {
                                        Ok(true) => {
                                            let pkt = build_delete_chat_packet(kind, &name, 0);
                                            for sub_id in subs {
                                                let s_name = state.resolve_username(&sub_id).await;
                                                send_to_user_sessions(&state, &s_name, pkt.clone())
                                                    .await;
                                            }
                                        }
                                        Ok(false) => {
                                            let _ = send_system_message(
                                                &tx,
                                                "[Система] Только владелец может удалить канал",
                                            )
                                            .await;
                                        }
                                        Err(e) => {
                                            let _ = send_system_message(
                                                &tx,
                                                &format!("[Система] Ошибка удаления: {}", e),
                                            )
                                            .await;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }

                    let dtype = if rest.len() >= 10 { rest[9] } else { 0 };
                    if dtype == MSG_DELETE_FOR_ME {
                        let result = state.hide_message(&my_user_id, kind, msg_id).await;
                        if let Err(e) = result {
                            let _ = send_system_message(
                                &tx,
                                &format!("[Система] Ошибка скрытия: {}", e),
                            )
                            .await;
                        }
                        continue;
                    }

                    match kind {
                        MSG_KIND_PERSONAL => {
                            let lookup = state.lookup_personal_message(msg_id).await;

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

                                    // Отправляем FCM на удаление получателю
                                    if recipient_id != my_user_id {
                                        let rec_name = state.resolve_username(&recipient_id).await;
                                        if rec_name != DELETED_LABEL {
                                            let is_online =
                                                state.online_users.contains_key(&rec_name);
                                            if !is_online {
                                                let fcm_tokens = state
                                                    .get_fcm_tokens_for_user(&recipient_id)
                                                    .await
                                                    .unwrap_or_default();
                                                let data_payload = json!({
                                                    "kind": "delete",
                                                    "msg_id": msg_id.to_string()
                                                });
                                                for fcm_tok in fcm_tokens {
                                                    let state_fcm = state.clone();
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

                                    let del = state.delete_message(msg_id).await;
                                    if let Err(e) = del {
                                        let _ = send_system_message(
                                            &tx,
                                            &format!("[Система] Ошибка удаления: {}", e),
                                        )
                                        .await;
                                        continue;
                                    }

                                    let pkt = crate::senders::build_delete_packet(
                                        msg_id,
                                        kind,
                                        MSG_DELETE_FOR_ALL,
                                    );
                                    let _ = tx.send(Message::Binary(pkt.clone()));

                                    if recipient_id != my_user_id {
                                        let rec_name = state.resolve_username(&recipient_id).await;

                                        if rec_name != DELETED_LABEL {
                                            let tokens = {
                                                state
                                                    .online_users
                                                    .get(&rec_name)
                                                    .map(|r| r.clone())
                                                    .unwrap_or_default()
                                            };
                                            for tok in tokens {
                                                let target =
                                                    state.sessions.get(&tok).map(|r| r.clone());
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
                            let lookup = state.lookup_channel_message(msg_id).await;

                            match lookup {
                                Ok(Some((channel_name, creator_id, _sender_id))) => {
                                    if creator_id != my_user_id {
                                        let _ = send_system_message(&tx, "[Система] Только владелец канала может удалять сообщения").await;
                                        continue;
                                    }

                                    let del = state.delete_channel_message(msg_id).await;
                                    if let Err(e) = del {
                                        let _ = send_system_message(
                                            &tx,
                                            &format!("[Система] Ошибка удаления: {}", e),
                                        )
                                        .await;
                                        continue;
                                    }

                                    let subs_ids = state
                                        .get_channel_subscribers(&channel_name)
                                        .await
                                        .unwrap_or_default();

                                    let pkt = crate::senders::build_delete_packet(
                                        msg_id,
                                        kind,
                                        MSG_DELETE_FOR_ALL,
                                    );

                                    let sessions: Vec<Arc<Session>> =
                                        state.sessions.iter().map(|r| r.value().clone()).collect();
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
                    if rest.len() < 12 + 4 {
                        continue;
                    }
                    let nonce = &rest[0..12];
                    let enc_len = u32::from_be_bytes(rest[12..16].try_into().unwrap()) as usize;
                    if rest.len() < 16 + enc_len {
                        continue;
                    }
                    let encrypted = &rest[16..16 + enc_len];

                    let cipher =
                        aes_gcm::Aes256Gcm::new(Key::<aes_gcm::Aes256Gcm>::from_slice(&keys.key));
                    let nonce_ref = aes_gcm::Nonce::from_slice(nonce);
                    let plaintext = match cipher.decrypt(nonce_ref, encrypted) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("0x06: ошибка расшифровки: {}", e);
                            continue;
                        }
                    };
                    let cmd_str = String::from_utf8_lossy(&plaintext).to_string();
                    let parts: Vec<&str> = cmd_str.split('|').collect();
                    if parts.len() < 2 {
                        continue;
                    }

                    let token = parts[0].trim();
                    let ltype: u8 = parts[1].parse().unwrap_or(LOGOUT_TYPE_EXIT);
                    let password = if parts.len() > 2 { parts[2].trim() } else { "" };

                    if token.is_empty() {
                        continue;
                    }

                    if ltype == LOGOUT_TYPE_DELETE_ACCOUNT {
                        info!("Logout: DELETE_ACCOUNT от user_id={}", my_user_id);

                        if password.is_empty() {
                            let _ = send_system_message(&tx, "[Система] Неверный пароль").await;
                            continue;
                        }

                        let pwd_check = state.verify_password_for_user(&my_user_id, password).await;

                        match pwd_check {
                            Ok(true) => {}
                            Ok(false) => {
                                warn!("DELETE_ACCOUNT: неверный пароль для user_id={}", my_user_id);
                                let _ = send_system_message(&tx, "[Система] Неверный пароль").await;
                                continue;
                            }
                            Err(e) => {
                                error!("DELETE_ACCOUNT: {}", e);
                                let _ = send_system_message(&tx, &format!("[Система] {}", e)).await;
                                continue;
                            }
                        }

                        let result = state.soft_delete_account(&my_user_id).await;

                        let tokens_to_kill = match result {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Ошибка удаления аккаунта: {}", e);
                                let _ = send_system_message(
                                    &tx,
                                    &format!("[Система] Ошибка удаления аккаунта: {}", e),
                                )
                                .await;
                                continue;
                            }
                        };

                        info!(
                            "Аккаунт {} удалён, закрываю {} сессий",
                            my_username,
                            tokens_to_kill.len()
                        );

                        let reason = "Аккаунт удалён";
                        let rb = reason.as_bytes();
                        let mut pkt = Vec::with_capacity(1 + 4 + rb.len());
                        pkt.push(MSG_TYPE_LOGOUT);
                        pkt.extend_from_slice(&(rb.len() as u32).to_be_bytes());
                        pkt.extend_from_slice(rb);

                        for tok in &tokens_to_kill {
                            let sess = state.sessions.get(tok).map(|r| r.clone());
                            if let Some(s) = sess {
                                let _ = s.tx.send(Message::Binary(pkt.clone()));
                            }
                        }

                        state.online_users.remove(&my_username);
                        for tok in &tokens_to_kill {
                            state.sessions.remove(tok);
                        }

                        let msg = format!("[Система] Пользователь {} удалил аккаунт", my_username);
                        broadcast_system_message(&state, &msg, Some(&my_username)).await;

                        session.connected.store(false, Ordering::Relaxed);
                        continue;
                    }

                    info!("Logout: EXIT, token={}", token);

                    let is_owner = state
                        .verify_session_ownership(token, &my_user_id)
                        .await
                        .unwrap_or(false);
                    if !is_owner {
                        let _ = send_system_message(&tx, "[Система] Сессия не найдена").await;
                        continue;
                    }

                    let is_current = token == session.token.get().map(|s| s.as_str()).unwrap_or("");

                    let result = state.delete_session(token).await;

                    match result {
                        Ok(_) => {
                            state.sessions.remove(token);

                            if !is_background {
                                let mut should_remove = false;
                                if let Some(mut tokens) = state.online_users.get_mut(&my_username) {
                                    tokens.retain(|t| t != token);
                                    if tokens.is_empty() {
                                        should_remove = true;
                                    }
                                }
                                if should_remove {
                                    state.online_users.remove(&my_username);
                                }

                                if is_current {
                                    let _ = state.update_last_seen(&my_user_id).await;
                                    let msg = format!(
                                        "[Система] Пользователь {} отключился",
                                        my_username
                                    );
                                    broadcast_system_message(&state, &msg, Some(&my_username))
                                        .await;
                                }
                            }

                            if is_current {
                                session.connected.store(false, Ordering::Relaxed);
                                let _ =
                                    send_system_message(&tx, "[Система] Вы вышли из системы").await;
                                info!("Сессия {} завершена по logout", token);
                            } else {
                                let _ = send_system_message(
                                    &tx,
                                    "[Система] Устройство успешно отключено",
                                )
                                .await;
                                info!(
                                    "Сессия {} принудительно завершена пользователем {}",
                                    token, my_username
                                );
                            }
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
                    if rest.len() < 4 {
                        continue;
                    }
                    let cmd = String::from_utf8_lossy(&rest[4..]).to_string();
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

                MSG_TYPE_TYPING => {
                    debug!("Получен пакет TYPING от {}", my_username);
                    if rest.len() < 1 + 4 + 4 {
                        continue;
                    }
                    let kind = rest[0];
                    let mut offset = 1;

                    let sender_len =
                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;
                    offset += 4;
                    if rest.len() < offset + sender_len {
                        continue;
                    }
                    let _sender_name =
                        String::from_utf8_lossy(&rest[offset..offset + sender_len]).to_string();
                    offset += sender_len;

                    let recipient_len =
                        u32::from_be_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize;
                    offset += 4;
                    if rest.len() < offset + recipient_len {
                        continue;
                    }
                    let recipient_name =
                        String::from_utf8_lossy(&rest[offset..offset + recipient_len]).to_string();

                    if kind == MSG_KIND_PERSONAL {
                        let target_tokens = {
                            state
                                .online_users
                                .get(&recipient_name)
                                .map(|r| r.clone())
                                .unwrap_or_default()
                        };
                        for tok in target_tokens {
                            let target_session = state.sessions.get(&tok).map(|r| r.clone());
                            if let Some(ts) = target_session {
                                debug!("Пересылаю TYPING от {} к {}", my_username, recipient_name);
                                let _ = ts.tx.send(Message::Binary(data.clone()));
                            }
                        }
                    } else if kind == MSG_KIND_GROUP {
                        let group_name = recipient_name.trim_start_matches('#').to_string();

                        let members = state
                            .get_group_members(&group_name)
                            .await
                            .unwrap_or_default();

                        for member_id in members {
                            if member_id == my_user_id {
                                continue;
                            }

                            let member_name = state.resolve_username(&member_id).await;

                            let tokens = state
                                .online_users
                                .get(&member_name)
                                .map(|r| r.clone())
                                .unwrap_or_default();
                            for tok in tokens {
                                let target_session = state.sessions.get(&tok).map(|r| r.clone());
                                if let Some(ts) = target_session {
                                    let _ = ts.tx.send(Message::Binary(data.clone()));
                                }
                            }
                        }
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
