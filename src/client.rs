use aes_gcm::{
    Key,
    aead::{Aead, KeyInit},
};
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use rusqlite::params;
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
    send_messages_by_ids, send_system_message, send_to_all_my_sessions, send_to_user_sessions,
};

pub async fn resolve_display_name(state: &Arc<AppState>, user_id: &str, fallback: &str) -> String {
    let db = state.db.clone();
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
        result
    })
    .await
    .unwrap()
}

// ==================== process_command ====================
pub async fn process_command(
    cmd: &str,
    my_user_id: &str,
    _my_username: &str, // Исправлено (warning)
    state: &Arc<AppState>,
    _session: &Arc<Session>, // Исправлено (warning)
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
                let db = state.db.clone();
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
                let db = state.db.clone();
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
                let db = state.db.clone();
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
                let db = state.db.clone();
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
            let db = state.db.clone();
            let uid = my_user_id.to_string();
            let result = tokio::task::spawn_blocking(move || {
                let mut st = db.lock().unwrap();
                let mut stmt = st.conn
                    .prepare("SELECT g.name, g.creator_id, \
                                     (SELECT 1 FROM group_members gm WHERE gm.group_id = g.id AND gm.user_id = ?) AS is_member \
                              FROM groups g ORDER BY g.name")
                    .map_err(|e| e.to_string())?;
                let mut rows = stmt.query([&uid]).map_err(|e| e.to_string())?;
                let mut groups = Vec::new();
                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                    let name: String = row.get(0).map_err(|e| e.to_string())?;
                    let creator_id: String = row.get(1).map_err(|e| e.to_string())?;
                    let is_member: Option<i64> = row.get(2).ok();
                    groups.push((name, creator_id, is_member.is_some()));
                }
                drop(rows);
                drop(stmt);
                let out: Vec<String> = groups
                    .into_iter()
                    .map(|(name, cid, is_member)| format!("{}|{}|{}", name, st.resolve_username(&cid), if is_member { "1" } else { "0" }))
                    .collect();
                Ok::<_, String>(out)
            }).await.unwrap();

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
                let db = state.db.clone();
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
                let db = state.db.clone();
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
                let db = state.db.clone();
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
            let db = state.db.clone();
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
            let db = state.db.clone();
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
            let db = state.db.clone();
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
                let db = state.db.clone();
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
                let db = state.db.clone();
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
                let db = state.db.clone();
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
                        format!(
                            "[Система] Username изменён на {}. Переподключитесь для применения.",
                            new_username
                        )
                    }
                    Err(e) => format!("[Система] Ошибка: {}", e),
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

    if auth_data.len() < 1 + 12 + 4 {
        error!("AUTH: пакет слишком короткий для v3");
        let _ = send_task.await;
        return;
    }
    let nonce = &auth_data[1..13];
    let enc_len = u32::from_be_bytes(auth_data[13..17].try_into().unwrap()) as usize;
    if auth_data.len() < 17 + enc_len {
        error!("AUTH: не хватает данных enc");
        let _ = send_task.await;
        return;
    }
    let encrypted = &auth_data[17..17 + enc_len];

    let cipher = aes_gcm::Aes256Gcm::new(Key::<aes_gcm::Aes256Gcm>::from_slice(&keys.key));
    let nonce_ref = aes_gcm::Nonce::from_slice(nonce);
    let auth_str = match cipher.decrypt(nonce_ref, encrypted) {
        Ok(p) => String::from_utf8_lossy(&p).to_string(),
        Err(e) => {
            error!("AUTH: ошибка расшифровки: {}", e);
            let _ = send_task.await;
            return;
        }
    };

    info!("Auth string: {}", auth_str);
    let parts: Vec<&str> = auth_str.split('|').collect();
    if parts.is_empty() {
        error!("Неверный формат аутентификации");
        let _ = send_task.await;
        return;
    }

    let command = parts[0];

    let auth_result = match command {
        "token" => {
            let token = parts.get(1).map(|s| s.trim()).unwrap_or("");
            let device_name = parts.get(2).map(|s| s.trim()).unwrap_or("unknown");
            let fcm_token = parts
                .get(3)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let db = state.db.clone();
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
                        let db = state.db.clone();
                        let uid = user_id.clone();
                        let session_tok = token.to_string();
                        let dev = device_name.to_string();
                        tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            let _ = AppState::save_fcm_token(
                                &mut st.conn,
                                &uid,
                                &session_tok,
                                &fcm,
                                &dev,
                            );
                        })
                        .await
                        .unwrap();
                    }

                    session.user_id.set(user_id.clone()).ok();
                    session.username.set(username.clone()).ok(); // String
                    session.token.set(token.to_string()).ok();

                    state.sessions.remove(&temp_id);
                    state.sessions.insert(token.to_string(), session.clone());
                    state
                        .online_users
                        .entry(username.clone())
                        .or_insert_with(Vec::new)
                        .push(token.to_string());

                    {
                        let db_ls = state.db.clone();
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
            let phone = parts.get(1).map(|s| s.trim()).unwrap_or("");
            let password = parts.get(2).map(|s| s.trim()).unwrap_or("");
            let device_name = parts.get(3).map(|s| s.trim()).unwrap_or("unknown");
            let fcm_token = parts
                .get(4)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let db = state.db.clone();
            let ph = phone.to_string();
            let pwd = password.to_string();
            let result = tokio::task::spawn_blocking(move || {
                let mut st = db.lock().unwrap();
                AppState::login_user_by_phone(&mut st.conn, &ph, &pwd)
            })
            .await
            .unwrap();

            match result {
                Ok(user_id) => {
                    let db3 = state.db.clone();
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
                    let username = username_from_db.unwrap_or_else(|_| phone.to_string()); // String

                    let db2 = state.db.clone();
                    let uid2 = user_id.clone();
                    let dev = device_name.to_string();
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
                                let db = state.db.clone();
                                let uid = user_id.clone();
                                let session_tok = token.clone();
                                let dev = device_name.to_string();
                                tokio::task::spawn_blocking(move || {
                                    let mut st = db.lock().unwrap();
                                    let _ = AppState::save_fcm_token(
                                        &mut st.conn,
                                        &uid,
                                        &session_tok,
                                        &fcm,
                                        &dev,
                                    );
                                })
                                .await
                                .unwrap();
                            }

                            session.user_id.set(user_id.clone()).ok();
                            session.username.set(username.clone()).ok(); // String
                            session.token.set(token.clone()).ok();

                            state.sessions.remove(&temp_id);
                            state.sessions.insert(token.clone(), session.clone());
                            state
                                .online_users
                                .entry(username.clone())
                                .or_insert_with(Vec::new)
                                .push(token.clone());

                            {
                                let db_ls = state.db.clone();
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

            let username = username_opt.unwrap_or(phone).to_string(); // <-- ИСПРАВЛЕНО НА String

            let db = state.db.clone();
            let ph = phone.to_string();
            let pwd = password.to_string();
            let uname = username.clone(); // String
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
                    let db2 = state.db.clone();
                    let uid = user_id.clone();
                    let dev = device_name.to_string();
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
                                let db = state.db.clone();
                                let uid = user_id.clone();
                                let session_tok = token.clone();
                                let dev = device_name.to_string();
                                tokio::task::spawn_blocking(move || {
                                    let mut st = db.lock().unwrap();
                                    let _ = AppState::save_fcm_token(
                                        &mut st.conn,
                                        &uid,
                                        &session_tok,
                                        &fcm,
                                        &dev,
                                    );
                                })
                                .await
                                .unwrap();
                            }

                            session.user_id.set(user_id.clone()).ok();
                            session.username.set(username.clone()).ok(); // String
                            session.token.set(token.clone()).ok();

                            state.sessions.remove(&temp_id);
                            state.sessions.insert(token.clone(), session.clone());
                            state
                                .online_users
                                .entry(username.clone())
                                .or_insert_with(Vec::new)
                                .push(token.clone()); // String

                            {
                                let db_ls = state.db.clone();
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
        let db = state_h.db.clone();
        let uid = uid_h.clone();
        let personal = tokio::task::spawn_blocking(move || {
            let mut st = db.lock().unwrap();
            AppState::get_recent_personal(&mut st.conn, &uid, LOGIN_PER_CHAT)
        })
        .await
        .unwrap();
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
                let db = state_h.db.clone();
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
                        edited,
                    },
                    None,
                )
                .await;
            }
            info!("Логин: {} последних личных ({} шт)", LOGIN_PER_CHAT, count);
        }

        // Группы
        let db = state_h.db.clone();
        let uid = uid_h.clone();
        let groups = tokio::task::spawn_blocking(move || {
            let mut st = db.lock().unwrap();
            AppState::get_recent_groups(&mut st.conn, &uid, LOGIN_PER_CHAT)
        })
        .await
        .unwrap();
        if let Ok(msgs) = groups {
            let count = msgs.len();
            for (msg_id, gname, sender_id, content, ts, reply_id, flag_me, flag_any, edited) in msgs
            {
                let db = state_h.db.clone();
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
        let db = state_h.db.clone();
        let uid = uid_h.clone();
        let channels = tokio::task::spawn_blocking(move || {
            let mut st = db.lock().unwrap();
            AppState::get_recent_channels(&mut st.conn, &uid, LOGIN_PER_CHAT)
        })
        .await
        .unwrap();
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
                let db = state_h.db.clone();
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

                    let reply_opt: Option<i64> = if reply_to_id == 0 {
                        None
                    } else {
                        Some(reply_to_id)
                    };

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
                    if !recipient_name.starts_with('#') && !recipient_name.starts_with('&') {
                        let db = state.db.clone();
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

                        let db = state.db.clone();
                        let sender_id = my_user_id.clone();
                        let rec_id = recipient_id.clone();
                        let content_clone = content.clone();
                        let stored_id: i64 = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::store_message(
                                &mut st.conn,
                                &sender_id,
                                &rec_id,
                                &content_clone,
                                timestamp,
                                reply_opt,
                            )
                        })
                        .await
                        .unwrap()
                        .unwrap_or(0);

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

                            let db = state.db.clone();
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
                            let db_fcm = state.db.clone();

                            // ИСПРАВЛЕНО: убрали кортеж
                            for fcm_tok in fcm_tokens {
                                let title = format!("{}", sender_display_name);
                                let body = content.chars().take(100).collect::<String>();
                                let data_payload =
                                    json!({ "sender": sender_display_name, "type": "private" });
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
                        let db = state.db.clone();
                        let uid = my_user_id.clone();
                        let gname = group_name.clone();
                        let is_member = tokio::task::spawn_blocking(move || {
                            let st = db.lock().unwrap();
                            let mut stmt = st.conn.prepare("SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE g.name = ? AND gm.user_id = ?").unwrap();
                            let mut rows = stmt.query(params![gname, uid]).unwrap();
                            rows.next().unwrap().is_some()
                        }).await.unwrap_or(false);

                        if !is_member {
                            let _ =
                                send_system_message(&tx, "[Система] Вы не состоите в этой группе")
                                    .await;
                            continue;
                        }

                        let db = state.db.clone();
                        let sender_id = my_user_id.clone();
                        let gname = group_name.clone();
                        let cnt = content.clone();
                        let stored_id: i64 = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::store_group_message(
                                &mut st.conn,
                                &gname,
                                &sender_id,
                                &cnt,
                                timestamp,
                                reply_opt,
                            )
                        })
                        .await
                        .unwrap()
                        .unwrap_or(0);

                        let db = state.db.clone();
                        let gname = group_name.clone();
                        let members = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::get_group_members(&mut st.conn, &gname)
                        })
                        .await
                        .unwrap()
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

                        for member_id in members {
                            if member_id == my_user_id {
                                continue;
                            }
                            let db = state.db.clone();
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
                                let db = state.db.clone();
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
                                let db_fcm = state.db.clone();

                                // ИСПРАВЛЕНО: убрали кортеж
                                for fcm_tok in fcm_tokens {
                                    let title = format!("Новое сообщение в группе {}", group_name);
                                    let body = format!(
                                        "{}: {}",
                                        sender_display_name,
                                        content.chars().take(100).collect::<String>()
                                    );
                                    let data_payload = json!({ "sender": sender_display_name, "group": group_name, "type": "group" });
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
                        let db = state.db.clone();
                        let uid = my_user_id.clone();
                        let ch = channel_name.clone();
                        let is_owner = tokio::task::spawn_blocking(move || {
                            let st = db.lock().unwrap();
                            let mut stmt = st
                                .conn
                                .prepare("SELECT 1 FROM channels WHERE name = ? AND creator_id = ?")
                                .unwrap();
                            let mut rows = stmt.query(params![ch, uid]).unwrap();
                            rows.next().unwrap().is_some()
                        })
                        .await
                        .unwrap_or(false);

                        if !is_owner {
                            let _ = send_system_message(
                                &tx,
                                "[Система] Только владелец канала может отправлять сообщения",
                            )
                            .await;
                            continue;
                        }

                        let db = state.db.clone();
                        let sender_id = my_user_id.clone();
                        let ch_name = channel_name.clone();
                        let cnt = content.clone();
                        let stored_id: i64 = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::store_channel_message(
                                &mut st.conn,
                                &ch_name,
                                &sender_id,
                                &cnt,
                                timestamp,
                                reply_opt,
                            )
                        })
                        .await
                        .unwrap()
                        .unwrap_or(0);

                        let db = state.db.clone();
                        let ch_name2 = channel_name.clone();
                        let subscribers = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::get_channel_subscribers(&mut st.conn, &ch_name2)
                        })
                        .await
                        .unwrap()
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
                            let db = state.db.clone();
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
                                let db = state.db.clone();
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
                                let db_fcm = state.db.clone();

                                // ИСПРАВЛЕНО: убрали кортеж
                                for fcm_tok in fcm_tokens {
                                    let title =
                                        format!("Новое сообщение в канале {}", channel_name);
                                    let body = content.chars().take(100).collect::<String>();
                                    let data_payload = json!({ "sender": sender_display_name, "channel": channel_name, "type": "channel" });
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
                            let db = state.db.clone();
                            let new_text_clone = new_text.clone();
                            let upd = tokio::task::spawn_blocking(move || {
                                let mut st = db.lock().unwrap();
                                AppState::update_personal_message_content(
                                    &mut st.conn,
                                    msg_id,
                                    &new_text_clone,
                                )
                            })
                            .await
                            .unwrap();

                            let (sender_id, recipient_id) = match upd {
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

                            let db = state.db.clone();
                            let mid = msg_id;
                            let extra = tokio::task::spawn_blocking(move || {
                                let st = db.lock().unwrap();
                                st.conn.query_row(
                                    "SELECT strftime('%s', sent_at) * 1000, reply_to_id, read_at FROM messages WHERE id = ?",
                                    [mid], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, Option<String>>(2)?))
                                ).ok()
                            }).await.unwrap();

                            let (ts, reply_opt, read_at) = match extra {
                                Some(v) => v,
                                None => continue,
                            };
                            let reply_id = reply_opt.unwrap_or(0);
                            let read_flag = read_at.is_some();

                            let db = state.db.clone();
                            let sid = sender_id.clone();
                            let rid = recipient_id.clone();
                            let (s_name, r_name) = tokio::task::spawn_blocking(move || {
                                let mut st = db.lock().unwrap();
                                (st.resolve_username(&sid), st.resolve_username(&rid))
                            })
                            .await
                            .unwrap();

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
                                let db = state.db.clone();
                                let rid2 = recipient_id.clone();
                                let mid2 = msg_id;
                                let hidden = tokio::task::spawn_blocking(move || {
                                    let st = db.lock().unwrap();
                                    st.conn.query_row("SELECT 1 FROM hidden_messages WHERE user_id = ? AND kind = 1 AND msg_id = ?", params![rid2, mid2], |_| Ok(())).is_ok()
                                }).await.unwrap();

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
                            let db = state.db.clone();
                            let new_text_clone = new_text.clone();
                            let upd = tokio::task::spawn_blocking(move || {
                                let mut st = db.lock().unwrap();
                                AppState::update_group_message_content(
                                    &mut st.conn,
                                    msg_id,
                                    &new_text_clone,
                                )
                            })
                            .await
                            .unwrap();

                            let sender_id = match upd {
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

                            let db = state.db.clone();
                            let mid = msg_id;
                            let extra = tokio::task::spawn_blocking(move || {
                                let st = db.lock().unwrap();
                                st.conn
                                    .query_row(
                                        "SELECT strftime('%s', gm.sent_at) * 1000, gm.reply_to_id, \
                                            gm.first_read_at, g.name \
                                     FROM group_messages gm \
                                     JOIN groups g ON gm.group_id = g.id \
                                     WHERE gm.id = ?",
                                        [mid],
                                        |row| {
                                            Ok((
                                                row.get::<_, i64>(0)?,
                                                row.get::<_, Option<i64>>(1)?,
                                                row.get::<_, Option<String>>(2)?,
                                                row.get::<_, String>(3)?,
                                            ))
                                        },
                                    )
                                    .ok()
                            })
                            .await
                            .unwrap();

                            let (ts, reply_opt, first_read_at, gname) = match extra {
                                Some(v) => v,
                                None => continue,
                            };
                            let reply_id = reply_opt.unwrap_or(0);
                            let flag_any = first_read_at.is_some();
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

                            let db = state.db.clone();
                            let gname2 = gname.clone();
                            let members = tokio::task::spawn_blocking(move || {
                                let mut st = db.lock().unwrap();
                                AppState::get_group_members(&mut st.conn, &gname2)
                            })
                            .await
                            .unwrap()
                            .unwrap_or_default();

                            for member_id in members {
                                if member_id == my_user_id {
                                    continue;
                                }
                                let db = state.db.clone();
                                let mid_c = member_id.clone();
                                let hidden = tokio::task::spawn_blocking(move || {
                                    let st = db.lock().unwrap();
                                    st.conn.query_row("SELECT 1 FROM hidden_messages WHERE user_id = ? AND kind = 2 AND msg_id = ?", params![mid_c, msg_id], |_| Ok(())).is_ok()
                                }).await.unwrap();
                                if hidden {
                                    continue;
                                }

                                let db = state.db.clone();
                                let mid_c = member_id.clone();
                                let member_name_opt = tokio::task::spawn_blocking(move || {
                                    let mut st = db.lock().unwrap();
                                    let name = st.resolve_username(&mid_c);
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
                            let db = state.db.clone();
                            let new_text_clone = new_text.clone();
                            let upd = tokio::task::spawn_blocking(move || {
                                let mut st = db.lock().unwrap();
                                AppState::update_channel_message_content(
                                    &mut st.conn,
                                    msg_id,
                                    &new_text_clone,
                                )
                            })
                            .await
                            .unwrap();

                            let (cname, creator_id, _sender_id) = match upd {
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

                            let db = state.db.clone();
                            let mid = msg_id;
                            let extra = tokio::task::spawn_blocking(move || {
                                let st = db.lock().unwrap();
                                st.conn
                                    .query_row(
                                        "SELECT strftime('%s', cm.sent_at) * 1000, cm.reply_to_id, \
                                            (SELECT COUNT(*) FROM channel_message_views v \
                                             WHERE v.channel_msg_id = cm.id) \
                                     FROM channel_messages cm WHERE cm.id = ?",
                                        [mid],
                                        |row| {
                                            Ok((
                                                row.get::<_, i64>(0)?,
                                                row.get::<_, Option<i64>>(1)?,
                                                row.get::<_, i64>(2).unwrap_or(0),
                                            ))
                                        },
                                    )
                                    .ok()
                            })
                            .await
                            .unwrap();

                            let (ts, reply_opt, views) = match extra {
                                Some(v) => v,
                                None => continue,
                            };
                            let reply_id = reply_opt.unwrap_or(0);
                            let views_u = views as u32;
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

                            let db = state.db.clone();
                            let cname2 = cname.clone();
                            let subscribers = tokio::task::spawn_blocking(move || {
                                let mut st = db.lock().unwrap();
                                AppState::get_channel_subscribers(&mut st.conn, &cname2)
                            })
                            .await
                            .unwrap()
                            .unwrap_or_default();

                            for sub_id in subscribers {
                                if sub_id == my_user_id {
                                    continue;
                                }
                                let db = state.db.clone();
                                let sid_c = sub_id.clone();
                                let hidden = tokio::task::spawn_blocking(move || {
                                    let st = db.lock().unwrap();
                                    st.conn.query_row("SELECT 1 FROM hidden_messages WHERE user_id = ? AND kind = 3 AND msg_id = ?", params![sid_c, msg_id], |_| Ok(())).is_ok()
                                }).await.unwrap();
                                if hidden {
                                    continue;
                                }

                                let db = state.db.clone();
                                let sid_c = sub_id.clone();
                                let sub_name_opt = tokio::task::spawn_blocking(move || {
                                    let mut st = db.lock().unwrap();
                                    let name = st.resolve_username(&sid_c);
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

                    // --- Личные ---
                    if !personal_ids.is_empty() {
                        let db = state.db.clone();
                        let me = my_user_id.clone();
                        let ids = personal_ids.clone();
                        let by_author = tokio::task::spawn_blocking(move || {
                            let st = db.lock().unwrap();
                            let mut map: std::collections::HashMap<String, Vec<i64>> = std::collections::HashMap::new();
                            for msg_id in ids {
                                let row: Option<(String, String)> = st.conn.query_row(
                                    "SELECT sender_id, recipient_id FROM messages WHERE id = ?",
                                    [msg_id], |row| Ok((row.get(0)?, row.get(1)?))
                                ).ok();
                                if let Some((sender_id, recipient_id)) = row {
                                    if recipient_id == me {
                                        let _ = st.conn.execute("UPDATE messages SET read_at = CURRENT_TIMESTAMP WHERE id = ? AND read_at IS NULL", [msg_id]);
                                        map.entry(sender_id).or_default().push(msg_id);
                                    }
                                }
                            }
                            map
                        }).await.unwrap();

                        for (author_id, ids) in by_author {
                            if author_id == my_user_id {
                                continue;
                            }
                            let author_name = {
                                let db = state.db.clone();
                                let aid = author_id.clone();
                                tokio::task::spawn_blocking(move || {
                                    let mut st = db.lock().unwrap();
                                    st.resolve_username(&aid)
                                })
                                .await
                                .unwrap()
                            };
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
                                    let _ = s.tx.send(Message::Binary(pkt.clone().into()));
                                }
                            }
                        }
                    }

                    // --- Группы ---
                    if !group_ids.is_empty() {
                        let db = state.db.clone();
                        let ids = group_ids.clone();
                        let by_group = tokio::task::spawn_blocking(move || {
                            let st = db.lock().unwrap();
                            let mut map: std::collections::HashMap<String, Vec<i64>> = std::collections::HashMap::new();
                            for msg_id in ids {
                                let gid: Option<String> = st.conn.query_row("SELECT group_id FROM group_messages WHERE id = ?", [msg_id], |row| row.get(0)).ok();
                                if let Some(gid) = gid {
                                    let _ = st.conn.execute("UPDATE group_messages SET first_read_at = CURRENT_TIMESTAMP WHERE id = ? AND first_read_at IS NULL", [msg_id]);
                                    map.entry(gid).or_default().push(msg_id);
                                }
                            }
                            map
                        }).await.unwrap();

                        for (group_id, ids) in by_group {
                            let db = state.db.clone();
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
                            let pkt = crate::senders::build_read_packet(&items);

                            for mid in members {
                                if mid == my_user_id {
                                    continue;
                                }
                                let name = {
                                    let db = state.db.clone();
                                    let m = mid.clone();
                                    tokio::task::spawn_blocking(move || {
                                        let mut st = db.lock().unwrap();
                                        st.resolve_username(&m)
                                    })
                                    .await
                                    .unwrap()
                                };
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
                                        let _ = s.tx.send(Message::Binary(pkt.clone().into()));
                                    }
                                }
                            }
                        }
                    }

                    // --- Каналы ---
                    if !channel_ids.is_empty() {
                        let db = state.db.clone();
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
                        }).await;
                    }
                }

                MSG_TYPE_DELETE => {
                    if rest.len() < 9 {
                        warn!("0x05: мало данных");
                        continue;
                    }
                    let msg_id = i64::from_be_bytes(rest[0..8].try_into().unwrap());
                    let kind = rest[8];

                    // ---- УДАЛЕНИЕ ЦЕЛОГО ЧАТА (msg_id == 0) ----
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
                                let db = state.db.clone();
                                let target_name = name.clone();
                                let peer_id_opt = tokio::task::spawn_blocking(move || {
                                    let mut st = db.lock().unwrap();
                                    st.resolve_id(&target_name)
                                })
                                .await
                                .unwrap();

                                if let Some(peer_id) = peer_id_opt {
                                    if dtype == MSG_DELETE_FOR_ME {
                                        let db = state.db.clone();
                                        let uid = my_user_id.clone();
                                        let pid = peer_id.clone();
                                        let _ = tokio::task::spawn_blocking(move || {
                                            let mut st = db.lock().unwrap();
                                            AppState::hide_personal_chat(&mut st.conn, &uid, &pid)
                                        })
                                        .await;
                                    } else {
                                        let db = state.db.clone();
                                        let uid = my_user_id.clone();
                                        let pid = peer_id.clone();
                                        let _ = tokio::task::spawn_blocking(move || {
                                            let mut st = db.lock().unwrap();
                                            AppState::delete_personal_chat(&mut st.conn, &uid, &pid)
                                        })
                                        .await;

                                        let pkt = build_delete_chat_packet(kind, &name, 0);
                                        send_to_user_sessions(&state, &my_username, pkt.clone())
                                            .await;
                                        send_to_user_sessions(&state, &name, pkt).await;
                                    }
                                }
                            }
                            MSG_KIND_GROUP => {
                                if dtype == MSG_DELETE_FOR_ME {
                                    let db = state.db.clone();
                                    let uid = my_user_id.clone();
                                    let gname = name.clone();
                                    let _ = tokio::task::spawn_blocking(move || {
                                        let mut st = db.lock().unwrap();
                                        AppState::leave_group(&mut st.conn, &gname, &uid)
                                    })
                                    .await;
                                } else {
                                    let db = state.db.clone();
                                    let uid = my_user_id.clone();
                                    let gname = name.clone();
                                    let del_res = tokio::task::spawn_blocking(move || {
                                        let mut st = db.lock().unwrap();
                                        AppState::delete_group(&mut st.conn, &gname, &uid)
                                    })
                                    .await
                                    .unwrap();

                                    match del_res {
                                        Ok(true) => {
                                            let pkt = build_delete_chat_packet(kind, &name, 0);
                                            let db = state.db.clone();
                                            let gname2 = name.clone();
                                            let members = tokio::task::spawn_blocking(move || {
                                                let mut st = db.lock().unwrap();
                                                AppState::get_group_members(&mut st.conn, &gname2)
                                            })
                                            .await
                                            .unwrap()
                                            .unwrap_or_default();

                                            for m_id in members {
                                                let db = state.db.clone();
                                                let m = m_id.clone();
                                                let m_name =
                                                    tokio::task::spawn_blocking(move || {
                                                        let mut st = db.lock().unwrap();
                                                        st.resolve_username(&m)
                                                    })
                                                    .await
                                                    .unwrap();
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
                                    let db = state.db.clone();
                                    let uid = my_user_id.clone();
                                    let cname = name.clone();
                                    let _ = tokio::task::spawn_blocking(move || {
                                        let mut st = db.lock().unwrap();
                                        AppState::unsubscribe_channel(&mut st.conn, &cname, &uid)
                                    })
                                    .await;
                                } else {
                                    let db = state.db.clone();
                                    let uid = my_user_id.clone();
                                    let cname = name.clone();
                                    let del_res = tokio::task::spawn_blocking(move || {
                                        let mut st = db.lock().unwrap();
                                        AppState::delete_channel(&mut st.conn, &cname, &uid)
                                    })
                                    .await
                                    .unwrap();

                                    match del_res {
                                        Ok(true) => {
                                            let pkt = build_delete_chat_packet(kind, &name, 0);
                                            let db = state.db.clone();
                                            let cname2 = name.clone();
                                            let subs = tokio::task::spawn_blocking(move || {
                                                let mut st = db.lock().unwrap();
                                                AppState::get_channel_subscribers(
                                                    &mut st.conn,
                                                    &cname2,
                                                )
                                            })
                                            .await
                                            .unwrap()
                                            .unwrap_or_default();

                                            for sub_id in subs {
                                                let db = state.db.clone();
                                                let s = sub_id.clone();
                                                let s_name =
                                                    tokio::task::spawn_blocking(move || {
                                                        let mut st = db.lock().unwrap();
                                                        st.resolve_username(&s)
                                                    })
                                                    .await
                                                    .unwrap();
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

                    // ---- УДАЛЕНИЕ ОДНОГО СООБЩЕНИЯ ----
                    let dtype = if rest.len() >= 10 { rest[9] } else { 0 };
                    if dtype == MSG_DELETE_FOR_ME {
                        let db = state.db.clone();
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
                        }
                        continue;
                    }

                    match kind {
                        MSG_KIND_PERSONAL => {
                            let db = state.db.clone();
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
                                    let db = state.db.clone();
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

                                    let pkt = crate::senders::build_delete_packet(
                                        msg_id,
                                        kind,
                                        MSG_DELETE_FOR_ALL,
                                    );
                                    let _ = tx.send(Message::Binary(pkt.clone().into()));

                                    if recipient_id != my_user_id {
                                        let db = state.db.clone();
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
                                                    let _ = ts
                                                        .tx
                                                        .send(Message::Binary(pkt.clone().into()));
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
                            let db = state.db.clone();
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
                                    let db = state.db.clone();
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

                                    let db = state.db.clone();
                                    let ch = channel_name.clone();
                                    let subs_ids = tokio::task::spawn_blocking(move || {
                                        let mut st = db.lock().unwrap();
                                        AppState::get_channel_subscribers(&mut st.conn, &ch)
                                    })
                                    .await
                                    .unwrap()
                                    .unwrap_or_default();

                                    let pkt = crate::senders::build_delete_packet(
                                        msg_id,
                                        kind,
                                        MSG_DELETE_FOR_ALL,
                                    );

                                    let sessions: Vec<Arc<Session>> =
                                        state.sessions.iter().map(|r| r.value().clone()).collect();
                                    for s in sessions {
                                        if let Some(uid) = s.user_id.get() {
                                            if subs_ids.contains(uid) {
                                                let _ =
                                                    s.tx.send(Message::Binary(pkt.clone().into()));
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

                        // --- Проверка пароля ---
                        if password.is_empty() {
                            let _ = send_system_message(&tx, "[Система] Неверный пароль").await;
                            continue;
                        }
                        let db = state.db.clone();
                        let uid = my_user_id.clone();
                        let pwd = password.to_string();
                        let pwd_check = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::verify_password_for_user(&mut st.conn, &uid, &pwd)
                        })
                        .await
                        .unwrap();

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

                        let db = state.db.clone();
                        let uid = my_user_id.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            let mut st = db.lock().unwrap();
                            AppState::soft_delete_account(&mut st, &uid)
                        })
                        .await
                        .unwrap();

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
                                let _ = s.tx.send(Message::Binary(pkt.clone().into()));
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

                    // Обычный logout (exit)
                    info!("Logout: EXIT, token={}", token);
                    let db = state.db.clone();
                    let tok = token.to_string();
                    let result = tokio::task::spawn_blocking(move || {
                        let mut st = db.lock().unwrap();
                        AppState::delete_session(&mut st.conn, &tok)
                    })
                    .await
                    .unwrap();

                    match result {
                        Ok(_) => {
                            state.sessions.remove(token);

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

                            session.connected.store(false, Ordering::Relaxed);
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

        if !token.is_empty() {
            state.sessions.remove(&token);
        }

        let msg = format!("[Система] Пользователь {} отключился", username);

        if !my_user_id.is_empty() {
            let db_ls = state.db.clone();
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
