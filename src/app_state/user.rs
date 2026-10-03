use bcrypt::{DEFAULT_COST, hash, verify};
use log::info;
use rusqlite::{Connection, params};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use super::core::{AppState, DbState};
use crate::constants::*;

impl AppState {
    // ---- Регистрация / логин ----
    pub fn register_user(
        st: &mut DbState,
        username: &str,
        phone: &str,
        password: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
    ) -> Result<String, String> {
        let password_hash =
            hash(password, DEFAULT_COST).map_err(|e| format!("Ошибка хеширования: {}", e))?;
        let user_id = Uuid::new_v4().to_string();
        let display_name = match (first_name, last_name) {
            (Some(f), Some(l)) => format!("{} {}", f, l),
            (Some(f), None) => f.to_string(),
            _ => username.to_string(),
        };
        let first_name_str = first_name.unwrap_or("");
        let last_name_str = last_name.unwrap_or("");
        st.conn.execute(
            "INSERT INTO users (id, username, phone, password_hash, first_name, last_name, display_name) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![user_id, username, phone, password_hash, first_name_str, last_name_str, display_name],
        ).map_err(|e| format!("Ошибка регистрации: {}", e))?;

        st.username_to_id
            .insert(username.to_string(), user_id.clone());
        st.id_to_username
            .insert(user_id.clone(), username.to_string());

        Ok(user_id)
    }

    pub fn login_user_by_phone(
        conn: &mut Connection,
        phone: &str,
        password: &str,
    ) -> Result<String, String> {
        let mut stmt = conn
            .prepare("SELECT id, password_hash FROM users WHERE phone = ?")
            .map_err(|e| format!("Ошибка запроса: {}", e))?;
        let mut rows = stmt
            .query([phone])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let user_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            let hash: String = row
                .get(1)
                .map_err(|e| format!("Ошибка чтения hash: {}", e))?;
            if verify(password, &hash).map_err(|e| format!("Ошибка проверки пароля: {}", e))?
            {
                return Ok(user_id);
            }
        }
        Err("Неверный телефон или пароль".to_string())
    }

    // ---- Сессии ----
    pub fn create_session(
        conn: &mut Connection,
        user_id: &str,
        device_name: &str,
    ) -> Result<String, String> {
        let token = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO sessions (token, user_id, device_name, last_seen) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            params![token, user_id, device_name],
        ).map_err(|e| format!("Ошибка создания сессии: {}", e))?;
        Ok(token)
    }

    pub fn check_session(conn: &mut Connection, token: &str) -> Result<(String, String), String> {
        let mut stmt = conn
            .prepare("SELECT user_id, username FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.token = ?")
            .map_err(|e| format!("Ошибка подготовки: {}", e))?;
        let mut rows = stmt
            .query([token])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let user_id: String = row
                .get(0)
                .map_err(|e| format!("Ошибка чтения user_id: {}", e))?;
            let username: String = row
                .get(1)
                .map_err(|e| format!("Ошибка чтения username: {}", e))?;
            conn.execute(
                "UPDATE sessions SET last_seen = CURRENT_TIMESTAMP WHERE token = ?",
                [token],
            )
            .map_err(|e| format!("Ошибка обновления last_seen: {}", e))?;
            Ok((user_id, username))
        } else {
            Err("Недействительный токен".to_string())
        }
    }

    pub fn delete_session(conn: &mut Connection, token: &str) -> Result<(), String> {
        conn.execute("DELETE FROM sessions WHERE token = ?", [token])
            .map_err(|e| format!("Ошибка удаления сессии: {}", e))?;
        Ok(())
    }

    // ---- FCM ----
    pub fn save_fcm_token(
        conn: &mut Connection,
        user_id: &str,
        session_token: &str,
        token: &str,
        device_name: &str,
    ) -> Result<(), String> {
        conn.execute("DELETE FROM fcm_tokens WHERE token = ?", params![token])
            .map_err(|e| format!("Ошибка очистки старого FCM-токена: {}", e))?;
        conn.execute(
            "INSERT INTO fcm_tokens (user_id, session_token, token, device_name) VALUES (?, ?, ?, ?)",
            params![user_id, session_token, token, device_name],
        ).map_err(|e| format!("Ошибка сохранения FCM-токена: {}", e))?;
        Ok(())
    }

    pub fn get_fcm_tokens_for_user(
        conn: &mut Connection,
        user_id: &str,
    ) -> Result<Vec<String>, String> {
        let mut stmt = conn
            .prepare("SELECT token FROM fcm_tokens WHERE user_id = ?")
            .map_err(|e| format!("Ошибка запроса FCM: {}", e))?;
        let mut rows = stmt
            .query([user_id])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        let mut tokens = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))?
        {
            let token: String = row
                .get(0)
                .map_err(|e| format!("Ошибка чтения токена: {}", e))?;
            tokens.push(token);
        }
        Ok(tokens)
    }

    pub fn delete_fcm_token(conn: &mut Connection, token: &str) -> Result<(), String> {
        let affected = conn
            .execute("DELETE FROM fcm_tokens WHERE token = ?", [token])
            .map_err(|e| format!("Ошибка удаления FCM-токена: {}", e))?;
        if affected > 0 {
            info!("FCM-токен удалён из БД: {}", token);
        }
        Ok(())
    }

    // ---- Профиль ----
    pub fn get_profile(
        conn: &mut Connection,
        user_id: &str,
    ) -> Result<(String, String, String, String, String), String> {
        let mut stmt = conn.prepare("SELECT username, phone, first_name, last_name, display_name FROM users WHERE id = ?")
            .map_err(|e| format!("Ошибка подготовки запроса: {}", e))?;
        let mut rows = stmt
            .query([user_id])
            .map_err(|e| format!("Ошибка выполнения запроса: {}", e))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| format!("Ошибка чтения результата: {}", e))?
        {
            Ok((
                row.get(0).map_err(|e| e.to_string())?,
                row.get(1).map_err(|e| e.to_string())?,
                row.get(2).map_err(|e| e.to_string())?,
                row.get(3).map_err(|e| e.to_string())?,
                row.get(4).map_err(|e| e.to_string())?,
            ))
        } else {
            Err("Пользователь не найден".to_string())
        }
    }

    pub fn set_name(
        conn: &mut Connection,
        user_id: &str,
        first_name: &str,
        last_name: &str,
    ) -> Result<(), String> {
        let display_name = if last_name.is_empty() {
            first_name.to_string()
        } else {
            format!("{} {}", first_name, last_name)
        };
        conn.execute(
            "UPDATE users SET first_name = ?, last_name = ?, display_name = ? WHERE id = ?",
            params![first_name, last_name, display_name, user_id],
        )
        .map_err(|e| format!("Ошибка обновления имени: {}", e))?;
        Ok(())
    }

    pub fn set_display_name(
        conn: &mut Connection,
        user_id: &str,
        display_name: &str,
    ) -> Result<(), String> {
        conn.execute(
            "UPDATE users SET display_name = ? WHERE id = ?",
            params![display_name, user_id],
        )
        .map_err(|e| format!("Ошибка обновления отображаемого имени: {}", e))?;
        Ok(())
    }

    pub fn set_username(
        st: &mut DbState,
        user_id: &str,
        new_username: &str,
    ) -> Result<String, String> {
        let mut stmt = st
            .conn
            .prepare("SELECT id FROM users WHERE username = ?")
            .map_err(|e| format!("Ошибка подготовки запроса: {}", e))?;
        let mut rows = stmt
            .query([new_username])
            .map_err(|e| format!("Ошибка выполнения запроса: {}", e))?;
        if rows
            .next()
            .map_err(|e| format!("Ошибка чтения: {}", e))?
            .is_some()
        {
            return Err("Username уже занят".to_string());
        }

        let old_username: String = st
            .conn
            .query_row(
                "SELECT username FROM users WHERE id = ?",
                [user_id],
                |row| row.get(0),
            )
            .map_err(|_| "Пользователь не найден".to_string())?;

        st.conn
            .execute(
                "UPDATE users SET username = ? WHERE id = ?",
                params![new_username, user_id],
            )
            .map_err(|e| format!("Ошибка обновления username: {}", e))?;

        st.username_to_id.remove(&old_username);
        st.username_to_id
            .insert(new_username.to_string(), user_id.to_string());
        st.id_to_username
            .insert(user_id.to_string(), new_username.to_string());

        Ok(old_username)
    }

    pub fn update_last_seen(conn: &mut Connection, user_id: &str) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis() as i64;
        conn.execute(
            "UPDATE users SET last_seen = ? WHERE id = ?",
            params![now, user_id],
        )
        .map_err(|e| format!("Ошибка обновления last_seen: {}", e))?;
        Ok(())
    }

    pub fn get_display_name(conn: &mut Connection, user_id: &str) -> Result<String, String> {
        conn.query_row(
            "SELECT display_name FROM users WHERE id = ?",
            [user_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(|e| e.to_string())
    }

    // ---- Личные сообщения ----
    pub fn store_message(
        conn: &mut Connection,
        sender_id: &str,
        recipient_id: &str,
        content: &str,
        timestamp: i64,
        reply_to_id: Option<i64>,
    ) -> Result<i64, String> {
        conn.execute(
            "INSERT INTO messages (sender_id, recipient_id, content, sent_at, reply_to_id) \
             VALUES (?, ?, ?, datetime(?/1000, 'unixepoch'), ?)",
            params![sender_id, recipient_id, content, &timestamp, reply_to_id],
        )
        .map_err(|e| format!("Ошибка сохранения сообщения: {}", e))?;
        Ok(conn.last_insert_rowid())
    }

    /// (msg_id, sender_id, recipient_id, content, ts, reply_to_id, flag_me, flag_any).
    pub fn get_recent_personal(
        conn: &mut Connection,
        user_id: &str,
        per_chat: i64,
    ) -> Result<Vec<(i64, String, String, String, i64, Option<i64>, bool, bool)>, String> {
        let mut stmt = conn
            .prepare(
                "WITH ranked AS (
                    SELECT m.id, m.sender_id, m.recipient_id, m.content,
                           strftime('%s', m.sent_at) * 1000 AS ts,
                           m.reply_to_id, m.read_at,
                           ROW_NUMBER() OVER (
                               PARTITION BY CASE WHEN m.sender_id = ?1 THEN m.recipient_id
                                                 ELSE m.sender_id END
                               ORDER BY m.id DESC
                           ) AS rn
                    FROM messages m
                    LEFT JOIN hidden_messages h
                           ON h.kind = 1 AND h.msg_id = m.id AND h.user_id = ?1
                    WHERE (m.sender_id = ?1 OR m.recipient_id = ?1)
                      AND h.msg_id IS NULL
                )
                SELECT id, sender_id, recipient_id, content, ts, reply_to_id, read_at
                FROM ranked
                WHERE rn <= ?2
                ORDER BY id ASC",
            )
            .map_err(|e| e.to_string())?;
        let iter = stmt
            .query_map(params![user_id, per_chat], |row| {
                let sender_id: String = row.get(1)?;
                let read_at: Option<String> = row.get(6)?;
                let is_sender = sender_id == user_id;
                let read_flag = read_at.is_some();
                let flag_me = if is_sender { true } else { read_flag };
                let flag_any = if is_sender { read_flag } else { true };
                Ok((
                    row.get::<_, i64>(0)?,
                    sender_id,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    flag_me,
                    flag_any,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in iter {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn lookup_personal_message(
        conn: &mut Connection,
        msg_id: i64,
    ) -> Result<Option<(String, String)>, String> {
        let mut stmt = conn
            .prepare("SELECT sender_id, recipient_id FROM messages WHERE id = ?")
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query([msg_id]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            Ok(Some((
                row.get(0).map_err(|e| e.to_string())?,
                row.get(1).map_err(|e| e.to_string())?,
            )))
        } else {
            Ok(None)
        }
    }

    pub fn delete_message(conn: &mut Connection, msg_id: i64) -> Result<(), String> {
        conn.execute("DELETE FROM messages WHERE id = ?", [msg_id])
            .map_err(|e| format!("Ошибка удаления: {}", e))?;
        Ok(())
    }

    pub fn hide_message(
        conn: &mut Connection,
        user_id: &str,
        kind: u8,
        msg_id: i64,
    ) -> Result<(), String> {
        conn.execute(
            "INSERT OR IGNORE INTO hidden_messages (user_id, kind, msg_id) VALUES (?, ?, ?)",
            params![user_id, kind as i64, msg_id],
        )
        .map_err(|e| format!("Ошибка скрытия: {}", e))?;
        Ok(())
    }

    /// Точечная выборка сообщений по списку id (для /getmsg).
    pub fn get_messages_by_ids(
        st: &mut DbState,
        kind: u8,
        ids: &[i64],
        user_id: &str,
    ) -> Result<
        Vec<(
            i64,
            String,
            String,
            String,
            i64,
            Option<i64>,
            bool,
            bool,
            Option<u32>,
        )>,
        String,
    > {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let mut out = Vec::new();

        match kind {
            MSG_KIND_PERSONAL => {
                let sql = format!(
                    "SELECT m.id, m.sender_id, m.recipient_id, m.content, \
                            strftime('%s', m.sent_at) * 1000, m.reply_to_id, m.read_at \
                     FROM messages m \
                     LEFT JOIN hidden_messages h \
                            ON h.kind = 1 AND h.msg_id = m.id AND h.user_id = ? \
                     WHERE m.id IN ({}) \
                       AND (m.sender_id = ? OR m.recipient_id = ?) \
                       AND h.msg_id IS NULL",
                    placeholders
                );

                let raw: Vec<(
                    i64,
                    String,
                    String,
                    String,
                    i64,
                    Option<i64>,
                    Option<String>,
                )> = {
                    let mut stmt = st.conn.prepare(&sql).map_err(|e| e.to_string())?;
                    let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();
                    params_vec.push(rusqlite::types::Value::Text(user_id.to_string()));
                    for id in ids {
                        params_vec.push(rusqlite::types::Value::Integer(*id));
                    }
                    params_vec.push(rusqlite::types::Value::Text(user_id.to_string()));
                    params_vec.push(rusqlite::types::Value::Text(user_id.to_string()));
                    let iter = stmt
                        .query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
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

                for (id, sender_id, recipient_id, content, ts, reply_id, read_at) in raw {
                    let sender = st.resolve_username(&sender_id);
                    let recipient = st.resolve_username(&recipient_id);
                    let is_sender = sender_id == user_id;
                    let read_flag = read_at.is_some();
                    let flag_me = if is_sender { true } else { read_flag };
                    let flag_any = if is_sender { read_flag } else { true };
                    out.push((
                        id, sender, recipient, content, ts, reply_id, flag_me, flag_any, None,
                    ));
                }
            }
            MSG_KIND_GROUP => {
                let sql = format!(
                    "SELECT gm.id, g.name, gm.sender_id, gm.content, \
                            strftime('%s', gm.sent_at) * 1000, gm.reply_to_id, gm.first_read_at \
                     FROM group_messages gm \
                     JOIN groups g ON gm.group_id = g.id \
                     JOIN group_members gmem ON gmem.group_id = g.id AND gmem.user_id = ? \
                     LEFT JOIN hidden_messages h \
                            ON h.kind = 2 AND h.msg_id = gm.id AND h.user_id = ? \
                     WHERE gm.id IN ({}) AND h.msg_id IS NULL",
                    placeholders
                );

                let raw: Vec<(
                    i64,
                    String,
                    String,
                    String,
                    i64,
                    Option<i64>,
                    Option<String>,
                )> = {
                    let mut stmt = st.conn.prepare(&sql).map_err(|e| e.to_string())?;
                    let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();
                    params_vec.push(rusqlite::types::Value::Text(user_id.to_string()));
                    params_vec.push(rusqlite::types::Value::Text(user_id.to_string()));
                    for id in ids {
                        params_vec.push(rusqlite::types::Value::Integer(*id));
                    }
                    let iter = stmt
                        .query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
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

                for (id, gname, sender_id, content, ts, reply_id, first_read_at) in raw {
                    let sender = st.resolve_username(&sender_id);
                    let recipient = format!("#{}", gname);
                    let is_sender = sender_id == user_id;
                    let flag_me = is_sender;
                    let flag_any = first_read_at.is_some();
                    out.push((
                        id, sender, recipient, content, ts, reply_id, flag_me, flag_any, None,
                    ));
                }
            }
            MSG_KIND_CHANNEL => {
                let sql = format!(
                    "SELECT cm.id, c.name, cm.sender_id, cm.content, \
                            strftime('%s', cm.sent_at) * 1000, cm.reply_to_id, \
                            (SELECT COUNT(*) FROM channel_message_views v WHERE v.channel_msg_id = cm.id) \
                     FROM channel_messages cm \
                     JOIN channels c ON cm.channel_id = c.id \
                     JOIN channel_subscribers cs ON cs.channel_id = c.id AND cs.user_id = ? \
                     LEFT JOIN hidden_messages h \
                            ON h.kind = 3 AND h.msg_id = cm.id AND h.user_id = ? \
                     WHERE cm.id IN ({}) AND h.msg_id IS NULL",
                    placeholders
                );

                let raw: Vec<(i64, String, String, String, i64, Option<i64>, i64)> = {
                    let mut stmt = st.conn.prepare(&sql).map_err(|e| e.to_string())?;
                    let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();
                    params_vec.push(rusqlite::types::Value::Text(user_id.to_string()));
                    params_vec.push(rusqlite::types::Value::Text(user_id.to_string()));
                    for id in ids {
                        params_vec.push(rusqlite::types::Value::Integer(*id));
                    }
                    let iter = stmt
                        .query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, String>(3)?,
                                row.get::<_, i64>(4)?,
                                row.get::<_, Option<i64>>(5)?,
                                row.get::<_, i64>(6).unwrap_or(0),
                            ))
                        })
                        .map_err(|e| e.to_string())?;
                    let mut v = Vec::new();
                    for r in iter {
                        v.push(r.map_err(|e| e.to_string())?);
                    }
                    v
                };

                for (id, cname, sender_id, content, ts, reply_id, views) in raw {
                    let sender = st.resolve_username(&sender_id);
                    let recipient = format!("&{}", cname);
                    let v = views as u32;
                    out.push((
                        id,
                        sender,
                        recipient,
                        content,
                        ts,
                        reply_id,
                        true,
                        v > 0,
                        Some(v),
                    ));
                }
            }
            _ => return Err(format!("Неизвестный kind: {}", kind)),
        }

        Ok(out)
    }
}
