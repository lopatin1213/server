use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::TimeZone;
use deadpool_postgres::Pool;
use log::info;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use super::core::AppState;
use crate::constants::*;

impl AppState {
    pub async fn is_user_banned(&self, user_id: &str) -> Result<Option<String>, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client.query_opt(
            "SELECT reason, expires_at FROM bans WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
            &[&user_id],
        ).await.map_err(|e| e.to_string())?;

        if let Some(row) = row_opt {
            let reason: String = row.get(0);
            let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.get(1);
            if let Some(exp) = expires_at {
                if exp > chrono::Utc::now() {
                    return Ok(Some(reason));
                }
            } else {
                return Ok(Some(reason));
            }
        }
        Ok(None)
    }

    pub async fn register_user(
        &self,
        username: &str,
        phone: &str,
        password: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        phone_hash: Option<&str>,
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

        let final_phone_hash = match phone_hash {
            Some(h) => h.to_string(),
            None => AppState::compute_phone_hash(phone),
        };

        let mut client = self.db.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;

        tx.execute(
            "INSERT INTO users (id, username, phone, password_hash, first_name, last_name, display_name, phone_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[&user_id, &username, &phone, &password_hash, &first_name_str, &last_name_str, &display_name, &final_phone_hash],
        ).await.map_err(|e| format!("Ошибка регистрации: {}", e))?;

        tx.execute(
            "INSERT INTO user_settings (user_id) VALUES ($1)",
            &[&user_id],
        )
        .await
        .map_err(|e| format!("Ошибка создания настроек: {}", e))?;

        tx.commit().await.map_err(|e| e.to_string())?;

        self.username_to_id
            .insert(username.to_string(), user_id.clone());
        self.id_to_username
            .insert(user_id.clone(), username.to_string());

        Ok(user_id)
    }

    pub async fn login_user_by_phone(&self, phone: &str, password: &str) -> Result<String, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt(
                "SELECT id, password_hash FROM users WHERE phone = $1",
                &[&phone],
            )
            .await
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = row_opt {
            let user_id: String = row.get(0);
            let hash: String = row.get(1);
            if verify(password, &hash).map_err(|e| format!("Ошибка проверки пароля: {}", e))?
            {
                return Ok(user_id);
            }
        }
        Err("Неверный телефон или пароль".to_string())
    }

    pub async fn sync_contacts(&self, user_id: &str, hashes: &[String]) -> Result<(), String> {
        if hashes.is_empty() {
            return Ok(());
        }
        let client = self.db.get().await.map_err(|e| e.to_string())?;

        let rows = client
            .query(
                "SELECT id FROM users WHERE phone_hash = ANY($1)",
                &[&hashes],
            )
            .await
            .map_err(|e| format!("Ошибка поиска контактов: {}", e))?;

        let mut client = self.db.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;

        for row in rows {
            let contact_id: String = row.get(0);
            if contact_id != user_id {
                let _ = tx.execute(
                    "INSERT INTO user_contacts (owner_id, contact_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    &[&user_id, &contact_id],
                ).await;
            }
        }
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn add_contact(&self, user_id: &str, target_username: &str) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let target_id: String = client
            .query_one(
                "SELECT id FROM users WHERE username = $1",
                &[&target_username],
            )
            .await
            .map_err(|_| "Пользователь не найден".to_string())?
            .get(0);

        if user_id == target_id {
            return Err("Нельзя добавить себя".to_string());
        }

        client.execute(
            "INSERT INTO user_contacts (owner_id, contact_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&user_id, &target_id],
        ).await.map_err(|e| format!("Ошибка добавления контакта: {}", e))?;
        Ok(())
    }

    pub async fn get_contacts(&self, user_id: &str) -> Result<Vec<String>, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let rows = client
            .query(
                "SELECT u.phone, u.username, COALESCE(u.display_name, ''), COALESCE(u.last_seen, 0)
             FROM users u JOIN user_contacts c ON u.id = c.contact_id
             WHERE c.owner_id = $1 ORDER BY u.username",
                &[&user_id],
            )
            .await
            .map_err(|e| e.to_string())?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let phone: String = r.get(0);
                let username: String = r.get(1);
                let display: String = r.get(2);
                let last_seen: i64 = r.get(3);
                format!("{}|{}|{}|{}", phone, username, display, last_seen)
            })
            .collect())
    }

    pub async fn create_session(&self, user_id: &str, device_name: &str) -> Result<String, String> {
        let token = Uuid::new_v4().to_string();
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        client.execute("INSERT INTO sessions (token, user_id, device_name, last_seen) VALUES ($1, $2, $3, CURRENT_TIMESTAMP)", &[&token, &user_id, &device_name]).await.map_err(|e| format!("Ошибка создания сессии: {}", e))?;
        Ok(token)
    }

    pub async fn check_session(&self, token: &str) -> Result<(String, String), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client.query_opt("SELECT user_id, username FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.token = $1", &[&token]).await.map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = row_opt {
            let user_id: String = row.get(0);
            let username: String = row.get(1);
            client
                .execute(
                    "UPDATE sessions SET last_seen = CURRENT_TIMESTAMP WHERE token = $1",
                    &[&token],
                )
                .await
                .map_err(|e| format!("Ошибка обновления last_seen: {}", e))?;
            Ok((user_id, username))
        } else {
            Err("Недействительный токен".to_string())
        }
    }

    pub async fn delete_session(&self, token: &str) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        client
            .execute("DELETE FROM sessions WHERE token = $1", &[&token])
            .await
            .map_err(|e| format!("Ошибка удаления сессии: {}", e))?;
        Ok(())
    }

    pub async fn get_user_sessions(
        &self,
        user_id: &str,
    ) -> Result<Vec<(String, String, i64)>, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let rows = client.query("SELECT token, device_name, (EXTRACT(EPOCH FROM last_seen) * 1000)::bigint FROM sessions WHERE user_id = $1 ORDER BY last_seen DESC", &[&user_id]).await.map_err(|e| e.to_string())?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let token: String = r.get(0);
                let device: String = r
                    .get::<_, Option<String>>(1)
                    .unwrap_or_else(|| "Unknown".to_string());
                let last_seen: i64 = r.get::<_, Option<i64>>(2).unwrap_or(0);
                (token, device, last_seen)
            })
            .collect())
    }

    pub async fn save_fcm_token(
        &self,
        user_id: &str,
        session_token: &str,
        token: &str,
        device_name: &str,
    ) -> Result<(), String> {
        let token = token.trim();
        if token.is_empty() {
            return Ok(());
        }
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let existing_opt = client
            .query_opt("SELECT user_id FROM fcm_tokens WHERE token = $1", &[&token])
            .await
            .map_err(|e| e.to_string())?;
        let existing: Option<String> = existing_opt.map(|r| r.get(0));
        if existing.as_deref() == Some(user_id) {
            client
                .execute(
                    "UPDATE fcm_tokens SET session_token = $1, device_name = $2 WHERE token = $3",
                    &[&session_token, &device_name, &token],
                )
                .await
                .map_err(|e| format!("Ошибка обновления FCM-токена: {}", e))?;
            return Ok(());
        }
        client
            .execute("DELETE FROM fcm_tokens WHERE token = $1", &[&token])
            .await
            .map_err(|e| format!("Ошибка очистки старого FCM-токена: {}", e))?;
        let dev = if device_name.is_empty() {
            "unknown"
        } else {
            device_name
        };
        client.execute("INSERT INTO fcm_tokens (user_id, session_token, token, device_name) VALUES ($1, $2, $3, $4)", &[&user_id, &session_token, &token, &dev]).await.map_err(|e| format!("Ошибка сохранения FCM-токена: {}", e))?;
        Ok(())
    }

    pub async fn get_fcm_tokens_for_user(&self, user_id: &str) -> Result<Vec<String>, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let rows = client
            .query(
                "SELECT token FROM fcm_tokens WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }

    pub async fn delete_fcm_token(&self, token: &str) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        client
            .execute("DELETE FROM fcm_tokens WHERE token = $1", &[&token])
            .await
            .map_err(|e| format!("Ошибка удаления FCM-токена: {}", e))?;
        Ok(())
    }

    pub async fn get_profile(
        &self,
        user_id: &str,
    ) -> Result<(String, String, String, String, String, String), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client.query_opt("SELECT username, phone, COALESCE(first_name, ''), COALESCE(last_name, ''), COALESCE(display_name, ''), COALESCE(bio, '') FROM users WHERE id = $1", &[&user_id]).await.map_err(|e| format!("Ошибка выполнения запроса: {}", e))?;
        if let Some(row) = row_opt {
            Ok((
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
            ))
        } else {
            Err("Пользователь не найден".to_string())
        }
    }

    pub async fn update_profile(
        &self,
        user_id: &str,
        first_name: &str,
        last_name: &str,
        display_name: &str,
        username: &str,
        bio: &str,
    ) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let old_username: String = client
            .query_one("SELECT username FROM users WHERE id = $1", &[&user_id])
            .await
            .map_err(|_| "Пользователь не найден".to_string())?
            .get(0);
        if old_username != username {
            let exists = client
                .query_opt("SELECT id FROM users WHERE username = $1", &[&username])
                .await
                .map_err(|e| e.to_string())?;
            if exists.is_some() {
                return Err("Username уже занят".to_string());
            }
            self.username_to_id.remove(&old_username);
            self.username_to_id
                .insert(username.to_string(), user_id.to_string());
            self.id_to_username
                .insert(user_id.to_string(), username.to_string());
        }
        let final_display_name = if display_name.trim().is_empty() {
            username
        } else {
            display_name
        };
        client.execute("UPDATE users SET first_name = $1, last_name = $2, display_name = $3, username = $4, bio = $5 WHERE id = $6", &[&first_name, &last_name, &final_display_name, &username, &bio, &user_id]).await.map_err(|e| format!("Ошибка обновления профиля: {}", e))?;
        Ok(())
    }

    pub async fn update_password(&self, user_id: &str, new_password: &str) -> Result<(), String> {
        let new_hash =
            hash(new_password, DEFAULT_COST).map_err(|e| format!("Ошибка хеширования: {}", e))?;
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        client
            .execute(
                "UPDATE users SET password_hash = $1 WHERE id = $2",
                &[&new_hash, &user_id],
            )
            .await
            .map_err(|e| format!("Ошибка обновления пароля: {}", e))?;
        Ok(())
    }

    pub async fn get_user_settings(&self, user_id: &str) -> Result<(bool, i16), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row = client
            .query_opt(
                "SELECT hide_phone, last_seen_privacy FROM user_settings WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        match row {
            Some(r) => Ok((r.get(0), r.get(1))),
            None => Ok((false, 0)),
        }
    }

    pub async fn update_user_settings(
        &self,
        user_id: &str,
        hide_phone: bool,
        last_seen_privacy: i16,
    ) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        client.execute("INSERT INTO user_settings (user_id, hide_phone, last_seen_privacy) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO UPDATE SET hide_phone = $2, last_seen_privacy = $3", &[&user_id, &hide_phone, &last_seen_privacy]).await.map_err(|e| format!("Ошибка обновления настроек: {}", e))?;
        Ok(())
    }

    pub async fn update_last_seen(&self, user_id: &str) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis() as i64;
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        client
            .execute(
                "UPDATE users SET last_seen = $1 WHERE id = $2",
                &[&now, &user_id],
            )
            .await
            .map_err(|e| format!("Ошибка обновления last_seen: {}", e))?;
        Ok(())
    }

    pub async fn get_display_name(&self, user_id: &str) -> Result<String, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row = client
            .query_one("SELECT display_name FROM users WHERE id = $1", &[&user_id])
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.get(0))
    }

    pub async fn verify_password_for_user(
        &self,
        user_id: &str,
        password: &str,
    ) -> Result<bool, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row = client
            .query_one("SELECT password_hash FROM users WHERE id = $1", &[&user_id])
            .await
            .map_err(|_| "Пользователь не найден".to_string())?;
        let hash: String = row.get(0);
        verify(password, &hash).map_err(|e| format!("Ошибка проверки пароля: {}", e))
    }

    pub async fn store_message(
        &self,
        sender_id: &str,
        recipient_id: &str,
        content: &str,
        timestamp: i64,
        reply_to_id: Option<i64>,
    ) -> Result<i64, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let dt = chrono::Utc.timestamp_millis_opt(timestamp).unwrap();
        let row = client.query_one("INSERT INTO messages (sender_id, recipient_id, content, sent_at, reply_to_id) VALUES ($1, $2, $3, $4, $5) RETURNING id", &[&sender_id, &recipient_id, &content, &dt, &reply_to_id]).await.map_err(|e| format!("Ошибка сохранения сообщения: {}", e))?;
        Ok(row.get(0))
    }

    pub async fn get_recent_personal(
        &self,
        user_id: &str,
        per_chat: i64,
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
            bool,
        )>,
        String,
    > {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let stmt = client.prepare_cached("WITH ranked AS (SELECT m.id, m.sender_id, m.recipient_id, m.content, (EXTRACT(EPOCH FROM m.sent_at) * 1000)::bigint AS ts, m.reply_to_id, m.read_at, m.edited, ROW_NUMBER() OVER (PARTITION BY CASE WHEN m.sender_id = $1 THEN m.recipient_id ELSE m.sender_id END ORDER BY m.id DESC) AS rn FROM messages m LEFT JOIN hidden_messages h ON h.kind = 1 AND h.msg_id = m.id AND h.user_id = $1 WHERE (m.sender_id = $1 OR m.recipient_id = $1) AND h.msg_id IS NULL) SELECT id, sender_id, recipient_id, content, ts, reply_to_id, read_at, edited FROM ranked WHERE rn <= $2 ORDER BY id ASC").await.map_err(|e| e.to_string())?;
        let rows = client
            .query(&stmt, &[&user_id, &per_chat])
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let sender_id: String = row.get(1);
            let read_at: Option<chrono::DateTime<chrono::Utc>> = row.get(6);
            let is_sender = sender_id == user_id;
            let read_flag = read_at.is_some();
            out.push((
                row.get(0),
                sender_id,
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
                if is_sender { true } else { read_flag },
                if is_sender { read_flag } else { true },
                row.get(7),
            ));
        }
        Ok(out)
    }

    pub async fn lookup_personal_message(
        &self,
        msg_id: i64,
    ) -> Result<Option<(String, String)>, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt(
                "SELECT sender_id, recipient_id FROM messages WHERE id = $1",
                &[&msg_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        if let Some(row) = row_opt {
            Ok(Some((row.get(0), row.get(1))))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_message(&self, msg_id: i64) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        client
            .execute("DELETE FROM messages WHERE id = $1", &[&msg_id])
            .await
            .map_err(|e| format!("Ошибка удаления: {}", e))?;
        Ok(())
    }

    pub async fn delete_personal_chat(&self, user_id1: &str, user_id2: &str) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        client.execute("DELETE FROM messages WHERE (sender_id = $1 AND recipient_id = $2) OR (sender_id = $2 AND recipient_id = $1)", &[&user_id1, &user_id2]).await.map_err(|e| format!("Ошибка удаления личного чата: {}", e))?;
        Ok(())
    }

    pub async fn hide_personal_chat(&self, user_id: &str, peer_id: &str) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        client.execute("INSERT INTO hidden_messages (user_id, kind, msg_id) SELECT $1, 1, id FROM messages WHERE (sender_id = $1 AND recipient_id = $2) OR (sender_id = $2 AND recipient_id = $1) ON CONFLICT DO NOTHING", &[&user_id, &peer_id]).await.map_err(|e| format!("Ошибка скрытия личного чата: {}", e))?;
        Ok(())
    }

    pub async fn update_personal_message_content(
        &self,
        msg_id: i64,
        new_text: &str,
    ) -> Result<Option<(String, String)>, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client.query_opt("UPDATE messages SET content = $1, edited = true WHERE id = $2 RETURNING sender_id, recipient_id", &[&new_text, &msg_id]).await.map_err(|e| format!("Ошибка обновления сообщения: {}", e))?;
        if let Some(row) = row_opt {
            Ok(Some((row.get(0), row.get(1))))
        } else {
            Ok(None)
        }
    }

    pub async fn hide_message(&self, user_id: &str, kind: u8, msg_id: i64) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        client.execute("INSERT INTO hidden_messages (user_id, kind, msg_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", &[&user_id, &(kind as i32), &msg_id]).await.map_err(|e| format!("Ошибка скрытия: {}", e))?;
        Ok(())
    }

    pub async fn get_messages_by_ids(
        &self,
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
            bool,
        )>,
        String,
    > {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        match kind {
            MSG_KIND_PERSONAL => {
                let rows = client.query("SELECT m.id, m.sender_id, m.recipient_id, m.content, (EXTRACT(EPOCH FROM m.sent_at) * 1000)::bigint, m.reply_to_id, m.read_at, m.edited FROM messages m LEFT JOIN hidden_messages h ON h.kind = 1 AND h.msg_id = m.id AND h.user_id = $1 WHERE m.id = ANY($2) AND (m.sender_id = $1 OR m.recipient_id = $1) AND h.msg_id IS NULL", &[&user_id, &ids]).await.map_err(|e| e.to_string())?;
                for row in rows {
                    let sender_id: String = row.get(1);
                    let recipient_id: String = row.get(2);
                    let read_at: Option<chrono::DateTime<chrono::Utc>> = row.get(6);
                    let is_sender = sender_id == user_id;
                    let read_flag = read_at.is_some();
                    out.push((
                        row.get(0),
                        self.resolve_username(&sender_id).await,
                        self.resolve_username(&recipient_id).await,
                        row.get(3),
                        row.get(4),
                        row.get(5),
                        if is_sender { true } else { read_flag },
                        if is_sender { read_flag } else { true },
                        None,
                        row.get(7),
                    ));
                }
            }
            MSG_KIND_GROUP => {
                let rows = client.query("SELECT gm.id, g.name, gm.sender_id, gm.content, (EXTRACT(EPOCH FROM gm.sent_at) * 1000)::bigint, gm.reply_to_id, gm.first_read_at, gm.edited FROM group_messages gm JOIN groups g ON gm.group_id = g.id JOIN group_members gmem ON gmem.group_id = g.id AND gmem.user_id = $1 LEFT JOIN hidden_messages h ON h.kind = 2 AND h.msg_id = gm.id AND h.user_id = $1 WHERE gm.id = ANY($2) AND h.msg_id IS NULL", &[&user_id, &ids]).await.map_err(|e| e.to_string())?;
                for row in rows {
                    let sender_id: String = row.get(2);
                    let is_sender = sender_id == user_id;
                    let first_read_at: Option<chrono::DateTime<chrono::Utc>> = row.get(6);
                    out.push((
                        row.get(0),
                        self.resolve_username(&sender_id).await,
                        format!("#{}", row.get::<_, String>(1)),
                        row.get(3),
                        row.get(4),
                        row.get(5),
                        is_sender,
                        first_read_at.is_some(),
                        None,
                        row.get(7),
                    ));
                }
            }
            MSG_KIND_CHANNEL => {
                let rows = client.query("SELECT cm.id, c.name, cm.sender_id, cm.content, (EXTRACT(EPOCH FROM cm.sent_at) * 1000)::bigint, cm.reply_to_id, (SELECT COUNT(*) FROM channel_message_views v WHERE v.channel_msg_id = cm.id), cm.edited FROM channel_messages cm JOIN channels c ON cm.channel_id = c.id JOIN channel_subscribers cs ON cs.channel_id = c.id AND cs.user_id = $1 LEFT JOIN hidden_messages h ON h.kind = 3 AND h.msg_id = cm.id AND h.user_id = $1 WHERE cm.id = ANY($2) AND h.msg_id IS NULL", &[&user_id, &ids]).await.map_err(|e| e.to_string())?;
                for row in rows {
                    let sender_id: String = row.get(2);
                    let views: i64 = row.get(6);
                    out.push((
                        row.get(0),
                        self.resolve_username(&sender_id).await,
                        format!("&{}", row.get::<_, String>(1)),
                        row.get(3),
                        row.get(4),
                        row.get(5),
                        true,
                        views > 0,
                        Some(views as u32),
                        row.get(7),
                    ));
                }
            }
            _ => return Err(format!("Неизвестный kind: {}", kind)),
        }
        Ok(out)
    }

    pub async fn soft_delete_account(&self, user_id: &str) -> Result<Vec<String>, String> {
        let now: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs() as i64;
        let expire = now + crate::constants::DELETE_GRACE_PERIOD_SECS;
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let rows = client
            .query("SELECT token FROM sessions WHERE user_id = $1", &[&user_id])
            .await
            .map_err(|e| e.to_string())?;
        let tokens: Vec<String> = rows.into_iter().map(|r| r.get(0)).collect();
        client
            .execute(
                "UPDATE messages SET sender_id = $1, delete_at = $2 WHERE sender_id = $3",
                &[&crate::constants::DELETED_LABEL, &expire, &user_id],
            )
            .await
            .map_err(|e| format!("messages sender: {}", e))?;
        client
            .execute(
                "UPDATE messages SET recipient_id = $1, delete_at = $2 WHERE recipient_id = $3",
                &[&crate::constants::DELETED_LABEL, &expire, &user_id],
            )
            .await
            .map_err(|e| format!("messages recipient: {}", e))?;
        client
            .execute(
                "UPDATE group_messages SET sender_id = $1, delete_at = $2 WHERE sender_id = $3",
                &[&crate::constants::DELETED_LABEL, &expire, &user_id],
            )
            .await
            .map_err(|e| format!("group_messages: {}", e))?;
        client
            .execute(
                "UPDATE channel_messages SET sender_id = $1, delete_at = $2 WHERE sender_id = $3",
                &[&crate::constants::DELETED_LABEL, &expire, &user_id],
            )
            .await
            .map_err(|e| format!("channel_messages: {}", e))?;
        client
            .execute("DELETE FROM groups WHERE creator_id = $1", &[&user_id])
            .await
            .map_err(|e| format!("groups: {}", e))?;
        client
            .execute("DELETE FROM channels WHERE creator_id = $1", &[&user_id])
            .await
            .map_err(|e| format!("channels: {}", e))?;
        client
            .execute("DELETE FROM users WHERE id = $1", &[&user_id])
            .await
            .map_err(|e| format!("users: {}", e))?;
        self.id_to_username.remove(user_id);
        self.username_to_id.retain(|_u, id| id != user_id);
        Ok(tokens)
    }

    pub async fn purge_expired(pool: &Pool) -> Result<usize, String> {
        let now: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs() as i64;
        let client = pool.get().await.map_err(|e| e.to_string())?;
        let mut total = 0;
        for table in ["messages", "group_messages", "channel_messages"] {
            let n = client
                .execute(
                    &format!(
                        "DELETE FROM {} WHERE delete_at IS NOT NULL AND delete_at <= $1",
                        table
                    ),
                    &[&now],
                )
                .await
                .map_err(|e| format!("{}: {}", table, e))?;
            total += n;
        }
        if total > 0 {
            info!("Purge: удалено {} старых строк", total);
        }
        Ok(total as usize)
    }

    pub async fn verify_session_ownership(
        &self,
        token: &str,
        user_id: &str,
    ) -> Result<bool, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt(
                "SELECT 1 FROM sessions WHERE token = $1 AND user_id = $2",
                &[&token, &user_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(row_opt.is_some())
    }
}
