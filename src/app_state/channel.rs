use rusqlite::{Connection, params};
use uuid::Uuid;

use super::core::AppState;

impl AppState {
    // ---- Каналы ----
    pub fn create_channel(
        conn: &mut Connection,
        name: &str,
        creator_id: &str,
    ) -> Result<(), String> {
        let channel_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO channels (id, name, creator_id) VALUES (?, ?, ?)",
            params![channel_id, name, creator_id],
        )
        .map_err(|e| format!("Ошибка создания канала: {}", e))?;
        conn.execute(
            "INSERT INTO channel_subscribers (channel_id, user_id) VALUES (?, ?)",
            params![channel_id, creator_id],
        )
        .map_err(|e| format!("Ошибка подписки создателя: {}", e))?;
        Ok(())
    }

    pub fn subscribe_channel(
        conn: &mut Connection,
        channel_name: &str,
        user_id: &str,
    ) -> Result<(), String> {
        let mut stmt = conn
            .prepare("SELECT id FROM channels WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса канала: {}", e))?;
        let mut rows = stmt
            .query([channel_name])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let channel_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            conn.execute(
                "INSERT OR IGNORE INTO channel_subscribers (channel_id, user_id) VALUES (?, ?)",
                params![channel_id, user_id],
            )
            .map_err(|e| format!("Ошибка подписки: {}", e))?;
            Ok(())
        } else {
            Err("Канал не найден".to_string())
        }
    }

    pub fn unsubscribe_channel(
        conn: &mut Connection,
        channel_name: &str,
        user_id: &str,
    ) -> Result<(), String> {
        let mut stmt = conn
            .prepare("SELECT id FROM channels WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса канала: {}", e))?;
        let mut rows = stmt
            .query([channel_name])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let channel_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            conn.execute(
                "DELETE FROM channel_subscribers WHERE channel_id = ? AND user_id = ?",
                params![channel_id, user_id],
            )
            .map_err(|e| format!("Ошибка отписки: {}", e))?;
            Ok(())
        } else {
            Err("Канал не найден".to_string())
        }
    }

    pub fn get_channel_subscribers(
        conn: &mut Connection,
        channel_name: &str,
    ) -> Result<Vec<String>, String> {
        let mut stmt = conn.prepare(
            "SELECT cs.user_id FROM channel_subscribers cs JOIN channels c ON cs.channel_id = c.id WHERE c.name = ?"
        ).map_err(|e| format!("Ошибка запроса подписчиков: {}", e))?;
        let mut rows = stmt
            .query([channel_name])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        let mut subscribers = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))?
        {
            let user_id: String = row
                .get(0)
                .map_err(|e| format!("Ошибка чтения user_id: {}", e))?;
            subscribers.push(user_id);
        }
        Ok(subscribers)
    }

    pub fn store_channel_message(
        conn: &mut Connection,
        channel_name: &str,
        sender_id: &str,
        content: &str,
        timestamp: i64,
        reply_to_id: Option<i64>,
    ) -> Result<i64, String> {
        let mut stmt = conn
            .prepare("SELECT id FROM channels WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса канала: {}", e))?;
        let mut rows = stmt
            .query([channel_name])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let channel_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            conn.execute(
                "INSERT INTO channel_messages (channel_id, sender_id, content, sent_at, reply_to_id) \
                 VALUES (?, ?, ?, datetime(?/1000, 'unixepoch'), ?)",
                params![channel_id, sender_id, content, &timestamp, reply_to_id],
            )
                .map_err(|e| format!("Ошибка сохранения сообщения канала: {}", e))?;
            Ok(conn.last_insert_rowid())
        } else {
            Err("Канал не найден".to_string())
        }
    }

    /// (msg_id, channel_name, sender_id, content, ts, reply_to_id, flag_me, flag_any, views).
    pub fn get_recent_channels(
        conn: &mut Connection,
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
            u32,
        )>,
        String,
    > {
        let mut stmt = conn
            .prepare(
                "WITH ranked AS (
                    SELECT cm.id, c.name AS channel_name,
                           cm.sender_id, cm.content,
                           strftime('%s', cm.sent_at) * 1000 AS ts,
                           cm.reply_to_id,
                           (SELECT COUNT(*) FROM channel_message_views v
                            WHERE v.channel_msg_id = cm.id) AS views,
                           ROW_NUMBER() OVER (
                               PARTITION BY cm.channel_id ORDER BY cm.id DESC
                           ) AS rn
                    FROM channel_messages cm
                    JOIN channels c ON cm.channel_id = c.id
                    JOIN channel_subscribers cs ON cs.channel_id = c.id AND cs.user_id = ?1
                    LEFT JOIN hidden_messages h
                           ON h.kind = 3 AND h.msg_id = cm.id AND h.user_id = ?1
                    WHERE h.msg_id IS NULL
                )
                SELECT id, channel_name, sender_id, content, ts, reply_to_id, views
                FROM ranked
                WHERE rn <= ?2
                ORDER BY id ASC",
            )
            .map_err(|e| e.to_string())?;
        let iter = stmt
            .query_map(params![user_id, per_chat], |row| {
                let views: i64 = row.get(6).unwrap_or(0);
                let v = views as u32;
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    true,
                    v > 0,
                    v,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in iter {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn lookup_channel_message(
        conn: &mut Connection,
        msg_id: i64,
    ) -> Result<Option<(String, String, String)>, String> {
        let mut stmt = conn
            .prepare(
                "SELECT c.name, c.creator_id, cm.sender_id \
                 FROM channel_messages cm JOIN channels c ON cm.channel_id = c.id \
                 WHERE cm.id = ?",
            )
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query([msg_id]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            Ok(Some((
                row.get(0).map_err(|e| e.to_string())?,
                row.get(1).map_err(|e| e.to_string())?,
                row.get(2).map_err(|e| e.to_string())?,
            )))
        } else {
            Ok(None)
        }
    }

    pub fn delete_channel_message(conn: &mut Connection, msg_id: i64) -> Result<(), String> {
        conn.execute("DELETE FROM channel_messages WHERE id = ?", [msg_id])
            .map_err(|e| format!("Ошибка удаления: {}", e))?;
        Ok(())
    }
}
