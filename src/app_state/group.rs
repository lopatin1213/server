use rusqlite::{Connection, params};
use uuid::Uuid;

use super::core::AppState;

impl AppState {
    // ---- Группы ----
    pub fn create_group(conn: &mut Connection, name: &str, creator_id: &str) -> Result<(), String> {
        let group_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO groups (id, name, creator_id) VALUES (?, ?, ?)",
            params![group_id, name, creator_id],
        )
        .map_err(|e| format!("Ошибка создания группы: {}", e))?;
        conn.execute(
            "INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, 'owner')",
            params![group_id, creator_id],
        )
        .map_err(|e| format!("Ошибка добавления создателя в группу: {}", e))?;
        Ok(())
    }

    pub fn join_group(
        conn: &mut Connection,
        group_name: &str,
        user_id: &str,
    ) -> Result<(), String> {
        let mut stmt = conn
            .prepare("SELECT id FROM groups WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса группы: {}", e))?;
        let mut rows = stmt
            .query([group_name])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let group_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            conn.execute(
                "INSERT OR IGNORE INTO group_members (group_id, user_id, role) VALUES (?, ?, 'member')",
                params![group_id, user_id],
            ).map_err(|e| format!("Ошибка присоединения к группе: {}", e))?;
            Ok(())
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    pub fn leave_group(
        conn: &mut Connection,
        group_name: &str,
        user_id: &str,
    ) -> Result<(), String> {
        let mut stmt = conn
            .prepare("SELECT id FROM groups WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса группы: {}", e))?;
        let mut rows = stmt
            .query([group_name])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let group_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            conn.execute(
                "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
                params![group_id, user_id],
            )
            .map_err(|e| format!("Ошибка выхода из группы: {}", e))?;
            Ok(())
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    /// Полное удаление группы (только владелец).
    /// Возвращает true, если удалено, false если нет прав.
    pub fn delete_group(
        conn: &mut Connection,
        group_name: &str,
        user_id: &str,
    ) -> Result<bool, String> {
        let mut stmt = conn
            .prepare("SELECT creator_id FROM groups WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса группы: {}", e))?;
        let mut rows = stmt
            .query([group_name])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;

        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let creator_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            if creator_id != user_id {
                return Ok(false); // Не владелец
            }
            conn.execute("DELETE FROM groups WHERE name = ?", [group_name])
                .map_err(|e| format!("Ошибка удаления группы: {}", e))?;
            Ok(true)
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    pub fn get_group_members(
        conn: &mut Connection,
        group_name: &str,
    ) -> Result<Vec<String>, String> {
        let mut stmt = conn.prepare(
            "SELECT gm.user_id FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE g.name = ?"
        ).map_err(|e| format!("Ошибка запроса участников: {}", e))?;
        let mut rows = stmt
            .query([group_name])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        let mut members = Vec::new();
        while let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))?
        {
            let user_id: String = row
                .get(0)
                .map_err(|e| format!("Ошибка чтения user_id: {}", e))?;
            members.push(user_id);
        }
        Ok(members)
    }

    pub fn store_group_message(
        conn: &mut Connection,
        group_name: &str,
        sender_id: &str,
        content: &str,
        timestamp: i64,
        reply_to_id: Option<i64>,
    ) -> Result<i64, String> {
        let mut stmt = conn
            .prepare("SELECT id FROM groups WHERE name = ?")
            .map_err(|e| format!("Ошибка запроса группы: {}", e))?;
        let mut rows = stmt
            .query([group_name])
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;
        if let Some(row) = rows.next().map_err(|e| format!("Ошибка чтения: {}", e))? {
            let group_id: String = row.get(0).map_err(|e| format!("Ошибка чтения id: {}", e))?;
            conn.execute(
                "INSERT INTO group_messages (group_id, sender_id, content, sent_at, reply_to_id) \
                 VALUES (?, ?, ?, datetime(?/1000, 'unixepoch'), ?)",
                params![group_id, sender_id, content, &timestamp, reply_to_id],
            )
            .map_err(|e| format!("Ошибка сохранения группового сообщения: {}", e))?;
            Ok(conn.last_insert_rowid())
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    pub fn get_recent_groups(
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
            bool,
        )>,
        String,
    > {
        let mut stmt = conn
            .prepare(
                "WITH ranked AS (
                    SELECT gm.id, g.name AS group_name,
                           gm.sender_id, gm.content,
                           strftime('%s', gm.sent_at) * 1000 AS ts,
                           gm.reply_to_id, gm.first_read_at,
                           COALESCE(gm.edited, 0) AS edited,
                           ROW_NUMBER() OVER (
                               PARTITION BY gm.group_id ORDER BY gm.id DESC
                           ) AS rn
                    FROM group_messages gm
                    JOIN groups g ON gm.group_id = g.id
                    JOIN group_members gmem ON gmem.group_id = g.id AND gmem.user_id = ?1
                    LEFT JOIN hidden_messages h
                           ON h.kind = 2 AND h.msg_id = gm.id AND h.user_id = ?1
                    WHERE h.msg_id IS NULL
                )
                SELECT id, group_name, sender_id, content, ts, reply_to_id, first_read_at, edited
                FROM ranked
                WHERE rn <= ?2
                ORDER BY id ASC",
            )
            .map_err(|e| e.to_string())?;
        let iter = stmt
            .query_map(params![user_id, per_chat], |row| {
                let sender_id: String = row.get(2)?;
                let first_read_at: Option<String> = row.get(6)?;
                let edited: i64 = row.get(7).unwrap_or(0);
                let is_sender = sender_id == user_id;
                let read_flag = first_read_at.is_some();
                let flag_me = is_sender;
                let flag_any = read_flag;
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    sender_id,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    flag_me,
                    flag_any,
                    edited != 0,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in iter {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn update_group_message_content(
        conn: &mut Connection,
        msg_id: i64,
        new_text: &str,
    ) -> Result<Option<String>, String> {
        let sender_id: Option<String> = conn
            .query_row(
                "SELECT sender_id FROM group_messages WHERE id = ?",
                [msg_id],
                |row| row.get(0),
            )
            .ok();

        if sender_id.is_none() {
            return Ok(None);
        }

        conn.execute(
            "UPDATE group_messages SET content = ?, edited = 1 WHERE id = ?",
            params![new_text, msg_id],
        )
        .map_err(|e| format!("Ошибка обновления группового сообщения: {}", e))?;

        Ok(sender_id)
    }
}
