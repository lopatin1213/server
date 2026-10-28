use chrono::TimeZone;
use uuid::Uuid;

use super::core::AppState;

impl AppState {
    // ---- Группы ----
    pub async fn create_group(&self, name: &str, creator_id: &str) -> Result<(), String> {
        let group_id = Uuid::new_v4().to_string();
        let mut client = self.db.get().await.map_err(|e| e.to_string())?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| format!("Ошибка старта транзакции: {}", e))?;

        tx.execute(
            "INSERT INTO groups (id, name, creator_id) VALUES ($1, $2, $3)",
            &[&group_id, &name, &creator_id],
        )
        .await
        .map_err(|e| format!("Ошибка создания группы: {}", e))?;

        tx.execute(
            "INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'owner')",
            &[&group_id, &creator_id],
        )
        .await
        .map_err(|e| format!("Ошибка добавления создателя в группу: {}", e))?;

        tx.commit()
            .await
            .map_err(|e| format!("Ошибка коммита транзакции: {}", e))?;
        Ok(())
    }

    pub async fn join_group(&self, group_name: &str, user_id: &str) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt("SELECT id FROM groups WHERE name = $1", &[&group_name])
            .await
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;

        if let Some(row) = row_opt {
            let group_id: String = row.get(0);
            client.execute(
                "INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING",
                &[&group_id, &user_id],
            ).await.map_err(|e| format!("Ошибка присоединения к группе: {}", e))?;
            Ok(())
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    pub async fn leave_group(&self, group_name: &str, user_id: &str) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt("SELECT id FROM groups WHERE name = $1", &[&group_name])
            .await
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;

        if let Some(row) = row_opt {
            let group_id: String = row.get(0);
            client
                .execute(
                    "DELETE FROM group_members WHERE group_id = $1 AND user_id = $2",
                    &[&group_id, &user_id],
                )
                .await
                .map_err(|e| format!("Ошибка выхода из группы: {}", e))?;
            Ok(())
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    /// Полное удаление группы (только владелец).
    pub async fn delete_group(&self, group_name: &str, user_id: &str) -> Result<bool, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt(
                "SELECT creator_id FROM groups WHERE name = $1",
                &[&group_name],
            )
            .await
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;

        if let Some(row) = row_opt {
            let creator_id: String = row.get(0);
            if creator_id != user_id {
                return Ok(false); // Не владелец
            }
            client
                .execute("DELETE FROM groups WHERE name = $1", &[&group_name])
                .await
                .map_err(|e| format!("Ошибка удаления группы: {}", e))?;
            Ok(true)
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    pub async fn get_group_members(&self, group_name: &str) -> Result<Vec<String>, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let rows = client.query(
            "SELECT gm.user_id FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE g.name = $1",
            &[&group_name],
        ).await.map_err(|e| format!("Ошибка выполнения: {}", e))?;

        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }

    pub async fn store_group_message(
        &self,
        group_name: &str,
        sender_id: &str,
        content: &str,
        timestamp: i64,
        reply_to_id: Option<i64>,
    ) -> Result<i64, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt("SELECT id FROM groups WHERE name = $1", &[&group_name])
            .await
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;

        if let Some(row) = row_opt {
            let group_id: String = row.get(0);
            let dt = chrono::Utc.timestamp_millis_opt(timestamp).unwrap();

            let inserted = client.query_one(
                "INSERT INTO group_messages (group_id, sender_id, content, sent_at, reply_to_id) \
                 VALUES ($1, $2, $3, $4, $5) RETURNING id",
                &[&group_id, &sender_id, &content, &dt, &reply_to_id],
            ).await.map_err(|e| format!("Ошибка сохранения группового сообщения: {}", e))?;

            Ok(inserted.get(0))
        } else {
            Err("Группа не найдена".to_string())
        }
    }

    pub async fn get_recent_groups(
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
        let stmt = client
            .prepare_cached(
                "WITH ranked AS (
                SELECT gm.id, g.name AS group_name,
                       gm.sender_id, gm.content,
                       (EXTRACT(EPOCH FROM gm.sent_at) * 1000)::bigint AS ts,
                       gm.reply_to_id, gm.first_read_at,
                       gm.edited,
                       ROW_NUMBER() OVER (
                           PARTITION BY gm.group_id ORDER BY gm.id DESC
                       ) AS rn
                FROM group_messages gm
                JOIN groups g ON gm.group_id = g.id
                JOIN group_members gmem ON gmem.group_id = g.id AND gmem.user_id = $1
                LEFT JOIN hidden_messages h
                       ON h.kind = 2 AND h.msg_id = gm.id AND h.user_id = $1
                WHERE h.msg_id IS NULL
            )
            SELECT id, group_name, sender_id, content, ts, reply_to_id, first_read_at, edited
            FROM ranked
            WHERE rn <= $2
            ORDER BY id ASC",
            )
            .await
            .map_err(|e| e.to_string())?;

        let rows = client
            .query(&stmt, &[&user_id, &per_chat])
            .await
            .map_err(|e| e.to_string())?;

        let mut out = Vec::new();
        for row in rows {
            let sender_id: String = row.get(2);
            let first_read_at: Option<chrono::DateTime<chrono::Utc>> = row.get(6);
            let is_sender = sender_id == user_id;
            let read_flag = first_read_at.is_some();

            out.push((
                row.get(0),
                row.get(1),
                sender_id,
                row.get(3),
                row.get(4),
                row.get(5),
                is_sender,
                read_flag,
                row.get(7),
            ));
        }
        Ok(out)
    }

    pub async fn update_group_message_content(
        &self,
        msg_id: i64,
        new_text: &str,
    ) -> Result<Option<String>, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client.query_opt(
            "UPDATE group_messages SET content = $1, edited = true WHERE id = $2 RETURNING sender_id",
            &[&new_text, &msg_id],
        ).await.map_err(|e| format!("Ошибка обновления группового сообщения: {}", e))?;

        if let Some(row) = row_opt {
            Ok(Some(row.get(0)))
        } else {
            Ok(None)
        }
    }
}
