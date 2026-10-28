use chrono::TimeZone;
use uuid::Uuid;

use super::core::AppState;

impl AppState {
    // ---- Каналы ----
    pub async fn create_channel(&self, name: &str, creator_id: &str) -> Result<(), String> {
        let channel_id = Uuid::new_v4().to_string();
        let mut client = self.db.get().await.map_err(|e| e.to_string())?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| format!("Ошибка старта транзакции: {}", e))?;

        tx.execute(
            "INSERT INTO channels (id, name, creator_id) VALUES ($1, $2, $3)",
            &[&channel_id, &name, &creator_id],
        )
        .await
        .map_err(|e| format!("Ошибка создания канала: {}", e))?;

        tx.execute(
            "INSERT INTO channel_subscribers (channel_id, user_id) VALUES ($1, $2)",
            &[&channel_id, &creator_id],
        )
        .await
        .map_err(|e| format!("Ошибка подписки создателя: {}", e))?;

        tx.commit()
            .await
            .map_err(|e| format!("Ошибка коммита транзакции: {}", e))?;
        Ok(())
    }

    pub async fn subscribe_channel(&self, channel_name: &str, user_id: &str) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt("SELECT id FROM channels WHERE name = $1", &[&channel_name])
            .await
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;

        if let Some(row) = row_opt {
            let channel_id: String = row.get(0);
            client.execute(
                "INSERT INTO channel_subscribers (channel_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                &[&channel_id, &user_id],
            ).await.map_err(|e| format!("Ошибка подписки: {}", e))?;
            Ok(())
        } else {
            Err("Канал не найден".to_string())
        }
    }

    pub async fn unsubscribe_channel(
        &self,
        channel_name: &str,
        user_id: &str,
    ) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt("SELECT id FROM channels WHERE name = $1", &[&channel_name])
            .await
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;

        if let Some(row) = row_opt {
            let channel_id: String = row.get(0);
            client
                .execute(
                    "DELETE FROM channel_subscribers WHERE channel_id = $1 AND user_id = $2",
                    &[&channel_id, &user_id],
                )
                .await
                .map_err(|e| format!("Ошибка отписки: {}", e))?;
            Ok(())
        } else {
            Err("Канал не найден".to_string())
        }
    }

    /// Полное удаление канала (только владелец).
    pub async fn delete_channel(&self, channel_name: &str, user_id: &str) -> Result<bool, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt(
                "SELECT creator_id FROM channels WHERE name = $1",
                &[&channel_name],
            )
            .await
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;

        if let Some(row) = row_opt {
            let creator_id: String = row.get(0);
            if creator_id != user_id {
                return Ok(false); // Не владелец
            }
            client
                .execute("DELETE FROM channels WHERE name = $1", &[&channel_name])
                .await
                .map_err(|e| format!("Ошибка удаления канала: {}", e))?;
            Ok(true)
        } else {
            Err("Канал не найден".to_string())
        }
    }

    pub async fn get_channel_subscribers(&self, channel_name: &str) -> Result<Vec<String>, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let rows = client.query(
            "SELECT cs.user_id FROM channel_subscribers cs JOIN channels c ON cs.channel_id = c.id WHERE c.name = $1",
            &[&channel_name],
        ).await.map_err(|e| format!("Ошибка выполнения: {}", e))?;

        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }

    pub async fn store_channel_message(
        &self,
        channel_name: &str,
        sender_id: &str,
        content: &str,
        timestamp: i64,
        reply_to_id: Option<i64>,
    ) -> Result<i64, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt("SELECT id FROM channels WHERE name = $1", &[&channel_name])
            .await
            .map_err(|e| format!("Ошибка выполнения: {}", e))?;

        if let Some(row) = row_opt {
            let channel_id: String = row.get(0);
            let dt = chrono::Utc.timestamp_millis_opt(timestamp).unwrap();

            let inserted = client.query_one(
                "INSERT INTO channel_messages (channel_id, sender_id, content, sent_at, reply_to_id) \
                 VALUES ($1, $2, $3, $4, $5) RETURNING id",
                &[&channel_id, &sender_id, &content, &dt, &reply_to_id],
            ).await.map_err(|e| format!("Ошибка сохранения сообщения канала: {}", e))?;

            Ok(inserted.get(0))
        } else {
            Err("Канал не найден".to_string())
        }
    }

    pub async fn get_recent_channels(
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
            u32,
            bool,
        )>,
        String,
    > {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let stmt = client
            .prepare_cached(
                "WITH ranked AS (
                SELECT cm.id, c.name AS channel_name,
                       cm.sender_id, cm.content,
                       (EXTRACT(EPOCH FROM cm.sent_at) * 1000)::bigint AS ts,
                       cm.reply_to_id,
                       cm.edited,
                       (SELECT COUNT(*) FROM channel_message_views v
                        WHERE v.channel_msg_id = cm.id) AS views,
                       ROW_NUMBER() OVER (
                           PARTITION BY cm.channel_id ORDER BY cm.id DESC
                       ) AS rn
                FROM channel_messages cm
                JOIN channels c ON cm.channel_id = c.id
                JOIN channel_subscribers cs ON cs.channel_id = c.id AND cs.user_id = $1
                LEFT JOIN hidden_messages h
                       ON h.kind = 3 AND h.msg_id = cm.id AND h.user_id = $1
                WHERE h.msg_id IS NULL
            )
            SELECT id, channel_name, sender_id, content, ts, reply_to_id, views, edited
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
            let views: i64 = row.get(6);
            let v = views as u32;

            out.push((
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
                true,
                v > 0,
                v,
                row.get(7),
            ));
        }
        Ok(out)
    }

    pub async fn lookup_channel_message(
        &self,
        msg_id: i64,
    ) -> Result<Option<(String, String, String)>, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt(
                "SELECT c.name, c.creator_id, cm.sender_id \
             FROM channel_messages cm JOIN channels c ON cm.channel_id = c.id \
             WHERE cm.id = $1",
                &[&msg_id],
            )
            .await
            .map_err(|e| e.to_string())?;

        if let Some(row) = row_opt {
            Ok(Some((row.get(0), row.get(1), row.get(2))))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_channel_message(&self, msg_id: i64) -> Result<(), String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        client
            .execute("DELETE FROM channel_messages WHERE id = $1", &[&msg_id])
            .await
            .map_err(|e| format!("Ошибка удаления: {}", e))?;
        Ok(())
    }

    pub async fn update_channel_message_content(
        &self,
        msg_id: i64,
        new_text: &str,
    ) -> Result<Option<(String, String, String)>, String> {
        let client = self.db.get().await.map_err(|e| e.to_string())?;
        let row_opt = client
            .query_opt(
                "UPDATE channel_messages SET content = $1, edited = true WHERE id = $2 \
             RETURNING (SELECT name FROM channels WHERE id = channel_id), \
                       (SELECT creator_id FROM channels WHERE id = channel_id), \
                       sender_id",
                &[&new_text, &msg_id],
            )
            .await
            .map_err(|e| format!("Ошибка обновления сообщения канала: {}", e))?;

        if let Some(row) = row_opt {
            Ok(Some((row.get(0), row.get(1), row.get(2))))
        } else {
            Ok(None)
        }
    }
}
