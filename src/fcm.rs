use log::{error, warn};
use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use crate::app_state::AppState;
use crate::app_state::DbState;

#[derive(Debug)]
pub enum FcmError {
    Connection(String),
    SendFailed(String),
}

impl std::fmt::Display for FcmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FcmError::Connection(s) => write!(f, "FCM недоступен: {}", s),
            FcmError::SendFailed(s) => write!(f, "FCM отклонил отправку: {}", s),
        }
    }
}

pub async fn send_fcm_push(
    fcm_token: &str,
    title: &str,
    body: &str,
    data: Option<serde_json::Value>,
) -> Result<(), FcmError> {
    if fcm_token.trim().is_empty() {
        return Err(FcmError::SendFailed("пустой токен".to_string()));
    }

    let data_map: Option<HashMap<String, String>> = data.map(|v| {
        v.as_object()
            .unwrap_or(&serde_json::Map::new())
            .iter()
            .map(|(k, v)| {
                let s = v
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| v.to_string());
                (k.clone(), s)
            })
            .collect()
    });

    let token = fcm_token.to_string();
    let title = title.to_string();
    let body = body.to_string();

    let joined = tokio::task::spawn_blocking(move || -> Result<(bool, bool), String> {
        Python::with_gil(|py| {
            let sys = py.import("sys").map_err(|e| format!("sys: {}", e))?;
            let path = sys
                .getattr("path")
                .map_err(|e| format!("sys.path: {}", e))?;
            if let Ok(exe_path) = std::env::current_exe() {
                if let Some(dir) = exe_path.parent() {
                    if let Some(dir_str) = dir.to_str() {
                        path.call_method1("insert", (0, dir_str))
                            .map_err(|e| format!("sys.path.insert: {}", e))?;
                    }
                }
            }
            let helper = py
                .import("fcm_helper")
                .map_err(|e| format!("import: {}", e))?;
            let send_func = helper
                .getattr("send_fcm_push")
                .map_err(|e| format!("getattr: {}", e))?;
            let result = send_func
                .call1((token, title, body, data_map))
                .map_err(|e| format!("call: {}", e))?;
            let extracted: (bool, bool) =
                result.extract().map_err(|e| format!("extract: {}", e))?;
            Ok(extracted)
        })
    })
    .await
    .map_err(|e| FcmError::Connection(format!("join: {}", e)))?
    .map_err(FcmError::Connection)?;

    let (success, connection_failed) = joined;
    if success {
        Ok(())
    } else if connection_failed {
        Err(FcmError::Connection(
            "send_fcm_push connection_failed".to_string(),
        ))
    } else {
        Err(FcmError::SendFailed("FCM отклонил отправку".to_string()))
    }
}

pub async fn send_fcm_push_and_cleanup(
    db: Arc<StdMutex<DbState>>,
    fcm_token: &str,
    title: &str,
    body: &str,
    data: Option<serde_json::Value>,
) {
    match send_fcm_push(fcm_token, title, body, data).await {
        Ok(()) => {}
        Err(FcmError::SendFailed(e)) => {
            warn!("Удаляю недействительный FCM-токен {}: {}", fcm_token, e);
            let tok = fcm_token.to_string();
            let _ = tokio::task::spawn_blocking(move || {
                let mut st = db.lock().unwrap();
                AppState::delete_fcm_token(&mut st.conn, &tok)
            })
            .await;
        }
        Err(FcmError::Connection(e)) => {
            error!("FCM недоступен, токен {} сохранён: {}", fcm_token, e);
        }
    }
}
