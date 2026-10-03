mod app_state;
mod client;
mod constants;
mod fcm;

use rusqlite::Connection;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use app_state::{AppState, DbState};

async fn run_server(
    listener: TcpListener,
    state: Arc<Mutex<AppState>>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state_clone = state.clone();
        tokio::spawn(async move {
            client::handle_client(stream, state_clone).await;
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let ip = env::var("IP").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8100".to_string());
    let addr = if ip.contains(':') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    };
    let listener = TcpListener::bind(&addr).await?;
    log::info!("WebSocket сервер запущен на {}", addr);

    let db_path = "data.db";
    let mut conn = Connection::open(db_path)?;
    conn.execute("PRAGMA foreign_keys = ON", [])?;

    let fk_enabled: i32 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
    if fk_enabled != 1 {
        eprintln!("ВНИМАНИЕ: foreign_keys не включены!");
    }

    AppState::init_db(&mut conn)?;

    let mut username_to_id = HashMap::new();
    let mut id_to_username = HashMap::new();
    {
        let mut stmt = conn.prepare("SELECT id, username FROM users")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let username: String = row.get(1)?;
            username_to_id.insert(username.clone(), id.clone());
            id_to_username.insert(id, username);
        }
    }
    log::info!("Кэш username↔id: {} пользователей", username_to_id.len());

    let db_state = DbState {
        conn,
        username_to_id,
        id_to_username,
    };
    let state = Arc::new(Mutex::new(AppState::new(db_state)));

    let ctrl_c = tokio::signal::ctrl_c();
    let terminate = async {
        #[cfg(unix)]
        {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install signal handler")
                .recv()
                .await;
        }
        #[cfg(not(unix))]
        std::future::pending::<()>().await;
    };

    tokio::select! {
        _ = run_server(listener, state) => {},
        _ = ctrl_c => {
            log::info!("Получен сигнал Ctrl+C, завершаем работу...");
        },
        _ = terminate => {
            log::info!("Получен сигнал завершения, завершаем работу...");
        },
    }

    Ok(())
}
