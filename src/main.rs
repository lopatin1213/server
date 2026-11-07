mod app_state;
mod client;
mod constants;
mod fcm;
mod handshake;
mod senders;

use deadpool_postgres::{Config, Runtime};
use std::env;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_postgres::NoTls;

use app_state::AppState;

async fn run_server(
    listener: TcpListener,
    state: Arc<AppState>,
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
    // Принудительно загружаем .env (для DB_PASSWORD и PEPPER)
    dotenvy::dotenv_override().ok();

    env_logger::init();

    // Проверяем наличие секретов перед стартом
    let db_password =
        env::var("DB_PASSWORD").expect("КРИТИЧЕСКАЯ ОШИБКА: DB_PASSWORD не задан в .env!");
    let pepper = env::var("PEPPER").expect("КРИТИЧЕСКАЯ ОШИБКА: PEPPER не задан в .env!");

    // Инициализируем PEPPER для доступа из migrate.rs
    unsafe {
        env::set_var("PEPPER", pepper);
    }

    // Остальные настройки берем из env (если заданы), иначе - дефолты
    let ip = env::var("IP").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8100".to_string());
    let db_host = env::var("DB_HOST").unwrap_or_else(|_| "localhost".to_string());
    let db_port: u16 = env::var("DB_PORT")
        .unwrap_or_else(|_| "5432".to_string())
        .parse()
        .unwrap_or(5432);
    let db_user = env::var("DB_USER").unwrap_or_else(|_| "vartchat_user".to_string());
    let db_name = env::var("DB_NAME").unwrap_or_else(|_| "vartchat".to_string());

    let addr = if ip.contains(':') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    };
    let listener = TcpListener::bind(&addr).await?;
    log::info!("WebSocket сервер запущен на {}", addr);

    let mut cfg = Config::new();
    cfg.host = Some(db_host);
    cfg.port = Some(db_port);
    cfg.user = Some(db_user);
    cfg.password = Some(db_password);
    cfg.dbname = Some(db_name);

    let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls)?;

    AppState::init_db(&pool).await?;

    let state = Arc::new(AppState::new(pool));

    // Прогрев кэшей (username <-> id)
    {
        let client = state.db.get().await?;
        let rows = client.query("SELECT id, username FROM users", &[]).await?;
        for row in rows {
            let id: String = row.get(0);
            let username: String = row.get(1);
            state.username_to_id.insert(username.clone(), id.clone());
            state.id_to_username.insert(id, username);
        }
        log::info!(
            "Кэш username↔id: {} пользователей",
            state.username_to_id.len()
        );
    }

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

    // Воркер чистки просроченных сообщений
    {
        let state_cleanup = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                crate::constants::PURGE_INTERVAL_SECS,
            ));
            loop {
                interval.tick().await;
                let _ = AppState::purge_expired(&state_cleanup.db).await;
            }
        });
    }

    tokio::select! {
        _ = run_server(listener, state) => {},
        _ = ctrl_c => { log::info!("Получен сигнал Ctrl+C, завершаем работу..."); },
        _ = terminate => { log::info!("Получен сигнал завершения, завершаем работу..."); },
    }

    Ok(())
}
