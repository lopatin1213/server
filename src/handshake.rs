use aes_gcm::aead::OsRng;
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use log::{info, warn};
use sha2::Sha256;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::app_state::SessionKeys;

pub async fn ws_handshake(
    stream: &mut tokio_tungstenite::WebSocketStream<TcpStream>,
) -> Result<SessionKeys, String> {
    info!("Handshake: ожидание первого сообщения");
    let msg = stream
        .next()
        .await
        .ok_or("No message received")?
        .map_err(|e| format!("WebSocket error: {}", e))?;
    let data = match msg {
        Message::Binary(d) => d,
        Message::Text(t) => {
            warn!("Handshake: получен текст вместо бинарных данных: {}", t);
            return Err("Expected binary".to_string());
        }
        _ => return Err("Expected binary".to_string()),
    };
    if data.len() != 32 {
        return Err(format!("Invalid public key length: {}", data.len()));
    }
    let client_key: [u8; 32] = data.to_vec().try_into().map_err(|_| "Invalid key array")?;
    info!("Handshake: получен публичный ключ клиента");

    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    stream
        .send(Message::Binary(public.as_bytes().to_vec().into()))
        .await
        .map_err(|e| format!("Failed to send public key: {}", e))?;
    info!("Handshake: отправлен публичный ключ сервера");

    let peer_public = PublicKey::from(client_key);
    let shared = secret.diffie_hellman(&peer_public);
    let shared_bytes = shared.to_bytes();

    let hk = Hkdf::<Sha256>::new(None, &shared_bytes);
    let mut derived = [0u8; 32];
    hk.expand(b"relay-server", &mut derived)
        .map_err(|e| format!("HKDF error: {}", e))?;
    let key = derived;
    info!("Handshake: успешно завершён");
    Ok(SessionKeys { key })
}
