use aes_gcm::aead::OsRng;
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use log::{info, warn};
use sha2::Sha256;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::app_state::SessionKeys;
use crate::constants::{CURRENT_PROTO_VERSION, HANDSHAKE_OK, HANDSHAKE_REJECT, MIN_PROTO_VERSION};

pub struct HandshakeResult {
    pub keys: SessionKeys,
    pub agreed_version: u16,
}

/// Handshake с версионированием.
/// v1 (старый):  [pub_key 32]                          — 32 байта
/// v2+ (новый):  [proto_version u16][pub_key 32]        — 34 байта
/// Ответ OK:   [0x00][agreed u16][pub_key 32]           — 35 байт
/// Ответ fail: [0xFF][reason_len u32][reason utf8]
pub async fn ws_handshake(
    stream: &mut tokio_tungstenite::WebSocketStream<TcpStream>,
) -> Result<HandshakeResult, String> {
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

    let (client_version, client_key_slice): (u16, &[u8]) = if data.len() == 32 {
        (1, &data[..])
    } else if data.len() == 34 {
        let v = u16::from_be_bytes([data[0], data[1]]);
        (v, &data[2..])
    } else {
        let reason = format!("Неверная длина handshake: {}", data.len());
        reject(stream, &reason).await;
        return Err(reason);
    };

    if client_version < MIN_PROTO_VERSION || client_version > CURRENT_PROTO_VERSION {
        let reason = format!(
            "Несовместимая версия протокола: клиент {}, сервер поддерживает {}..={}",
            client_version, MIN_PROTO_VERSION, CURRENT_PROTO_VERSION
        );
        reject(stream, &reason).await;
        return Err(reason);
    }

    let client_key: [u8; 32] = client_key_slice
        .try_into()
        .map_err(|_| "Invalid key array")?;

    info!("Handshake: клиент v{}, ключ получен", client_version);

    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let server_pub = public.as_bytes().to_vec();

    let agreed = client_version.min(CURRENT_PROTO_VERSION);

    let mut resp = Vec::with_capacity(35);
    resp.push(HANDSHAKE_OK);
    resp.extend_from_slice(&agreed.to_be_bytes());
    resp.extend_from_slice(&server_pub);
    stream
        .send(Message::Binary(resp.into()))
        .await
        .map_err(|e| format!("Failed to send handshake response: {}", e))?;
    info!("Handshake: отправлен OK v{} + публичный ключ", agreed);

    let peer_public = PublicKey::from(client_key);
    let shared = secret.diffie_hellman(&peer_public);
    let shared_bytes = shared.to_bytes();

    let hk = Hkdf::<Sha256>::new(None, &shared_bytes);
    let mut derived = [0u8; 32];
    hk.expand(b"relay-server", &mut derived)
        .map_err(|e| format!("HKDF error: {}", e))?;
    info!("Handshake: успешно завершён (v{})", agreed);

    Ok(HandshakeResult {
        keys: SessionKeys { key: derived },
        agreed_version: agreed,
    })
}

async fn reject(stream: &mut tokio_tungstenite::WebSocketStream<TcpStream>, reason: &str) {
    let bytes = reason.as_bytes();
    let mut resp = Vec::with_capacity(1 + 4 + bytes.len());
    resp.push(HANDSHAKE_REJECT);
    resp.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    resp.extend_from_slice(bytes);
    let _ = stream.send(Message::Binary(resp.into())).await;
    warn!("Handshake: отказ — {}", reason);
}
