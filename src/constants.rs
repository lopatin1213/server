use std::time::Duration as StdDuration;

// ==================== Версия протокола ====================
pub const MIN_PROTO_VERSION: u16 = 1;
pub const CURRENT_PROTO_VERSION: u16 = 2;

pub const HANDSHAKE_OK: u8 = 0x00;
pub const HANDSHAKE_REJECT: u8 = 0xFF;

// ==================== MSG_TYPES ====================
pub const MSG_TYPE_USER: u8 = 0x01;
pub const MSG_TYPE_SYSTEM: u8 = 0x02;
pub const MSG_TYPE_COMMAND: u8 = 0x03;
pub const MSG_TYPE_AUTH: u8 = 0x04;
pub const MSG_TYPE_DELETE: u8 = 0x05;
pub const MSG_TYPE_LOGOUT: u8 = 0x06;
pub const MSG_TYPE_READ: u8 = 0x07;
pub const MSG_TYPE_EDIT: u8 = 0x08;

pub const MSG_KIND_PERSONAL: u8 = 1;
pub const MSG_KIND_GROUP: u8 = 2;
pub const MSG_KIND_CHANNEL: u8 = 3;

pub const MSG_DELETE_FOR_ALL: u8 = 0;
pub const MSG_DELETE_FOR_ME: u8 = 1;

pub const LOGOUT_TYPE_EXIT: u8 = 0;
pub const LOGOUT_TYPE_DELETE_ACCOUNT: u8 = 1;

// ==================== Лимиты ====================
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;
pub const RATE_LIMIT_WINDOW: StdDuration = StdDuration::from_secs(1);
pub const RATE_LIMIT_MAX: usize = 10;
pub const HISTORY_PAGE_SIZE: i64 = 1000;
pub const LOGIN_PER_CHAT: i64 = 5;

pub const PING_INTERVAL: StdDuration = StdDuration::from_secs(30);
pub const PONG_TIMEOUT: StdDuration = StdDuration::from_secs(90);

pub const DELETED_LABEL: &str = "deleted";

// ==================== Удаление аккаунта ====================
pub const DELETE_GRACE_PERIOD_SECS: i64 = 7 * 24 * 60 * 60;
pub const PURGE_INTERVAL_SECS: u64 = 60 * 60;
