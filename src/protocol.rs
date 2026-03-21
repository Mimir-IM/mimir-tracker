// ── Protocol constants ───────────────────────────────────────────────────────

pub const VERSION_V1: u8 = 1;
pub const VERSION_V2: u8 = 2;
pub const PORT_TRACKER: u16 = 69;

pub const CMD_ANNOUNCE: u8 = 0;
pub const CMD_GET_ADDRS: u8 = 1;
pub const CMD_PING: u8 = 2;
pub const CMD_SYNC_DATA: u8 = 10;
pub const CMD_SYNC_PING: u8 = 20;

pub const MAX_HOP_COUNT: u8 = 3;

pub const KEY_FILE: &str = "tracker.key";
pub const DATA_FILE: &str = "data.bin";

// ── TLV Tags ────────────────────────────────────────────────────────────────

pub const TAG_USER_PUB: u8 = 0x01;
pub const TAG_NODE_PUB: u8 = 0x02;
pub const TAG_SIGNATURE: u8 = 0x03;
#[allow(dead_code)]
pub const TAG_NONCE: u8 = 0x04;
pub const TAG_PRIORITY: u8 = 0x05;
pub const TAG_CLIENT_ID: u8 = 0x06;
pub const TAG_TTL_SECS: u8 = 0x07;
pub const TAG_EXPIRES_MS: u8 = 0x08;
pub const TAG_HOP: u8 = 0x09;
pub const TAG_PREV_TTL: u8 = 0x0A;
pub const TAG_COUNT: u8 = 0x0B;
pub const TAG_RECORD: u8 = 0x0C;