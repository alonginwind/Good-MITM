#[cfg(feature = "js")]
pub mod js;
mod log;
mod modify;

pub use self::log::*;
pub use modify::Modify;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Reject(u16),
    Redirect(String),
    ModifyRequest(Modify),
    ModifyResponse(Modify),
    LogRes,
    LogReq,

    #[cfg(feature = "js")]
    JsReq {
        code: String,
        #[serde(rename = "requires-body", default)]
        requires_body: i32,
        #[serde(rename = "binary-body-mode", default)]
        binary_body_mode: i32,
    },
    #[cfg(feature = "js")]
    JsRes {
        code: String,
        #[serde(rename = "requires-body", default)]
        requires_body: i32,
        #[serde(rename = "binary-body-mode", default)]
        binary_body_mode: i32,
    },
}
