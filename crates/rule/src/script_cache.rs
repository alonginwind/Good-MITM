use anyhow::Result;
use log::{error, info};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

/// 缓存有效期：24小时
const CACHE_TTL: Duration = Duration::from_secs(86400);

/// 内存缓存条目
struct CacheEntry {
    code: String,
    last_check: SystemTime,
}

/// 脚本缓存管理器（纯内存，不写入磁盘）
struct ScriptCache {
    memory: Mutex<HashMap<String, CacheEntry>>,
}

static SCRIPT_CACHE: OnceLock<ScriptCache> = OnceLock::new();

fn get_script_cache() -> &'static ScriptCache {
    SCRIPT_CACHE.get_or_init(|| ScriptCache {
        memory: Mutex::new(HashMap::new()),
    })
}

/// 解析脚本内容：code 优先，如果 code 为空则从 url 拉取
///
/// - 如果 `code` 非空，直接返回 code（code 优先）
/// - 如果 `code` 为空且 `url` 存在，从远程拉取并缓存到内存
/// - 缓存仅在内存中，进程重启后自动重新拉取
pub async fn resolve_script(code: &str, url: Option<&String>) -> Result<String> {
    // code 优先：如果 code 非空，直接使用
    if !code.is_empty() {
        return Ok(code.to_string());
    }

    let url = match url {
        Some(u) => u,
        None => return Ok(String::new()),
    };

    let cache = get_script_cache();

    // 1. 检查内存缓存
    {
        let mem = cache.memory.lock().unwrap();
        if let Some(entry) = mem.get(url) {
            let age = SystemTime::now()
                .duration_since(entry.last_check)
                .unwrap_or(Duration::MAX);
            if age < CACHE_TTL {
                info!("[ScriptCache] 内存缓存命中: {}", url);
                return Ok(entry.code.clone());
            }
            info!("[ScriptCache] 缓存已过期({:.1}h), 重新拉取: {}",
                age.as_secs_f64() / 3600.0, url);
        } else {
            info!("[ScriptCache] 首次拉取: {}", url);
        }
    }

    // 2. 缓存未命中或已过期，从远程拉取
    match fetch_remote(url).await {
        Ok(code) => {
            let size = code.len();
            // 更新内存缓存
            {
                let mut mem = cache.memory.lock().unwrap();
                mem.insert(
                    url.clone(),
                    CacheEntry {
                        code: code.clone(),
                        last_check: SystemTime::now(),
                    },
                );
            }
            info!("[ScriptCache] 拉取成功: {} ({} bytes)", url, size);
            Ok(code)
        }
        Err(e) => {
            error!("[ScriptCache] 拉取失败: {} - {}", url, e);
            Ok(String::new())
        }
    }
}

/// 从远程 URL 拉取脚本内容
/// 支持 http:// / https:// URL 和本地文件路径
async fn fetch_remote(url: &str) -> Result<String> {
    // 支持本地文件路径（绝对路径或 file:// 协议）
    if url.starts_with("file://") {
        let path = &url[7..];
        info!("[ScriptCache] 读取本地文件: {}", path);
        return Ok(std::fs::read_to_string(path)?);
    }
    if url.starts_with('/') {
        info!("[ScriptCache] 读取本地文件: {}", url);
        return Ok(std::fs::read_to_string(url)?);
    }

    // HTTP/HTTPS 拉取
    info!("[ScriptCache] HTTP 请求: {}", url);
    let uri: hyper::Uri = url.parse()?;

    let https = {
        let tls = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        let mut http = hyper::client::HttpConnector::new();
        http.enforce_http(false);
        hyper_tls::HttpsConnector::from((http, tls.into()))
    };

    let client = hyper::Client::builder().build::<_, hyper::Body>(https);
    let res = client.get(uri).await?;

    let body = hyper::body::to_bytes(res.into_body()).await?;
    Ok(String::from_utf8(body.to_vec())?)
}
