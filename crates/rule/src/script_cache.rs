use anyhow::Result;
use log::{error, info};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use tokio::sync::OnceCell;

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
    /// 正在拉取中的 URL，防止重复拉取
    in_flight: Mutex<HashMap<String, Arc<OnceCell<String>>>>,
}

static SCRIPT_CACHE: OnceLock<ScriptCache> = OnceLock::new();

fn get_script_cache() -> &'static ScriptCache {
    SCRIPT_CACHE.get_or_init(|| ScriptCache {
        memory: Mutex::new(HashMap::new()),
        in_flight: Mutex::new(HashMap::new()),
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

    // 2. 检查是否有正在进行的拉取
    let in_flight_cell = {
        let mut in_flight = cache.in_flight.lock().unwrap();
        if let Some(cell) = in_flight.get(url) {
            // 已有拉取在进行，等待它完成
            info!("[ScriptCache] 等待已有拉取完成: {}", url);
            cell.clone()
        } else {
            // 创建新的 OnceCell 并记录
            let cell = Arc::new(OnceCell::new());
            in_flight.insert(url.clone(), cell.clone());
            cell
        }
    };

    // 3. 尝试获取或执行拉取
    let code = match in_flight_cell.get_or_try_init(|| async {
        // 再次检查缓存（可能在等待锁期间被其他请求填充）
        {
            let mem = cache.memory.lock().unwrap();
            if let Some(entry) = mem.get(url) {
                let age = SystemTime::now()
                    .duration_since(entry.last_check)
                    .unwrap_or(Duration::MAX);
                if age < CACHE_TTL {
                    info!("[ScriptCache] 缓存命中（等待后）: {}", url);
                    return Ok::<String, anyhow::Error>(entry.code.clone());
                }
            }
        }

        // 执行拉取
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
    }).await {
        Ok(code) => code.clone(),
        Err(_) => String::new(),
    };

    // 4. 清理 in_flight 记录
    {
        let mut in_flight = cache.in_flight.lock().unwrap();
        in_flight.remove(url);
    }

    Ok(code)
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
