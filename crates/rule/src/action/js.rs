use crate::handler::JsInfo;
use anyhow::Result;
use http::{header::HeaderName, Response};
use hyper::{
    body::{to_bytes, Body, Bytes},
    Request,
};
use rquickjs::Module;
use rquickjs::WriteOptions;
use rquickjs::{
    async_with, function::Func, ArrayBuffer, AsyncContext, AsyncRuntime, CatchResultExt, Error,
    Function, Object, TypedArray, Value,
};
use rquickjs_extra_console::{Console, Formatter};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, OnceLock};
use std::{collections::HashMap, str::FromStr};
use tokio::sync::oneshot;

static BYTECODE_CACHE: OnceLock<Mutex<HashMap<u64, Vec<u8>>>> = OnceLock::new();
static PERSISTENT_STORE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn get_cache() -> &'static Mutex<HashMap<u64, Vec<u8>>> {
    BYTECODE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_persistent_store() -> &'static Mutex<HashMap<String, String>> {
    PERSISTENT_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn code_hash(code: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    code.hash(&mut hasher);
    hasher.finish()
}

macro_rules! to_js_object {
    (
        $ctx:expr,
        $parts:expr,
        $body_bytes:expr,
        $requires_body:expr,
        $binary_body_mode:expr
    ) => {{
        let console = Console::new("js-action", Formatter::default());
        $ctx.globals().set("console", console)?;

        let obj = Object::new($ctx.clone())?;

        // headers
        let headers = Object::new($ctx.clone())?;
        for (name, value) in &$parts.headers {
            headers.set(name.to_string(), value.to_str().unwrap_or_default())?;
        }
        obj.set("headers", headers)?;

        if $requires_body == 1 {
            // body
            let body_bytes = $body_bytes.to_vec();
            if $binary_body_mode == 1 {
                let uint8_array = TypedArray::<u8>::new($ctx.clone(), body_bytes)?;
                obj.set("body", uint8_array)?;
            } else if let Ok(text) = std::str::from_utf8(&body_bytes) {
                obj.set("body", text)?;
            }
        }

        obj
    }};
}

pub async fn modify_req(code: &str, js_info: &JsInfo, req: Request<Body>) -> Result<Request<Body>> {
    let (mut parts, body) = req.into_parts();
    let body_bytes = to_bytes(body).await.unwrap_or_default();

    // 全局字节码缓存
    let hash = code_hash(code);
    let cached = {
        let cache = get_cache().lock().unwrap();
        cache.get(&hash).cloned()
    };

    let runtime = AsyncRuntime::new()?;
    let context = AsyncContext::full(&runtime).await?;

    // 首次编译成字节码并缓存
    let bytecode = if let Some(bc) = cached {
        bc
    } else {
        let code_str = code.to_string();
        let bc = async_with!(context => |ctx| {
            let module = Module::declare(ctx.clone(), "script.mjs", code_str)?;
            module.write(WriteOptions::default())
                .map_err(|_| Error::Unknown)
        })
        .await?;
        {
            let mut cache = get_cache().lock().unwrap();
            cache.entry(hash).or_insert_with(|| bc.clone());
        }
        log::info!("首次编译字节码");
        bc
    };

    async_with!(context => |ctx| {
        let req_obj = to_js_object!(&ctx, &parts, &body_bytes, js_info.requires_body, js_info.binary_body_mode);
        req_obj.set("method", parts.method.to_string())?;
        req_obj.set("url", parts.uri.to_string())?;

        // $done - 使用 oneshot 通道通知完成
        let (done_tx, done_rx) = oneshot::channel::<(Vec<(String, String)>, Vec<u8>)>();
        let done_tx = std::sync::Mutex::new(Some(done_tx));
        let js_done = Func::from(move |obj: Value| -> Result<(), Error> {
            if let Some(obj_ref) = obj.as_object() {
                let mut headers = Vec::new();
                if let Ok(headers_obj) = obj_ref.get::<_, Object>("headers") {
                    let props = headers_obj.props::<String, String>();
                    for entry in props {
                        if let Ok((key, value)) = entry {
                            headers.push((key, value));
                        }
                    }
                }

                let body: Vec<u8> = if let Ok(body_str) = obj_ref.get::<_, String>("body") {
                    log::info!("收到字符串数据");
                    body_str.into_bytes()
                } else if let Ok(body_binary) = obj_ref.get::<_, TypedArray<u8>>("body") {
                    log::info!("收到TypedArray数据");
                    body_binary.as_bytes().map(|bytes| bytes.to_vec()).unwrap_or_default()
                } else if let Ok(body_array) = obj_ref.get::<_, ArrayBuffer>("body") {
                    log::info!("收到ArrayBuffer数据");
                    body_array.as_bytes().map(|bytes| bytes.to_vec()).unwrap_or_default()
                } else {
                    log::warn!("未收到body数据");
                    Vec::new()
                };
                // 发送信号
                if let Some(tx) = done_tx.lock().unwrap().take() {
                    let _ = tx.send((headers, body));
                }
            } else {
                log::error!("$done 回传不是对象");
                return Err(Error::new_from_js("TypeError", "$done 回传不是对象"));
            }
            Ok(())
        });

        // $persistentStore - 使用全局存储
        let read_method = Func::from(move |key: String| -> Result<Option<String>, Error> {
            log::info!("[read] 被调用");
            let store = get_persistent_store().lock().unwrap();
            Ok(store.get(&key).cloned())
        });
        let write_method = Func::from(move |key: String, value: String| -> Result<(), Error> {
            log::info!("[write] 被调用");
            let mut store = get_persistent_store().lock().unwrap();
            store.insert(key, value);
            Ok(())
        });
        let persistent_store = Object::new(ctx.clone())?;
        persistent_store.set("read", read_method)?;
        persistent_store.set("write", write_method)?;

        // $httpClient
        let http_client = Object::new(ctx.clone())?;
        let get_func = Func::from(move |_options: Object, callback: Function| -> Result<(), Error> {
            log::info!("[HTTP GET] 被调用");
            let ctx = callback.ctx().clone();
            let null_val = Value::new_null(ctx);
            callback.call::<_, ()>((null_val.clone(), null_val.clone(), null_val))?;
            Ok(())
        });
        http_client.set("get", get_func)?;

        // 注入全局变量
        let globals = ctx.globals();
        globals.set("$request", req_obj)?;
        globals.set("$done", js_done)?;
        globals.set("$persistentStore", persistent_store)?;
        globals.set("$httpClient", http_client)?;

        // 从字节码加载
        let module = match unsafe { Module::load(ctx.clone(), &bytecode) } {
            Ok(m) => m,
            Err(e) => {
                log::error!("字节码加载失败: {:?}--异常输出: {:?}", e, ctx.catch());
                return Ok(Request::from_parts(parts, Body::from(body_bytes)));
            }
        };

        // 执行模块
        let (_, promise) = match module.eval() {
            Ok(v) => v,
            Err(e) => {
                log::error!("JS 执行失败: {:?}--异常输出: {:?}", e, ctx.catch());
                return Ok(Request::from_parts(parts, Body::from(body_bytes)));
            }
        };

        // 等待 Promise
        match promise.into_future::<Value>().await.catch(&ctx) {
            Ok(val) => {
                log::info!("JS Promise 完成");
                Some(val)
            },
            Err(e) => {
                log::error!("JS Promise 失败: {}", e);
                None
            }
        };

        // 等待 $done 被调用（最多等待 8 秒）
        let done_result = match tokio::time::timeout(std::time::Duration::from_secs(8), done_rx).await {
            Ok(Ok(result)) => Some(result),
            Ok(Err(_)) => {
                log::error!("$done 通道被关闭");
                None
            }
            Err(_) => {
                log::warn!("等待 $done 超时（8秒）");
                None
            }
        };

        // 使用 $done 回传的结果
        if let Some((headers, body)) = done_result {
            for (key, value) in &headers {
                if let Ok(header_name) = HeaderName::from_str(key) {
                    if let Ok(header_value) = value.parse() {
                        parts.headers.insert(header_name, header_value);
                    }
                }
            }
            let body = if !body.is_empty() {
                Bytes::from(body)
            } else {
                body_bytes
            };
            return Ok(Request::from_parts(parts, Body::from(body)));
        }

        log::warn!("JS 执行完成，但没有调用 $done");
        Ok(Request::from_parts(parts, Body::from(body_bytes)))
    }).await
}

pub async fn modify_res(
    code: &str,
    js_info: &JsInfo,
    res: Response<Body>,
) -> Result<Response<Body>> {
    let (mut parts, body) = res.into_parts();
    let body_bytes = to_bytes(body).await.unwrap_or_default();

    // 全局字节码缓存
    let hash = code_hash(code);
    let cached = {
        let cache = get_cache().lock().unwrap();
        cache.get(&hash).cloned()
    };

    let runtime = AsyncRuntime::new()?;
    let context = AsyncContext::full(&runtime).await?;

    // 首次编译成字节码并缓存
    let bytecode = if let Some(bc) = cached {
        bc
    } else {
        let code_str = code.to_string();
        let bc = async_with!(context => |ctx| {
            let module = Module::declare(ctx.clone(), "script.mjs", code_str)?;
            module.write(WriteOptions::default())
                .map_err(|_| Error::Unknown)
        })
        .await?;
        {
            let mut cache = get_cache().lock().unwrap();
            cache.entry(hash).or_insert_with(|| bc.clone());
        }
        log::info!("首次编译字节码");
        bc
    };

    async_with!(context => |ctx| {
        let req_obj = Object::new(ctx.clone())?;
        req_obj.set("url", js_info.uri.to_string())?;
        req_obj.set("method", js_info.method.to_string())?;
        // 添加请求头
        let req_headers = Object::new(ctx.clone())?;
        for (key, value) in &js_info.headers {
            req_headers.set(key.as_str(), value.as_str())?;
        }
        req_obj.set("headers", req_headers)?;
        let res_obj = to_js_object!(&ctx, &parts, &body_bytes, js_info.requires_body, js_info.binary_body_mode);
        let status_code = parts.status.as_u16();
        res_obj.set("status", status_code)?;

        // $done - 使用 oneshot 通道通知完成
        let (done_tx, done_rx) = oneshot::channel::<(Vec<(String, String)>, Vec<u8>)>();
        let done_tx = std::sync::Mutex::new(Some(done_tx));
        let js_done = Func::from(move |obj: Value| -> Result<(), Error> {
            if let Some(obj_ref) = obj.as_object() {
                let mut headers = Vec::new();
                if let Ok(headers_obj) = obj_ref.get::<_, Object>("headers") {
                    let props = headers_obj.props::<String, String>();
                    for entry in props {
                        if let Ok((key, value)) = entry {
                            headers.push((key, value));
                        }
                    }
                }

                let body: Vec<u8> = if let Ok(body_str) = obj_ref.get::<_, String>("body") {
                    log::info!("收到字符串数据");
                    body_str.into_bytes()
                } else if let Ok(body_binary) = obj_ref.get::<_, TypedArray<u8>>("body") {
                    log::info!("收到TypedArray数据");
                    body_binary.as_bytes().map(|bytes| bytes.to_vec()).unwrap_or_default()
                } else if let Ok(body_array) = obj_ref.get::<_, ArrayBuffer>("body") {
                    log::info!("收到ArrayBuffer数据");
                    body_array.as_bytes().map(|bytes| bytes.to_vec()).unwrap_or_default()
                } else {
                    log::warn!("未收到body数据");
                    Vec::new()
                };
                // 发送信号
                if let Some(tx) = done_tx.lock().unwrap().take() {
                    let _ = tx.send((headers, body));
                }
            } else {
                log::error!("$done 回传不是对象");
                return Err(Error::new_from_js("TypeError", "$done 回传不是对象"));
            }
            Ok(())
        });

        // $persistentStore - 使用全局存储
        let read_method = Func::from(move |key: String| -> Result<Option<String>, Error> {
            log::info!("[read] 被调用");
            let store = get_persistent_store().lock().unwrap();
            Ok(store.get(&key).cloned())
        });
        let write_method = Func::from(move |key: String, value: String| -> Result<(), Error> {
            log::info!("[write] 被调用");
            let mut store = get_persistent_store().lock().unwrap();
            store.insert(key, value);
            Ok(())
        });
        let persistent_store = Object::new(ctx.clone())?;
        persistent_store.set("read", read_method)?;
        persistent_store.set("write", write_method)?;

        // $httpClient
        let http_client = Object::new(ctx.clone())?;
        let get_func = Func::from(move |_options: Object, callback: Function| -> Result<(), Error> {
            log::info!("[HTTP GET] 被调用");
            let ctx = callback.ctx().clone();
            let null_val = Value::new_null(ctx);
            callback.call::<_, ()>((null_val.clone(), null_val.clone(), null_val))?;
            Ok(())
        });
        http_client.set("get", get_func)?;

        // 注入全局变量
        let globals = ctx.globals();
        globals.set("$request", req_obj)?;
        globals.set("$response", res_obj)?;
        globals.set("$done", js_done)?;
        globals.set("$persistentStore", persistent_store)?;
        globals.set("$httpClient", http_client)?;

        // 从字节码加载
        let module = match unsafe { Module::load(ctx.clone(), &bytecode) } {
            Ok(m) => m,
            Err(e) => {
                log::error!("字节码加载失败: {:?}--异常输出: {:?}", e, ctx.catch());
                return Ok(Response::from_parts(parts, Body::from(body_bytes)));
            }
        };

        // 执行模块
        let (_, promise) = match module.eval() {
            Ok(v) => v,
            Err(e) => {
                log::error!("JS 执行失败: {:?}--异常输出: {:?}", e, ctx.catch());
                return Ok(Response::from_parts(parts, Body::from(body_bytes)));
            }
        };

        // 等待 Promise
        match promise.into_future::<Value>().await.catch(&ctx) {
            Ok(val) => {
                log::info!("JS Promise 完成");
                Some(val)
            },
            Err(e) => {
                log::error!("JS Promise 失败: {}", e);
                None
            }
        };

        // 等待 $done 被调用（最多等待 8 秒）
        let done_result = match tokio::time::timeout(std::time::Duration::from_secs(8), done_rx).await {
            Ok(Ok(result)) => Some(result),
            Ok(Err(_)) => {
                log::error!("$done 通道被关闭");
                None
            }
            Err(_) => {
                log::warn!("等待 $done 超时（8秒）");
                None
            }
        };

        // 使用 $done 回传的结果
        if let Some((headers, body)) = done_result {
            for (key, value) in &headers {
                if let Ok(header_name) = HeaderName::from_str(key) {
                    if let Ok(header_value) = value.parse() {
                        parts.headers.insert(header_name, header_value);
                    }
                }
            }
            let body = if !body.is_empty() {
                Bytes::from(body)
            } else {
                body_bytes
            };
            return Ok(Response::from_parts(parts, Body::from(body)));
        }

        log::warn!("JS 执行完成，但没有调用 $done");
        Ok(Response::from_parts(parts, Body::from(body_bytes)))
    }).await
}
