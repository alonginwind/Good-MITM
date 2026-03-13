use anyhow::Result;
use http::{header::HeaderName, Response, Uri};
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
use std::{cell::RefCell, collections::HashMap, rc::Rc, str::FromStr};

static BYTECODE_CACHE: OnceLock<Mutex<HashMap<u64, Vec<u8>>>> = OnceLock::new();

fn get_cache() -> &'static Mutex<HashMap<u64, Vec<u8>>> {
    BYTECODE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn code_hash(code: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    code.hash(&mut hasher);
    hasher.finish()
}

macro_rules! to_js_object {
    ($ctx:expr, $parts:expr, $body_bytes:expr) => {{
        let console = Console::new("js-action", Formatter::default());
        $ctx.globals().set("console", console)?;

        let obj = Object::new($ctx.clone())?;

        // headers
        let headers = Object::new($ctx.clone())?;
        for (name, value) in &$parts.headers {
            headers.set(name.to_string(), value.to_str().unwrap_or_default())?;
        }
        obj.set("headers", headers)?;

        let body_bytes = $body_bytes.to_vec();
        // body
        if let Ok(text) = std::str::from_utf8(&body_bytes) {
            obj.set("body", text)?;
        }
        // 始终提供 bodyBytes 字段（二进制数据）
        let uint8_array = TypedArray::<u8>::new($ctx.clone(), body_bytes)?;
        obj.set("bodyBytes", uint8_array)?;

        obj
    }};
}

pub async fn modify_req(code: &str, req: Request<Body>) -> Result<Request<Body>> {
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
        let req_obj = to_js_object!(&ctx, &parts, &body_bytes);
        req_obj.set("method", parts.method.to_string())?;
        req_obj.set("url", parts.uri.to_string())?;

        // $done
        let result_data: Rc<RefCell<Option<(Vec<(String, String)>, Vec<u8>)>>> = Rc::new(RefCell::new(None));
        let result_clone = result_data.clone();
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

                *result_clone.borrow_mut() = Some((headers, body));
            } else {
                log::error!("$done 回传不是对象");
                return Err(Error::new_from_js("TypeError", "$done 回传不是对象"));
            }
            Ok(())
        });

        // 注入全局变量
        let globals = ctx.globals();
        globals.set("$request", req_obj)?;
        globals.set("$done", js_done)?;

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

        // 使用 $done 回传的结果
        if let Some((headers, body)) = result_data.borrow().as_ref() {
            for (key, value) in headers {
                if let Ok(header_name) = HeaderName::from_str(&key) {
                    if let Ok(header_value) = value.parse() {
                        parts.headers.insert(header_name, header_value);
                    }
                }
            }
            let body = if !body.is_empty() {
                Bytes::from(body.clone())
            } else {
                body_bytes
            };
            return Ok(Request::from_parts(parts, Body::from(body)));
        }

        log::warn!("JS 执行完成，但没有调用 $done");
        Ok(Request::from_parts(parts, Body::from(body_bytes)))
    }).await
}

pub async fn modify_res(code: &str, req_url: &Uri, res: Response<Body>) -> Result<Response<Body>> {
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
        req_obj.set("url", req_url.to_string())?;
        let res_obj = to_js_object!(&ctx, &parts, &body_bytes);

        // $done
        let result_data: Rc<RefCell<Option<(Vec<(String, String)>, Vec<u8>)>>> = Rc::new(RefCell::new(None));
        let result_clone = result_data.clone();
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
                *result_clone.borrow_mut() = Some((headers, body));
            } else {
                log::error!("$done 回传不是对象");
                return Err(Error::new_from_js("TypeError", "$done 回传不是对象"));
            }
            Ok(())
        });

        // $persistentStore
        let store_data: Rc<RefCell<HashMap<String, String>>> = Rc::new(RefCell::new(HashMap::new()));
        let store_data_read = store_data.clone();
        let read_method = Func::from(move |key: String| -> Result<String, Error> {
            log::info!("[read] 被调用");
            let store = store_data_read.borrow();
            Ok(store.get(&key).cloned().unwrap_or_default())
        });
        let store_data_write = store_data.clone();
        let write_method = Func::from(move |key: String, value: String| -> Result<(), Error> {
            log::info!("[write] 被调用");
            let mut store = store_data_write.borrow_mut();
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

        // 使用 $done 回传的结果
        if let Some((headers, body)) = result_data.borrow().as_ref() {
            for (key, value) in headers {
                if let Ok(header_name) = HeaderName::from_str(&key) {
                    if let Ok(header_value) = value.parse() {
                        parts.headers.insert(header_name, header_value);
                    }
                }
            }
            let body = if !body.is_empty() {
                Bytes::from(body.clone())
            } else {
                body_bytes
            };
            return Ok(Response::from_parts(parts, Body::from(body)));
        }

        log::warn!("JS 执行完成，但没有调用 $done");
        Ok(Response::from_parts(parts, Body::from(body_bytes)))
    }).await
}
