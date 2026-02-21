use anyhow::Result;
use http::{
    header::{HeaderName, HeaderValue},
    Response,
};
use hyper::{
    body::{to_bytes, Body, Bytes},
    Request,
};
use rquickjs::{function::Func, ArrayBuffer, Context, Ctx, Object, Runtime, Value};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// ============================================================
/// 通用 HTTP → JS Object 宏
/// req / res 共用
/// ============================================================
macro_rules! create_js_http_object {
    (
        $ctx:expr,
        $parts:expr,
        $body_bytes:expr
        $(, method = $method:expr, url = $url:expr )?
    ) => {{
        let ctx = &$ctx;
        let obj = Object::new(ctx.clone())?;

        // headers
        let js_headers = Object::new(ctx.clone())?;
        for (name, value) in &$parts.headers {
            if let Ok(v) = value.to_str() {
                js_headers.set(name.to_string(), v.to_string())?;
            }
        }
        obj.set("headers", js_headers)?;

        // method + url（仅 request）
        $(
            obj.set("method", $method.to_string())?;
            obj.set("url", $url.to_string())?;
        )?

        // body
        if let Ok(text) = std::str::from_utf8(&$body_bytes) {
            obj.set("body", text)?;
        } else {
            let buffer = ArrayBuffer::new(ctx.clone(), $body_bytes.to_vec())?;
            obj.set("body", buffer)?;
        }

        obj
    }};
}

/// ============================================================
/// 注入 Surge / Quantumult X 风格 JS 运行时
/// ============================================================
fn inject_surge_runtime<'js>(
    ctx: &Ctx<'js>,
    req: Option<Object<'js>>,
    res: Option<Object<'js>>,
) -> Result<Rc<RefCell<Option<String>>>> {
    let globals = ctx.globals();

    // =========================
    // 注入 $request / $response
    // =========================
    match req {
        Some(r) => globals.set("$request", r)?,
        None => globals.set("$request", ())?,
    }
    match res {
        Some(r) => globals.set("$response", r)?,
        None => globals.set("$response", ())?,
    }

    // =========================
    // console.log
    // =========================
    let console = Object::new(ctx.clone())?;
    console.set(
        "log",
        Func::from(|msg: String| {
            println!("[JS LOG] {}", msg);
        }),
    )?;
    globals.set("console", console)?;

    // =========================
    // $prefs & $persistentStore
    // =========================
    let storage = Object::new(ctx.clone())?;
    storage.set(
        "valueForKey",
        Func::from(|key: String| -> Option<String> {
            println!("[JS PREFS READ] {}", key);
            None
        }),
    )?;
    storage.set(
        "setValueForKey",
        Func::from(|value: String, key: String| {
            println!("[JS PREFS WRITE] {}={}", key, value);
        }),
    )?;
    globals.set("$prefs", storage.clone())?;
    globals.set("$persistentStore", storage)?;

    // =========================
    // $task.fetch
    // =========================
    let task = Object::new(ctx.clone())?;
    task.set(
        "fetch",
        Func::from(|ctx: Ctx<'js>, _opts: Object<'js>| -> rquickjs::Result<Object<'js>> {
            println!("[JS FETCH CALLED]");
            Ok(Object::new(ctx)?)
        }),
    )?;
    globals.set("$task", task)?;

    // =========================
    // $httpClient
    // =========================
    let http_client = Object::new(ctx.clone())?;
    http_client.set(
        "get",
        Func::from(|_opts: Object| {
            println!("[JS HTTP GET]");
        }),
    )?;
    http_client.set(
        "post",
        Func::from(|_opts: Object| {
            println!("[JS HTTP POST]");
        }),
    )?;
    globals.set("$httpClient", http_client)?;

    // =========================
    // $done
    // =========================
    let done_result: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let done_clone = done_result.clone();

    globals.set(
        "$done",
        Func::from(move |ctx: Ctx<'js>, obj: Value<'js>| -> rquickjs::Result<()> {
            let json = ctx
                .json_stringify(obj)?
                .ok_or_else(|| {
                    rquickjs::Error::new_from_js_message(
                        "object",
                        "string",
                        "Failed to stringify JS object",
                    )
                })?
                .to_string()?;

            *done_clone.borrow_mut() = Some(json);
            Ok(())
        }),
    )?;

    Ok(done_result)
}

/// ============================================================
/// JS 返回 body 解析函数
/// ============================================================
fn parse_js_body(ret: &Object, original: &Bytes) -> Result<Bytes> {
    // string
    if let Ok(Some(body_str)) = ret.get::<_, Option<String>>("body") {
        return Ok(Bytes::from(body_str));
    }

    // ArrayBuffer
    if let Ok(Some(buffer)) = ret.get::<_, Option<ArrayBuffer>>("body") {
        if let Some(bytes) = buffer.as_bytes() {
            return Ok(Bytes::from(bytes.to_vec()));
        } else {
            return Ok(original.clone());
        }
    }

    // Uint8Array -> buffer
    if let Ok(Some(obj)) = ret.get::<_, Option<Object>>("body") {
        if let Ok(Some(buffer)) = obj.get::<_, Option<ArrayBuffer>>("buffer") {
            if let Some(bytes) = buffer.as_bytes() {
                return Ok(Bytes::from(bytes.to_vec()));
            } else {
                return Ok(original.clone());
            }
        } else {
            return Ok(original.clone());
        }
    }

    // fallback
    Ok(original.clone())
}

/// ============================================================
/// 修改请求
/// ============================================================
pub async fn modify_req(code: &str, req: Request<Body>) -> Result<Request<Body>> {
    let (mut parts, body) = req.into_parts();
    let body_bytes = to_bytes(body).await.unwrap_or_default();

    let runtime = Runtime::new()?;
    let context = Context::full(&runtime)?;

    context.with(|ctx| {
        let req_js = create_js_http_object!(ctx, parts, body_bytes, method = parts.method, url = parts.uri);
        let done_result = inject_surge_runtime(&ctx, Some(req_js.clone()), None)?;

        ctx.eval::<(), _>(code)?;

        let ret = if let Some(json_str) = done_result.borrow().clone() {
            ctx.eval::<Object, _>(json_str)?
        } else {
            Object::new(ctx.clone())?
        };

        // headers
        if let Ok(Some(headers_map)) = ret.get::<_, Option<HashMap<String, String>>>("headers") {
            for (key, value) in headers_map {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(&value),
                ) {
                    parts.headers.insert(name, val);
                }
            }
        }

        // url
        if let Ok(Some(url)) = ret.get::<_, Option<String>>("url") {
            if let Ok(uri) = url.parse() {
                parts.uri = uri;
            }
        }

        // body
        let new_body = parse_js_body(&ret, &body_bytes)?;

        Ok(Request::from_parts(parts, Body::from(new_body)))
    })
}

/// ============================================================
/// 修改响应
/// ============================================================
pub async fn modify_res(code: &str, res: Response<Body>) -> Result<Response<Body>> {
    let (mut parts, body) = res.into_parts();
    let body_bytes = to_bytes(body).await.unwrap_or_default();

    let runtime = Runtime::new()?;
    let context = Context::full(&runtime)?;

    context.with(|ctx| {
        let res_js = create_js_http_object!(ctx, parts, body_bytes);
        let done_result = inject_surge_runtime(&ctx, None, Some(res_js.clone()))?;

        ctx.eval::<(), _>(code)?;

        let ret = if let Some(json_str) = done_result.borrow().clone() {
            ctx.eval::<Object, _>(json_str)?
        } else {
            Object::new(ctx.clone())?
        };

        // headers
        if let Ok(Some(headers_map)) = ret.get::<_, Option<HashMap<String, String>>>("headers") {
            for (key, value) in headers_map {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(&value),
                ) {
                    parts.headers.insert(name, val);
                }
            }
        }

        // body
        let new_body = parse_js_body(&ret, &body_bytes)?;

        Ok(Response::from_parts(parts, Body::from(new_body)))
    })
}
