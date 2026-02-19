use anyhow::{anyhow, Result};
use http::{
    header::{HeaderName, HeaderValue},
    Response,
};
use hyper::{
    body::{to_bytes, Body, Bytes},
    Request,
};
use rquickjs::{
    function::Func,
    ArrayBuffer, Context, Object, Runtime,
};
use std::collections::HashMap;


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
            let buffer = ArrayBuffer::new(
                ctx.clone(),
                $body_bytes.to_vec(),
            )?;
            obj.set("body", buffer)?;
        }

        obj
    }};
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
        let data = Object::new(ctx.clone())?;
        let req_js = create_js_http_object!(
            ctx,
            parts,
            body_bytes,
            method = parts.method,
            url = parts.uri
        );

        data.set("request", req_js)?;
        ctx.globals().set("data", data)?;

        // console.log
        let console = Object::new(ctx.clone())?;
        console.set(
            "log",
            Func::from(|msg: String| {
                println!("[JS LOG] {}", msg);
            }),
        )?;
        ctx.globals().set("console", console)?;

        // 执行 JS
        let ret: Object =
            ctx.eval(code).map_err(|e| anyhow!("JS Eval Error: {:?}", e))?;

        // 处理 headers
        if let Ok(Some(headers_map)) =
            ret.get::<_, Option<HashMap<String, String>>>("headers")
        {
            for (key, value) in headers_map {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(&value),
                ) {
                    parts.headers.insert(name, val);
                }
            }
        }

        // 处理 url
        if let Ok(Some(url)) = ret.get::<_, Option<String>>("url") {
            if let Ok(uri) = url.parse() {
                parts.uri = uri;
            }
        }

        // 处理 body
        let new_body = if let Ok(Some(body_str)) =
            ret.get::<_, Option<String>>("body")
        {
            Bytes::from(body_str)
        } else {
            body_bytes.clone()
        };

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
        let data = Object::new(ctx.clone())?;
        let res_js = create_js_http_object!(
            ctx,
            parts,
            body_bytes
        );

        data.set("response", res_js)?;
        ctx.globals().set("data", data)?;

        // console.log
        let console = Object::new(ctx.clone())?;
        console.set(
            "log",
            Func::from(|msg: String| {
                println!("[JS LOG] {}", msg);
            }),
        )?;
        ctx.globals().set("console", console)?;

        let ret: Object =
            ctx.eval(code).map_err(|e| anyhow!("JS Eval Error: {:?}", e))?;

        // headers
        if let Ok(Some(headers_map)) =
            ret.get::<_, Option<HashMap<String, String>>>("headers")
        {
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
        let new_body = if let Ok(Some(body_str)) =
            ret.get::<_, Option<String>>("body")
        {
            Bytes::from(body_str)
        } else {
            body_bytes.clone()
        };

        Ok(Response::from_parts(parts, Body::from(new_body)))
    })
}
