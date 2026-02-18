use anyhow::{anyhow, Result};
use http::{header::{HeaderName, HeaderValue}, Response};
use hyper::{
    body::{to_bytes, Body, Bytes},
    Request,
};
use rquickjs::{Context, Runtime, Object, Value, function::Func};
use std::collections::HashMap;

/// 辅助函数：将 hyper 的内容转换为 JS Object
fn create_js_request_object<'js>(
    ctx: &rquickjs::Ctx<'js>,
    parts: &http::request::Parts,
    body_bytes: &Bytes,
) -> Result<Object<'js>> {
    let obj = Object::new(ctx.clone())?;

    // 转换 Headers 为 JS 对象
    let js_headers = Object::new(ctx.clone())?;
    for (name, value) in &parts.headers {
        js_headers.set(
            name.to_string(),
            value.to_str().unwrap_or_default().to_string(),
        )?;
    }
    obj.set("headers", js_headers)?;

    // 设置 Method 和 URL
    obj.set("method", parts.method.to_string())?;
    obj.set("url", parts.uri.to_string())?;

    // 设置 Body
    if let Ok(text) = String::from_utf8(body_bytes.to_vec()) {
        obj.set("body", text)?;
    } else {
        obj.set("body", Value::new_undefined(ctx.clone()))?;
    }

    Ok(obj)
}

pub async fn modify_req(code: &str, req: Request<Body>) -> Result<Request<Body>> {
    let (mut parts, body) = req.into_parts();
    let body_bytes = to_bytes(body).await.unwrap_or_default();

    let runtime = Runtime::new()?;
    let context = Context::full(&runtime)?;

    context.with(|ctx| {
        let data = Object::new(ctx.clone())?;
        let req_js = create_js_request_object(&ctx, &parts, &body_bytes)?;
        data.set("request", req_js)?;
        ctx.globals().set("data", data)?;

        let console = Object::new(ctx.clone())?;
        console.set("log", Func::from(|msg: String| {
            println!("[JS LOG] {}", msg);
        }))?;
        ctx.globals().set("console", console)?;

        // 执行 JS，返回值通常是一个 Object
        let ret: Object = ctx.eval(code).map_err(|e| anyhow!("JS Eval Error: {:?}", e))?;

        // 核心修正：使用 .get::<_, HashMap<String, String>> 直接触发 FromJs 转换
        if let Ok(Some(headers_map)) = ret.get::<_, Option<HashMap<String, String>>>("headers") {
            for (key, value) in headers_map {
                // 显式指定 HeaderName 和 HeaderValue 的转换
                let name = HeaderName::from_bytes(key.as_bytes())?;
                let val = HeaderValue::from_str(&value)?;
                parts.headers.insert(name, val);
            }
        }

        if let Ok(Some(url)) = ret.get::<_, Option<String>>("url") {
            parts.uri = url.parse()?;
        }

        let new_body = if let Ok(Some(body_str)) = ret.get::<_, Option<String>>("body") {
            Bytes::from(body_str)
        } else {
            body_bytes.clone()
        };

        Ok(Request::from_parts(parts, Body::from(new_body)))
    })
}

pub async fn modify_res(code: &str, res: Response<Body>) -> Result<Response<Body>> {
    let (mut parts, body) = res.into_parts();
    let body_bytes = to_bytes(body).await.unwrap_or_default();

    let runtime = Runtime::new()?;
    let context = Context::full(&runtime)?;

    context.with(|ctx| {
        let data = Object::new(ctx.clone())?;
        let res_js = Object::new(ctx.clone())?;
        let js_headers = Object::new(ctx.clone())?;
        for (name, value) in &parts.headers {
            js_headers.set(name.to_string(), value.to_str().unwrap_or_default().to_string())?;
        }
        res_js.set("headers", js_headers)?;
        if let Ok(text) = String::from_utf8(body_bytes.to_vec()) {
            res_js.set("body", text)?;
        }

        data.set("response", res_js)?;
        ctx.globals().set("data", data)?;

        let console = Object::new(ctx.clone())?;
        console.set("log", Func::from(|msg: String| {
            println!("[JS LOG] {}", msg);
        }))?;
        ctx.globals().set("console", console)?;

        let ret: Object = ctx.eval(code).map_err(|e| anyhow!("JS Eval Error: {:?}", e))?;

        // 同上，处理响应头
        if let Ok(Some(headers_map)) = ret.get::<_, Option<HashMap<String, String>>>("headers") {
            for (key, value) in headers_map {
                let name = HeaderName::from_bytes(key.as_bytes())?;
                let val = HeaderValue::from_str(&value)?;
                parts.headers.insert(name, val);
            }
        }

        let new_body = if let Ok(Some(body_str)) = ret.get::<_, Option<String>>("body") {
            Bytes::from(body_str)
        } else {
            body_bytes.clone()
        };

        Ok(Response::from_parts(parts, Body::from(new_body)))
    })
}
