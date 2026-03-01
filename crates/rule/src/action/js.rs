use anyhow::{Result};
use http::{header::HeaderName, Response, Uri};
use hyper::{
    body::{to_bytes, Body, Bytes},
    Request,
};
use rquickjs::{Runtime, Context, Object};
use std::str::FromStr;
use rquickjs_extra_console::{Console, Formatter};

macro_rules! to_js_object {
    ($ctx:expr, $parts:expr, $body_bytes:expr) => {{
        let console = Console::new("js-action", Formatter::default());
        $ctx.globals().set("console", console)?;

        let obj = Object::new($ctx.clone())?;

        // headers
        let headers = Object::new($ctx.clone())?;
        for (name, value) in &$parts.headers {
            headers.set(
                name.to_string(),
                value.to_str().unwrap_or_default(),
            )?;
        }
        obj.set("headers", headers)?;

        // body
        if let Ok(text) = String::from_utf8($body_bytes.to_vec()) {
            obj.set("body", text)?;
        }

        obj
    }};
}

pub async fn modify_req(code: &str, req: Request<Body>) -> Result<Request<Body>> {
    let (mut parts, body) = req.into_parts();
    let body_bytes = to_bytes(body).await.unwrap_or_default();

    let runtime = Runtime::new()?;
    let context = Context::full(&runtime)?;
    context.with(|ctx| -> Result<_> {
        let req_obj = to_js_object!(&ctx, &parts, &body_bytes);
        req_obj.set("method", parts.method.to_string())?;
        req_obj.set("url", parts.uri.to_string())?;

        let globals = ctx.globals();
        globals.set("$request", req_obj)?;
        let result: Object = ctx.eval(code)?;

        // headers
        if let Ok(headers) = result.get::<_, Object>("headers") {
            for entry in headers.props::<String, String>() {
                let (key, value) = entry?;
                parts.headers.insert(
                    HeaderName::from_str(&key)?,
                    value.parse()?,
                );
            }
        }

        // url
        if let Ok(url) = result.get::<_, String>("url") {
            parts.uri = url.parse()?;
        }

        // body
        let body = if let Ok(body) = result.get::<_, String>("body") {
            Bytes::from(body)
        } else {
            body_bytes
        };
        Ok(Request::from_parts(parts, Body::from(body)))
    })
}

pub async fn modify_res(code: &str, req_url: &Uri, res: Response<Body>) -> Result<Response<Body>> {
    let (mut parts, body) = res.into_parts();
    let body_bytes = to_bytes(body).await.unwrap_or_default();

    let runtime = Runtime::new()?;
    let context = Context::full(&runtime)?;
    context.with(|ctx| -> Result<_> {
        let req_obj = Object::new(ctx.clone())?;
        req_obj.set("url", req_url.to_string())?;
        let res_obj = to_js_object!(&ctx, &parts, &body_bytes);

        let globals = ctx.globals();
        globals.set("$request", req_obj)?;
        globals.set("$response", res_obj)?;
        let result: Object = ctx.eval(code)?;

        // headers
        if let Ok(headers) = result.get::<_, Object>("headers") {
            for entry in headers.props::<String, String>() {
                let (key, value) = entry?;
                parts.headers.insert(
                    HeaderName::from_str(&key)?,
                    value.parse()?,
                );
            }
        }

        // body
        let body = if let Ok(body) = result.get::<_, String>("body") {
            Bytes::from(body)
        } else {
            body_bytes
        };
        Ok(Response::from_parts(parts, Body::from(body)))
    })
}
