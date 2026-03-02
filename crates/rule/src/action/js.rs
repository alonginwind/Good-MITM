use anyhow::{Result};
use http::{header::HeaderName, Response, Uri};
use hyper::{
    body::{to_bytes, Body, Bytes},
    Request,
};
use rquickjs::{Runtime, Context, Object, function::Func, Value, Error, TypedArray, ArrayBuffer};
use std::{str::FromStr, rc::Rc, cell::RefCell};
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

        // $done
        let result_data: Rc<RefCell<Option<(Vec<(String, String)>, Vec<u8>)>>> = Rc::new(RefCell::new(None));
        let result_clone = result_data.clone();
        let js_done = Func::from(move |obj: Value| -> Result<(), Error> {
            if let Some(obj_ref) = obj.as_object() {
                // 提取 headers
                let mut headers = Vec::new();
                if let Ok(headers_obj) = obj_ref.get::<_, Object>("headers") {
                    let props = headers_obj.props::<String, String>();
                    for entry in props {
                        if let Ok((key, value)) = entry {
                            headers.push((key, value));
                        }
                    }
                }

                // 提取 body - 支持多种类型
                let body: Vec<u8> = if let Ok(body_str) = obj_ref.get::<_, String>("body") {
                    body_str.into_bytes()
                } else if let Ok(body_binary) = obj_ref.get::<_, TypedArray<u8>>("body") {
                    // TypedArray: as_bytes() 返回 Option<&[u8]>
                    body_binary.as_bytes().map(|bytes| bytes.to_vec()).unwrap_or_default()
                } else if let Ok(body_array) = obj_ref.get::<_, ArrayBuffer>("body") {
                    // ArrayBuffer: as_bytes() 返回 Option<&[u8]>
                    body_array.as_bytes().map(|bytes| bytes.to_vec()).unwrap_or_default()
                } else {
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
        globals.set("$response", res_obj)?;
        globals.set("$done", js_done)?;

        // 执行 JS，得到返回值
        let result_val: Value = ctx.eval(code)?;
        // 优先使用 $done 回传的结果
        if let Some((headers, body)) = result_data.borrow().as_ref() {
            // headers
            for (key, value) in headers {
                parts.headers.insert(
                    HeaderName::from_str(key)?,
                    value.parse()?,
                );
            }

            // body
            let body = if !body.is_empty() {
                Bytes::from(body.clone())
            } else {
                body_bytes
            };
            return Ok(Response::from_parts(parts, Body::from(body)));
        }

        // 如果没有调用 $done，则尝试使用 JS return 的对象
        if let Some(result) = result_val.as_object() {
            // headers
            if let Ok(headers) = result.get::<_, Object>("headers") {
                for entry in headers.props::<String, String>() {
                    let (key, value) = entry?;
                    let key = key.to_string();
                    let value = value.to_string();
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
            return Ok(Response::from_parts(parts, Body::from(body)));
        }

        // JS没返回结果，也没调用$done，返回原始Response
        Ok(Response::from_parts(parts, Body::from(body_bytes)))
    })
}
