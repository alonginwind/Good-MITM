pub use action::Action;
pub use filter::Filter;
pub use handler::*;
use hyper::{header, header::HeaderValue, Body, Request, Response, StatusCode};
use log::*;
use mitm_core::mitm::RequestOrResponse;
use std::vec::Vec;

mod action;
mod cache;
mod filter;
mod handler;

#[derive(Debug, Clone)]
pub struct Rule {
    pub filters: Vec<Filter>,
    pub actions: Vec<Action>,

    pub url: Option<String>,
}

impl Rule {
    pub async fn do_req(&mut self, req: Request<Body>, js_info: &JsInfo) -> RequestOrResponse {
        let url = req.uri().to_string();
        self.url = Some(url.clone());
        let mut tmp_req = req;

        for action in &self.actions {
            match action {
                Action::Reject(status_code) => {
                    let status =
                        StatusCode::from_u16(*status_code).unwrap_or(StatusCode::BAD_GATEWAY);
                    info!("[Reject-{}] {}", status, url);
                    let res = Response::builder()
                        .status(status)
                        .body(Body::default())
                        .unwrap();

                    return RequestOrResponse::Response(res);
                }

                Action::Redirect(target) => {
                    if target.contains('$') {
                        for filter in self.filters.clone() {
                            if let Filter::UrlRegex(re) = filter {
                                let target = cache::get_regex(&re)
                                    .replace(tmp_req.uri().to_string().as_str(), target.as_str())
                                    .to_string();
                                if let Ok(target_url) = HeaderValue::from_str(target.as_str()) {
                                    let mut res = Response::builder()
                                        .status(StatusCode::FOUND)
                                        .body(Body::default())
                                        .unwrap();
                                    res.headers_mut().insert(header::LOCATION, target_url);
                                    info!("[Redirect] {} -> {}", url, target);
                                    return RequestOrResponse::Response(res);
                                }
                            }
                        }
                    }
                    if let Ok(target_url) = HeaderValue::from_str(target.as_str()) {
                        let mut res = Response::builder()
                            .status(StatusCode::FOUND)
                            .body(Body::default())
                            .unwrap();
                        res.headers_mut().insert(header::LOCATION, target_url);
                        info!("[Redirect] {} -> {}", url, target);
                        return RequestOrResponse::Response(res);
                    };
                }

                Action::ModifyRequest(modify) => {
                    info!("[ModifyRequest] {}", url);
                    match modify.modify_req(tmp_req).await {
                        Some(new_req) => tmp_req = new_req,
                        None => {
                            return RequestOrResponse::Response(
                                Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(Body::default())
                                    .unwrap(),
                            );
                        }
                    }
                }

                Action::LogReq => {
                    info!("[LogRequest] {}", url);
                    action::log_req(&tmp_req).await;
                }

                #[cfg(feature = "js")]
                Action::JsReq {
                    ref code,
                    requires_body,
                    binary_body_mode,
                } => {
                    info!("[LogRequest] {}", url);
                    // 提取需要在闭包中使用的数据
                    let code = code.clone();
                    let mut js_info = js_info.clone();
                    js_info.requires_body = *requires_body;
                    js_info.binary_body_mode = *binary_body_mode;
                    // 使用 spawn_blocking 处理非 Send 的 JS 执行
                    let result = tokio::task::spawn_blocking(move || {
                        // 创建新的运行时用于 JS 执行
                        let runtime = tokio::runtime::Runtime::new()
                            .expect("Failed to create runtime for JS execution");
                        runtime.block_on(async {
                            action::js::modify_req(&code, &js_info, tmp_req).await
                        })
                    })
                    .await;

                    match result {
                        Ok(Ok(modified_req)) => {
                            tmp_req = modified_req; // 更新响应，继续处理后续 actions
                        }
                        Ok(Err(e)) => {
                            error!("JS error: {}", e);
                            return RequestOrResponse::Response(
                                Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(Body::default())
                                    .unwrap(),
                            );
                        }
                        Err(e) => {
                            error!("Spawn error: {}", e);
                            return RequestOrResponse::Response(
                                Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(Body::default())
                                    .unwrap(),
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        RequestOrResponse::Request(tmp_req)
    }

    pub async fn do_res(&self, res: Response<Body>, js_info: &JsInfo) -> Response<Body> {
        let url = js_info.uri.to_string();
        let mut tmp_res = res;

        for action in &self.actions {
            match action {
                Action::ModifyResponse(modify) => {
                    info!("[ModifyResponse] {}", url);
                    tmp_res = modify.modify_res(tmp_res).await
                }
                Action::LogRes => {
                    info!("[LogResponse] {}", url);
                    action::log_res(&tmp_res).await;
                }

                #[cfg(feature = "js")]
                Action::JsRes {
                    ref code,
                    requires_body,
                    binary_body_mode,
                } => {
                    info!("[LogResponse] {}", url);
                    // 提取需要在闭包中使用的数据
                    let code = code.clone();
                    let mut js_info = js_info.clone();
                    js_info.requires_body = *requires_body;
                    js_info.binary_body_mode = *binary_body_mode;
                    // 使用 spawn_blocking 处理非 Send 的 JS 执行
                    let result = tokio::task::spawn_blocking(move || {
                        // 创建新的运行时用于 JS 执行
                        let runtime = tokio::runtime::Runtime::new()
                            .expect("Failed to create runtime for JS execution");
                        runtime.block_on(async {
                            action::js::modify_res(&code, &js_info, tmp_res).await
                        })
                    })
                    .await;

                    match result {
                        Ok(Ok(modified_res)) => {
                            tmp_res = modified_res; // 更新响应，继续处理后续 actions
                        }
                        Ok(Err(e)) => {
                            error!("JS error: {}", e);
                            return Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::default())
                                .unwrap();
                        }
                        Err(e) => {
                            error!("Spawn error: {}", e);
                            return Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::default())
                                .unwrap();
                        }
                    }
                }
                _ => {}
            }
        }

        tmp_res
    }
}
