//! 协议层共享的阻塞 reqwest 工具。
//!
//! 网络类命令在 Tauri 侧以 `#[tauri::command(async)]` 调度到阻塞线程池，
//! 因此这里使用 blocking client 且无需 async runtime。

use std::time::Duration;

use reqwest::blocking::Client;

use dosword_sdk::domain::AppSettings;

/// 依据全局设置构建 HTTP 客户端。
/// 重定向策略固定为 `none()`：防止密码参数随 301/302 泄露到其他主机。
pub fn build_client(settings: &AppSettings) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(settings.default_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("DoSword/1.0");
    if let Some(proxy) = settings.proxy.as_deref().filter(|value| !value.is_empty()) {
        if let Ok(proxy) = reqwest::Proxy::all(proxy) {
            builder = builder.proxy(proxy);
        }
    }
    builder.build().expect("构建 HTTP 客户端失败")
}
