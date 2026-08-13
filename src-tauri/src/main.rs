// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// WebKitGTK 2.42+ 的 DMABUF 渲染器在无 GPU 加速的环境（VM / 软件渲染）下会白屏。
/// 检测到虚拟化环境时在创建 WebView 之前禁用该渲染器（仅 Linux 生效，其他平台无副作用）。
fn configure_webkit_renderer() {
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_some() {
        return;
    }
    if !is_virtualized() {
        return;
    }
    // 必须在 GTK/WebView 初始化之前设置；此刻为单线程 main 入口，无数据竞争
    unsafe { std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1") };
}

fn is_virtualized() -> bool {
    let markers = [
        "vmware",
        "qemu",
        "kvm",
        "virtualbox",
        "innotek",
        "microsoft corporation",
        "xen",
        "parallels",
        "bochs",
        "oracle corporation",
    ];
    for path in [
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/board_vendor",
    ] {
        if let Ok(content) = std::fs::read_to_string(path) {
            let lower = content.to_lowercase();
            if markers.iter().any(|marker| lower.contains(marker)) {
                return true;
            }
        }
    }
    // KVM 等虚拟化 CPU（DMI 信息可能被隐藏）
    std::fs::read_to_string("/proc/cpuinfo")
        .map(|content| content.to_lowercase().contains("hypervisor"))
        .unwrap_or(false)
}

fn main() {
    configure_webkit_renderer();
    dosword_lib::run()
}
