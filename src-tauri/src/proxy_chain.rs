//! 多跳 SOCKS5 代理链。
//!
//! 链路语义：`hops[0]` 离操作机最近，`hops[n-1]` 离目标最近。
//! 拨号时先连 `hops[0]` 并与它握手，然后让它 CONNECT 到 `hops[1]` 的 SOCKS 端口，
//! 在这条隧道里再与 `hops[1]` 握手……最后一跳 CONNECT 到真正的目标。
//!
//! 每一跳都必须是标准 SOCKS5（RFC 1928，可选 RFC 1929 认证），
//! 也就是说每一跳上都要先跑 `socks_proxy` 插件。

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ChainHop {
    pub host: String,
    pub port: u16,
    /// RFC 1929 用户名/密码；None 表示免认证。
    pub auth: Option<(String, String)>,
}

/// 经代理链连接到目标，返回一条已就绪的隧道。
pub fn dial_chain(
    hops: &[ChainHop],
    dest_host: &str,
    dest_port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let first = hops.first().ok_or_else(|| "代理链为空".to_string())?;
    let mut stream = TcpStream::connect((first.host.as_str(), first.port))
        .map_err(|error| format!("连接第一跳 {}:{} 失败：{error}", first.host, first.port))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;

    for (index, hop) in hops.iter().enumerate() {
        socks5_greet(&mut stream, hop.auth.as_ref())
            .map_err(|error| format!("第 {} 跳握手失败：{error}", index + 1))?;
        let (host, port) = match hops.get(index + 1) {
            Some(next) => (next.host.as_str(), next.port),
            None => (dest_host, dest_port),
        };
        socks5_connect(&mut stream, host, port)
            .map_err(|error| format!("第 {} 跳 CONNECT {host}:{port} 失败：{error}", index + 1))?;
    }
    Ok(stream)
}

fn socks5_greet(stream: &mut TcpStream, auth: Option<&(String, String)>) -> Result<(), String> {
    let methods: Vec<u8> = if auth.is_some() {
        vec![0x00, 0x02]
    } else {
        vec![0x00]
    };
    let mut request = vec![0x05, methods.len() as u8];
    request.extend(&methods);
    stream
        .write_all(&request)
        .map_err(|error| format!("发送握手失败：{error}"))?;
    let mut response = [0u8; 2];
    stream
        .read_exact(&mut response)
        .map_err(|error| format!("读取握手响应失败：{error}"))?;
    if response[0] != 0x05 {
        return Err(format!("非 SOCKS5 代理（版本 {}）", response[0]));
    }
    match response[1] {
        0x00 => Ok(()),
        0x02 => {
            let (user, pass) = auth.ok_or_else(|| "代理要求认证但未提供账号".to_string())?;
            if user.len() > 255 || pass.len() > 255 {
                return Err("用户名/密码过长".to_string());
            }
            let mut request = vec![0x01, user.len() as u8];
            request.extend(user.as_bytes());
            request.push(pass.len() as u8);
            request.extend(pass.as_bytes());
            stream
                .write_all(&request)
                .map_err(|error| format!("发送认证失败：{error}"))?;
            let mut response = [0u8; 2];
            stream
                .read_exact(&mut response)
                .map_err(|error| format!("读取认证响应失败：{error}"))?;
            if response[1] != 0x00 {
                return Err("用户名或密码错误".to_string());
            }
            Ok(())
        }
        0xff => Err("代理不接受任何认证方式".to_string()),
        other => Err(format!("不支持的认证方式：0x{other:02x}")),
    }
}

fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), String> {
    let mut request = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        request.push(0x01);
        request.extend(ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        request.push(0x04);
        request.extend(ip.octets());
    } else {
        if host.len() > 255 {
            return Err("目标域名过长".to_string());
        }
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend(host.as_bytes());
    }
    request.extend(port.to_be_bytes());
    stream
        .write_all(&request)
        .map_err(|error| format!("发送 CONNECT 失败：{error}"))?;

    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .map_err(|error| format!("读取 CONNECT 响应失败：{error}"))?;
    if head[1] != 0x00 {
        return Err(format!("代理拒绝连接（rep={}）", head[1]));
    }
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream
                .read_exact(&mut rest)
                .map_err(|error| error.to_string())?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream
                .read_exact(&mut rest)
                .map_err(|error| error.to_string())?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|error| error.to_string())?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .map_err(|error| error.to_string())?;
        }
        other => return Err(format!("未知地址类型 {other}")),
    }
    Ok(())
}

/// 本地 SOCKS5 监听器：把应用流量按链路转发出去。
pub struct LocalChain {
    pub port: u16,
    stop: Arc<AtomicBool>,
}

impl LocalChain {
    pub fn addr(&self) -> String {
        format!("socks5://127.0.0.1:{}", self.port)
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        // 唤醒 accept：连一下自己即可（线程会在下一次轮询看到 stop 后退出）
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

/// 启动本地 SOCKS5 监听器。`fixed_target` 为 Some 时忽略客户端请求的目标（固定转发）。
pub fn start_local_listener(
    hops: Vec<ChainHop>,
    fixed_target: Option<(String, u16)>,
    port: u16,
    timeout: Duration,
) -> Result<LocalChain, String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|error| format!("本地监听 127.0.0.1:{port} 失败：{error}"))?;
    let actual_port = listener
        .local_addr()
        .map_err(|error| error.to_string())?
        .port();
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();

    std::thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((client, _)) => {
                    let hops = hops.clone();
                    let fixed = fixed_target.clone();
                    std::thread::spawn(move || {
                        let _ = handle_client(client, &hops, fixed.as_ref(), timeout);
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
    });

    Ok(LocalChain {
        port: actual_port,
        stop,
    })
}

fn handle_client(
    mut client: TcpStream,
    hops: &[ChainHop],
    fixed_target: Option<&(String, u16)>,
    timeout: Duration,
) -> Result<(), String> {
    client
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    let requested = server_handshake(&mut client)?;
    let (host, port) = match fixed_target {
        Some((host, port)) => (host.as_str(), *port),
        None => (requested.0.as_str(), requested.1),
    };
    let upstream = match dial_chain(hops, host, port, timeout) {
        Ok(stream) => stream,
        Err(error) => {
            // 0x05 = connection refused
            let _ = client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            return Err(error);
        }
    };
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|error| error.to_string())?;
    client
        .set_read_timeout(None)
        .map_err(|error| error.to_string())?;
    pipe(client, upstream);
    Ok(())
}

fn server_handshake(stream: &mut TcpStream) -> Result<(String, u16), String> {
    let mut head = [0u8; 2];
    stream
        .read_exact(&mut head)
        .map_err(|error| format!("读取客户端握手失败：{error}"))?;
    if head[0] != 0x05 {
        return Err("非 SOCKS5 客户端".to_string());
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream
        .read_exact(&mut methods)
        .map_err(|error| error.to_string())?;
    if !methods.contains(&0x00) {
        let _ = stream.write_all(&[0x05, 0xff]);
        return Err("客户端不支持免认证".to_string());
    }
    stream
        .write_all(&[0x05, 0x00])
        .map_err(|error| error.to_string())?;

    let mut request = [0u8; 4];
    stream
        .read_exact(&mut request)
        .map_err(|error| error.to_string())?;
    if request[1] != 0x01 {
        return Err("仅支持 CONNECT".to_string());
    }
    let host = match request[3] {
        0x01 => {
            let mut buf = [0u8; 4];
            stream
                .read_exact(&mut buf)
                .map_err(|error| error.to_string())?;
            Ipv4Addr::from(buf).to_string()
        }
        0x04 => {
            let mut buf = [0u8; 16];
            stream
                .read_exact(&mut buf)
                .map_err(|error| error.to_string())?;
            Ipv6Addr::from(buf).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|error| error.to_string())?;
            let mut buf = vec![0u8; len[0] as usize];
            stream
                .read_exact(&mut buf)
                .map_err(|error| error.to_string())?;
            String::from_utf8_lossy(&buf).into_owned()
        }
        other => return Err(format!("未知地址类型 {other}")),
    };
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .map_err(|error| error.to_string())?;
    Ok((host, u16::from_be_bytes(port)))
}

fn pipe(client: TcpStream, upstream: TcpStream) {
    let (mut client_read, mut upstream_write) = match (client.try_clone(), upstream.try_clone()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return,
    };
    let mut client_write = client;
    let mut upstream_read = upstream;
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(std::net::Shutdown::Write);
    });
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut upstream_read, &mut client_write);
        let _ = client_write.shutdown(std::net::Shutdown::Write);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// 极简 SOCKS5 服务端（直连目标），用于验证客户端与链路拼接。
    fn spawn_mock_socks() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut client) = stream else { continue };
                std::thread::spawn(move || {
                    let target = match server_handshake(&mut client) {
                        Ok(value) => value,
                        Err(_) => return,
                    };
                    let Ok(upstream) = TcpStream::connect(target) else {
                        let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
                        return;
                    };
                    let _ = client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                    pipe(client, upstream);
                });
            }
        });
        port
    }

    fn spawn_echo() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = stream.read(&mut buf) {
                        let _ = stream.write_all(&buf[..n]);
                    }
                });
            }
        });
        port
    }

    fn round_trip(port: u16, target: (&str, u16)) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        // 本地监听器是 SOCKS5 服务端，必须先完成客户端握手
        socks5_greet(&mut stream, None).unwrap();
        socks5_connect(&mut stream, target.0, target.1).unwrap();
        stream.write_all(b"PING").unwrap();
        let mut buf = [0u8; 8];
        let n = stream.read(&mut buf).unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[test]
    fn single_hop_reaches_target() {
        let echo = spawn_echo();
        let socks = spawn_mock_socks();
        let hops = vec![ChainHop {
            host: "127.0.0.1".into(),
            port: socks,
            auth: None,
        }];
        let tunnel = dial_chain(&hops, "127.0.0.1", echo, Duration::from_secs(3)).unwrap();
        drop(tunnel);
        // 通过本地监听器走完整链路
        let chain = start_local_listener(
            hops,
            Some(("127.0.0.1".into(), echo)),
            0,
            Duration::from_secs(3),
        )
        .unwrap();
        assert_eq!(round_trip(chain.port, ("127.0.0.1", echo)), "PING");
        chain.stop();
    }

    #[test]
    fn two_hops_are_chained() {
        let echo = spawn_echo();
        let second = spawn_mock_socks();
        let first = spawn_mock_socks();
        let hops = vec![
            ChainHop {
                host: "127.0.0.1".into(),
                port: first,
                auth: None,
            },
            ChainHop {
                host: "127.0.0.1".into(),
                port: second,
                auth: None,
            },
        ];
        let chain = start_local_listener(
            hops,
            Some(("127.0.0.1".into(), echo)),
            0,
            Duration::from_secs(3),
        )
        .unwrap();
        assert_eq!(round_trip(chain.port, ("127.0.0.1", echo)), "PING");
        chain.stop();
    }

    #[test]
    fn empty_chain_is_rejected() {
        assert!(dial_chain(&[], "127.0.0.1", 80, Duration::from_secs(1)).is_err());
    }
}
