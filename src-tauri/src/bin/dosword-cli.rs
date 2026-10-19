//! DoSword 无头 CLI（W6）：复用桌面端同一套服务层与数据目录。
//!
//! 仅用于**授权**安全测试；所有操作都经过与 GUI 相同的授权范围复查与审计。
//!
//! ```text
//! dosword-cli shells                      # 列出已登记 Shell
//! dosword-cli exec --shell <id> -- id -a  # 连接并执行（一次性会话）
//! dosword-cli fs ls --shell <id> --path /var/www
//! dosword-cli fs read --shell <id> --path /etc/passwd --out ./passwd
//! dosword-cli fs write --shell <id> --path /tmp/x --content-file ./x
//! dosword-cli db query --shell <id> --driver sqlite --dbname /tmp/a.db --sql "select 1"
//! dosword-cli playbook run ./smoke.yml --json
//! dosword-cli stub generate --language php --encoder native --password secret
//! ```
//!
//! 全局 `--json` 输出机器可读结果；否则输出人读文本。

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use dosword_lib::build_app_state;
use dosword_lib::load_feature_plugins;
use dosword_lib::playbook;
use dosword_lib::storage::Database;

#[derive(Parser)]
#[command(
    name = "dosword-cli",
    version,
    about = "DoSword 无头 CLI（仅限授权测试）"
)]
struct Cli {
    /// 数据目录（默认与桌面端一致：<XDG_DATA_HOME>/io.dosword.desktop）
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// 输出 JSON（便于脚本 / agent 调度）
    #[arg(long, global = true)]
    json: bool,
    /// 本次运行强制使用代理（覆盖设置，不写回数据库）
    #[arg(long, global = true)]
    proxy: Option<String>,
    /// 本次运行覆盖请求超时（秒，1-300）
    #[arg(long, global = true)]
    timeout: Option<u64>,
    /// 本次运行强制校验 TLS 证书（默认沿用设置）
    #[arg(long, global = true)]
    tls_verify: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 列出已登记的 Shell（不含密码）
    Shells,
    /// 在指定 Shell 上执行命令（自动连接；进程退出即断开）
    Exec {
        #[arg(long)]
        shell: String,
        /// 命令（建议用 `--` 分隔，避免参数被 clap 吞掉）
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// 文件操作
    Fs {
        #[command(subcommand)]
        command: FsCommand,
    },
    /// 数据库查询（连接参数与 GUI 一致）
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    /// Playbook：一次执行多步操作并输出断言报告
    Playbook {
        #[command(subcommand)]
        command: PlaybookCommand,
    },
    /// 生成服务端 stub
    Stub {
        #[command(subcommand)]
        command: StubCommand,
    },
}

#[derive(Subcommand)]
enum FsCommand {
    /// 列出目录
    Ls {
        #[arg(long)]
        shell: String,
        #[arg(long, default_value = ".")]
        path: String,
    },
    /// 读取文件（默认 base64 输出；`--out` 写原始字节）
    Read {
        #[arg(long)]
        shell: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// 写入文件（内容来自本地文件）
    Write {
        #[arg(long)]
        shell: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        content_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum DbCommand {
    /// 执行 SQL
    Query {
        #[arg(long)]
        shell: String,
        #[arg(long, default_value = "mysql")]
        driver: String,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        dbname: Option<String>,
        #[arg(long)]
        sql: String,
    },
}

#[derive(Subcommand)]
enum PlaybookCommand {
    /// 执行 YAML playbook
    Run {
        file: PathBuf,
        /// 全部步骤跑完（即使某步失败）
        #[arg(long)]
        continue_on_error: bool,
    },
}

#[derive(Subcommand)]
enum StubCommand {
    /// 生成 stub 并打印到标准输出
    Generate {
        #[arg(long, default_value = "php")]
        language: String,
        #[arg(long, default_value = "native")]
        encoder: String,
        #[arg(long)]
        password: String,
        /// 分阶段载荷（session 模式）
        #[arg(long)]
        session: bool,
        /// 加盐（打印盐以便登记 Shell 时填写）
        #[arg(long)]
        salted: bool,
        /// Transport Profile：请求参数名（需与登记 Shell 一致）
        #[arg(long)]
        param: Option<String>,
        /// Transport Profile：鉴权头名
        #[arg(long)]
        header: Option<String>,
        /// 写入文件（默认打印到标准输出）
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("错误：{error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    // stub 生成不依赖数据库/会话
    if let Command::Stub { command } = &cli.command {
        return stub(command, cli.json);
    }

    let data_dir = cli
        .data_dir
        .clone()
        .unwrap_or_else(dosword_lib::default_data_dir);
    std::fs::create_dir_all(&data_dir).map_err(|error| format!("创建数据目录失败：{error}"))?;
    let database = Database::open(data_dir.join("dosword.sqlite3"))
        .map_err(|error| format!("打开数据库失败：{error}"))?;
    // 运行期设置覆盖（不写回数据库）：--proxy / --timeout / --tls-verify
    let mut settings = database
        .get_settings()
        .map_err(|error| format!("读取设置失败：{error}"))?;
    if let Some(proxy) = cli.proxy.as_deref() {
        reqwest::Proxy::all(proxy).map_err(|error| format!("代理地址无效：{error}"))?;
        settings.proxy = Some(proxy.to_string());
    }
    if let Some(timeout) = cli.timeout {
        settings.default_timeout_secs = timeout.clamp(1, 300);
    }
    if cli.tls_verify {
        settings.tls_verify = true;
    }
    let plugins = load_feature_plugins(&data_dir.join("plugins"));
    let state = build_app_state(database, plugins);
    state.set_settings_override(settings);

    match &cli.command {
        Command::Shells => {
            let dashboard = state
                .database()
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?
                .dashboard()
                .map_err(|error| error.to_string())?;
            let shells: Vec<Value> = dashboard
                .shells
                .iter()
                .map(|shell| {
                    json!({
                        "id": shell.id,
                        "name": shell.name,
                        "runtime": shell.runtime,
                        "protocolId": shell.protocol_id,
                        "endpoint": shell.endpoint,
                        "status": shell.status,
                        "workspaceId": shell.workspace_id,
                    })
                })
                .collect();
            emit(cli.json, &Value::Array(shells), |value| {
                for shell in value.as_array().into_iter().flatten() {
                    println!(
                        "{}\t{}\t{}\t{}",
                        shell["id"].as_str().unwrap_or(""),
                        shell["name"].as_str().unwrap_or(""),
                        shell["runtime"].as_str().unwrap_or(""),
                        shell["endpoint"].as_str().unwrap_or("")
                    );
                }
                Ok(())
            })
        }
        Command::Exec { shell, command } => {
            let session_id = connect(&state, shell)?;
            let ctx = dosword_lib::commands::session_ctx(&state, &session_id)?;
            let joined = command.join(" ");
            let output = dosword_lib::commands::with_session(&state, &session_id, |session| {
                ctx.protocol
                    .execute_command(session, &joined, &ctx.settings)
            })?;
            emit(
                cli.json,
                &json!({ "stdout": output.stdout, "cwd": output.cwd, "durationMs": output.duration_ms }),
                |value| {
                    print!("{}", value["stdout"].as_str().unwrap_or(""));
                    Ok(())
                },
            )
        }
        Command::Fs { command } => fs_command(&state, command, cli.json),
        Command::Db { command } => db_command(&state, command, cli.json),
        Command::Playbook { command } => playbook_command(&state, command, cli.json),
        Command::Stub { .. } => unreachable!("已在前面处理"),
    }
}

fn connect(state: &dosword_lib::AppState, shell_id: &str) -> Result<String, String> {
    let (_result, session_id) = dosword_lib::commands::connect_shell_impl(state, shell_id)?;
    Ok(session_id)
}

fn fs_command(
    state: &dosword_lib::AppState,
    command: &FsCommand,
    json_mode: bool,
) -> Result<(), String> {
    match command {
        FsCommand::Ls { shell, path } => {
            let session_id = connect(state, shell)?;
            let ctx = dosword_lib::commands::session_ctx(state, &session_id)?;
            let listing = dosword_lib::commands::with_session(state, &session_id, |session| {
                ctx.protocol.list_dir(session, path, &ctx.settings)
            })?;
            emit(
                json_mode,
                &serde_json::to_value(&listing).map_err(|e| e.to_string())?,
                |value| {
                    for entry in value["entries"].as_array().into_iter().flatten() {
                        println!(
                            "{}\t{:>10}\t{}\t{}",
                            if entry["isDir"].as_bool().unwrap_or(false) {
                                "d"
                            } else {
                                "-"
                            },
                            entry["size"].as_u64().unwrap_or(0),
                            entry["perms"].as_str().unwrap_or(""),
                            entry["name"].as_str().unwrap_or("")
                        );
                    }
                    Ok(())
                },
            )
        }
        FsCommand::Read { shell, path, out } => {
            let session_id = connect(state, shell)?;
            let ctx = dosword_lib::commands::session_ctx(state, &session_id)?;
            let bytes = dosword_lib::commands::with_session(state, &session_id, |session| {
                ctx.protocol.read_file(session, path, &ctx.settings)
            })?;
            if let Some(out) = out {
                std::fs::write(out, &bytes).map_err(|error| format!("写本地文件失败：{error}"))?;
                emit(
                    json_mode,
                    &json!({ "size": bytes.len(), "path": out.display().to_string() }),
                    |_| {
                        println!("已写入 {}（{} 字节）", out.display(), bytes.len());
                        Ok(())
                    },
                )
            } else {
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                emit(
                    json_mode,
                    &json!({ "size": bytes.len(), "dataB64": encoded }),
                    |value| {
                        println!("{}", value["dataB64"].as_str().unwrap_or(""));
                        Ok(())
                    },
                )
            }
        }
        FsCommand::Write {
            shell,
            path,
            content_file,
        } => {
            let content = std::fs::read(content_file)
                .map_err(|error| format!("读取本地文件失败：{error}"))?;
            let session_id = connect(state, shell)?;
            let ctx = dosword_lib::commands::session_ctx(state, &session_id)?;
            dosword_lib::commands::with_session(state, &session_id, |session| {
                ctx.protocol
                    .write_file(session, path, &content, &ctx.settings)
            })?;
            emit(json_mode, &json!({ "bytes": content.len() }), |_| {
                println!("已写入 {path}（{} 字节）", content.len());
                Ok(())
            })
        }
    }
}

fn db_command(
    state: &dosword_lib::AppState,
    command: &DbCommand,
    json_mode: bool,
) -> Result<(), String> {
    match command {
        DbCommand::Query {
            shell,
            driver,
            host,
            port,
            username,
            password,
            dbname,
            sql,
        } => {
            let connection = dosword_sdk::domain::DbConnection {
                driver: driver.clone(),
                host: host.clone(),
                port: *port,
                username: username.clone(),
                password: password.clone(),
                dbname: dbname.clone(),
            };
            let session_id = connect(state, shell)?;
            let ctx = dosword_lib::commands::session_ctx(state, &session_id)?;
            let result = dosword_lib::commands::with_session(state, &session_id, |session| {
                ctx.protocol
                    .db_query(session, &connection, sql, &ctx.settings)
            })?;
            emit(
                json_mode,
                &serde_json::to_value(&result).map_err(|e| e.to_string())?,
                |value| {
                    println!(
                        "{}",
                        value["columns"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|item| item.as_str())
                            .collect::<Vec<_>>()
                            .join("\t")
                    );
                    for row in value["rows"].as_array().into_iter().flatten() {
                        let cells: Vec<String> = row
                            .as_array()
                            .into_iter()
                            .flatten()
                            .map(|cell| cell.as_str().unwrap_or("NULL").to_string())
                            .collect();
                        println!("{}", cells.join("\t"));
                    }
                    Ok(())
                },
            )
        }
    }
}

fn playbook_command(
    state: &dosword_lib::AppState,
    command: &PlaybookCommand,
    json_mode: bool,
) -> Result<(), String> {
    match command {
        PlaybookCommand::Run {
            file,
            continue_on_error,
        } => {
            let mut yaml = std::fs::read_to_string(file)
                .map_err(|error| format!("读取 playbook 失败：{error}"))?;
            if *continue_on_error {
                // 在 YAML 顶层补 continue_on_error（仅当用户显式要求）
                if !yaml.contains("continue_on_error") {
                    yaml.push_str("\ncontinue_on_error: true\n");
                }
            }
            let report = playbook::run(state, &yaml)?;
            let ok = report.ok;
            emit(
                json_mode,
                &serde_json::to_value(&report).map_err(|e| e.to_string())?,
                |value| {
                    for step in value["steps"].as_array().into_iter().flatten() {
                        println!(
                            "[{}] {} {} ({} ms){}",
                            if step["ok"].as_bool().unwrap_or(false) {
                                "PASS"
                            } else {
                                "FAIL"
                            },
                            step["index"].as_u64().unwrap_or(0),
                            step["action"].as_str().unwrap_or(""),
                            step["durationMs"].as_u64().unwrap_or(0),
                            step["error"]
                                .as_str()
                                .map(|error| format!(" — {error}"))
                                .unwrap_or_default()
                        );
                    }
                    Ok(())
                },
            )?;
            if !ok {
                return Err("Playbook 存在失败步骤".to_string());
            }
            Ok(())
        }
    }
}

fn stub(command: &StubCommand, json_mode: bool) -> Result<(), String> {
    let StubCommand::Generate {
        language,
        encoder,
        password,
        session,
        salted,
        param,
        header,
        out,
    } = command;
    let encoder = dosword_sdk::EncoderRegistry::global()
        .get(encoder)
        .ok_or_else(|| format!("未知编码器：{encoder}"))?;
    let salt = salted.then(|| uuid::Uuid::new_v4().simple().to_string()[..16].to_string());
    let effective = match &salt {
        Some(salt) => format!("{salt}:{password}"),
        None => password.clone(),
    };
    let opts = dosword_sdk::encoder::StubOptions {
        param: param.clone().unwrap_or_else(|| "formData".to_string()),
        header: header.clone().unwrap_or_else(|| "X-Debug-Key".to_string()),
    };
    opts.validate().map_err(|error| error.to_string())?;
    let content = if *session {
        encoder
            .stub_session(language, &effective)
            .map_err(|error| error.to_string())?
    } else {
        encoder
            .stub_with(language, &effective, &opts)
            .map_err(|error| error.to_string())?
    };
    let written = match out {
        Some(path) => {
            std::fs::write(path, &content).map_err(|error| format!("写入文件失败：{error}"))?;
            Some(path.display().to_string())
        }
        None => None,
    };
    if json_mode {
        let mut value = json!({
            "language": language,
            "encoder": encoder.id(),
            "salt": salt,
            "bytes": content.len(),
        });
        if let Some(written) = &written {
            value["path"] = json!(written);
        } else {
            value["content"] = json!(content);
        }
        println!("{value}");
    } else if let Some(path) = &written {
        if let Some(salt) = &salt {
            eprintln!("盐（登记 Shell 时填写）：{salt}");
        }
        println!("已写入 {path}（{} 字节）", content.len());
    } else {
        if let Some(salt) = &salt {
            eprintln!("盐（登记 Shell 时填写）：{salt}");
        }
        print!("{content}");
    }
    Ok(())
}

/// 统一输出：`--json` 打印整份 JSON，否则调用人读格式化回调。
fn emit(
    json_mode: bool,
    value: &Value,
    human: impl FnOnce(&Value) -> Result<(), String>,
) -> Result<(), String> {
    if json_mode {
        println!("{value}");
        Ok(())
    } else {
        human(value)
    }
}
