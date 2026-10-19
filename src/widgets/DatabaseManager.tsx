import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ChevronsLeft,
  ChevronsRight,
  Database,
  Download,
  LoaderCircle,
  Play,
  RefreshCw,
  Sparkles,
  Table2,
} from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText } from "../api";
import type { DbConnection, DbQueryResult } from "../api";
import { Empty, ErrorBanner, UpwardPageSizeSelect } from "../components/common";
import { useToast } from "../components/Toast";

const CONN_KEY = "dosword:db-conn";
const DEFAULT_CONN: DbConnection = {
  driver: "mysql",
  host: "127.0.0.1",
  port: 3306,
  username: "root",
  password: "",
  dbname: "",
};

const isRedis = (driver: string) => driver === "redis";

/** 标识符引号：各驱动语法不同（MySQL 反引号 / 标准双引号 / MSSQL 方括号）。 */
function quoteIdent(driver: string, name: string): string {
  if (driver === "mysql") return `\`${name.replace(/`/g, "``")}\``;
  if (driver === "mssql") return `[${name.replace(/]/g, "]]")}]`;
  // pgsql / oracle / sqlite 用标准双引号
  return `"${name.replace(/"/g, '""')}"`;
}

/** 预览语句：引号与分页语法都必须按驱动分派。 */
function previewSqlFor(driver: string, table: string): string {
  const target = quoteIdent(driver, table);
  if (driver === "mssql") return `SELECT TOP 100 * FROM ${target};`;
  if (driver === "oracle") return `SELECT * FROM ${target} FETCH FIRST 100 ROWS ONLY;`;
  return `SELECT * FROM ${target} LIMIT 100;`;
}

const TABLE_SQL: Record<string, (db: string) => string> = {
  mysql: () => "SHOW TABLES",
  pgsql: () => "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
  sqlite: () => "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
  mssql: (db) => `SELECT name FROM ${db}.sys.tables`,
  oracle: () => "SELECT table_name FROM user_tables",
};

const SQL_TEMPLATES: Record<string, { label: string; sql: string }[]> = {
  mysql: [
    { label: "查看数据库", sql: "SHOW DATABASES;" },
    { label: "查看用户与权限", sql: "SELECT user, host, authentication_string FROM mysql.user;" },
    { label: "查看进程列表", sql: "SHOW FULL PROCESSLIST;" },
    { label: "系统版本与变量", sql: "SELECT @@version, @@version_compile_os, @@datadir, @@secure_file_priv;" },
  ],
  pgsql: [
    { label: "查看数据库", sql: "SELECT datname FROM pg_database WHERE datistemplate = false;" },
    { label: "查看用户列表", sql: "SELECT usename, usesuper FROM pg_user;" },
    { label: "查看版本", sql: "SELECT version();" },
  ],
  mssql: [
    { label: "查看数据库", sql: "SELECT name FROM sys.databases;" },
    { label: "当前系统用户", sql: "SELECT SYSTEM_USER, USER_NAME();" },
    { label: "系统版本", sql: "SELECT @@VERSION;" },
  ],
  oracle: [
    { label: "查看表空间", sql: "SELECT tablespace_name FROM user_tablespaces;" },
    { label: "查看当前用户", sql: "SELECT user FROM dual;" },
  ],
  redis: [
    { label: "服务器信息", sql: "INFO" },
    { label: "枚举所有 Key", sql: "KEYS *" },
    { label: "客户端连接", sql: "CLIENT LIST" },
  ],
  sqlite: [
    { label: "所有表结构", sql: "SELECT type, name, sql FROM sqlite_master WHERE type='table';" },
  ],
};

export function DatabaseManager({ sessionId }: { sessionId: string }) {
  const toast = useToast();
  const [connection, setConnection] = useState<DbConnection>(() => {
    try {
      return { ...DEFAULT_CONN, ...JSON.parse(localStorage.getItem(CONN_KEY) ?? "{}") };
    } catch {
      return { ...DEFAULT_CONN };
    }
  });
  const [databases, setDatabases] = useState<string[]>([]);
  const [selectedDb, setSelectedDb] = useState<string>(connection.dbname ?? "");
  const [tables, setTables] = useState<string[]>([]);
  const [sql, setSql] = useState("");
  const [result, setResult] = useState<DbQueryResult | null>(null);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(100);
  const [jumpPageInput, setJumpPageInput] = useState("");
  const [busy, setBusy] = useState<"probe" | "tables" | "query" | null>(null);
  const [error, setError] = useState("");

  const saveConn = useCallback((next: DbConnection) => {
    setConnection(next);
    try {
      localStorage.setItem(CONN_KEY, JSON.stringify(next));
    } catch {
      // 忽略
    }
  }, []);

  async function probe() {
    setBusy("probe");
    setError("");
    try {
      const res = await api.dbProbe(sessionId, connection);
      setDatabases(res.databases);
      if (connection.driver === "sqlite" && res.databases.length > 0) {
        setSelectedDb(res.databases[0]);
      }
      toast.success(`成功探测到 ${res.databases.length} 个数据库`, "数据库连接成功");
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "数据库探测失败");
    } finally {
      setBusy(null);
    }
  }

  async function loadTables() {
    if (isRedis(connection.driver)) return;
    if (!selectedDb) return;
    const conn = { ...connection, dbname: selectedDb };
    setBusy("tables");
    setError("");
    try {
      const tableSql = TABLE_SQL[connection.driver]?.(selectedDb) ?? "SHOW TABLES";
      const res = await api.dbQuery(sessionId, conn, tableSql);
      const list = res.rows.map((row) => row[0] ?? "");
      setTables(list);
      toast.info(`已加载 ${list.length} 张数据表`);
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "加载表失败");
    } finally {
      setBusy(null);
    }
  }

  async function runQuery(sqlText: string) {
    if (!selectedDb && connection.driver !== "sqlite" && !isRedis(connection.driver)) {
      toast.warning("请先在上方选择或输入目标数据库名称");
      return;
    }
    if (!sqlText.trim()) return;
    setBusy("query");
    setError("");
    try {
      const conn = { ...connection, dbname: selectedDb };
      const res = await api.dbQuery(sessionId, conn, sqlText);
      setResult(res);
      setPage(0);
      toast.success(
        res.columns.length > 0
          ? `查询完成：返回 ${res.rows.length} 行 (${res.durationMs} ms)`
          : `执行完成：影响 ${res.affected} 行 (${res.durationMs} ms)`,
      );
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "SQL 执行异常");
    } finally {
      setBusy(null);
    }
  }

  useEffect(() => {
    if (databases.length > 0 && connection.driver !== "sqlite" && !selectedDb) {
      setSelectedDb(databases[0]);
    }
  }, [databases, connection.driver, selectedDb]);

  // 预览必须按驱动分派：反引号只在 MySQL 合法，MSSQL/Oracle 的 `LIMIT` 也不存在。
  // 旧实现硬编码反引号 + LIMIT，pgsql / mssql / oracle 上点表名必然报错。
  const previewSql = (table: string) => previewSqlFor(connection.driver, table);

  const cellCount = useMemo(() => result?.columns.length ?? 0, [result]);

  function csvCell(value: unknown): string {
    if (value === null || value === undefined) return "";
    const text = String(value);
    return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }

  async function exportResult(format: "csv" | "json") {
    if (!result) return;
    const stamp = new Date().toISOString().slice(0, 19).replace(/:/g, "-");
    const localPath = await save({
      defaultPath: `dosword-db-${selectedDb || "query"}-${stamp}.${format}`,
      filters: [{ name: format.toUpperCase(), extensions: [format] }],
    });
    if (!localPath) return;
    let content: string;
    if (format === "csv") {
      const rows = [
        result.columns,
        ...result.rows.map((row) => result.columns.map((_, i) => csvCell(row[i]))),
      ];
      content = "\uFEFF" + rows.map((row) => row.join(",")).join("\r\n");
    } else {
      const items = result.rows.map((row) =>
        Object.fromEntries(result.columns.map((column, i) => [column, row[i]])),
      );
      content = JSON.stringify(items, null, 2);
    }
    try {
      await api.writeLocalFile(localPath, b64.encodeBytes(new TextEncoder().encode(content)));
      toast.success(`查询结果已导出至 ${localPath}`, "导出成功");
    } catch (cause) {
      toast.error(`导出失败：${errorText(cause)}`);
    }
  }

  const templates = SQL_TEMPLATES[connection.driver] ?? [];

  return (
    <div className="db-manager">
      {error && <ErrorBanner message={error} />}

      {/* 数据库连接表单 */}
      <div className="db-conn-form">
        <label>
          驱动类型
          <select
            value={connection.driver}
            onChange={(event) =>
              saveConn({
                ...connection,
                driver: event.target.value,
                port:
                  event.target.value === "pgsql"
                    ? 5432
                    : event.target.value === "mssql"
                      ? 1433
                      : event.target.value === "oracle"
                        ? 1521
                        : event.target.value === "redis"
                          ? 6379
                          : 3306,
              })
            }
          >
            <option value="mysql">MySQL / MariaDB</option>
            <option value="pgsql">PostgreSQL</option>
            <option value="mssql">Microsoft SQL Server</option>
            <option value="oracle">Oracle Database</option>
            <option value="redis">Redis (K/V Cache)</option>
            <option value="sqlite">SQLite 本地文件</option>
          </select>
        </label>

        {connection.driver !== "sqlite" && (
          <>
            <label>
              主机地址
              <input
                value={connection.host ?? ""}
                onChange={(event) => saveConn({ ...connection, host: event.target.value })}
                placeholder="127.0.0.1"
                spellCheck={false}
              />
            </label>
            <label>
              端口
              <input
                type="number"
                value={connection.port ?? ""}
                onChange={(event) =>
                  saveConn({ ...connection, port: Number(event.target.value) || null })
                }
              />
            </label>
            <label>
              用户名
              <input
                value={connection.username ?? ""}
                onChange={(event) => saveConn({ ...connection, username: event.target.value })}
                placeholder="root"
                spellCheck={false}
              />
            </label>
            <label>
              数据库密码
              <input
                type="password"
                value={connection.password ?? ""}
                onChange={(event) => saveConn({ ...connection, password: event.target.value })}
              />
            </label>
          </>
        )}

        <label>
          {connection.driver === "sqlite" ? "SQLite 文件路径" : "数据库库名"}
          <input
            value={connection.dbname ?? ""}
            onChange={(event) => saveConn({ ...connection, dbname: event.target.value })}
            placeholder={connection.driver === "sqlite" ? "/var/www/data.db" : "mysql"}
            spellCheck={false}
          />
        </label>

        <button
          className="button primary"
          onClick={() => void probe()}
          disabled={busy !== null}
        >
          {busy === "probe" ? <LoaderCircle className="spin" size={14} /> : <Database size={14} />}
          测试连接
        </button>
      </div>

      {/* 数据库与表选择器 */}
      {databases.length > 0 && connection.driver !== "sqlite" && (
        <div className="db-databases">
          <label>
            目标数据库
            <select
              value={selectedDb}
              onChange={(event) => {
                setSelectedDb(event.target.value);
                setTables([]);
              }}
            >
              {databases.map((db) => (
                <option key={db} value={db}>
                  {db}
                </option>
              ))}
            </select>
          </label>
          <button
            className="button secondary compact"
            onClick={() => void loadTables()}
            style={isRedis(connection.driver) ? { display: "none" } : undefined}
            disabled={busy !== null || !selectedDb}
          >
            {busy === "tables" ? (
              <LoaderCircle className="spin" size={13} />
            ) : (
              <Table2 size={13} />
            )}
            加载数据表
          </button>
        </div>
      )}

      {/* 数据表芯片列表 */}
      {tables.length > 0 && (
        <div className="db-tables">
          <span style={{ fontSize: 11, color: "var(--text-faint)", alignSelf: "center", marginRight: 4 }}>
            数据表 ({tables.length}):
          </span>
          {tables.map((table) => (
            <button
              key={table}
              className="db-table-chip"
              title="点击自动构造并执行查询"
              onClick={() => {
                setSql(previewSql(table));
                void runQuery(previewSql(table));
              }}
            >
              {table}
            </button>
          ))}
        </div>
      )}

      {/* SQL 快捷模板 */}
      {templates.length > 0 && (
        <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
          <span style={{ fontSize: 11, color: "var(--text-faint)", display: "inline-flex", alignItems: "center", gap: 3 }}>
            <Sparkles size={12} color="var(--accent)" />
            常用探测语句:
          </span>
          {templates.map((tpl) => (
            <button
              key={tpl.label}
              className="file-bookmark-chip"
              onClick={() => {
                setSql(tpl.sql);
                void runQuery(tpl.sql);
              }}
              title={tpl.sql}
            >
              {tpl.label}
            </button>
          ))}
        </div>
      )}

      {/* SQL 输入与执行栏 */}
      <div className="db-sql-box">
        <textarea
          value={sql}
          onChange={(event) => setSql(event.target.value)}
          onKeyDown={(event) => {
            if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
              void runQuery(sql);
            }
          }}
          placeholder={
            isRedis(connection.driver)
              ? "输入 Redis 命令，如：INFO / KEYS * / GET key / CLIENT LIST (Ctrl+Enter 执行)"
              : "输入 SQL 查询语句，例如：SELECT * FROM users LIMIT 100; (Ctrl+Enter 快捷执行)"
          }
          rows={4}
          spellCheck={false}
        />
        <div className="db-sql-actions">
          <button
            className="button primary compact"
            onClick={() => void runQuery(sql)}
            disabled={busy !== null || !sql.trim()}
          >
            {busy === "query" ? <LoaderCircle className="spin" size={13} /> : <Play size={13} />}
            执行语句
          </button>
          <button
            className="button secondary compact"
            onClick={() => void loadTables()}
            title="刷新表列表"
          >
            <RefreshCw size={13} />
            刷新表
          </button>
        </div>
      </div>

      {result && result.columns.length === 0 && (
        <p className="muted pad" style={{ background: "var(--panel-2)", borderRadius: "var(--radius-md)" }}>
          执行成功，影响记录行数: <strong>{result.affected}</strong>（耗时 {result.durationMs} ms）。
        </p>
      )}

      {result && result.columns.length > 0 && (
        <div className="db-result">
          <div className="db-result-head">
            <span className="mono">
              {result.columns.length} 列 × {result.rows.length} 条记录（耗时 {result.durationMs} ms）
            </span>
            <div className="db-result-actions">
              <button className="button compact secondary" onClick={() => void exportResult("csv")}>
                <Download size={13} />
                导出 CSV
              </button>
              <button className="button compact secondary" onClick={() => void exportResult("json")}>
                <Download size={13} />
                导出 JSON
              </button>
            </div>
          </div>

          <div className="db-result-table">
            <div className="db-result-row head">
              {result.columns.map((column, index) => (
                <span key={index}>{column}</span>
              ))}
            </div>
            {result.rows.length === 0 ? (
              <Empty icon={<Table2 size={24} />} title="查询结果为空 (0 行记录)" />
            ) : (
              <>
                {(() => {
                  const effectiveSize = pageSize === 0 ? result.rows.length : pageSize;
                  const start = pageSize === 0 ? 0 : page * effectiveSize;
                  const slice = pageSize === 0 ? result.rows : result.rows.slice(start, start + effectiveSize);
                  return slice.map((row, rowIndex) => (
                    <div className="db-result-row" key={start + rowIndex}>
                      {Array.from({ length: cellCount }, (_, i) => {
                        const val = row[i];
                        return (
                          <span
                            key={i}
                            className={val === null ? "null" : ""}
                            title={String(val ?? "NULL")}
                            onClick={() => {
                              if (val !== null && val !== undefined) {
                                void navigator.clipboard.writeText(String(val));
                                toast.info("单元格内容已复制");
                              }
                            }}
                            style={{ cursor: "pointer" }}
                          >
                            {val === null ? "NULL" : String(val)}
                          </span>
                        );
                      })}
                    </div>
                  ));
                })()}

                {result.rows.length > 0 && (
                  <div className="file-pager" style={{ borderTop: "1px solid var(--border)", margin: 0, borderRadius: "0 0 var(--radius-md) var(--radius-md)" }}>
                    {(() => {
                      const effectiveSize = pageSize === 0 ? result.rows.length : pageSize;
                      const pageCount = pageSize === 0 ? 1 : Math.max(1, Math.ceil(result.rows.length / effectiveSize));

                      const handleJump = () => {
                        const p = parseInt(jumpPageInput.trim(), 10);
                        if (!Number.isNaN(p) && p >= 1 && p <= pageCount) {
                          setPage(p - 1);
                          setJumpPageInput("");
                        } else {
                          toast.warning(`请输入 1 到 ${pageCount} 之间的有效页码`);
                        }
                      };

                      return (
                        <>
                          <div className="file-pager-info">
                            共 <strong>{result.rows.length}</strong> 行记录
                          </div>

                          <div className="file-pager-controls">
                            <button
                              className="button compact secondary"
                              disabled={page === 0}
                              onClick={() => setPage(0)}
                              title="第一页"
                            >
                              <ChevronsLeft size={13} />
                            </button>
                            <button
                              className="button compact secondary"
                              disabled={page === 0}
                              onClick={() => setPage((p) => Math.max(0, p - 1))}
                            >
                              上一页
                            </button>
                            <span className="pagination-info" style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                              第 <strong>{page + 1}</strong> / {pageCount} 页
                            </span>
                            <button
                              className="button compact secondary"
                              disabled={page + 1 >= pageCount}
                              onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                            >
                              下一页
                            </button>
                            <button
                              className="button compact secondary"
                              disabled={page + 1 >= pageCount}
                              onClick={() => setPage(pageCount - 1)}
                              title="最后一页"
                            >
                              <ChevronsRight size={13} />
                            </button>
                          </div>

                          <div className="file-pager-jump">
                            <span style={{ fontSize: 11, color: "var(--text-faint)" }}>每页:</span>
                            <UpwardPageSizeSelect
                              value={pageSize}
                              onChange={(val) => {
                                setPageSize(val);
                                setPage(0);
                              }}
                              unit="行"
                            />

                            <span style={{ fontSize: 11, color: "var(--text-faint)", marginLeft: 6 }}>跳至:</span>
                            <input
                              className="file-pager-input"
                              value={jumpPageInput}
                              onChange={(e) => setJumpPageInput(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === "Enter") handleJump();
                              }}
                              placeholder={String(page + 1)}
                            />
                            <button className="button compact secondary" onClick={handleJump}>
                              跳转
                            </button>
                          </div>
                        </>
                      );
                    })()}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
