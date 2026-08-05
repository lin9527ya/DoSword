import { useCallback, useEffect, useMemo, useState } from "react";
import { Database, Download, LoaderCircle, Play, RefreshCw, Table2 } from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText } from "../api";
import type { DbConnection, DbQueryResult } from "../api";
import { Empty, ErrorBanner } from "../components/common";

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

const TABLE_SQL: Record<string, (db: string) => string> = {
  mysql: () => "SHOW TABLES",
  pgsql: () => "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
  sqlite: () => "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
  mssql: (db) => `SELECT name FROM ${db}.sys.tables`,
  oracle: () => "SELECT table_name FROM user_tables",
};

/**
 * 数据库管理：连接表单（localStorage 持久化）→ 探测数据库 → 表浏览 → SQL 执行。
 * 后端通过 PHP PDO 模板执行，全部语句记入审计。
 */
export function DatabaseManager({ sessionId }: { sessionId: string }) {
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
  const [busy, setBusy] = useState<"probe" | "tables" | "query" | null>(null);
  const [error, setError] = useState("");

  const saveConn = useCallback((next: DbConnection) => {
    setConnection(next);
    try {
      localStorage.setItem(CONN_KEY, JSON.stringify(next));
    } catch {
      // 忽略存储失败
    }
  }, []);

  async function probe() {
    setBusy("probe");
    setError("");
    try {
      const result = await api.dbProbe(sessionId, connection);
      setDatabases(result.databases);
      if (connection.driver === "sqlite" && result.databases.length > 0) {
        setSelectedDb(result.databases[0]);
      }
    } catch (cause) {
      setError(errorText(cause));
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
      const result = await api.dbQuery(sessionId, conn, tableSql);
      setTables(result.rows.map((row) => row[0] ?? ""));
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(null);
    }
  }

  async function runQuery(sqlText: string) {
    if (!selectedDb && connection.driver !== "sqlite" && !isRedis(connection.driver)) {
      setError("请先选择数据库（sqlite 模式请填写文件路径）");
      return;
    }
    if (!sqlText.trim()) return;
    setBusy("query");
    setError("");
    try {
      const conn = { ...connection, dbname: selectedDb };
      setResult(await api.dbQuery(sessionId, conn, sqlText));
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(null);
    }
  }

  useEffect(() => {
    if (databases.length > 0 && connection.driver !== "sqlite" && !selectedDb) {
      setSelectedDb(databases[0]);
    }
  }, [databases, connection.driver, selectedDb]);

  const previewSql = (table: string) =>
    `SELECT * FROM \`${table}\` LIMIT 100`;

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
      defaultPath: `dosword-query-${stamp}.${format}`,
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
    } catch (cause) {
      setError(`导出失败：${errorText(cause)}`);
    }
  }

  return (
    <div className="db-manager">
      <ErrorBanner message={error} />

      <div className="db-conn-form">
        <label>
          驱动
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
            <option value="mysql">MySQL</option>
            <option value="pgsql">PostgreSQL</option>
            <option value="mssql">MSSQL</option>
            <option value="oracle">Oracle</option>
            <option value="redis">Redis</option>
            <option value="sqlite">SQLite（本地文件）</option>
          </select>
        </label>
        {connection.driver !== "sqlite" && (
          <>
            <label>
              主机
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
              用户
              <input
                value={connection.username ?? ""}
                onChange={(event) => saveConn({ ...connection, username: event.target.value })}
                spellCheck={false}
              />
            </label>
            <label>
              密码
              <input
                type="password"
                value={connection.password ?? ""}
                onChange={(event) => saveConn({ ...connection, password: event.target.value })}
              />
            </label>
          </>
        )}
        <label className="db-conn-db">
          {connection.driver === "sqlite" ? "数据库文件路径" : "数据库"}
          <input
            value={connection.dbname ?? ""}
            onChange={(event) => saveConn({ ...connection, dbname: event.target.value })}
            placeholder={connection.driver === "sqlite" ? "/tmp/demo.sqlite" : "test"}
            spellCheck={false}
          />
        </label>
        <button
          className="button primary"
          onClick={() => void probe()}
          disabled={busy !== null}
        >
          {busy === "probe" ? <LoaderCircle className="spin" size={15} /> : <Database size={15} />}
          连接
        </button>
      </div>

      {databases.length > 0 && connection.driver !== "sqlite" && (
        <div className="db-databases">
          <label>
            数据库
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
            className="button compact"
            onClick={() => void loadTables()}
            style={isRedis(connection.driver) ? { display: "none" } : undefined}
            disabled={busy !== null || !selectedDb}
          >
            {busy === "tables" ? <LoaderCircle className="spin" size={14} /> : <Table2 size={14} />}
            加载表
          </button>
        </div>
      )}

      {tables.length > 0 && (
        <div className="db-tables">
          {tables.map((table) => (
            <button
              key={table}
              className="db-table-chip"
              title="点击填入查询"
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
              ? "Redis 命令，如：GET key / KEYS * / SET k v / INFO"
              : "SELECT * FROM users LIMIT 100（Ctrl+Enter 执行）"
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
            {busy === "query" ? <LoaderCircle className="spin" size={14} /> : <Play size={14} />}
            执行
          </button>
          <button className="button compact" onClick={() => void loadTables()} title="刷新表列表">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {result && result.columns.length === 0 && result.rows.length === 0 && (
        <p className="muted pad">执行完成，影响 {result.affected} 行（{result.durationMs} ms）。</p>
      )}

      {result && result.columns.length > 0 && (
        <div className="db-result">
          <div className="db-result-head">
            <span className="mono">
              {result.columns.length} 列 × {result.rows.length} 行（{result.durationMs} ms）
            </span>
            <span className="db-result-actions">
              <button className="button compact" onClick={() => void exportResult("csv")}>
                <Download size={13} />
                CSV
              </button>
              <button className="button compact" onClick={() => void exportResult("json")}>
                <Download size={13} />
                JSON
              </button>
            </span>
          </div>
          <div className="db-result-table">
            <div className="db-result-row head">
              {result.columns.map((column, index) => (
                <span key={index}>{column}</span>
              ))}
            </div>
            {result.rows.length === 0 ? (
              <Empty icon={<Table2 />} title="查询无结果" />
            ) : (
              result.rows.map((row, rowIndex) => (
                <div className="db-result-row" key={rowIndex}>
                  {Array.from({ length: cellCount }, (_, i) => (
                    <span key={i} className={row[i] === null ? "null" : ""}>
                      {row[i] === null ? "NULL" : row[i]}
                    </span>
                  ))}
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
