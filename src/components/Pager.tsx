import { ChevronsLeft, ChevronsRight } from "lucide-react";
import { useState, type ReactNode } from "react";

import { UpwardPageSizeSelect } from "./common";
import { useToast } from "./Toast";

/**
 * 分页栏：首 / 上一页 / 页码 / 下一页 / 末 + 每页条数 + 跳页。
 *
 * 文件管理器与查询结果此前各写一份（连跳页的校验与提示都重复），收敛到一处。
 * `info` 由调用方渲染（各处的「共 N 项」措辞不同）。
 */
export function Pager({
  page,
  pageCount,
  pageSize,
  onPage,
  onPageSize,
  unit = "条",
  info,
  className,
  style,
}: {
  /** 当前页（0 起） */
  page: number;
  pageCount: number;
  /** 每页条数，0 表示「全部」 */
  pageSize: number;
  onPage: (page: number) => void;
  onPageSize: (size: number) => void;
  /** 每页条数的单位（条 / 行 / 项） */
  unit?: string;
  info?: ReactNode;
  className?: string;
  style?: React.CSSProperties;
}) {
  const toast = useToast();
  const [jumpInput, setJumpInput] = useState("");

  function handleJump() {
    const target = parseInt(jumpInput.trim(), 10);
    if (!Number.isNaN(target) && target >= 1 && target <= pageCount) {
      onPage(target - 1);
      setJumpInput("");
    } else {
      toast.warning(`请输入 1 到 ${pageCount} 之间的有效页码`);
    }
  }

  return (
    <div className={className ?? "file-pager"} style={style}>
      {info !== undefined && <div className="file-pager-info">{info}</div>}

      <div className="file-pager-controls">
        <button
          className="button compact secondary"
          disabled={page === 0}
          onClick={() => onPage(0)}
          title="第一页"
        >
          <ChevronsLeft size={13} />
        </button>
        <button
          className="button compact secondary"
          disabled={page === 0}
          onClick={() => onPage(Math.max(0, page - 1))}
        >
          上一页
        </button>
        <span
          className="pagination-info"
          style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}
        >
          第 <strong>{page + 1}</strong> / {pageCount} 页
        </span>
        <button
          className="button compact secondary"
          disabled={page + 1 >= pageCount}
          onClick={() => onPage(Math.min(pageCount - 1, page + 1))}
        >
          下一页
        </button>
        <button
          className="button compact secondary"
          disabled={page + 1 >= pageCount}
          onClick={() => onPage(pageCount - 1)}
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
            onPageSize(val);
            onPage(0);
          }}
          unit={unit}
        />

        <span style={{ fontSize: 11, color: "var(--text-faint)", marginLeft: 6 }}>跳至:</span>
        <input
          className="file-pager-input"
          value={jumpInput}
          onChange={(event) => setJumpInput(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") handleJump();
          }}
          placeholder={String(page + 1)}
        />
        <button className="button compact secondary" onClick={handleJump}>
          跳转
        </button>
      </div>
    </div>
  );
}
