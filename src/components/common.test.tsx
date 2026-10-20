import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ErrorBanner, ErrorBoundary, Metric, Panel, UpwardPageSizeSelect } from "./common";

describe("Metric", () => {
  it("数字补零到两位，字符串与负数原样", () => {
    const { rerender } = render(<Metric label="目标" value={5} detail="在线" />);
    expect(screen.getByText("05")).toBeTruthy();

    rerender(<Metric label="目标" value={12} detail="在线" />);
    expect(screen.getByText("12")).toBeTruthy();

    rerender(<Metric label="目标" value="—" detail="在线" />);
    expect(screen.getByText("—")).toBeTruthy();

    // 负数不补零（否则 -1 会变成 "0-1"）
    rerender(<Metric label="目标" value={-1} detail="变化" />);
    expect(screen.getByText("-1")).toBeTruthy();
  });

  it("仅在有 onClick 时标为可点击并触发回调", () => {
    const onClick = vi.fn();
    const { container } = render(
      <Metric label="目标" value={1} detail="d" onClick={onClick} />,
    );
    const card = container.querySelector("article")!;
    expect(card.className).toContain("clickable");
    fireEvent.click(card);
    expect(onClick).toHaveBeenCalledTimes(1);

    const { container: plain } = render(<Metric label="目标" value={1} detail="d" />);
    expect(plain.querySelector("article")!.className).not.toContain("clickable");
  });
});

describe("ErrorBanner", () => {
  it("空消息不渲染任何节点", () => {
    const { container } = render(<ErrorBanner message="" />);
    expect(container.querySelector(".error-banner")).toBeNull();
  });

  it("有消息时展示原文", () => {
    render(<ErrorBanner message="连接超时" />);
    expect(screen.getByText("连接超时")).toBeTruthy();
  });
});

describe("ErrorBoundary", () => {
  it("无异常时直接渲染子视图", () => {
    render(
      <ErrorBoundary>
        <p>正常内容</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText("正常内容")).toBeTruthy();
  });

  it("子视图抛错时显示提示而非白屏，点「重试恢复」后重新渲染", () => {
    // React 与 componentDidCatch 都会往 console.error 写，测试里静音以免污染输出
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    let explode = true;
    function Flaky() {
      if (explode) throw new Error("第一次渲染就炸了");
      return <p>恢复了</p>;
    }
    render(
      <ErrorBoundary>
        <Flaky />
      </ErrorBoundary>,
    );
    expect(screen.getByText("视图渲染异常")).toBeTruthy();
    expect(screen.getByText(/第一次渲染就炸了/)).toBeTruthy();

    explode = false;
    fireEvent.click(screen.getByText("重试恢复"));
    expect(screen.getByText("恢复了")).toBeTruthy();
    spy.mockRestore();
  });
});

describe("Panel", () => {
  it("渲染 eyebrow / 标题 / 操作区 / 子内容", () => {
    render(
      <Panel title="目标列表" eyebrow="TARGETS" actions={<button>刷新</button>}>
        <p>子内容</p>
      </Panel>,
    );
    expect(screen.getByText("TARGETS")).toBeTruthy();
    expect(screen.getByText("目标列表")).toBeTruthy();
    expect(screen.getByText("刷新")).toBeTruthy();
    expect(screen.getByText("子内容")).toBeTruthy();
  });
});

describe("UpwardPageSizeSelect", () => {
  it("value=0 显示「全部显示」，否则显示「N 条 / 页」", () => {
    const { rerender } = render(<UpwardPageSizeSelect value={100} onChange={() => {}} />);
    expect(screen.getByText("100 条 / 页")).toBeTruthy();
    rerender(<UpwardPageSizeSelect value={0} onChange={() => {}} />);
    expect(screen.getByText("全部显示")).toBeTruthy();
  });

  it("点击展开、选中后回调并收起", () => {
    const onChange = vi.fn();
    const { container } = render(
      <UpwardPageSizeSelect value={50} onChange={onChange} options={[50, 200]} />,
    );
    expect(container.querySelector(".upward-select-menu")).toBeNull();

    fireEvent.click(container.querySelector(".upward-select-trigger")!);
    const options = container.querySelectorAll(".upward-select-option");
    expect(options.length).toBe(2);

    fireEvent.click(options[1]);
    expect(onChange).toHaveBeenCalledWith(200);
    expect(container.querySelector(".upward-select-menu")).toBeNull();
  });

  it("点击外部收起", () => {
    const { container } = render(<UpwardPageSizeSelect value={50} onChange={() => {}} />);
    fireEvent.click(container.querySelector(".upward-select-trigger")!);
    expect(container.querySelector(".upward-select-menu")).not.toBeNull();

    fireEvent.mouseDown(document.body);
    expect(container.querySelector(".upward-select-menu")).toBeNull();
  });
});
