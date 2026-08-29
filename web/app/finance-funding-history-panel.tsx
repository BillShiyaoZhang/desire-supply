"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  type FinanceFundingHistoryItem,
  type FinanceFundingHistoryPage,
  parseFinanceFundingHistoryEnvelope,
} from "../lib/app-contract.mjs";

type FinanceFundingHistoryState = {
  items: FinanceFundingHistoryItem[];
  nextCursor: string | null;
  hasMore: boolean;
  phase: "LOADING" | "READY" | "LOADING_MORE" | "INITIAL_ERROR" | "PAGINATION_ERROR";
};

type StoredFinanceFundingHistoryState = FinanceFundingHistoryState & {
  workspaceId: string;
};

const EMPTY_STATE: FinanceFundingHistoryState = {
  items: [],
  nextCursor: null,
  hasMore: false,
  phase: "LOADING",
};

async function readPage(
  workspaceId: string,
  cursor: string | null,
  signal: AbortSignal,
): Promise<FinanceFundingHistoryPage> {
  const suffix = cursor === null ? "?limit=25" : `?limit=25&cursor=${cursor}`;
  const response = await fetch(`/v1/app/finance/funding-review-history${suffix}`, {
    method: "GET",
    cache: "no-store",
    credentials: "same-origin",
    redirect: "error",
    headers: {
      accept: "application/json",
      "x-workspace-id": workspaceId,
    },
    signal,
  });
  if (!response.ok || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")) {
    throw new TypeError("FINANCE_FUNDING_HISTORY_UNAVAILABLE");
  }
  return parseFinanceFundingHistoryEnvelope(await response.json());
}

function isStrictlyAfter(left: FinanceFundingHistoryItem, right: FinanceFundingHistoryItem) {
  const instant = (value: string) => {
    const match = value.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)$/);
    if (match === null) throw new TypeError("INVALID_FINANCE_FUNDING_HISTORY_TIMESTAMP");
    const seconds = Date.parse(`${match[1]}Z`);
    if (!Number.isFinite(seconds) || new Date(seconds).toISOString().slice(0, 19) !== match[1]) {
      throw new TypeError("INVALID_FINANCE_FUNDING_HISTORY_TIMESTAMP");
    }
    return `${match[1]}.${(match[2] ?? "").padEnd(9, "0")}`;
  };
  const leftAt = instant(left.completed_at);
  const rightAt = instant(right.completed_at);
  return leftAt > rightAt || (
    leftAt === rightAt
    && left.funding_review_id > right.funding_review_id
  );
}

function formatCompletedAt(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function statusLabel(status: FinanceFundingHistoryItem["status"]) {
  if (status === "SECURED") return "合成证据已双人确认";
  if (status === "DISCREPANCY") return "存在资金审查差异";
  return "资金审查已拒绝";
}

export function FinanceFundingHistoryPanel({
  busy,
  onOpen,
  workspaceId,
}: {
  busy: boolean;
  onOpen: (item: FinanceFundingHistoryItem) => void | Promise<void>;
  workspaceId: string;
}) {
  const [storedState, setStoredState] = useState<StoredFinanceFundingHistoryState>(() => ({
    ...EMPTY_STATE,
    workspaceId,
  }));
  const state: FinanceFundingHistoryState = storedState.workspaceId === workspaceId
    ? storedState
    : EMPTY_STATE;
  const generation = useRef(0);
  const activeRequest = useRef<AbortController | null>(null);

  const loadInitialPage = useCallback(() => {
    generation.current += 1;
    const requestGeneration = generation.current;
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    void readPage(workspaceId, null, controller.signal).then((page) => {
      if (generation.current !== requestGeneration) return;
      setStoredState({
        items: page.items,
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        phase: "READY",
        workspaceId,
      });
    }).catch((error: unknown) => {
      if (controller.signal.aborted || generation.current !== requestGeneration) return;
      void error;
      setStoredState({ ...EMPTY_STATE, phase: "INITIAL_ERROR", workspaceId });
    });
  }, [workspaceId]);

  const retryInitialPage = useCallback(() => {
    setStoredState({ ...EMPTY_STATE, workspaceId });
    loadInitialPage();
  }, [loadInitialPage, workspaceId]);

  useEffect(() => {
    loadInitialPage();
    return () => activeRequest.current?.abort();
  }, [loadInitialPage]);

  async function loadMore() {
    if (
      (state.phase !== "READY" && state.phase !== "PAGINATION_ERROR")
      || !state.hasMore
      || state.nextCursor === null
    ) return;
    const prior = state;
    generation.current += 1;
    const requestGeneration = generation.current;
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    setStoredState({ ...prior, phase: "LOADING_MORE", workspaceId });
    try {
      const page = await readPage(workspaceId, prior.nextCursor, controller.signal);
      if (generation.current !== requestGeneration) return;
      const existingIds = new Set(prior.items.map((item) => item.funding_review_id));
      if (
        page.items.some((item) => existingIds.has(item.funding_review_id))
        || page.next_cursor === prior.nextCursor
        || (prior.items.length > 0 && page.items.length > 0
          && !isStrictlyAfter(prior.items[prior.items.length - 1], page.items[0]))
      ) throw new TypeError("FINANCE_FUNDING_HISTORY_PAGE_MISMATCH");
      setStoredState({
        items: [...prior.items, ...page.items],
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        phase: "READY",
        workspaceId,
      });
    } catch (error: unknown) {
      if (controller.signal.aborted || generation.current !== requestGeneration) return;
      void error;
      setStoredState({ ...prior, phase: "PAGINATION_ERROR", workspaceId });
    }
  }

  return <section
    className="review-history-panel finance-funding-history-panel"
    aria-labelledby="finance-funding-history-title"
  >
    <div className="review-history-heading">
      <div>
        <p className="eyebrow">FINANCE OPERATOR · 本人终态记录</p>
        <h2 id="finance-funding-history-title" tabIndex={-1}>我的已完成资金审查</h2>
      </div>
      <span>{state.items.length}</span>
    </div>
    <p>这里只展示当前 Finance Operator 本人完成并参与确认或提交结论的终态记录，不包含组织、其他操作员、真实支付或权限证据。</p>
    {state.phase === "LOADING" && <p className="empty-state" role="status">正在读取本人资金审查历史…</p>}
    {state.phase === "INITIAL_ERROR" && <div className="error-notice" role="alert">
      <p>资金审查历史首次读取失败或未能通过封闭契约校验；页面没有把失败显示为“零条记录”。</p>
      <button className="quiet-button" disabled={busy} type="button" onClick={retryInitialPage}>重新读取资金审查历史</button>
    </div>}
    {state.phase === "PAGINATION_ERROR" && <div className="error-notice" role="alert">
      <p>更早的资金审查历史读取失败或未能通过封闭契约校验；已保留上次成功读取的 {state.items.length} 条记录和同一分页位置。</p>
      <button className="quiet-button" disabled={busy} type="button" onClick={() => void loadMore()}>重试加载更早资金审查</button>
    </div>}
    {state.phase === "READY" && state.items.length === 0 && state.hasMore && <p className="empty-state" role="status">
      当前页没有返回资金审查记录，但服务端仍有更早记录；请继续加载。
    </p>}
    {state.phase === "READY" && state.items.length === 0 && !state.hasMore && <p className="empty-state">当前账号还没有已完成的资金审查。</p>}
    {state.items.length > 0 && <ol className="review-history-list">
      {state.items.map((item) => <li key={item.funding_review_id}>
        <article>
          <div className="review-history-item-heading">
            <strong>{statusLabel(item.status)}</strong>
            <time dateTime={item.completed_at}>{formatCompletedAt(item.completed_at)}</time>
          </div>
          <dl>
            <div><dt>Demand</dt><dd><code>{item.demand_id}</code></dd></div>
            <div><dt>版本</dt><dd><code>{item.demand_version_id}</code></dd></div>
            <div><dt>资金审查记录</dt><dd><code>{item.funding_review_id}</code></dd></div>
            <div><dt>终态</dt><dd>{item.status}</dd></div>
          </dl>
          <button
            className="quiet-button"
            disabled={busy}
            type="button"
            onClick={() => void onOpen(item)}
          >打开记录</button>
        </article>
      </li>)}
    </ol>}
    {state.hasMore && (state.phase === "READY" || state.phase === "LOADING_MORE") && <button
      className="quiet-button"
      disabled={busy || state.phase !== "READY"}
      type="button"
      onClick={() => void loadMore()}
    >{state.phase === "LOADING_MORE" ? "正在加载…" : "加载更多"}</button>}
  </section>;
}
