"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  type EditorReviewHistoryItem,
  type EditorReviewHistoryPage,
  parseEditorReviewHistoryEnvelope,
} from "../lib/app-contract.mjs";

type ReviewHistoryState = {
  items: EditorReviewHistoryItem[];
  nextCursor: string | null;
  hasMore: boolean;
  phase: "LOADING" | "READY" | "LOADING_MORE" | "INITIAL_ERROR" | "PAGINATION_ERROR";
};

type StoredReviewHistoryState = ReviewHistoryState & {
  workspaceId: string;
};

const EMPTY_STATE: ReviewHistoryState = {
  items: [],
  nextCursor: null,
  hasMore: false,
  phase: "LOADING",
};

async function readPage(
  workspaceId: string,
  cursor: string | null,
  signal: AbortSignal,
): Promise<EditorReviewHistoryPage> {
  const suffix = cursor === null ? "?limit=25" : `?limit=25&cursor=${cursor}`;
  const response = await fetch(`/v1/app/review-history${suffix}`, {
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
    throw new TypeError("REVIEW_HISTORY_UNAVAILABLE");
  }
  return parseEditorReviewHistoryEnvelope(await response.json());
}

function isStrictlyAfter(left: EditorReviewHistoryItem, right: EditorReviewHistoryItem) {
  const leftAt = Date.parse(left.reviewed_at);
  const rightAt = Date.parse(right.reviewed_at);
  return leftAt > rightAt || (leftAt === rightAt && left.review_id > right.review_id);
}

function formatReviewedAt(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

export function ReviewHistoryPanel({ workspaceId }: { workspaceId: string }) {
  const [storedState, setStoredState] = useState<StoredReviewHistoryState>(() => ({
    ...EMPTY_STATE,
    workspaceId,
  }));
  const state: ReviewHistoryState = storedState.workspaceId === workspaceId
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
      const existingIds = new Set(prior.items.map((item) => item.review_id));
      if (
        page.items.some((item) => existingIds.has(item.review_id))
        || page.next_cursor === prior.nextCursor
        || (prior.items.length > 0 && page.items.length > 0
          && !isStrictlyAfter(prior.items[prior.items.length - 1], page.items[0]))
      ) throw new TypeError("REVIEW_HISTORY_PAGE_MISMATCH");
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

  return <section className="review-history-panel" aria-labelledby="review-history-title">
    <div className="review-history-heading">
      <div>
        <p className="eyebrow">OPERATIONS REVIEWER · 本人终态记录</p>
        <h2 id="review-history-title" tabIndex={-1}>我的已完成审核</h2>
      </div>
      <span>{state.items.length}</span>
    </div>
    <p>这里只展示当前审核员本人已完成的审核结论与结构化代码，不包含需求正文、组织、owner、权限证据、内部备注或原始哈希。</p>
    {state.phase === "LOADING" && <p className="empty-state" role="status">正在读取本人审核历史…</p>}
    {state.phase === "INITIAL_ERROR" && <div className="error-notice" role="alert">
      <p>审核历史首次读取失败或未能通过封闭契约校验；页面没有把失败显示为“零条记录”。</p>
      <button className="quiet-button" type="button" onClick={retryInitialPage}>重新读取审核历史</button>
    </div>}
    {state.phase === "PAGINATION_ERROR" && <div className="error-notice" role="alert">
      <p>更早的审核历史读取失败或未能通过封闭契约校验；已保留上次成功读取的 {state.items.length} 条记录和同一分页位置。</p>
      <button className="quiet-button" type="button" onClick={() => void loadMore()}>重试加载更早审核</button>
    </div>}
    {state.phase === "READY" && state.items.length === 0 && state.hasMore && <p className="empty-state" role="status">
      当前页没有返回审核记录，但服务端仍有更早记录；请继续加载。
    </p>}
    {state.phase === "READY" && state.items.length === 0 && !state.hasMore && <p className="empty-state">当前账号还没有已完成的需求审核。</p>}
    {state.items.length > 0 && <ol className="review-history-list">
      {state.items.map((item) => <li key={item.review_id}>
        <article>
          <div className="review-history-item-heading">
            <strong>{item.decision === "VERIFIED" ? "已验证" : "需要修改"}</strong>
            <time dateTime={item.reviewed_at}>{formatReviewedAt(item.reviewed_at)}</time>
          </div>
          <dl>
            <div><dt>Demand</dt><dd><code>{item.demand_id}</code></dd></div>
            <div><dt>版本</dt><dd><code>{item.demand_version_id}</code></dd></div>
            <div><dt>审核记录</dt><dd><code>{item.review_id}</code></dd></div>
            {item.reason_codes.length > 0 && <div><dt>原因代码</dt><dd>{item.reason_codes.join(" · ")}</dd></div>}
            {item.required_field_codes.length > 0 && <div><dt>整改字段</dt><dd>{item.required_field_codes.join(" · ")}</dd></div>}
            {item.budget_health_code !== null && <div><dt>预算健康</dt><dd>{item.budget_health_code}</dd></div>}
            {item.risk_code !== null && <div><dt>风险结论</dt><dd>{item.risk_code}</dd></div>}
          </dl>
        </article>
      </li>)}
    </ol>}
    {state.hasMore && (state.phase === "READY" || state.phase === "LOADING_MORE") && <button
      className="quiet-button"
      disabled={state.phase !== "READY"}
      type="button"
      onClick={() => void loadMore()}
    >{state.phase === "LOADING_MORE" ? "正在加载…" : "加载更多"}</button>}
  </section>;
}
