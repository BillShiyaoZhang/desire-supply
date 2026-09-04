"use client";

import { useCallback, useEffect, useState } from "react";
import type { WorkspaceCandidate } from "../lib/app-contract.mjs";
import {
  type AdminDemandCollection,
  type AdminDemandEvent,
  type AdminDemandParticipant,
  type AdminDemandTimeline,
  ADMIN_DEMAND_STAGE_LABELS,
  adminDemandBlockerLabel,
  adminDemandDetailLabel,
  adminDemandDetailValue,
  adminDemandRoleLabel,
  adminDemandStatusLabel,
  canInspectDemandTimeline,
  mergeAdminDemandCollection,
  mergeAdminDemandTimeline,
  parseAdminDemandCollection,
  parseAdminDemandTimeline,
} from "../lib/admin-demand-contract.mjs";
import { createAdminDemandReader } from "../lib/admin-demand-read.mjs";

const COLLECTION_PATH = "/v1/app/admin/demands";

class AdminDemandReadError extends Error {
  constructor(public status: number) { super("ADMIN_DEMAND_READ_UNAVAILABLE"); }
}

async function readJson(path: string, workspaceId: string, signal: AbortSignal, cursor: string | null) {
  const query = new URLSearchParams({ limit: path === COLLECTION_PATH ? "25" : "100" });
  if (cursor !== null) query.set("cursor", cursor);
  const response = await fetch(`${path}?${query.toString()}`, {
    method: "GET",
    cache: "no-store",
    credentials: "same-origin",
    redirect: "error",
    headers: { accept: "application/json", "x-workspace-id": workspaceId },
    signal,
  });
  if (!response.ok) {
    if (response.status === 409) {
      const error: unknown = await response.json().catch(() => null);
      if (error && typeof error === "object" && "error" in error
        && error.error && typeof error.error === "object" && "code" in error.error
        && error.error.code === "TIMELINE_CHANGED") throw new TypeError("ADMIN_DEMAND_TIMELINE_CHANGED");
    }
    throw new AdminDemandReadError(response.status);
  }
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")) {
    throw new TypeError("ADMIN_DEMAND_RESPONSE_INVALID");
  }
  return response.json() as Promise<unknown>;
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function participantName(participant: AdminDemandParticipant | undefined, id: string | null, role = "UNKNOWN") {
  if (id === null) return role === "SYSTEM" ? "系统" : "未记录操作人";
  return participant?.display_name ?? `用户 ${id.slice(0, 8)}`;
}

function errorMessage(error: unknown) {
  if (error instanceof AdminDemandReadError && error.status === 401) return "登录已失效，请重新登录后查看需求进度。";
  if (error instanceof AdminDemandReadError && error.status === 403) return "当前工作区已无查看权限，请刷新权限或切换工作区。";
  if (error instanceof AdminDemandReadError && error.status === 404) return "这条需求已不可见，请刷新需求列表。";
  return "暂时无法读取需求进度。请重试；读取失败不代表没有记录。";
}

export function AdminDemandTimelinePanel({ workspace, sessionId, accountId }: {
  workspace: WorkspaceCandidate;
  sessionId: string;
  accountId: string;
}) {
  if (!canInspectDemandTimeline(workspace)) return null;
  return <ScopedAdminDemandTimeline
    key={`${sessionId}:${accountId}:${workspace.workspace_id}`}
    workspace={workspace}
  />;
}

function ScopedAdminDemandTimeline({ workspace }: { workspace: WorkspaceCandidate }) {
  const [collectionReader] = useState(createAdminDemandReader);
  const [timelineReader] = useState(createAdminDemandReader);
  const [collection, setCollection] = useState<AdminDemandCollection | null>(null);
  const [collectionBusy, setCollectionBusy] = useState(true);
  const [collectionError, setCollectionError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [timeline, setTimeline] = useState<AdminDemandTimeline | null>(null);
  const [timelineBusy, setTimelineBusy] = useState(false);
  const [timelineError, setTimelineError] = useState<string | null>(null);
  const [stageFilter, setStageFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");

  const clearUnauthorized = useCallback((error: unknown) => {
    if (error instanceof AdminDemandReadError && [401, 403].includes(error.status)) {
      collectionReader.cancel();
      timelineReader.cancel();
      setCollection(null);
      setTimeline(null);
      setSelectedId(null);
      setCollectionBusy(false);
      setTimelineBusy(false);
      setCollectionError(errorMessage(error));
      return true;
    }
    return false;
  }, [collectionReader, timelineReader]);

  const loadCollection = useCallback((prior: AdminDemandCollection | null) => {
    return collectionReader.run(
      async (signal) => {
        const next = parseAdminDemandCollection(
          await readJson(COLLECTION_PATH, workspace.workspace_id, signal, prior?.next_cursor ?? null),
          workspace.workspace_id,
        );
        return prior === null ? next : mergeAdminDemandCollection(prior, next);
      },
      (next) => { setCollection(next); setCollectionError(null); setCollectionBusy(false); },
      (error) => {
        if (clearUnauthorized(error)) return;
        setCollectionError(errorMessage(error));
        setCollectionBusy(false);
      },
    );
  }, [clearUnauthorized, collectionReader, workspace.workspace_id]);

  useEffect(() => {
    void loadCollection(null);
    return () => { collectionReader.cancel(); timelineReader.cancel(); };
  }, [loadCollection, collectionReader, timelineReader]);

  function refreshCollection() {
    timelineReader.cancel();
    setTimeline(null);
    setSelectedId(null);
    setTimelineError(null);
    setTimelineBusy(false);
    setCollection(null);
    setCollectionError(null);
    setCollectionBusy(true);
    void loadCollection(null);
  }

  function loadTimeline(demandId: string, prior: AdminDemandTimeline | null = null) {
    setSelectedId(demandId);
    setTimelineBusy(true);
    setTimelineError(null);
    if (prior === null) {
      setTimeline(null);
      setStageFilter("");
      setActorFilter("");
    }
    void timelineReader.run(
      async (signal) => {
        const next = parseAdminDemandTimeline(
          await readJson(`${COLLECTION_PATH}/${demandId}/timeline`, workspace.workspace_id, signal, prior?.next_cursor ?? null),
          demandId,
          workspace.workspace_id,
        );
        return prior === null ? next : mergeAdminDemandTimeline(prior, next);
      },
      (next) => {
        setTimeline(next);
        setCollection((current) => current === null ? null : {
          ...current,
          items: current.items.map((item) => item.demand_id === next.demand.demand_id ? next.demand : item),
        });
        setTimelineBusy(false);
      },
      (error) => {
        if (clearUnauthorized(error)) return;
        if (error instanceof AdminDemandReadError && error.status === 404) setTimeline(null);
        const changed = error instanceof TypeError && error.message === "ADMIN_DEMAND_TIMELINE_CHANGED";
        if (changed) setTimeline(null);
        setTimelineError(changed
          ? "需求进度已更新，已清除旧记录。请刷新此需求后继续查看。"
          : errorMessage(error));
        setTimelineBusy(false);
      },
    );
  }

  const visibleEvents = timeline?.events.filter((event) =>
    (!stageFilter || event.stage === stageFilter)
    && (!actorFilter || event.actor_user_id === actorFilter),
  ) ?? [];

  return <section className="admin-demand-panel" aria-labelledby="admin-demand-title">
    <div className="admin-demand-heading">
      <div>
        <p className="eyebrow">管理员 · 需求进度</p>
        <h2 id="admin-demand-title">需求全流程</h2>
        <p>{workspace.workspace_kind === "PLATFORM" ? "查看平台需求的" : "查看本组织需求的"}各阶段进度、参与人员和操作记录。</p>
      </div>
      <button type="button" className="quiet-button" onClick={refreshCollection} disabled={collectionBusy}>刷新需求列表</button>
    </div>

    {collectionError && <div className="error-notice" role="alert">
      <p>{collectionError}</p>
      <button type="button" className="quiet-button" onClick={refreshCollection} disabled={collectionBusy}>重新读取需求列表</button>
    </div>}
    {collectionBusy && collection === null && <p className="empty-state" role="status">正在读取可查看的需求…</p>}
    {collection?.items.length === 0 && !collection.has_more && <p className="empty-state">当前工作区还没有可查看的需求。</p>}

    {collection && <div className="admin-demand-browser">
      <div className="admin-demand-list" aria-label="可查看的需求">
        {collection.items.map((demand) => <button
          type="button"
          key={demand.demand_id}
          aria-pressed={selectedId === demand.demand_id}
          onClick={() => loadTimeline(demand.demand_id)}
        >
          <strong title={demand.title}>{demand.title}</strong>
          <span>{adminDemandStatusLabel(demand.status)} · {ADMIN_DEMAND_STAGE_LABELS[demand.current_stage]}</span>
          <small>更新于 {formatTime(demand.updated_at)}</small>
          {demand.blocker_codes.length > 0 && <small className="admin-demand-blocked">{demand.blocker_codes.map(adminDemandBlockerLabel).join("；")}</small>}
        </button>)}
        {collection.has_more && <button type="button" className="quiet-button" disabled={collectionBusy} onClick={() => {
          setCollectionBusy(true);
          setCollectionError(null);
          void loadCollection(collection);
        }}>{collectionBusy ? "正在加载…" : "加载更多需求"}</button>}
      </div>

      <div className="admin-demand-detail" aria-busy={timelineBusy}>
        {selectedId === null && <p className="empty-state">选择一条需求，查看它从提出到后续交付的完整进度。</p>}
        {timelineBusy && timeline === null && <p className="empty-state" role="status">正在读取流程、参与人员和操作记录…</p>}
        {timelineError && <div className="error-notice" role="alert">
          <p>{timelineError}</p>
          {selectedId && <button type="button" className="quiet-button" disabled={timelineBusy} onClick={() => loadTimeline(selectedId)}>刷新此需求</button>}
        </div>}
        {timeline && <>
          <div className="admin-demand-heading">
            <div>
              <h3>{timeline.demand.title}</h3>
              <p><span className="status">{adminDemandStatusLabel(timeline.demand.status)}</span> 当前阶段：{ADMIN_DEMAND_STAGE_LABELS[timeline.demand.current_stage]}</p>
              <small>读取时间：{formatTime(timeline.generated_at)}</small>
            </div>
            <button type="button" className="quiet-button" disabled={timelineBusy} onClick={() => loadTimeline(timeline.demand.demand_id)}>刷新进度</button>
          </div>
          <details className="admin-demand-identifiers"><summary>需求信息</summary>
            <dl>
              <div><dt>需求编号</dt><dd>{timeline.demand.demand_id}</dd></div>
              <div><dt>组织编号</dt><dd>{timeline.demand.organization_id}</dd></div>
              <div><dt>创建时间</dt><dd>{formatTime(timeline.demand.created_at)}</dd></div>
              <div><dt>到期时间</dt><dd>{formatTime(timeline.demand.expires_at)}</dd></div>
            </dl>
          </details>
          {timeline.demand.blocker_codes.length > 0 && <div className="admin-demand-blocker-box">
            <strong>当前需要关注</strong>
            <ul>{timeline.demand.blocker_codes.map((code) => <li key={code}>{adminDemandBlockerLabel(code)}</li>)}</ul>
          </div>}
          <ol className="admin-demand-stages" aria-label="流程各阶段">
            {timeline.stages.map((stage, index) => <li key={stage.code} className={`admin-demand-stage admin-demand-stage--${stage.status.toLowerCase()}`}>
              <div><span className="admin-demand-stage-number">{index + 1}</span><h4>{stage.label}</h4></div>
              <strong>{adminDemandStatusLabel(stage.status)}</strong>
              <p>{stage.participant_ids.length > 0
                ? stage.participant_ids.map((id) => participantName(timeline.participants.find((person) => person.user_id === id), id)).join("、")
                : stage.status === "NOT_IMPLEMENTED" ? "此环节尚未接入" : "暂无参与记录"}</p>
              <small>{stage.event_count} 条操作记录</small>
              {stage.blocker_codes.map((code) => <small key={code}>{adminDemandBlockerLabel(code)}</small>)}
            </li>)}
          </ol>

          <div className="admin-demand-participants">
            <h3>参与人员 <span>{timeline.participants.length}</span></h3>
            {timeline.participants.length === 0 && <p className="empty-state">现有记录中没有可关联的参与人员。</p>}
            <ul>{timeline.participants.map((person) => <li key={person.user_id}>
              <strong>{participantName(person, person.user_id)}</strong>
              <span>{person.roles.map(adminDemandRoleLabel).join(" · ")}</span>
              <small>参与环节：{timeline.stages.filter((stage) => stage.participant_ids.includes(person.user_id)).map((stage) => stage.label).join("、") || "暂无"}</small>
              <details><summary>查看用户编号</summary><small>{person.user_id}</small></details>
            </li>)}</ul>
          </div>

          <div className="admin-demand-events">
            <h3>操作时间线</h3>
            <div className="admin-demand-filters">
              <label>流程环节<select value={stageFilter} onChange={(event) => setStageFilter(event.target.value)}>
                <option value="">全部环节</option>
                {timeline.stages.map((stage) => <option key={stage.code} value={stage.code}>{stage.label}</option>)}
              </select></label>
              <label>参与人员<select value={actorFilter} onChange={(event) => setActorFilter(event.target.value)}>
                <option value="">全部人员与系统</option>
                {timeline.participants.map((person) => <option key={person.user_id} value={person.user_id}>{participantName(person, person.user_id)}</option>)}
              </select></label>
            </div>
            <p className="admin-demand-count" role="status">已加载 {timeline.events.length} 条记录；当前显示 {visibleEvents.length} 条。{timeline.has_more ? "筛选只针对已加载记录，请继续加载以查看全部过程。" : "全部可用记录已加载。"}</p>
            {visibleEvents.length === 0 && <p className="empty-state">{timeline.events.length === 0 ? "暂无操作记录。" : "已加载记录中没有符合筛选条件的操作。"}</p>}
            <ol className="admin-demand-event-list">
              {visibleEvents.map((event) => <TimelineEvent key={event.event_id} event={event} participants={timeline.participants} />)}
            </ol>
            {timeline.has_more && <button type="button" className="quiet-button" disabled={timelineBusy} onClick={() => loadTimeline(timeline.demand.demand_id, timeline)}>{timelineBusy ? "正在加载…" : "加载更多操作记录"}</button>}
          </div>

          <div className="admin-demand-coverage">
            <h3>记录范围与待接入环节</h3>
            <p>流程以当前系统保存的记录为准。未保存的历史操作不能还原；尚未接入的环节不会显示为已完成。</p>
            <ul>{timeline.coverage.map((item) => <li key={item.source}>
              <span className={`admin-demand-coverage-status admin-demand-coverage-status--${item.status.toLowerCase()}`}>{item.status === "COMPLETE" ? "已覆盖" : item.status === "PARTIAL" ? "部分记录" : "尚未接入"}</span>
              <span>{item.description}</span>
            </li>)}</ul>
          </div>
        </>}
      </div>
    </div>}
  </section>;
}

function TimelineEvent({ event, participants }: { event: AdminDemandEvent; participants: AdminDemandParticipant[] }) {
  return <li>
    <div className="admin-demand-event-meta"><span>{ADMIN_DEMAND_STAGE_LABELS[event.stage]}</span><time dateTime={event.occurred_at}>{formatTime(event.occurred_at)}</time></div>
    <h4>{event.summary}</h4>
    <p><strong>{participantName(participants.find((person) => person.user_id === event.actor_user_id), event.actor_user_id, event.actor_role)}</strong> · {adminDemandRoleLabel(event.actor_role)}</p>
    {Object.keys(event.details).length > 0 && <details>
      <summary>查看操作详情</summary>
      <dl>{Object.entries(event.details).map(([name, value]) => <div key={name}>
        <dt>{adminDemandDetailLabel(name)}</dt>
        <dd>{adminDemandDetailValue(name, value)}</dd>
      </div>)}</dl>
    </details>}
  </li>;
}
