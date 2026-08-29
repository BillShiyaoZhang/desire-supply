import argparse
from collections import Counter
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .budget import assess_budget
from .config import ConfigBundle, ConfigError, default_config_dir, load_config
from .decisions import DecisionError, validate_decision
from .explanations import brief_to_markdown, explain_candidate
from .matching import rank_candidates
from .migration_support import (
    CURRENT_DATABASE_VERSION,
    CURRENT_PAYLOAD_SCHEMA_VERSION,
)
from .migrations import MigrationError, MigrationPlan, MigrationRunner
from .privacy import assert_external_output_safe, find_prohibited_identity_fields
from .reports import build_pilot_report, report_to_csv, report_to_markdown
from .repository import Repository
from .validation import (
    is_public_identifier,
    validate_creator,
    validate_demand,
    validate_outcome,
)


class CliError(ValueError):
    pass


IMPORT_READINESS_BLOCKERS = {
    "DECISION_AUTHORITY_UNVERIFIED",
    "FUNDING_UNCOMMITTED",
}


def default_data_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "local-data"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _load_json(path: str) -> Any:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise CliError("找不到文件: {}".format(path)) from exc
    except json.JSONDecodeError as exc:
        raise CliError("JSON 格式错误: {} ({})".format(path, exc)) from exc


def _records(value: Any) -> List[Dict[str, Any]]:
    items = value if isinstance(value, list) else [value]
    if not all(isinstance(item, dict) for item in items):
        raise CliError("导入文件必须是 JSON 对象或对象数组")
    return items


def _repo(args: argparse.Namespace) -> Repository:
    repository = Repository(Path(args.data_dir))
    repository.initialize()
    return repository


def _read_repo(args: argparse.Namespace) -> Repository:
    """Return a repository only after proving that its database is readable.

    This deliberately avoids ``initialize`` so the three historical read
    commands cannot mutate a legacy database during a migration window.
    Repository read methods subsequently use SQLite's read-only adapter.
    """

    repository = Repository(Path(args.data_dir))
    repository.ensure_readable()
    return repository


def _configs(args: argparse.Namespace):
    return load_config(Path(args.config_dir))


def _load_migration_resolutions(path: Optional[str]) -> List[Any]:
    if path is None:
        return []
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise MigrationError("INVALID_DEMAND_STATUS_RESOLUTION") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "demand_status_resolutions"}
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != CURRENT_PAYLOAD_SCHEMA_VERSION
        or not isinstance(document.get("demand_status_resolutions"), list)
    ):
        raise MigrationError("INVALID_DEMAND_STATUS_RESOLUTION")
    return list(document["demand_status_resolutions"])


def _migration_target(args: argparse.Namespace) -> int:
    canonical = args.payload_schema
    legacy = args.legacy_payload_schema
    if canonical is not None and legacy is not None:
        raise CliError("--payload-schema 与兼容别名 --to 不能同时使用")
    target = canonical if canonical is not None else legacy
    if target is None:
        raise CliError("迁移必须指定 --payload-schema 1（旧脚本可使用 --to 1）")
    if target != CURRENT_PAYLOAD_SCHEMA_VERSION:
        raise MigrationError("UNSUPPORTED_SCHEMA_VERSION")
    return target


def _migration_status_payload(status: Any) -> Dict[str, Any]:
    return {
        "code": "MIGRATION_REQUIRED" if status.state == "migration_required" else "OK",
        "status": status.state,
        "source_database_version": status.database_version,
        "target_database_version": CURRENT_DATABASE_VERSION,
        "target_payload_schema_version": CURRENT_PAYLOAD_SCHEMA_VERSION,
        "plan_id": status.plan_id,
    }


def _migration_plan_payload(plan: MigrationPlan) -> Dict[str, Any]:
    blocked = bool(plan.blockers)
    return {
        "code": "MIGRATION_BLOCKED" if blocked else "OK",
        "status": "blocked" if blocked else "planned",
        "plan_id": plan.plan_id,
        "source_database_version": plan.source_database_version,
        "target_database_version": plan.target_database_version,
        "target_payload_schema_version": plan.target_payload_schema_version,
        "counts": dict(plan.counts),
        "blockers": [item.to_dict() for item in plan.blockers],
    }


def cmd_migrate(args: argparse.Namespace) -> None:
    repository = Repository(Path(args.data_dir))
    runner = MigrationRunner(repository)

    if args.migration_action == "status":
        if (
            args.payload_schema is not None
            or args.legacy_payload_schema is not None
            or args.dry_run
            or args.apply
            or args.plan_out is not None
            or args.plan is not None
            or args.backup_dir is not None
            or args.resolutions is not None
        ):
            raise CliError("migrate status 只接受可选参数 --plan-id")
        print(_json(_migration_status_payload(runner.status(plan_id=args.plan_id))))
        return

    if args.migration_action is not None:
        raise CliError("未知迁移操作")
    if args.plan_id is not None:
        raise CliError("--plan-id 只适用于 migrate status")
    target = _migration_target(args)
    resolutions = _load_migration_resolutions(args.resolutions)

    if args.dry_run:
        if not args.plan_out:
            raise CliError("--dry-run 必须同时提供 --plan-out")
        if args.plan or args.backup_dir:
            raise CliError("--dry-run 不能使用 --plan 或 --backup-dir")
        plan = runner.plan(target_version=target, resolutions=resolutions)
        if plan.source_database_version == CURRENT_DATABASE_VERSION:
            print(
                _json(
                    {
                        "code": "OK",
                        "status": "no_changes",
                        "source_database_version": CURRENT_DATABASE_VERSION,
                        "target_database_version": CURRENT_DATABASE_VERSION,
                        "target_payload_schema_version": CURRENT_PAYLOAD_SCHEMA_VERSION,
                        "plan_id": plan.plan_id,
                    }
                )
            )
            return
        # A blocked plan is still durable review evidence.  Persist it before
        # returning exit 2, and never print record payloads or resolution refs.
        plan.write(Path(args.plan_out))
        print(_json(_migration_plan_payload(plan)))
        if plan.blockers:
            raise SystemExit(2)
        return

    if args.apply:
        if not args.plan:
            raise CliError("--apply 必须同时提供 --plan")
        if not args.backup_dir:
            raise CliError("--apply 必须同时提供 --backup-dir")
        if args.plan_out:
            raise CliError("--apply 不能使用 --plan-out")
        plan = MigrationPlan.read(Path(args.plan))
        if plan.target_payload_schema_version != target:
            raise MigrationError("STALE_MIGRATION_PLAN")
        result = runner.apply(
            plan,
            backup_dir=Path(args.backup_dir),
            resolutions=resolutions,
        )
        print(
            _json(
                {
                    "code": "OK",
                    "status": result.status,
                    "plan_id": result.plan_id,
                    "backup_created": result.backup_path is not None,
                }
            )
        )
        return

    raise CliError("migrate 必须选择 --dry-run 或 --apply；状态查询使用 migrate status")


def cmd_init(args: argparse.Namespace) -> None:
    configs = _configs(args)
    repository = _repo(args)
    print(_json({"database": str(repository.path), "rule_version": configs.rule_version, "status": "ready"}))


def cmd_import(args: argparse.Namespace) -> None:
    configs = _configs(args)
    records = _records(_load_json(args.file))
    if not records:
        raise CliError("导入批次不能为空")
    raw_ids = [record.get("id") for record in records]
    valid_ids = [value for value in raw_ids if is_public_identifier(value)]
    duplicate_ids = {
        entity_id for entity_id, count in Counter(valid_ids).items() if count > 1
    }

    failures = []
    for index, record in enumerate(records):
        record_id = record.get("id")
        record_issues = []
        if isinstance(record_id, str) and record_id in duplicate_ids:
            record_issues.append({"code": "DUPLICATE_ID", "field": "id"})
        prohibited = find_prohibited_identity_fields(record)
        if prohibited:
            record_issues.extend(
                {"code": "PROHIBITED_IDENTITY_FIELD", "field": "<redacted>"}
                for _ in prohibited
            )
        validation = (
            validate_creator(record, configs)
            if args.kind == "creator"
            else validate_demand(record, configs)
        )
        record_issues.extend(
            {"code": issue.code, "field": issue.field}
            for issue in validation.issues
            if issue.level == "BLOCKER" and issue.code not in IMPORT_READINESS_BLOCKERS
        )
        if record_issues:
            failures.append(
                {
                    "index": index,
                    "id": "<redacted>",
                    "issues": record_issues,
                }
            )
    if failures:
        raise CliError("导入预检失败: {}".format(json.dumps(failures, ensure_ascii=False)))

    _repo(args).put_entities(args.kind, records)
    print(_json({"kind": args.kind, "imported": valid_ids, "count": len(valid_ids)}))


def cmd_list(args: argparse.Namespace) -> None:
    records = _read_repo(args).list_entities(args.kind, getattr(args, "pilot", None))
    print(_json([{"id": item.get("id"), "status": item.get("status"), "pilot_id": item.get("pilot_id")} for item in records]))


def cmd_validate(args: argparse.Namespace) -> None:
    configs = _configs(args)
    repository = _repo(args)
    record = repository.get_entity(args.kind, args.entity_id)
    result = (
        validate_creator(record, configs)
        if args.kind == "creator"
        else validate_demand(record, configs)
    )
    print(_json(result.to_dict()))
    if not result.ready:
        raise SystemExit(1)


def cmd_budget(args: argparse.Namespace) -> None:
    configs = _configs(args)
    repository = _repo(args)
    demand = repository.get_entity("demand", args.demand_id)
    validation = validate_demand(demand, configs)
    if not validation.ready:
        raise CliError("需求存在 BLOCKER，请先运行 validate demand {}".format(args.demand_id))
    print(_json(assess_budget(demand, configs.budget).to_dict()))


def _match_payload(
    demand: Dict[str, Any], creators: Iterable[Dict[str, Any]], configs: ConfigBundle
) -> Dict[str, Any]:
    valid_creators = []
    invalid_creators = []
    for creator in creators:
        validation = validate_creator(creator, configs)
        if validation.ready:
            valid_creators.append(creator)
        else:
            invalid_creators.append({"creator_id": creator.get("id"), "validation": validation.to_dict()})
    ranked, excluded = rank_candidates(demand, valid_creators, configs.matching)
    return {
        "ranked": [item.to_dict() for item in ranked],
        "excluded": excluded,
        "invalid_creators": invalid_creators,
    }


def cmd_match(args: argparse.Namespace) -> None:
    configs = _configs(args)
    repository = _repo(args)
    demand = repository.get_entity("demand", args.demand_id)
    validation = validate_demand(demand, configs)
    if not validation.ready:
        print(_json(validation.to_dict()))
        raise CliError("需求存在 BLOCKER，不能进入匹配")
    budget = assess_budget(demand, configs.budget)
    if budget.status == "RED":
        print(_json(budget.to_dict()))
        raise CliError("预算健康状态为 RED，不能进入匹配")
    if budget.status == "YELLOW" and not args.allow_yellow:
        print(_json(budget.to_dict()))
        raise CliError("预算健康状态为 YELLOW；请缩小范围，或用 --allow-yellow 并记录人工理由")
    if budget.status == "YELLOW" and not args.reason:
        raise CliError("--allow-yellow 必须同时提供 --reason")

    creators = repository.list_entities("creator")
    result = _match_payload(demand, creators, configs)
    result["budget_exception_reason"] = args.reason if budget.status == "YELLOW" else None
    recommendation_id = repository.record_recommendation(
        demand, creators, configs.rule_version, result, budget.to_dict()
    )
    top = result["ranked"][: args.top]
    briefs = []
    creator_by_id = {str(item.get("id")): item for item in creators}
    for score_dict in top:
        creator = creator_by_id[score_dict["creator_id"]]
        from .models import MatchScore

        score = MatchScore(**score_dict)
        briefs.append(explain_candidate(demand, creator, score).to_dict())
    public_payload = {
        "recommendation_id": recommendation_id,
        "demand_id": args.demand_id,
        "rule_version": configs.rule_version,
        "budget": budget.to_dict(),
        "recommended": top,
        "briefs": briefs,
        "excluded_count": len(result["excluded"]),
        "invalid_creator_count": len(result["invalid_creators"]),
    }
    assert_external_output_safe(
        briefs,
        [creator_by_id[item["creator_id"]] for item in top],
    )
    print(_json(public_payload))


def cmd_explain(args: argparse.Namespace) -> None:
    repository = _read_repo(args)
    recommendation = repository.latest_recommendation(args.demand_id)
    snapshot = recommendation["input_snapshot"]
    demand = snapshot["demand"]
    creator = next(
        (item for item in snapshot["creators"] if str(item.get("id")) == args.creator_id), None
    )
    if creator is None:
        raise CliError("该创作者不在最新匹配快照中")
    score_dict = next(
        (item for item in recommendation["result"]["ranked"] if item["creator_id"] == args.creator_id), None
    )
    if score_dict is None:
        excluded = next(
            (item for item in recommendation["result"]["excluded"] if item["creator_id"] == args.creator_id), None
        )
        raise CliError("该创作者被硬过滤: {}".format(_json(excluded or {})))
    from .models import MatchScore

    brief = explain_candidate(demand, creator, MatchScore(**score_dict))
    assert_external_output_safe(brief.to_dict(), [creator])
    print(brief_to_markdown(brief) if args.format == "markdown" else _json(brief.to_dict()))


def cmd_decision(args: argparse.Namespace) -> None:
    configs = _configs(args)
    repository = _repo(args)
    recommendation = repository.latest_recommendation(args.demand_id)
    invited = args.invited or ([args.selected] if args.selected else [])
    participant_responses = []
    if args.responses:
        participant_responses = _load_json(args.responses)
        if not isinstance(participant_responses, list) or not all(
            isinstance(item, dict) for item in participant_responses
        ):
            raise CliError("--responses 文件必须是 JSON 对象数组")
    validate_decision(
        recommendation,
        args.selected,
        invited,
        participant_responses,
        args.reason,
        args.note,
        configs.reason_codes,
    )
    decision_id = repository.record_decision(
        recommendation["id"],
        args.demand_id,
        recommendation["pilot_id"],
        args.selected,
        invited,
        participant_responses,
        args.reason,
        args.note,
    )
    print(_json({"decision_id": decision_id, "recommendation_id": recommendation["id"], "selected": args.selected, "invited": invited, "responses_recorded": len(participant_responses)}))


def cmd_outcome(args: argparse.Namespace) -> None:
    configs = _configs(args)
    outcome = _load_json(args.file)
    if not isinstance(outcome, dict):
        raise CliError("结果文件必须是 JSON 对象")
    if str(outcome.get("project_id")) != args.project_id:
        raise CliError("命令中的 project-id 与文件内 project_id 不一致")
    validation = validate_outcome(outcome, configs)
    if not validation.ready:
        print(_json(validation.to_dict()))
        raise CliError("项目结果存在 BLOCKER，未写入数据库")
    _repo(args).record_outcome(outcome)
    print(_json({"project_id": args.project_id, "status": outcome.get("status"), "recorded": True}))


def cmd_report(args: argparse.Namespace) -> None:
    report = build_pilot_report(_read_repo(args), args.pilot_id)
    markdown = report_to_markdown(report)
    csv_text = report_to_csv(report)
    output_dir = Path(args.output_dir) if args.output_dir else Path(args.data_dir) / "reports" / args.pilot_id
    output_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = output_dir / "report.md"
    csv_path = output_dir / "metrics.csv"
    markdown_path.write_text(markdown, encoding="utf-8")
    csv_path.write_text(csv_text, encoding="utf-8")
    print(_json({"pilot_id": args.pilot_id, "markdown": str(markdown_path), "csv": str(csv_path), "metrics": report["metrics"]}))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mvp", description="愿作礼宾式 MVP 本地运营工具")
    parser.add_argument("--data-dir", default=str(default_data_dir()), help="匿名化本地数据目录")
    parser.add_argument("--config-dir", default=str(default_config_dir()), help="版本化规则配置目录")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="初始化本地数据库并检查配置")
    init.set_defaults(func=cmd_init)

    migrate = commands.add_parser("migrate", help="只读规划或受保护地执行资料迁移")
    migrate.add_argument("migration_action", nargs="?", choices=("status",))
    migrate.add_argument("--plan-id", help="查询一个已执行 plan 的状态；仅用于 status")
    migrate.add_argument("--payload-schema", type=int, help="目标 payload schema；当前仅支持 1")
    migrate.add_argument(
        "--to",
        dest="legacy_payload_schema",
        type=int,
        help=argparse.SUPPRESS,
    )
    migration_mode = migrate.add_mutually_exclusive_group()
    migration_mode.add_argument("--dry-run", action="store_true", help="只读生成迁移计划")
    migration_mode.add_argument("--apply", action="store_true", help="按已审核计划执行迁移")
    migrate.add_argument("--plan-out", help="dry-run 写入的全新安全计划文件")
    migrate.add_argument("--plan", help="apply 使用的已审核计划文件")
    migrate.add_argument("--backup-dir", help="apply 前备份到的既有安全目录")
    migrate.add_argument("--resolutions", help="closed demand 的显式状态裁决文件")
    migrate.set_defaults(func=cmd_migrate)

    importer = commands.add_parser("import", help="导入匿名化 JSON 资料")
    importer.add_argument("kind", choices=("creator", "demand"))
    importer.add_argument("file")
    importer.set_defaults(func=cmd_import)

    listing = commands.add_parser("list", help="列出资料 ID 和状态")
    listing.add_argument("kind", choices=("creator", "demand"))
    listing.add_argument("--pilot")
    listing.set_defaults(func=cmd_list)

    validate = commands.add_parser("validate", help="检查资料完整性")
    validate.add_argument("kind", choices=("creator", "demand"))
    validate.add_argument("entity_id")
    validate.set_defaults(func=cmd_validate)

    budget = commands.add_parser("budget", help="评估需求预算健康度")
    budget.add_argument("demand_id")
    budget.set_defaults(func=cmd_budget)

    match = commands.add_parser("match", help="执行硬过滤、透明排序并保存快照")
    match.add_argument("demand_id")
    match.add_argument("--top", type=int, default=3, choices=range(1, 6))
    match.add_argument("--allow-yellow", action="store_true")
    match.add_argument("--reason", help="允许 YELLOW 预算继续时的人工理由")
    match.set_defaults(func=cmd_match)

    explain = commands.add_parser("explain", help="从最新不可变快照生成对外候选说明")
    explain.add_argument("demand_id")
    explain.add_argument("creator_id")
    explain.add_argument("--format", choices=("markdown", "json"), default="markdown")
    explain.set_defaults(func=cmd_explain)

    decision = commands.add_parser("decision", help="记录邀请和最终选择")
    decision.add_argument("demand_id")
    decision.add_argument("--selected", help="最终选中的 creator id；未成交时省略")
    decision.add_argument("--invited", nargs="+", help="实际邀请的 creator id")
    decision.add_argument("--responses", help="候选接受/拒绝原因 JSON 文件")
    decision.add_argument("--reason", required=True, help="标准决定/覆盖原因代码")
    decision.add_argument("--note", help="补充说明；OTHER 时必填")
    decision.set_defaults(func=cmd_decision)

    outcome = commands.add_parser("outcome", help="录入完成、退出或失败结果")
    outcome.add_argument("project_id")
    outcome.add_argument("--file", required=True)
    outcome.set_defaults(func=cmd_outcome)

    report = commands.add_parser("report", help="生成 Markdown 和 CSV 批次报告")
    report.add_argument("pilot_id")
    report.add_argument("--output-dir")
    report.set_defaults(func=cmd_report)
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except MigrationError as exc:
        print("错误: {}".format(exc.code), file=sys.stderr)
        raise SystemExit(3 if exc.code == "MIGRATION_RECOVERY_REQUIRED" else 2)
    except (CliError, ConfigError, DecisionError, KeyError, ValueError) as exc:
        print("错误: {}".format(exc), file=sys.stderr)
        raise SystemExit(2)
