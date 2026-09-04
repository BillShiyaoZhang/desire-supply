"""Verify the Docsify source tree, navigation coverage, and internal links."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_ROOT = REPO_ROOT / "docs"
SIDEBAR = DOCS_ROOT / "_sidebar.md"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "deploy-docs.yml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PLATFORM_PYPROJECT = REPO_ROOT / "platform" / "pyproject.toml"
FOUNDATIONS_ROOT = DOCS_ROOT / "foundations"
IGNORED_PARTS = {"node_modules", ".vitepress"}
SPECIAL_MARKDOWN = {"_coverpage.md", "_navbar.md", "_sidebar.md"}
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
FENCE_RE = re.compile(r"^```", re.MULTILINE)
PINNED_ACTION_RE = re.compile(r"[^/\s]+/[^@\s]+@[0-9a-f]{40}")
PLATFORM_PYTHON_VERSIONS = ("3.9.25", "3.14.1")


def markdown_files() -> list[Path]:
    return sorted(
        path
        for path in DOCS_ROOT.rglob("*.md")
        if not any(part in IGNORED_PARTS for part in path.relative_to(DOCS_ROOT).parts)
    )


def normalized_link(link: str) -> str:
    return link.strip().strip("<>").split("#", 1)[0].split("?", 1)[0]


def resolve_internal_link(source: Path, link: str) -> Path | None:
    target = normalized_link(link)
    if not target or target.startswith(("http://", "https://", "mailto:")):
        return None
    if target.startswith("file://"):
        return Path(target)
    path = DOCS_ROOT / target.lstrip("/") if target.startswith("/") else source.parent / target
    if target.endswith("/"):
        path = path / "index.md"
    elif path.suffix == "":
        path = path.with_suffix(".md")
    return path.resolve()


def yaml_mapping_block(document: str, key: str, indent: int) -> str:
    """Return one indentation-delimited YAML mapping block without parsing YAML."""

    lines = document.splitlines()
    marker = " " * indent + key + ":"
    try:
        start = lines.index(marker)
    except ValueError:
        return ""
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith(" "):
            current_indent = 0
        else:
            current_indent = len(line) - len(line.lstrip(" "))
        if line.strip() and not line.lstrip().startswith("#") and current_indent <= indent:
            end = index
            break
    return "\n".join(lines[start:end])


def verify_ci_contract(ci_workflow: str, errors: list[str]) -> None:
    """Keep the G1 CI baseline reproducible, complete, and non-publishing."""

    platform_job = yaml_mapping_block(ci_workflow, "platform", 2)
    web_job = yaml_mapping_block(ci_workflow, "web", 2)
    demo_job = yaml_mapping_block(ci_workflow, "demo", 2)
    deployment_job = yaml_mapping_block(ci_workflow, "deployment", 2)
    matrix_match = re.search(
        r"(?m)^      matrix:\s*$\n"
        r"^        python-version:\s*$\n"
        r"(?P<items>(?:^          -\s+[^\n]+\n?)+)",
        platform_job,
    )
    matrix_versions = ()
    if matrix_match:
        matrix_versions = tuple(
            value.strip().strip("\"'")
            for value in re.findall(
                r"(?m)^          -\s+([^#\n]+?)\s*$",
                matrix_match.group("items"),
            )
        )
    if matrix_versions != PLATFORM_PYTHON_VERSIONS:
        errors.append(
            "Platform CI must use the exact Python matrix: "
            + ", ".join(PLATFORM_PYTHON_VERSIONS)
        )
    if "fail-fast: false" not in platform_job:
        errors.append("Platform CI matrix must preserve both version results")
    if "python-version: ${{ matrix.python-version }}" not in platform_job:
        errors.append("Platform setup-python must consume matrix.python-version")

    action_uses = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", ci_workflow)
    if not action_uses:
        errors.append("CI workflow must use explicitly pinned actions")
    for action_use in action_uses:
        if not PINNED_ACTION_RE.fullmatch(action_use):
            errors.append(f"CI action is not pinned to a full commit SHA: {action_use}")

    required_platform_contracts = (
        "working-directory: platform",
        "uv sync --locked --extra test --extra server",
        "uv run --offline --locked --extra test --extra server",
        "tests.packaging.test_distribution_resources -v",
        "PYTHONPATH: src",
        "postgres:18.4-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15",
        "DESIRE_IAM_TEST_POSTGRES_DSN",
        "python3 -m unittest discover -s tests -t . -v",
    )
    for expected in required_platform_contracts:
        if expected not in platform_job:
            errors.append(f"Missing platform CI contract: {expected}")
    if platform_job.count("uv run --offline --locked --extra test --extra server") < 2:
        errors.append("Packaging and full platform tests must both run locked and offline")
    if "PYTHONPATH: src:tests" in platform_job:
        errors.append(
            "Platform CI must not put tests/ on PYTHONPATH because tests/http "
            "shadows the Python standard library"
        )
    if "--frozen" in platform_job:
        errors.append("Platform CI must reject stale locks with --locked, not --frozen")

    required_web_contracts = (
        "working-directory: web",
        "cache-dependency-path: web/package-lock.json",
        "npm ci --ignore-scripts --no-audit",
        "npm audit --audit-level=high",
        "npm test",
        "npm run typecheck",
        "npm run lint",
        "docker build --target web-runtime --tag desire-supply-web:ci .",
        "sh scripts/smoke_web_container.sh desire-supply-web:ci",
    )
    for expected in required_web_contracts:
        if expected not in web_job:
            errors.append(f"Missing web CI contract: {expected}")

    required_demo_contracts = (
        "working-directory: demo",
        "cache-dependency-path: demo/package-lock.json",
        "npm ci --ignore-scripts --no-audit",
        "npm audit --audit-level=high",
        "npm test",
        "npm run lint",
        "npx --no-install tsc --noEmit",
    )
    for expected in required_demo_contracts:
        if expected not in demo_job:
            errors.append(f"Missing synthetic Demo CI contract: {expected}")

    required_deployment_contracts = (
        "python -B scripts/verify_container_stack.py",
        "python -B scripts/verify_current_head_v28.py",
        "python -B -m unittest discover -s tests/deployment -v",
    )
    for expected in required_deployment_contracts:
        if expected not in deployment_job:
            errors.append(f"Missing deployment CI contract: {expected}")

    checkout_count = sum(
        action_use.startswith("actions/checkout@") for action_use in action_uses
    )
    if ci_workflow.count("persist-credentials: false") != checkout_count:
        errors.append("Every CI checkout must disable persisted credentials")
    if "permissions:\n  contents: read" not in ci_workflow:
        errors.append("CI permissions must remain contents: read")

    forbidden_patterns = {
        "deploy": (
            r"(?i)(?:"
            r"uses:\s*(?:actions/deploy-[^\s@]+|cloudflare/[^\s@]+|"
            r"vercel/[^\s@]+)@|"
            r"\bdocker\s+push\b|"
            r"\bkubectl\s+(?:apply|create|replace|set)\b|"
            r"\b(?:wrangler|vercel|netlify|flyctl)\s+(?:deploy|publish)\b"
            r")"
        ),
        "publish": r"(?i)\bpublish(?:ed|ing)?\b",
        "artifact upload": r"(?i)actions/upload-artifact@",
        "OpenAI Sites": r"(?i)openai[-_ ]?sites|\.openai/hosting\.json",
    }
    for label, pattern in forbidden_patterns.items():
        if re.search(pattern, ci_workflow):
            errors.append(f"CI workflow contains forbidden {label} behavior")


def main() -> int:
    errors: list[str] = []
    docs = markdown_files()
    sidebar_links = {
        normalized_link(link).lstrip("/")
        for link in LINK_RE.findall(SIDEBAR.read_text(encoding="utf-8"))
        if normalized_link(link).startswith("/")
    }

    for source in docs:
        relative = source.relative_to(DOCS_ROOT)
        content = source.read_text(encoding="utf-8")
        if source.name not in SPECIAL_MARKDOWN:
            if not content.startswith("# "):
                errors.append(f"Page must start with one H1: docs/{relative}")
            if relative.as_posix() not in sidebar_links:
                errors.append(f"Page missing from sidebar: docs/{relative}")
        if len(FENCE_RE.findall(content)) % 2:
            errors.append(f"Unclosed fenced code block: docs/{relative}")
        if "file://" in content:
            errors.append(f"Local file URL is not portable: docs/{relative}")
        for raw_link in LINK_RE.findall(content):
            link = raw_link.strip().strip("<>")
            target = resolve_internal_link(source, link)
            if target is None or link.startswith("file://"):
                continue
            try:
                target.relative_to(DOCS_ROOT.resolve())
            except ValueError:
                errors.append(f"Link escapes docs artifact: docs/{relative} -> {link}")
                continue
            if not target.exists():
                errors.append(f"Broken link: docs/{relative} -> {link}")

    index_html = (DOCS_ROOT / "index.html").read_text(encoding="utf-8")
    for expected in (
        "homepage: 'index.md'",
        "loadSidebar: true",
        "loadNavbar: true",
        "coverpage: true",
        "'/.*/_sidebar.md': '/_sidebar.md'",
        "'/.*/_navbar.md': '/_navbar.md'",
    ):
        if expected not in index_html:
            errors.append(f"Missing Docsify setting in docs/index.html: {expected}")

    workflow = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.exists() else ""
    for expected in ("python3 scripts/verify_docs.py", "path: docs", "actions/deploy-pages@"):
        if expected not in workflow:
            errors.append(f"Missing Pages workflow setting: {expected}")

    ci_workflow = CI_WORKFLOW.read_text(encoding="utf-8") if CI_WORKFLOW.exists() else ""
    verify_ci_contract(ci_workflow, errors)

    platform_pyproject = (
        PLATFORM_PYPROJECT.read_text(encoding="utf-8")
        if PLATFORM_PYPROJECT.exists()
        else ""
    )
    for expected in ("PyYAML==6.0.3", "psycopg[binary]==3.2.13"):
        if expected not in platform_pyproject:
            errors.append(f"Missing locked platform test dependency: {expected}")

    # The founder-directed G1 path is deliberately narrow: it may replace
    # pre-G1 discovery evidence, but it must never erase the G2 boundary or
    # upgrade E0 assumptions merely because production-quality code exists.
    gate_contracts = {
        "g1-direct-build-decision.md": (
            "`DEC-033`",
            "`G1-02`",
            "`E0`",
            "G2",
            "真实用户",
            "真实数据",
            "真实资金",
        ),
        "readiness-and-start-decision.md": (
            "`G1-02`",
            "`PASS — DEC-033`",
            "G2：允许封闭付费试点",
            "当前状态：`NO-GO`",
        ),
        "risk-decision-and-assumption-register.md": (
            "`DEC-033`",
            "`RSK-037`",
            "`E0`",
        ),
        "research-and-evidence-plan.md": (
            "`DEC-033`",
            "不得因代码、测试或创始人决定而升级",
        ),
        "software-delivery-charter.md": (
            "`DEC-033`",
            "真实用户、真实产品数据、合同或资金仍须通过 `G2`",
        ),
        "business-finance-and-go-to-market.md": (
            "`E0 / FOUNDER-DIRECTED BUILD HYPOTHESIS`",
            "`DEC-033` 不构成需求、购买、付费意愿或单位经济证据",
        ),
        "g1-engineering-baseline-2026-08-12.md": (
            "`G1-08`",
            "`UNVERIFIED`",
            "503/503",
            "PostgreSQL",
            "0 个已跟踪文件",
        ),
    }
    for relative, expected_values in gate_contracts.items():
        path = FOUNDATIONS_ROOT / relative
        if not path.exists():
            errors.append(f"Missing Foundations gate artifact: docs/foundations/{relative}")
            continue
        content = path.read_text(encoding="utf-8")
        for expected in expected_values:
            if expected not in content:
                errors.append(
                    "Missing founder-directed G1 boundary in "
                    f"docs/foundations/{relative}: {expected}"
                )

    if errors:
        print("Documentation verification failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    content_pages = [path for path in docs if path.name not in SPECIAL_MARKDOWN]
    print(f"Documentation verification succeeded: {len(content_pages)} navigable pages.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
