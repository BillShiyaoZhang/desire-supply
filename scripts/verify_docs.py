"""Verify the Docsify source tree, navigation coverage, and internal links."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_ROOT = REPO_ROOT / "docs"
SIDEBAR = DOCS_ROOT / "_sidebar.md"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "deploy-docs.yml"
IGNORED_PARTS = {"node_modules", ".vitepress"}
SPECIAL_MARKDOWN = {"_coverpage.md", "_navbar.md", "_sidebar.md"}
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
FENCE_RE = re.compile(r"^```", re.MULTILINE)


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
