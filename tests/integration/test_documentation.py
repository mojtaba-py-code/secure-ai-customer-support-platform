"""The documentation is part of the product: its references must stay true.

* every test cited as evidence (``test_...``) exists in the suite;
* every relative link between Markdown files points to an existing file (and anchor file);
* every ``AEGIS_*`` variable mentioned in the prose is a real setting or a documented extra.
"""

from __future__ import annotations

import re
from pathlib import Path

from aegis.core.config import Settings
from tests.conftest import ROOT

DOCUMENTS = sorted([ROOT / "README.md", ROOT / "SECURITY.md", *(ROOT / "docs").rglob("*.md")])
TEST_SOURCES = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "tests").rglob("*.py"))
LINK = re.compile(r"\]\(([^)#\s]*\.md)?(?:#([^)\s]+))?\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)
EXTRA_VARIABLES = {
    "AEGIS_SECRETS_DIR",
    "AEGIS_MIGRATION_DATABASE_URL",
    "AEGIS_DB_APP_ROLE",
    "AEGIS_DB_OWNER_PASSWORD",
    "AEGIS_DB_APP_PASSWORD",
    "AEGIS_BOOTSTRAP_ADMIN_PASSWORD",
    "AEGIS_TEST_DATABASE_URL",
}


def test_documents_exist() -> None:
    names = {p.name for p in DOCUMENTS}
    for required in (
        "README.md",
        "SECURITY.md",
        "architecture.md",
        "security-architecture.md",
        "threat-model.md",
        "security-audit.md",
        "api.md",
        "database.md",
        "rag.md",
        "agent.md",
        "testing.md",
        "deployment.md",
        "operations.md",
        "development-levels.md",
    ):
        assert required in names, required


def test_cited_tests_exist() -> None:
    cited = {
        name
        for document in DOCUMENTS
        for name in re.findall(r"`(test_[a-z0-9_]+)`", document.read_text(encoding="utf-8"))
    }
    assert cited, "the documents should cite their evidence"
    missing = sorted(name for name in cited if f"def {name}(" not in TEST_SOURCES)
    assert not missing, missing


def github_anchor(heading: str) -> str:
    """GitHub's heading slug: lower-case, punctuation removed, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def anchors_of(path: Path) -> set[str]:
    text = re.sub(r"```.*?```", "", path.read_text(encoding="utf-8"), flags=re.DOTALL)
    return {github_anchor(h.replace("`", "")) for h in HEADING.findall(text)}


def test_relative_links_and_anchors_resolve() -> None:
    broken = []
    for document in DOCUMENTS:
        for target, anchor in LINK.findall(document.read_text(encoding="utf-8")):
            if not target and not anchor:
                continue
            path = (document.parent / target).resolve() if target else document
            if not path.exists():
                broken.append(f"{document.relative_to(ROOT)} -> {target}")
            elif anchor and anchor not in anchors_of(path):
                broken.append(f"{document.relative_to(ROOT)} -> {target}#{anchor}")
    assert not broken, broken


def test_mentioned_settings_exist() -> None:
    known = {f"AEGIS_{name.upper()}" for name in Settings.model_fields} | EXTRA_VARIABLES
    unknown = set()
    for document in DOCUMENTS:
        text = document.read_text(encoding="utf-8")
        for variable in re.findall(r"\bAEGIS_[A-Z0-9_]+\b", text):
            if variable.endswith("_") or variable in known:
                continue
            unknown.add(f"{document.name}: {variable}")
    assert not unknown, sorted(unknown)
