"""Optional Batfish stage. Enabled when `pybatfish` is installed and BATFISH_HOST is set.

The snapshot is IBN's full view of every device after the change, so Batfish can parse the
AI-generated configuration in context and report parse problems and undefined references for any
technique, including ones the built-in simulator does not model.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ibn.kb.knowledge_base import KnowledgeBase
from ibn.models.report import StageResult, error, info, warning


def batfish_stage(kb: KnowledgeBase, configs_after: dict[str, str]) -> StageResult:
    stage = StageResult(name="Simulation (Batfish)")
    host = os.environ.get("BATFISH_HOST")
    try:
        from pybatfish.client.session import Session  # type: ignore
    except ImportError:
        host = None
    if not host:
        stage.skipped = True
        stage.issues.append(info("skipped: install pybatfish and set BATFISH_HOST to enable"))
        return stage
    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = Path(tmp) / "configs"
        cfg_dir.mkdir()
        for dev, text in configs_after.items():
            (cfg_dir / f"{dev}.cfg").write_text(text + "\nend\n")
        try:
            bf = Session(host=host)
            bf.set_network("ibn")
            bf.init_snapshot(tmp, name="candidate", overwrite=True)
            parse = bf.q.initIssues().answer().frame()
            undefined = bf.q.undefinedReferences().answer().frame()
        except Exception as exc:  # network / server errors must not crash validation
            stage.issues.append(warning(f"Batfish unavailable: {exc}"))
            return stage
    for _, row in parse.iterrows():
        stage.issues.append(warning(f"parse: {row.get('Details', row.to_dict())}"))
    for _, row in undefined.iterrows():
        stage.issues.append(error(f"undefined reference: {row.to_dict()}"))
    return stage
