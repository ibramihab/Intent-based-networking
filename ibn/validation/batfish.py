"""Optional Batfish stage. Enabled when `pybatfish` is installed, BATFISH_HOST is set and
running configs were synced into kb/configs/ (`ibn kb sync`).

The candidate snapshot is the synced running config with the rendered additions appended
(IOS configs are command streams, so Batfish parses appended blocks normally).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ibn.kb.knowledge_base import KnowledgeBase
from ibn.models.netconfig import CandidateConfig
from ibn.models.report import StageResult, error, info, warning


def batfish_stage(kb: KnowledgeBase, candidate: CandidateConfig) -> StageResult:
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
    missing = [d for d in kb.interfaces if kb.l3_interfaces(d) and kb.running_config(d) is None]
    if missing:
        stage.skipped = True
        stage.issues.append(info(f"skipped: no synced running config for {', '.join(missing)} (run `ibn kb sync`)"))
        return stage

    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = Path(tmp) / "configs"
        cfg_dir.mkdir()
        for dev in kb.interfaces:
            text = kb.running_config(dev)
            if text is None:
                continue
            change = candidate.change(dev)
            if change:
                text += "\n" + "\n".join(c for c in change.commands if not c.lstrip().startswith("no ")) + "\nend\n"
            (cfg_dir / f"{dev}.cfg").write_text(text)
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
