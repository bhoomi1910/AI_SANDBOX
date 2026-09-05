"""Static analysis orchestrator.

Runs the analysis pipeline for an investigation (in a background thread after
upload), persists a structured result, and updates the investigation row.

Design guarantees:
- Every module fails independently; a module error never aborts the pipeline.
- The analysis never executes the sample; it only reads bytes.
- If a previously-analysed file with the same SHA-256 exists, its result is
  reused instead of re-analyzing (deterministic duplicate handling).
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import AnalysisResult, Investigation, utcnow
from app.services import detection as detection_mod
from app.services.analysis import entropy as entropy_mod
from app.services.analysis import filetype as ft_mod
from app.services.analysis import office as office_mod
from app.services.analysis import pdf as pdf_mod
from app.services.analysis import pe as pe_mod
from app.services.analysis import score as score_mod
from app.services.analysis import scripts as scripts_mod
from app.services.analysis import strings as strings_mod
from app.services.analysis import yara_lite

logger = logging.getLogger(__name__)


def start_analysis(inv_id: str) -> None:
    """Launch analysis in a daemon thread (fire-and-forget from the API)."""
    threading.Thread(target=_safe_run, args=(inv_id,), daemon=True).start()


def _safe_run(inv_id: str) -> None:
    try:
        run_static_analysis(inv_id)
    except Exception as exc:  # noqa: BLE001 — never crash the worker thread
        logger.exception("Analysis crashed for %s: %s", inv_id, exc)


def run_static_analysis(inv_id: str) -> None:
    db = SessionLocal()
    try:
        inv = db.get(Investigation, inv_id)
        if inv is None:
            return
        path = Path(inv.storage_path)
        if not path.exists():
            _update(db, inv, status="failed", progress=100, current_stage="Sample file not found on disk", completed_at=utcnow())
            return

        _update(db, inv, status="running", progress=5, current_stage="Detecting file type")
        detected = ft_mod.detect_file_type(path, Path(inv.filename).suffix or "")
        inv.file_type = detected["file_type"]
        inv.mime_type = detected["mime"]

        reused = _reuse_previous(db, inv)
        if reused:
            db.commit()
            return

        _update(db, inv, status="analysing", progress=30, current_stage="Extracting metadata & indicators")

        modules: dict[str, str] = {"filetype": "ok"}
        findings: list[dict] = []
        per_family: dict = {}
        raw = strings_mod.read_safe(path)

        try:
            extracted_strings = strings_mod.extract_strings(path)
            modules["strings"] = "ok"
        except Exception as exc:
            logger.warning("strings module failed: %s", exc)
            modules["strings"] = "failed"
            extracted_strings = []

        try:
            whole_entropy = entropy_mod.shannon(raw)
            modules["entropy"] = "ok"
        except Exception:
            whole_entropy = 0.0
            modules["entropy"] = "failed"

        family = detected["family"]
        try:
            if family == "pe":
                per_family = pe_mod.analyze_pe(path, findings)
                modules["pe"] = "ok"
            elif family == "pdf":
                per_family = pdf_mod.analyze_pdf(path, findings, extracted_strings)
                modules["pdf"] = "ok"
            elif family in ("ooxml", "ole"):
                per_family = office_mod.analyze_office(path, findings)
                modules["office"] = "ok"
            elif family == "script":
                per_family = scripts_mod.analyze_script(path, findings, extracted_strings)
                modules["script"] = "ok"
            else:
                modules["family"] = "skipped"
        except Exception as exc:
            logger.warning("%s module failed: %s", family, exc)
            modules[family] = "failed"

        try:
            yara_hits = yara_lite.match_file(yara_lite.get_rules(), raw)
            modules["yara"] = "ok"
        except Exception as exc:
            logger.warning("yara module failed: %s", exc)
            yara_hits = []
            modules["yara"] = "failed"

        for hit in yara_hits:
            findings.append(_yara_finding(hit))

        static = _build_static(whole_entropy, extracted_strings, yara_hits, per_family)

        # Phase 3 — Detection & Evidence Engine: normalize evidence, extract
        # IOCs, correlate findings, map MITRE techniques, build provenance graph.
        det = detection_mod.run_detection({
            "file": {
                "filename": inv.filename,
                "extension": Path(inv.filename).suffix or "",
                "family": family,
                "file_type": detected["file_type"],
                "sha256": inv.sha256,
            },
            "static": static,
            "findings": findings,
        })
        findings = det["findings"]
        score = score_mod.compute_score(findings, whole_entropy)

        tags = sorted({f["category"] for f in findings if f.get("severity") in ("medium", "high", "critical")})
        mitre = sorted({f["mitre"] for f in findings if f.get("mitre")})
        detections = sum(1 for f in findings if f.get("severity") in ("high", "critical"))
        total_engines = max(len(modules), 1)
        classification = _classification(score, findings)

        result_data = {
            "fileType": detected["file_type"],
            "family": family,
            "description": detected["description"],
            "modules": modules,
            "static": static,
            "findings": findings,
            "score": score,
            "evidence": det["evidence"],
            "iocs": det["iocs"],
            "mitre": det["mitre"],
            "graph": det["graph"],
            "classification": classification,
            "malware_family": "Unknown",
            "tags": tags,
            "detections": detections,
            "total_engines": total_engines,
            "mitre_techniques": mitre,
            "note": "Static analysis only — the sample was never executed.",
        }

        _update(
            db, inv,
            status="completed", progress=100,
            current_stage="Static analysis complete", completed_at=utcnow(),
            severity=score["severity"], risk_score=score["total"], verdict=score["verdict"],
            classification=classification,
            malware_family="Unknown",
            detections=detections, total_engines=total_engines,
            tags=tags, mitre_techniques=mitre,
        )
        db.add(AnalysisResult(investigation_id=inv.id, file_sha256=inv.sha256, data=json.dumps(result_data)))
        db.commit()
        logger.info(
            "Static analysis complete for %s (%s, score %s)",
            inv.case_id,
            score["verdict"],
            score["total"],
            extra={"investigation_id": inv.id, "analyzer": "static"},
        )
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Static analysis failed for %s", inv_id)
        try:
            inv = db.get(Investigation, inv_id)
            if inv:
                _update(db, inv, status="failed", progress=100, current_stage="Analysis error", completed_at=utcnow())
                db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


def _reuse_previous(db: Session, inv: Investigation) -> bool:
    """If the same hash was analysed before, copy that result into this case."""
    prev = (
        db.query(AnalysisResult)
        .filter(AnalysisResult.file_sha256 == inv.sha256)
        .order_by(AnalysisResult.created_at.desc())
        .first()
    )
    if not prev:
        return False
    prev_inv = db.get(Investigation, prev.investigation_id)
    data = json.loads(prev.data)
    data["note"] = f"Reused analysis from a prior upload (hash already seen). Original case: {prev_inv.case_id if prev_inv else 'unknown'}."
    _update(
        db, inv,
        status="completed", progress=100, current_stage="Static analysis complete (reused result)", completed_at=utcnow(),
        severity=data["score"]["severity"], risk_score=data["score"]["total"], verdict=data["score"]["verdict"],
        classification=data.get("classification", "Re-uploaded sample (analysed before)"),
        malware_family=data.get("malware_family", "Unknown"),
        detections=data.get("detections", 0), total_engines=data.get("total_engines", 1),
        tags=sorted({*data.get("tags", []), f"duplicate-of:{prev_inv.case_id if prev_inv else 'unknown'}"}),
        mitre_techniques=data.get("mitre_techniques", []),
    )
    db.add(AnalysisResult(investigation_id=inv.id, file_sha256=inv.sha256, data=json.dumps(data)))
    return True


def _build_static(entropy: float, strings: list[dict], yara_hits: list[dict], per_family: dict) -> dict:
    static = {
        "entropy": round(entropy, 2),
        "compiler": "Unknown",
        "packer": None,
        "arch": "N/A",
        "subsystem": "N/A",
        "timestamp": None,
        "imphash": "",
        "signatureStatus": "unsigned",
        "sections": [],
        "imports": [],
        "strings": strings,
        "yara": yara_hits,
        "capabilities": [],
    }
    for key in ("compiler", "packer", "arch", "subsystem", "timestamp", "imphash", "signatureStatus", "sections", "imports", "capabilities", "metadata"):
        if per_family.get(key):
            static[key] = per_family[key]
    return static


def _classification(score: dict, findings: list[dict]) -> str:
    cats = [f["category"] for f in findings if f.get("severity") in ("medium", "high", "critical")]
    top = ", ".join(dict.fromkeys(cats))[:120] or "no suspicious indicators"
    if score["verdict"] == "malicious":
        return f"Malicious — {top}"
    if score["verdict"] == "suspicious":
        return f"Suspicious — {top}"
    return "Clean — no suspicious static indicators"


def _yara_finding(hit: dict) -> dict:
    return {
        "severity": hit.get("severity", "medium"),
        "category": "yara",
        "title": f"YARA rule matched: {hit['rule']}",
        "detail": hit.get("description", ""),
        "evidence": f"matched strings: {', '.join(hit.get('matchedStrings', []))[:200]}",
        "mitre": hit.get("mitre"),
        "module": "yara",
        "rule": hit["rule"],
    }


def _update(db: Session, inv: Investigation, **fields) -> None:
    for key, value in fields.items():
        if key in ("tags", "mitre_techniques") and isinstance(value, (list, tuple, set)):
            value = json.dumps(sorted(value))
        setattr(inv, key, value)
    db.flush()
