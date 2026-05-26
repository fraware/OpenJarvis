"""Re-grade GAIA cells whose answers scored 0 under the old regex scorer.

The old ``runner._score_gaia`` only credited answers that emitted a literal
``FINAL ANSWER:`` line and exact-string-matched it. A verbose answer that
states the right answer in prose ("...therefore the answer is 4") silently
scored 0. Opus emits the marker ~92% of the time; GPT-5-mini / Haiku almost
never do, so their GAIA cells were badly undercounted.

The agents already produced correct answers in ``<cell>/results.jsonl`` —
only the grading step was broken. This script re-scores every non-error row
with the proper ``GAIAScorer`` (normalized exact-match + LLM-judge fallback)
and rewrites the row's ``score``. Error rows are left untouched (they really
did fail). ``summary.json`` accuracy is recomputed.

Usage:
    source .env   # OpenAI key for the judge
    .venv/bin/python scripts/ablation/rescore_gaia.py --all-gaia
    .venv/bin/python scripts/ablation/rescore_gaia.py \\
        --cells minions-qwen27b-haiku45-gaia-n100,minions-qwen27b-gpt5-gaia-n100

Idempotent: each cell writes ``_rescored_gaia_ids.txt`` listing task_ids
already rescored; reruns skip those. A one-time ``results.jsonl.bak-gaia*``
backup is made before the first rewrite.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

# Make `openjarvis` importable when running this script directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from openjarvis.evals.backends.jarvis_direct import JarvisDirectBackend  # noqa: E402
from openjarvis.evals.core.types import EvalRecord  # noqa: E402
from openjarvis.evals.datasets.gaia import GAIADataset  # noqa: E402
from openjarvis.evals.scorers.gaia_exact import GAIAScorer  # noqa: E402

HYBRID_DIR = Path(os.path.expanduser("~/.openjarvis/experiments/hybrid"))
RUNS_DIR = HYBRID_DIR / "runs"
DOCS_TABLE = HYBRID_DIR / "docs" / "results-table.md"

MAX_WORKERS = 8
RETRY_ATTEMPTS = 4
JUDGE_MODEL = os.environ.get("OPENJARVIS_GAIA_JUDGE_MODEL", "gpt-5-mini-2025-08-07")
PROGRESS_EVERY = 20


# ---------- IO helpers ----------

def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _atomic_write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    os.replace(tmp, path)


def _is_correct(row: Dict[str, Any]) -> bool:
    sc = row.get("score") or {}
    if not isinstance(sc, dict):
        return False
    return float(sc.get("score", 0) or 0) >= 0.5


# ---------- GAIA dataset (task_id -> question, reference) ----------

def _load_gaia_index() -> Dict[str, Tuple[str, str]]:
    """Map bare GAIA task_id -> (question, reference) over the full val set."""
    ds = GAIADataset()
    ds.load()
    index: Dict[str, Tuple[str, str]] = {}
    for rec in ds.iter_records():
        md = rec.metadata or {}
        task_id = str(md.get("task_id") or rec.record_id)
        question = str(md.get("question") or rec.problem or "")
        index[task_id] = (question, str(rec.reference or ""))
    return index


# ---------- Re-score one row with retry ----------

def _rescore_row(
    scorer: GAIAScorer,
    task_id: str,
    question: str,
    reference: str,
    answer: str,
    err_log: Path,
    err_log_lock: Lock,
) -> Optional[Dict[str, Any]]:
    """Re-score one answer. Returns the new score dict, or None if the judge
    kept failing (caller leaves the row untouched rather than writing a
    bogus 0)."""
    record = EvalRecord(
        record_id=task_id,
        problem=question,
        reference=reference,
        category="agentic",
        metadata={"task_id": task_id},
    )
    last_err = ""
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            is_correct, details = scorer.score(record, answer or "")
            details = dict(details or {})
            # A failed judge call must NOT be written as a real 0.
            if details.get("match_type") == "llm_fallback_error":
                last_err = f"attempt={attempt} judge_error: {details.get('error')}"
                time.sleep(min(2 ** attempt, 30))
                continue
            details.setdefault("reference", reference)
            return {
                "success": bool(is_correct),
                "score": 1.0 if is_correct else 0.0,
                "details": details,
            }
        except Exception as exc:  # noqa: BLE001
            last_err = f"attempt={attempt} {type(exc).__name__}: {exc}"
            time.sleep(min(2 ** attempt, 30))
    with err_log_lock:
        with err_log.open("a") as f:
            f.write(f"{task_id}\t{last_err}\n")
    return None


# ---------- Per-cell processing ----------

def _process_cell(
    cell_dir: Path,
    gaia_index: Dict[str, Tuple[str, str]],
) -> Dict[str, Any]:
    name = cell_dir.name
    results_path = cell_dir / "results.jsonl"
    if not results_path.exists():
        print(f"[SKIP] {name} — no results.jsonl", flush=True)
        return {"cell": name, "skipped": True}

    rows = _read_jsonl(results_path)
    n_total = len(rows)

    tracker_path = cell_dir / "_rescored_gaia_ids.txt"
    already_done: set[str] = set()
    if tracker_path.exists():
        already_done = {
            ln.strip() for ln in tracker_path.read_text().splitlines() if ln.strip()
        }

    old_resolved = sum(1 for r in rows if _is_correct(r))
    old_acc = old_resolved / n_total if n_total else 0.0

    # Worklist: non-error rows not yet rescored.
    worklist: List[Tuple[int, str, str, str, str]] = []
    skipped_err = 0
    for i, r in enumerate(rows):
        task_id = str(r.get("task_id") or "")
        if r.get("error"):
            skipped_err += 1
            continue
        if task_id in already_done:
            continue
        question, ref = gaia_index.get(task_id, ("", ""))
        if not ref:
            # fall back to the reference the old scorer stored
            ref = str(((r.get("score") or {}).get("details") or {}).get("reference") or "")
        worklist.append((i, task_id, question, ref, str(r.get("answer") or "")))

    print(
        f"[{name}] start: rows={n_total} error_rows={skipped_err} "
        f"already_rescored={len(already_done)} todo={len(worklist)} "
        f"old_acc={old_acc:.3f}",
        flush=True,
    )

    # One-time backup before the first rewrite.
    bak = cell_dir / f"results.jsonl.bak-gaiarescore-{int(time.time())}"
    if worklist and not any(cell_dir.glob("results.jsonl.bak-gaiarescore-*")):
        bak.write_text(results_path.read_text())

    scorer = GAIAScorer(JarvisDirectBackend(engine_key="cloud"), JUDGE_MODEL)
    err_log = cell_dir / "_rescore_gaia_errors.log"
    err_log_lock = Lock()
    tracker_lock = Lock()
    rows_lock = Lock()
    n_done = n_failed = n_flipped = 0

    def _flush_tracker(task_id: str) -> None:
        with tracker_lock:
            with tracker_path.open("a") as f:
                f.write(task_id + "\n")
            already_done.add(task_id)

    def _snapshot() -> None:
        with rows_lock:
            _atomic_write_jsonl(results_path, rows)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        fut_to_meta = {
            pool.submit(
                _rescore_row, scorer, tid, q, ref, ans, err_log, err_log_lock
            ): (i, tid)
            for (i, tid, q, ref, ans) in worklist
        }
        for fut in as_completed(fut_to_meta):
            i, tid = fut_to_meta[fut]
            new_score = fut.result()
            n_done += 1
            if new_score is None:
                n_failed += 1
            else:
                was = _is_correct(rows[i])
                with rows_lock:
                    rows[i]["score"] = new_score
                _flush_tracker(tid)
                if new_score["success"] and not was:
                    n_flipped += 1
            if n_done % PROGRESS_EVERY == 0:
                _snapshot()
                print(
                    f"[{name}] rescored={n_done}/{len(worklist)} "
                    f"newly_correct={n_flipped} judge_failed={n_failed}",
                    flush=True,
                )

    _snapshot()

    # Rebuild summary.json accuracy.
    summary_path = cell_dir / "summary.json"
    summary: Dict[str, Any] = {}
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text())
        except Exception:
            summary = {}
    new_resolved = sum(1 for r in rows if _is_correct(r))
    n_done_summary = summary.get("n_done", n_total) or n_total
    new_acc = new_resolved / n_done_summary if n_done_summary else 0.0
    summary["accuracy"] = new_acc
    summary_path.write_text(json.dumps(summary, indent=2))

    print(
        f"[DONE] {name} acc {old_acc:.3f} -> {new_acc:.3f} "
        f"(resolved {old_resolved} -> {new_resolved}, +{n_flipped} flipped) "
        f"judge_failed={n_failed}/{len(worklist)}",
        flush=True,
    )
    return {
        "cell": name,
        "old_acc": old_acc,
        "new_acc": new_acc,
        "old_resolved": old_resolved,
        "new_resolved": new_resolved,
        "judge_failed": n_failed,
        "n_done": n_done_summary,
    }


# ---------- results-table.md updater (auto-gen section only) ----------

def _update_results_table(summaries: List[Dict[str, Any]]) -> None:
    """Swap the accuracy in the auto-generated `| `cell` | GAIA | acc · $... `
    rows. Curated tables (different format) are left for a manual pass."""
    if not DOCS_TABLE.exists():
        print(f"[WARN] {DOCS_TABLE} missing — skipping table update")
        return
    lines = DOCS_TABLE.read_text().splitlines()
    updated = 0
    for s in summaries:
        if s.get("skipped"):
            continue
        needle = f"| `{s['cell']}` | GAIA | "
        for i, line in enumerate(lines):
            if line.startswith(needle):
                rest = line[len(needle):]
                # rest looks like "0.060 · $15.28 | 21619s | ..."
                parts = rest.split(" · ", 1)
                if len(parts) == 2:
                    lines[i] = f"{needle}{s['new_acc']:.3f} · {parts[1]}"
                    updated += 1
                break
    DOCS_TABLE.write_text("\n".join(lines) + "\n")
    print(f"[TABLE] updated {updated} auto-gen GAIA rows in {DOCS_TABLE.name}")


# ---------- CLI ----------

def _resolve_cells(args: argparse.Namespace) -> List[Path]:
    if args.all_gaia:
        cells = sorted(p for p in RUNS_DIR.glob("*-gaia-n100") if p.is_dir())
        return [c for c in cells if (c / "results.jsonl").exists()]
    if not args.cells:
        raise SystemExit("pass --all-gaia or --cells a,b,c")
    out = []
    for name in args.cells.split(","):
        name = name.strip()
        if name:
            out.append(RUNS_DIR / name)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all-gaia", action="store_true",
                    help="rescore every *-gaia-n100 cell")
    ap.add_argument("--cells", help="comma-separated cell names")
    args = ap.parse_args()

    cells = _resolve_cells(args)
    print(f"[rescore_gaia] judge={JUDGE_MODEL}  cells={len(cells)}", flush=True)
    print("[rescore_gaia] loading GAIA index...", flush=True)
    gaia_index = _load_gaia_index()
    print(f"[rescore_gaia] GAIA index: {len(gaia_index)} tasks", flush=True)

    summaries: List[Dict[str, Any]] = []
    for cell_dir in cells:
        if not cell_dir.exists():
            print(f"[SKIP] {cell_dir.name} — missing dir", flush=True)
            continue
        summaries.append(_process_cell(cell_dir, gaia_index))

    _update_results_table(summaries)

    print("\n=== rescore_gaia summary ===", flush=True)
    for s in sorted((x for x in summaries if not x.get("skipped")),
                     key=lambda x: x["new_acc"] - x["old_acc"], reverse=True):
        delta = s["new_acc"] - s["old_acc"]
        print(f"  {s['cell']:<46} {s['old_acc']:.3f} -> {s['new_acc']:.3f} "
              f"({delta:+.3f})  judge_failed={s['judge_failed']}", flush=True)


if __name__ == "__main__":
    main()
