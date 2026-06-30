"""Tests for source-aware HybridSearch behavior."""

from __future__ import annotations

from datetime import datetime, timezone

from openjarvis.connectors.hybrid_search import HybridSearch
from openjarvis.connectors.store import KnowledgeStore


def _store_doc(
    store: KnowledgeStore,
    *,
    title: str,
    source: str,
    timestamp: datetime,
) -> None:
    store.store(
        content=f"Title: {title}\nWhen: {timestamp.isoformat()}",
        source=source,
        doc_type="event" if source == "gcalendar" else "email",
        doc_id=f"{source}:{title.lower().replace(' ', '-')}",
        title=title,
        timestamp=timestamp,
    )


def test_next_calendar_events_returns_nearest_gcalendar_rows() -> None:
    """Generic upcoming-calendar queries should be chronological timelines."""
    store = KnowledgeStore(db_path=":memory:")
    _store_doc(
        store,
        title="Calendar Digest Email",
        source="gmail",
        timestamp=datetime(2999, 1, 1, 9, tzinfo=timezone.utc),
    )
    _store_doc(
        store,
        title="Birthday Reminder",
        source="gcalendar",
        timestamp=datetime(2999, 12, 1, 9, tzinfo=timezone.utc),
    )
    _store_doc(
        store,
        title="Music Lesson",
        source="gcalendar",
        timestamp=datetime(2999, 5, 26, 18, tzinfo=timezone.utc),
    )
    _store_doc(
        store,
        title="Team Sync",
        source="gcalendar",
        timestamp=datetime(2999, 5, 27, 10, tzinfo=timezone.utc),
    )

    search = HybridSearch(store)
    hits = search.search("what are my next calendar events?", limit=2)
    contraction_hits = search.search("what's next on my calendar?", limit=2)

    assert [hit.title for hit in hits] == ["Music Lesson", "Team Sync"]
    assert all(hit.source == "gcalendar" for hit in hits)
    assert [hit.title for hit in contraction_hits] == ["Music Lesson", "Team Sync"]
    assert all(hit.source == "gcalendar" for hit in contraction_hits)


def test_empty_upcoming_calendar_filter_uses_ascending_start_time() -> None:
    """Planner-emitted structured calendar searches return nearest first."""
    store = KnowledgeStore(db_path=":memory:")
    _store_doc(
        store,
        title="Later Event",
        source="gcalendar",
        timestamp=datetime(2999, 8, 1, 9, tzinfo=timezone.utc),
    )
    _store_doc(
        store,
        title="Sooner Event",
        source="gcalendar",
        timestamp=datetime(2999, 7, 1, 9, tzinfo=timezone.utc),
    )

    hits = HybridSearch(store).search(
        "",
        sources=["gcalendar"],
        time_range=(datetime(2999, 1, 1, tzinfo=timezone.utc), None),
        limit=2,
    )

    assert [hit.title for hit in hits] == ["Sooner Event", "Later Event"]
