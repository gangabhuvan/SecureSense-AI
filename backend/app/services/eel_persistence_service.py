"""
eel_persistence_service.py

Database persistence bridge for the SecureSense AI
Explainable Evidence Ledger (EEL).

The intelligence services remain responsible for generating
and committing evidence to the central in-memory EEL.

This service persists those committed ledger entries to the
database and associates them with a communication.
"""

from __future__ import annotations

from typing import Iterable

from sqlalchemy.orm import Session

from app.database.models import EELEntry
from app.eel.evidence_models import EvidenceLedgerEntry


class EELPersistenceService:
    """
    Persist Explainable Evidence Ledger entries.

    Persistence is idempotent by ledger_id and evidence_id so
    the same evidence cannot accidentally be inserted twice.
    """

    def persist_entry(
        self,
        db: Session,
        communication_id: str,
        ledger_entry: EvidenceLedgerEntry,
    ) -> EELEntry:
        """
        Persist one committed EEL entry.
        """

        if not communication_id:
            raise ValueError(
                "communication_id is required for EEL persistence."
            )

        if ledger_entry is None:
            raise ValueError(
                "ledger_entry is required for EEL persistence."
            )

        evidence = ledger_entry.evidence

        # --------------------------------------------------
        # Idempotency
        # --------------------------------------------------

        existing = (
            db.query(EELEntry)
            .filter(
                (
                    EELEntry.ledger_id
                    == ledger_entry.ledger_id
                )
                |
                (
                    EELEntry.evidence_id
                    == evidence.evidence_id
                )
            )
            .first()
        )

        if existing is not None:
            return existing

        # --------------------------------------------------
        # Persist complete evidence snapshot
        # --------------------------------------------------

        row = EELEntry(
            ledger_id=ledger_entry.ledger_id,

            evidence_id=evidence.evidence_id,

            communication_id=communication_id,

            module=evidence.module,

            evidence_type=evidence.evidence_type,

            prediction=evidence.prediction,

            confidence=float(evidence.confidence),

            risk_score=float(evidence.risk_score),

            recorded_at=ledger_entry.recorded_at,

            evidence=evidence.model_dump(
                mode="json"
            ),
        )

        db.add(row)

        return row

    def persist_entries(
        self,
        db: Session,
        communication_id: str,
        ledger_entries: Iterable[
            EvidenceLedgerEntry
        ],
    ) -> list[EELEntry]:
        """
        Persist multiple EEL entries atomically.

        The caller receives the persisted ORM rows.
        """

        persisted = []

        try:

            for ledger_entry in ledger_entries:

                if ledger_entry is None:
                    continue

                row = self.persist_entry(
                    db=db,
                    communication_id=communication_id,
                    ledger_entry=ledger_entry,
                )

                persisted.append(row)

            db.commit()

            for row in persisted:
                db.refresh(row)

            return persisted

        except Exception:

            db.rollback()
            raise


eel_persistence_service = EELPersistenceService()