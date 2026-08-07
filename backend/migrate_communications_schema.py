"""
One-time SQLite migration for the communications table.

Changes:
- communication_id: VARCHAR -> VARCHAR NOT NULL
- risk_score: INTEGER -> FLOAT

Existing data is preserved.
"""

import sqlite3


DB_PATH = "securesense.db"


def main():
    conn = sqlite3.connect(DB_PATH)

    try:
        cursor = conn.cursor()



        # --------------------------------------------------
        # 1. Pre-migration count
        # --------------------------------------------------

        old_count = cursor.execute(
            "SELECT COUNT(*) FROM communications"
        ).fetchone()[0]

    

        # --------------------------------------------------
        # 2. Start explicit transaction
        # --------------------------------------------------

        cursor.execute("BEGIN IMMEDIATE")

        # --------------------------------------------------
        # 3. Create replacement table
        # --------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE communications_new (
                id INTEGER NOT NULL,
                communication_id VARCHAR NOT NULL,
                filename VARCHAR,
                file_type VARCHAR,
                filepath VARCHAR,
                filesize INTEGER,
                mime_type VARCHAR,
                sha256 VARCHAR,
                status VARCHAR,
                uploaded_at DATETIME,
                extracted_text TEXT,
                ocr_status VARCHAR,
                risk_score FLOAT,
                risk_level VARCHAR,
                confidence FLOAT,
                document_type VARCHAR,
                document_confidence FLOAT,
                summary TEXT,
                entities JSON,
                findings JSON,
                processing_time FLOAT,
                PRIMARY KEY (id)
            )
            """
        )

        # --------------------------------------------------
        # 4. Copy existing records
        # --------------------------------------------------

        cursor.execute(
            """
            INSERT INTO communications_new (
                id,
                communication_id,
                filename,
                file_type,
                filepath,
                filesize,
                mime_type,
                sha256,
                status,
                uploaded_at,
                extracted_text,
                ocr_status,
                risk_score,
                risk_level,
                confidence,
                document_type,
                document_confidence,
                summary,
                entities,
                findings,
                processing_time
            )
            SELECT
                id,
                communication_id,
                filename,
                file_type,
                filepath,
                filesize,
                mime_type,
                sha256,
                status,
                uploaded_at,
                extracted_text,
                ocr_status,
                risk_score,
                risk_level,
                confidence,
                document_type,
                document_confidence,
                summary,
                entities,
                findings,
                processing_time
            FROM communications
            """
        )

        copied_count = cursor.execute(
            "SELECT COUNT(*) FROM communications_new"
        ).fetchone()[0]

    

        if copied_count != old_count:
            raise RuntimeError(
                "Row-count mismatch. Migration aborted."
            )

        # --------------------------------------------------
        # 5. Replace old table
        # --------------------------------------------------

        cursor.execute(
            "DROP TABLE communications"
        )

        cursor.execute(
            """
            ALTER TABLE communications_new
            RENAME TO communications
            """
        )

        # --------------------------------------------------
        # 6. Restore ORM-defined indexes
        # --------------------------------------------------

        cursor.execute(
            """
            CREATE UNIQUE INDEX
            ix_communications_communication_id
            ON communications (communication_id)
            """
        )

        cursor.execute(
            """
            CREATE INDEX
            ix_communications_id
            ON communications (id)
            """
        )

        # --------------------------------------------------
        # 7. Verify final count before commit
        # --------------------------------------------------

        final_count = cursor.execute(
            "SELECT COUNT(*) FROM communications"
        ).fetchone()[0]

        if final_count != old_count:
            raise RuntimeError(
                "Final row-count mismatch. Migration aborted."
            )

        conn.commit()



    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


if __name__ == "__main__":
    main()