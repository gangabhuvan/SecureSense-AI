import sqlite3


DATABASE = "securesense.db"


COLUMNS = {
    "nlp_result": "JSON",
    "visual_result": "JSON",
    "url_results": "JSON",
    "multimodal_fusion": "JSON",
    "evidence_references": "JSON",
    "passport": "JSON",
}


def main():
    connection = sqlite3.connect(DATABASE)

    try:
        cursor = connection.cursor()

        existing_columns = {
            row[1]
            for row in cursor.execute(
                "PRAGMA table_info(communications)"
            ).fetchall()
        }

        print(
            "=== RICH ANALYSIS SNAPSHOT MIGRATION ==="
        )

        for name, column_type in COLUMNS.items():
            if name in existing_columns:
                print(
                    f"{name}: already exists"
                )
                continue

            cursor.execute(
                f"ALTER TABLE communications "
                f"ADD COLUMN {name} {column_type}"
            )

            print(
                f"{name}: added"
            )

        connection.commit()

        print("Migration committed successfully.")

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    main()