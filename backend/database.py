import sqlite3
from pathlib import Path

DB_FILE = Path("database/honeyshield.db")
SCHEMA_FILE = Path("database/schema.sql")


def get_connection():
    return sqlite3.connect(DB_FILE)


def initialize_database():
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)

    connection = get_connection()

    with SCHEMA_FILE.open("r", encoding="utf-8") as file:
        schema = file.read()

    connection.executescript(schema)
    connection.commit()
    connection.close()

    print("Database initialized successfully.")


if __name__ == "__main__":
    initialize_database()

