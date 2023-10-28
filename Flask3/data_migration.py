import sqlite3
import psycopg2

# SQLite Connection Parameters
sqlite_conn = sqlite3.connect('F:\\SQLite\\Databases\\arc_ng_project.db')
sqlite_cursor = sqlite_conn.cursor()

# PostgreSQL Connection Parameters
pg_conn = psycopg2.connect(
    host="129.146.59.50",
    port="5433",  # Specify the port number here
    database="arc_ng_project",
    user="postgres",
    password="$Raj#123"
)
pg_cursor = pg_conn.cursor()

# Copy data from SQLite to PostgreSQL
sqlite_cursor.execute("SELECT * FROM ARC_PERSONS")
rows = sqlite_cursor.fetchall()

for row in rows:
    pg_cursor.execute("INSERT INTO app.ARC_PERSONS VALUES (%s, %s, %s, %s, %s)", row)

# Commit and close connections
pg_conn.commit()

sqlite_cursor.close()
sqlite_conn.close()

pg_cursor.close()
pg_conn.close()
