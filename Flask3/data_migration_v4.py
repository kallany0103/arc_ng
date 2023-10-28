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

# Get the list of table names from SQLite database excluding sqlite_sequence table
sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence';")
tables = sqlite_cursor.fetchall()

# Loop through each table and migrate data
for table in tables:
    table_name = table[0]
    sqlite_cursor.execute(f"SELECT * FROM {table_name}")
    rows = sqlite_cursor.fetchall()

    for row in rows:
        # Construct the INSERT statement dynamically based on table columns
        columns = ",".join([col_desc[0] for col_desc in sqlite_cursor.description])
        values = ",".join(["%s" for _ in range(len(row))])
        insert_query = f"INSERT INTO app.{table_name} ({columns}) VALUES ({values})"
        pg_cursor.execute(insert_query, row)

# Commit and close connections
pg_conn.commit()

sqlite_cursor.close()
sqlite_conn.close()

pg_cursor.close()
pg_conn.close()
