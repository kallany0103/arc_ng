import sqlite3
import psycopg2

# SQLite Connection Parameters
sqlite_conn = sqlite3.connect('F:\\SQLite\\Databases\\arc_ng_project.db')
print(sqlite_conn)
sqlite_cursor = sqlite_conn.cursor()
print(sqlite_cursor)

# PostgreSQL Connection Parameters
pg_conn = psycopg2.connect(
    host="129.146.59.50",
    port="5433",  # Specify the port number here
    database="arc_ng_project",
    user="postgres",
    password="$Raj#123"
)
print(pg_conn)
pg_conn.autocommit = True
pg_cursor = pg_conn.cursor()
print(pg_cursor)

try:
    # Get list of table names from SQLite database excluding sqlite_sequence
    sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence';")
    tables = sqlite_cursor.fetchall()
    print(tables)

    # Loop through tables and migrate schema and data
    for table in tables:
        table_name = table[0]
        print(table_name)
        sqlite_cursor.execute(f"PRAGMA table_info({table_name})")
        column_info = sqlite_cursor.fetchall()
        print(column_info)

        # Generate column names, data types, and constraints dynamically
        columns = []
        placeholders = []
        for col in column_info:
            column_name = col[1]
            print(column_name)
            data_type = col[2]
            print(data_type)
            columns.append(column_name)
            placeholders.append('%s')
            print(placeholders)

            # Mapping SQLite data types to PostgreSQL data types (customize if needed)
            # This example assumes INTEGER and TEXT data types, modify as per your schema
            if data_type == 'INTEGER':
                columns[-1] += ' INTEGER'
                print(columns)
            elif data_type == 'TEXT':
                columns[-1] += ' TEXT'
                print(columns)
            # Add more data type mappings as per your requirement

        # Create table in PostgreSQL with data types
        create_table_query = f"CREATE TABLE IF NOT EXISTS app.{table_name} ({', '.join(columns)})"
        print(create_table_query)
        pg_cursor.execute(create_table_query)

        # Retrieve data from SQLite table
        sqlite_cursor.execute(f"SELECT * FROM {table_name}")
        rows = sqlite_cursor.fetchall()
        print(rows)

        # Insert data into PostgreSQL table
        insert_query = f"INSERT INTO app.{table_name} VALUES ({', '.join(placeholders)})"
        print(insert_query)
        pg_cursor.executemany(insert_query, rows)
       

except Exception as e:
    # Handle the error
    print(f"Error: {e}")

finally:
    # Close connections
    sqlite_cursor.close()
    sqlite_conn.close()
    pg_cursor.close()
    pg_conn.close()
