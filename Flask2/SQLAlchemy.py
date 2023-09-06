from sqlalchemy import create_engine, text

db_file="F:\\SQLite\\Databases\\Student.db"
db_conn = create_engine("sqlite:///"+ db_file, echo=True, future=True)
db = db_conn.connect()
print(db_conn)

outs1 = db.execute(text("SELECT * FROM Student"))
for _r in outs1:
 print(_r)

outs2 = db.execute(text("SELECT * FROM Student"))
print(outs2.fetchall())
