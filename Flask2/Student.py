from sqlalchemy import create_engine, text
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

db_file="F:\\SQLite\\Databases\\Student.db"
db_conn = create_engine("sqlite:///"+ db_file, echo=True, future=True)
db = db_conn.connect()
print(db_conn)

class Student(Base):
   __tablename__ = 'Student'
   student_id = Column(Integer, primary_key =  True)
   first_name = Column(String)
   last_name = Column(String)

Session = sessionmaker(bind = db_conn)
session = Session()
result = session.query(Student).all()

for row in result:
   print ("First Name:",row.first_name,", Last Name:",row.last_name)