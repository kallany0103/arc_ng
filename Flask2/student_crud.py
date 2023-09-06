from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy

db_file = "F:\\SQLite\\Databases\\Student.db"

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///"+ db_file
db = SQLAlchemy(app)

class Student(db.Model):
    __tablename__ = 'Student'

    student_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))

    def json(self):
        return {'student_id': self.student_id, 'first_name': self.first_name, 'last_name': self.last_name}

# db.create_all()

# create a test route
@app.route('/test', methods=['GET'])
def test():
    return make_response(jsonify({'message': 'test route'}), 200)

# get all students
@app.route('/students', methods=['GET'])
def get_students():
    try:
        students = Student.query.all()
        return make_response(jsonify([student.json() for student in students]), 200)
    except:
        return make_response(jsonify({'message': 'error getting records'}), 500)

# get a student by student_id
@app.route('/students/<int:id>', methods=['GET'])
def get_student(id):
    try:
        student = Student.query.filter_by(student_id=id).first()
        if student:
            return make_response(jsonify({'student': student.json()}), 200)
        return make_response(jsonify({'message': 'record not found'}), 404)
    except:
        return make_response(jsonify({'message': 'error getting record'}), 500)

# create a new student
@app.route('/students', methods=['POST'])
def create_student():
    try:
        data = request.get_json()
        new_student = Student(
            student_id=data['student_id'],
            first_name=data['first_name'],
            last_name=data['last_name']
        )
        db.session.add(new_student)
        db.session.commit()
        return make_response(jsonify({'message': 'New record added'}), 201)
    except:
        return make_response(jsonify({'message': 'error adding new record'}), 500)

# update a student
@app.route('/students/<int:id>', methods=['PUT'])
def update_student(id):
    try:
        student = Student.query.filter_by(student_id=id).first()
        if student:
            data = request.get_json()
            student.first_name = data['first_name']
            student.last_name = data['last_name']
            db.session.commit()
            return make_response(jsonify({'message': 'record updated'}), 200)
        return make_response(jsonify({'message': 'record not found'}), 404)
    except:
        return make_response(jsonify({'message': 'error updating record'}), 500)

# delete a student
@app.route('/students/<int:id>', methods=['DELETE'])
def delete_student(id):
    try:
        student = Student.query.filter_by(student_id=id).first()
        if student:
            db.session.delete(student)
            db.session.commit()
            return make_response(jsonify({'message': 'record deleted'}), 200)
        return make_response(jsonify({'message': 'record not found'}), 404)
    except:
        return make_response(jsonify({'message': 'error deleting record'}), 500)

if __name__ == '__main__':
    app.run()
