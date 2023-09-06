import os
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import date, datetime

db_file = os.getenv('DB_FILE_PATH')
print(db_file)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///" + db_file
db = SQLAlchemy(app)

class Users(db.Model):
    __tablename__ = 'arc_users'
    
    user_id = db.Column(db.Integer, primary_key=True)
    created_by = db.Column(db.Integer)
    created_on = db.Column(db.Date)
    last_updated_by = db.Column(db.Integer)
    last_updated_on = db.Column(db.Date)
    tanent_id = db.Column(db.Integer)

    def json(self):
        return {
            'user_id': self.user_id,
            'created_by': self.created_by,
            'created_on': self.created_on,
            'last_updated_by': self.last_updated_by,
            'last_updated_on': self.last_updated_on,
            'tanent_id': self.tanent_id
        }

# create a test route
@app.route('/test', methods=['GET'])
def test():
    return make_response(jsonify({'message': 'test route'}), 200)

# get all users
@app.route('/users', methods=['GET'])
def get_users():
    try:
        users = Users.query.all()
        return make_response(jsonify([user.json() for user in users]), 200)
    except Exception as e:
        return make_response(jsonify({'message': 'error getting users', 'error': str(e)}), 500)

# get a user by id
@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        user = Users.query.filter_by(user_id=user_id).first()
        if user:
            return make_response(jsonify({'user': user.json()}), 200)
        return make_response(jsonify({'message': 'user not found'}), 404)
    except Exception as e:
        return make_response(jsonify({'message': 'error getting user', 'error': str(e)}), 500)

# create a user
@app.route('/users', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        new_user = Users(
                      user_id         = data['user_id'],
                      created_by      = data['created_by'],
                      created_on      = datetime.strptime(data['created_on'], "%Y-%m-%d").date(),
                      # The datetime.strptime() function is used to convert the date strings into Python date objects. 
                      # The format "%Y-%m-%d" is used to match the date string format you provided (YYYY-MM-DD).
                      last_updated_by = data['last_updated_by'],
                      last_updated_on = datetime.strptime(data['last_updated_on'], "%Y-%m-%d").date(),
                      tanent_id       = data['tanent_id']
                    )
        db.session.add(new_user)
        db.session.commit()
        return make_response(jsonify({'message': 'user created'}), 201)
    except Exception as e:
        return make_response(jsonify({'message': 'error creating user', 'error': str(e)}), 500)
    
# update a user
@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    try:
        user = Users.query.filter_by(user_id=user_id).first()
        if user:
            data = request.get_json()
            user.created_by = data['created_by']
            user.created_on  = datetime.strptime(data['created_on'], "%Y-%m-%d").date()
            db.session.commit()
            return make_response(jsonify({'message': 'user updated'}), 200)
        return make_response(jsonify({'message': 'user not found'}), 404)
    except Exception as e:
        return make_response(jsonify({'message': 'error updating user', 'error': str(e)}), 500)

# delete a user
@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        user = Users.query.filter_by(user_id=user_id).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return make_response(jsonify({'message': 'user deleted'}), 200)
        return make_response(jsonify({'message': 'user not found'}), 404)
    except:
        return make_response(jsonify({'message': 'error deleting user'}), 500)

if __name__ == '__main__':
    app.run()
