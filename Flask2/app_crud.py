from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy

db_file = "F:\\SQLite\\Databases\\arc_ng.db"

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///"+ db_file
db = SQLAlchemy(app)

class Users(db.Model):
    __tablename__ = 'arc_persons'

    user_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    email_address = db.Column(db.String(50), unique=True, nullable=False)

    def json(self):
        return {'user_id': self.user_id, 'user_name': self.user_name, 'email_address': self.email_address}

# db.create_all()

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
    except:
        return make_response(jsonify({'message': 'error getting users'}), 500)
# get a user by id
@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        user = Users.query.filter_by(user_id=user_id).first()
        if user:
            return make_response(jsonify({'user': user.json()}), 200)
        return make_response(jsonify({'message': 'user not found'}), 404)
    except:
        return make_response(jsonify({'message': 'error getting user'}), 500)

# create a user
@app.route('/users', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        new_user = Users(
            user_id=data['user_id'],
            user_name=data['user_name'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            email_address=data['email_address']
        )
        db.session.add(new_user)
        db.session.commit()
        return make_response(jsonify({'message': 'user created'}), 201)
    except:
        return make_response(jsonify({'message': 'error creating user'}), 500)
    
# update a user
@app.route('/users/<int:id>', methods=['PUT'])
def update_user(user_id):
    try:
        user = Users.query.filter_by(user_id=user_id).first()
        if user:
            data = request.get_json()
            user.user_name = data['user_name']
            user.first_name = data['first_name']
            user.last_name = data['last_name']
            db.session.commit()
            return make_response(jsonify({'message': 'user updated'}), 200)
        return make_response(jsonify({'message': 'user not found'}), 404)
    except:
        return make_response(jsonify({'message': 'error updating user'}), 500)

# delete a user
@app.route('/users/<int:id>', methods=['DELETE'])
def delete_user(id):
    try:
        user = Users.query.filter_by(user_id=id).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return make_response(jsonify({'message': 'user deleted'}), 200)
        return make_response(jsonify({'message': 'user not found'}), 404)
    except:
        return make_response(jsonify({'message': 'error deleting user'}), 500)

if __name__ == '__main__':
    app.run()
