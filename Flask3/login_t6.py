from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid

db_file = "F:\\SQLite\\Databases\\arc_ng.db"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'akmsnffjjhggkkd'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///"+ db_file
db = SQLAlchemy(app)

jwt = JWTManager(app)

class Users(db.Model):
    __tablename__ = 'arc_persons'

    user_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    email_address = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def json(self):
        return {'user_id': self.user_id, 'user_name': self.user_name, 'email_address': self.email_address}

class Authors(db.Model):
    __tablename__ = 'author'

    author_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    user_id = db.Column(db.Integer, db.ForeignKey('arc_persons.user_id'))

    def json(self):
        return {'author_id': self.author_id, 'first_name': self.first_name, 'last_name': self.last_name, 'user_id': self.user_id }


@app.route('/users', methods=['GET'])
def get_users():
    try:
        users = Users.query.all()
        return make_response(jsonify([user.json() for user in users]), 200)
    except:
        return make_response(jsonify({'message': 'Error getting users'}), 500)

@app.route('/register', methods=['POST'])
@jwt_required()
def register():
    data = request.get_json()
    user_name = data['user_name']
    first_name = data['first_name']
    last_name = data['last_name']
    email_address = data['email_address']
    password = data['password']
    hashed_password = generate_password_hash(password, method='sha256')

    new_user = Users(user_name=user_name, first_name=first_name, last_name=last_name, email_address=email_address, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user_name = data['user_name']  
    password = data['password']

    user = Users.query.filter_by(user_name=user_name).first()

    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.user_id)
        return jsonify({'access_token': access_token}), 200

    return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/create_author', methods=['POST'])
@jwt_required()  # This route requires authentication
def create_author():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()

        new_author = Authors(
            first_name=data['first_name'],
            last_name=data['last_name'],
            user_id=current_user_id  # Associate the author with the authenticated user
        )
        db.session.add(new_author)
        db.session.commit()

        return jsonify({'message': 'Author created successfully'}), 201
    except Exception as e:
        return make_response(jsonify({'message': str(e)}), 500)
    
@app.route('/delete_author/<int:author_id>', methods=['DELETE'])
@jwt_required()
def delete_author(author_id):
    try:
        current_user_id = get_jwt_identity()
        author_to_delete = Authors.query.filter_by(author_id=author_id, user_id=current_user_id).first()

        if not author_to_delete:
            return jsonify({'message': 'Author not found or you do not have permission to delete'}), 404

        db.session.delete(author_to_delete)
        db.session.commit()

        return jsonify({'message': 'Author deleted successfully'}), 200
    except Exception as e:
        return make_response(jsonify({'message': str(e)}), 500)
    
@app.route('/authors', methods=['GET'])
@jwt_required()
def get_authors():
    try:
        authors = Authors.query.all()
        return make_response(jsonify([author.json() for author in authors]), 200)
    except:
        return make_response(jsonify({'message': 'error getting authors'}), 500)
    
@app.route('/authors/<int:author_id>', methods=['GET'])
@jwt_required()
def get_user(author_id):
    try:
        author = Authors.query.filter_by(author_id=author_id).first()
        if author:
            return make_response(jsonify({'user': author.json()}), 200)
        return make_response(jsonify({'message': 'author not found'}), 404)
    except:
        return make_response(jsonify({'message': 'error getting author'}), 500)


@app.route('/reset_user_password', methods=['POST'])
@jwt_required()
def reset_user_password():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    old_password = data['old_password']
    new_password = data['new_password']
    
    user = Users.query.get(current_user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    if not check_password_hash(user.password, old_password):
        return jsonify({'message': 'Invalid old password'}), 401
    
    hashed_new_password = generate_password_hash(new_password, method='sha256')
    user.password = hashed_new_password
    
    db.session.commit()
    
    return jsonify({'message': 'Password reset successful'}), 200

if __name__ == '__main__':
    app.run(debug=True)
