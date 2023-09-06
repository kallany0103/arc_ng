from flask import Flask, make_response, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'akmsnffjjhggkkd'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///F:\\SQLite\\Databases\\arc_ng.db"
db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    __tablename__ = 'arc_persons'

    user_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    email_address = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def to_json(self):
        return {
            'user_id': self.user_id,
            'user_name': self.user_name,
            'email_address': self.email_address
        }

class Author(db.Model):
    __tablename__ = 'author'

    author_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    user_id = db.Column(db.Integer, db.ForeignKey('arc_persons.user_id'))

    def to_json(self):
        return {
            'author_id': self.author_id,
            'first_name': self.first_name,
            'last_name': self.last_name
        }

@app.route('/users', methods=['GET'])
def get_users():
    try:
        users = User.query.all()
        return jsonify([user.to_json() for user in users]), 200
    except Exception as e:
        return jsonify({'message': 'Error getting users'}), 500

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        user = User.query.get(user_id)
        if user:
            return jsonify({'user': user.to_json()}), 200
        return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'message': 'Error getting user'}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        user_name = data['user_name']
        first_name = data['first_name']
        last_name = data['last_name']
        email_address = data['email_address']
        password = data['password']
        hashed_password = generate_password_hash(password, method='sha256')

        new_user = User(user_name=user_name, first_name=first_name, last_name=last_name, email_address=email_address, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        return jsonify({'message': 'Error creating user'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        user_name = data['user_name']
        password = data['password']

        user = User.query.filter_by(user_name=user_name).first()

        if user and check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.user_id)
            return jsonify({'access_token': access_token}), 200

        return jsonify({'message': 'Invalid username or password'}), 401
    except Exception as e:
        return make_response(jsonify({'message': 'error getting token', 'error': str(e)}), 500)
    
if __name__ == '__main__':
    app.run(debug=True)
