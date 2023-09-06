from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'akmsnffjjhggkkd'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///F:\\SQLite\\Databases\\arc_ng.db"
db = SQLAlchemy(app)

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

def token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get('x-access-tokens')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorator

@app.route('/users', methods=['GET'])
def get_users():
    try:
        users = Users.query.all()
        return make_response(jsonify([user.json() for user in users]), 200)
    except:
        return make_response(jsonify({'message': 'error getting users'}), 500)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = Users(user_name=data['user_name'], first_name=data['first_name'], last_name=data['last_name'], email_address=data['email_address'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    print(data)
    user = Users.query.filter_by(user_name=data['user_name']).first()
    print(user)
    if user and check_password_hash(user.password, data['password']):
        token = jwt.encode({'user_id': user.user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})

    return jsonify({'message': 'Invalid credentials'}), 401
    return data

@app.route('/create_author', methods=['POST'])
@token_required
def create_author(current_user):
    data = request.get_json()
    new_author = Authors(first_name=data['first_name'], last_name=data['last_name'], user_id=current_user.user_id)
    db.session.add(new_author)
    db.session.commit()
    return jsonify({'message': 'Author created successfully'}), 201

if __name__ == '__main__':
    app.run(debug=True)
