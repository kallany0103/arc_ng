from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'akmsnffjjhggkkd'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///F:\\SQLite\\Databases\\arc_ng.db"

db = SQLAlchemy(app)
# jwt = JWTManager(app)

class Users(db.Model):
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

class Authors(db.Model):
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

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):

      token = None

      if 'x-access-tokens' in request.headers:
         token = request.headers['x-access-tokens']

      if not token:
         return jsonify({'message': 'a valid token is missing'})

      try:
         data = jwt.decode(token, app.config['SECRET_KEY'])
         current_user = Users.query.filter_by(public_id=data['public_id']).first()
      except:
         return jsonify({'message': 'token is invalid'})

         return f(current_user, *args, **kwargs)
   return decorator

@app.route('/register', methods=['GET', 'POST'])
def signup_user():  
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
   return jsonify({'message': 'registered successfully'})
 
@app.route('/login', methods=['GET', 'POST'])  
def login_user(): 
 
  auth = request.authorization   

  if not auth or not auth.user_name or not auth.password:  
     return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})    

  user = Users.query.filter_by(user_name=auth.user_name).first()   
     
  if check_password_hash(user.password, auth.password):  
     token = jwt.encode({'user_id': user.user_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
     return jsonify({'token' : token.decode('UTF-8')}) 

  return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/author', methods=['POST', 'GET'])
@token_required
def create_author(current_user):
   
   data = request.get_json() 

   new_author = Authors(first_name=data['first_name'], last_name=data['last_name'], user_id=current_user.user_id)  
   db.session.add(new_author)   
   db.session.commit()   

   return jsonify({'message' : 'new author created'})

if __name__ == '__main__':
    app.run(debug=True)