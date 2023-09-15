from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
from functools import wraps
import requests

db_file = "F:\\SQLite\\Databases\\arc_ng2.db"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'akmsnffjjhggkkd'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///"+ db_file
db = SQLAlchemy(app)

jwt = JWTManager(app)

class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)

class Users(db.Model):
    __tablename__ = 'arc_persons'

    user_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    email_address = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    #roles = db.relationship('Role', secondary='user_roles', backref='users')

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

class ApiEndpoints(db.Model):
    __tablename__ = 'api_endpoints'
    api_endpoint_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    api_endpoint = db.Column(db.String(30), nullable=False)
    parameter = db.Column(db.String(30), nullable=False)
    method = db.Column(db.String(30), nullable=False)
    privilege_id = db.Column(db.Integer)

    # Define a unique constraint on api_endpoint, parameter, and method
    __table_args__ = (
        db.UniqueConstraint('api_endpoint', 'parameter', 'method', name='uq_api_endpoint_parameters_method'),
    )
    def json(self):
        return {'api_endpoint': self.api_endpoint, 'parameter': self.parameter, 'method': self.method, 'privilege_id': self.privilege_id}

class ApiEndpointRoles(db.Model):
    __tablename__ = 'api_endpoint_roles'
    api_endpoint_id = db.Column(db.Integer(), db.ForeignKey('api_endpoints.api_endpoint_id'), primary_key=True)
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id'), primary_key=True)

    def json(self):
        return {'api_endpoint_id': self.api_endpoint_id, 'role_id': self.role_id }
    

class Privileges(db.Model):
    __tablename__ = 'privileges'
    privilege_id = db.Column(db.Integer, primary_key=True)
    privilege_name = db.Column(db.String(30))

    def json(self):
        return {'privilege_id': self.privilege_id, 'privilege_name': self.privilege_name}
#user_roles = db.Table('user_roles',
    #db.Column('user_id', db.Integer(), db.ForeignKey('arc_persons.user_id')),
    #db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class UserRole(db.Model):
    __tablename__ = 'user_roles'
    user_id = db.Column(db.Integer(), db.ForeignKey('arc_persons.user_id'), primary_key=True)
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id'), primary_key=True)

    def json(self):
        return {'user_id': self.user_id, 'role_id': self.role_id }
    
class UserPrivileges(db.Model):
    __tablename__ = 'user_privileges'
    user_id = db.Column(db.Integer(), db.ForeignKey('arc_persons.user_id'), primary_key=True)
    privilege_id = db.Column(db.Integer(), db.ForeignKey('privileges.privilege_id'), primary_key=True)

    def json(self):
        return {'user_id': self.user_id, 'privilege_id': self.privilege_id }

@app.route('/api_endpoints', methods=['GET'])
#@jwt_required()
def get_api_endpoints():
    try:
        api_endpoints = ApiEndpoints.query.all()
        return make_response(jsonify([api_endpoint.json() for api_endpoint in api_endpoints]), 200)
    except:
        return make_response(jsonify({'message': 'error getting api endpoints'}), 500)

# create an api endpoints
@app.route('/api_endpoints', methods=['POST'])
def create_api_endpoints():
    try:
        data = request.get_json()
        new_api = ApiEndpoints(
            #api_endpoints_id = data['api_endpoints_id'],
            api_endpoint      = data['api_endpoint'],
            parameter         = data['parameter'],
            method            = data['method'],
            privilege_id      = data['privilege_id']
        )
        db.session.add(new_api)
        db.session.commit()
        return make_response(jsonify({'message': 'New api created'}), 201)
    except:
        return make_response(jsonify({'message': 'Error creating api'}), 500)
       
# update an api_endpoint
@app.route('/api_endpoints/<int:api_endpoint_id>', methods=['PUT'])
def update_api_endpoint(api_endpoint_id):
    try:
        endpoint = ApiEndpoints.query.filter_by(api_endpoint_id=api_endpoint_id).first()
        print(endpoint)
        if endpoint:
            data = request.get_json()
            #endpoint.api_endpoint = data['api_endpoint']
            endpoint.parameter = data['parameter']
            #endpoint.method = data['method']
            endpoint.privilege_id = data['privilege_id']
            db.session.commit()
            return make_response(jsonify({'message': 'Endpoint updated'}), 200)
        return make_response(jsonify({'message': 'Endpoint not found'}), 404)
    except:
        return make_response(jsonify({'message': 'Error updating Endpoint'}), 500)

# Create a new user privilege by username and privilege_names
@app.route('/user_privileges', methods=['POST'])    
def create_user_privileges():
    try:
        # Parse username and privilege_names from the request body
        data = request.get_json()
        username = data['username']
        privilege_names = data['privilege_names']  # Expect a list of privilege names

        # Query the database to get the user by username
        user = Users.query.filter_by(user_name=username).first()

        if user:
            # Iterate through the list of privilege names
            for privilege_name in privilege_names:
                # Query the database to get the privilege by name
                privilege = Privileges.query.filter_by(privilege_name=privilege_name).first()

                if privilege:
                    # Check if the user privilege already exists
                    existing_user_privilege = UserPrivileges.query.filter_by(user_id=user.user_id, privilege_id=privilege.privilege_id).first()
                    if existing_user_privilege:
                        return make_response(jsonify({'message': f'User already has privilege: {privilege_name}'}), 400)

                    # Create a new user_privilege entry
                    new_user_privilege = UserPrivileges(user_id=user.user_id, privilege_id=privilege.privilege_id)
                    db.session.add(new_user_privilege)
                else:
                    return make_response(jsonify({'message': f'Privilege not found: {privilege_name}'}), 404)

            # Commit all user_privilege entries to the database
            db.session.commit()

            # Return a success message
            return jsonify({'message': 'User privileges assigned successfully'}), 201
        else:
            return make_response(jsonify({'message': 'User not found'}), 404)
    except Exception as e:
        return make_response(jsonify({'message': str(e)}), 500)
    
@app.route('/user_roles', methods=['POST'])
def create_user_roles():
    try:
        # Parse username and role_names from the request body
        data = request.get_json()
        username = data['username']
        role_names = data['role_names']  # Expect a list of role names

        # Query the database to get the user by username
        user = Users.query.filter_by(user_name=username).first()

        if user:
            # Iterate through the list of role names
            for role_name in role_names:
                # Query the database to get the role by name
                role = Role.query.filter_by(name=role_name).first()

                if role:
                    # Check if the user already has that role
                    existing_user_role = UserRole.query.filter_by(user_id=user.user_id, role_id=role.id).first()
                    if not existing_user_role:
                        # Create a new user_role entry
                        new_user_role = UserRole(user_id=user.user_id,
                                                 role_id=role.id)
                        db.session.add(new_user_role)
                else:
                    return make_response(jsonify({'message': f'Role not found: {role_name}'}), 404)

            # Commit all user_role entries to the database
            db.session.commit()

            # Return a success message
            return jsonify({'message': 'User roles assigned successfully'}), 201
        else:
            return make_response(jsonify({'message': 'User not found'}), 404)
    except Exception as e:
        return make_response(jsonify({'message': str(e)}), 500)
    
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        user_name = data['user_name']
        first_name = data['first_name']
        last_name = data['last_name']
        email_address = data['email_address']
        password = data['password']
        privilege_names = data.get('privilege_names', [])  # Get privilege names from the registration data, default to an empty list
        role_names = data.get('role_names', [])  # Get role names from the registration data, default to an empty list

        # Hash the password
        hashed_password = generate_password_hash(password, method='sha256')

        # Create a new user instance
        new_user = Users(
            user_name=user_name,
            first_name=first_name,
            last_name=last_name,
            email_address=email_address,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        # Now, call the user_privileges API to assign privileges to the user
        user_privileges_data = {
            "username": user_name,
            "privilege_names": privilege_names
        }

        user_privileges_response = requests.post("http://127.0.0.1:5000/user_privileges", json=user_privileges_data)

        # Check the response from the user_privileges API
        if user_privileges_response.status_code == 201:
            # Now, call the user_roles API to assign roles to the user
            user_roles_data = {
                "username": user_name,
                "role_names": role_names
            }

            user_roles_response = requests.post("http://127.0.0.1:5000/user_roles", json=user_roles_data)

            if user_roles_response.status_code == 201:
                return jsonify({'message': 'User created successfully with assigned privileges and roles'}), 201
            else:
                # Handle the case where user roles assignment failed
                return jsonify({'message': 'User created, but roles assignment failed'}), 500
        else:
            # Handle the case where user privileges assignment failed
            return jsonify({'message': 'User created, but privileges assignment failed'}), 500

    except Exception as e:
        return jsonify({'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)