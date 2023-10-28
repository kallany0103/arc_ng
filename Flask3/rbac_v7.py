from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
from functools import wraps
import requests
from flask_cors import CORS 
import json

postgres_uri = "postgresql://postgres:$Raj#123@129.146.59.50:5433/arc_ng_project"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'akmsnffjjhggkkd'
app.config['SQLALCHEMY_DATABASE_URI'] = postgres_uri
db = SQLAlchemy(app)
CORS(app)

jwt = JWTManager(app)


class ArcTenant(db.Model):
    __tablename__ = 'arc_tenants'

    tenant_id   = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_name = db.Column(db.String)

    def json(self):
        {'tenant_id'  : self.tenant_id,
         'tenant_name': self.tenant_name
         }

class ArcPerson(db.Model):
    __tablename__ = 'arc_persons'
    __table_args__ = {'schema': 'app'}

    user_id     = db.Column(db.Integer, primary_key=True)
    first_name  = db.Column(db.String(30))
    middle_name = db.Column(db.String(30))
    last_name   = db.Column(db.String(30))
    job_title   = db.Column(db.String(50))
    #roles = db.relationship('Role', secondary='user_roles', backref='users')

    def json(self):
        return {'user_id'    : self.user_id, 
                'first_name' : self.first_name, 
                'middle_name': self.middle_name,
                'last_name'  : self.last_name, 
                'job_title'  : self.job_title
                }
    
class ArcUser(db.Model):
    __tablename__ = 'arc_users'

    user_id         = db.Column(db.Integer, primary_key=True)
    created_by      = db.Column(db.Integer, nullable=False)
    created_on      = db.Column(db.String(30))
    last_updated_by = db.Column(db.Integer)
    last_updated_on = db.Column(db.String(50), unique=True, nullable=False)
    tenant_id       = db.Column(db.Integer, db.ForeignKey('arc_tenants.tenant_id'), nullable=False)  # Corrected line

    def json(self):
        return {
            'user_id': self.user_id,
            'created_by': self.created_by,
            'created_on': self.created_on,
            'last_updated_by': self.last_updated_by,
            'last_updated_on': self.last_updated_on,
            'tenant_id': self.tenant_id
        }

class ArcUserCredential(db.Model):
    __tablename__ = 'arc_user_credentials'

    user_id  = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(50), unique=True, nullable=False)

    def json(self):
        {'user_id' : self.user_id,
         'password': self.password
         }

class ArcUserProfile(db.Model):
    __tablename__ = 'arc_user_profiles'

    user_id      = db.Column(db.Integer, db.ForeignKey('arc_users.user_id'), primary_key=True)  # Corrected line
    profile_type = db.Column(db.String(50), db.ForeignKey('arc_profile_types.profile_type'), primary_key=True)
    profile_name = db.Column(db.String(50))

    def json(self):
        return {
            'user_id': self.user_id,
            'profile_type': self.profile_type,
            'profile_name': self.profile_name
        }

        
class ArcProfileType(db.Model):
    __tablename__ = 'arc_profile_types'

    profile_type = db.Column(db.String(30), primary_key=True)

    def json(self):
        {'profile_type': self.profile_type}

class ArcRole(db.Model):
    __tablename__ = 'arc_roles'

    role_id   = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50))
    role_type = db.Column(db.String, db.ForeignKey('arc_role_types.role_type'))

    def json(self):
        {'role_id'     : self.role_id,
         'role_name'   : self.role_name,
         'role_type'    : self.role_type
         }
        
class ArcRoleType(db.Model):
    __tablename__ = 'arc_role_types'

    role_type = db.Column(db.String, primary_key=True)

    def json(self):
        {'role_type': self.role_type}

class UserGrantedRole(db.Model):
    __tablename__ = 'user_granted_roles'
    user_id = db.Column(db.Integer(), db.ForeignKey('arc_persons.user_id'), primary_key=True)
    role_id = db.Column(db.Integer(), db.ForeignKey('arc_roles.role_id'), primary_key=True)

    def json(self):
        return {'user_id': self.user_id, 'role_id': self.role_id }
    
class ArcPrivilege(db.Model):
    __tablename__ = 'arc_privileges'

    privilege_id   = db.Column(db.Integer, primary_key=True)
    privilege_name = db.Column(db.String(50))
    privilege_type = db.Column(db.String, db.ForeignKey('arc_privilege_types.privilege_type'))

    def json(self):
        {'privilege_id'   : self.privilege_id,
         'privilege_name' : self.privilege_name,
         'privilege_type' : self.privilege_type
         }
        
class ArcPrivilegeType(db.Model):
    __tablename__ = 'arc_privilege_types'

    privilege_type = db.Column(db.String, primary_key=True)

    def json(self):
        {'privilege_type': self.privilege_type}

class UserGrantedPrivilege(db.Model):
    __tablename__ = 'user_granted_privileges'
    user_id = db.Column(db.Integer(), db.ForeignKey('arc_persons.user_id'), primary_key=True)
    privilege_id = db.Column(db.Integer(), db.ForeignKey('arc_privileges.privilege_id'), primary_key=True)

    def json(self):
        return {'user_id': self.user_id, 'privilege_id': self.privilege_id }
    
@app.route('/user_granted_roles', methods=['POST'])
def create_user_roles():
    try:
        data = request.get_json()
        user_id = data['user_id']
        role_names = data['role_names']

        for role_name in role_names:
            role = ArcRole.query.filter_by(role_name=role_name).first()
            if role:
                 new_user_role = UserGrantedRole(user_id=user_id, role_id=role.role_id)
                 db.session.add(new_user_role)
            else:
                 return make_response(jsonify({'message': f'Role "{role_name}" not found.'}), 404)

        db.session.commit()
        return jsonify({'message': 'User roles created successfully.'}), 201
    except Exception as e:
         return make_response(jsonify({'message': str(e)}), 500) 


@app.route('/user_granted_privileges', methods=['POST'])
def create_user_privileges():
     try:
         # Parse username and privilege_names from the request body
         data = request.get_json()
         user_id = data['user_id']
         privilege_names = data['privilege_names']  # Expect a list of privilege names

         for privilege_name in privilege_names:
             # Query the database to get the privilege by name
             privilege = ArcPrivilege.query.filter_by(privilege_name=privilege_name).first()

             if privilege:
                 new_user_privilege = UserGrantedPrivilege(user_id=user_id, privilege_id=privilege.privilege_id)
                 db.session.add(new_user_privilege)
             else:
                 return make_response(jsonify({'message': f'Privilege not found: {privilege_name}'}), 404)

         # Commit all user_privilege entries to the database
         db.session.commit()

         # Return a success message
         return jsonify({'message': 'User privileges assigned successfully'}), 201

     except Exception as e:
         return make_response(jsonify({'message': str(e)}), 500)



@app.route('/arcuser', methods=['POST'])
def create_arc_user():
    try:
        # Parse data from the request body
        data = request.get_json()
        user_id         = data['user_id']
        created_by      = data['created_by']
        created_on      = data['created_on']
        last_updated_by = data['last_updated_by']
        last_updated_on = data['last_updated_on']
        tenant_id       = data['tenant_id']

        # Create a new ArcUser object
        new_user = ArcUser(
            user_id         = user_id,
            created_by      = created_by,
            created_on      = created_on,
            last_updated_by = last_updated_by,
            last_updated_on = last_updated_on,
            tenant_id       = tenant_id
        )

        # Add the new user to the database session
        db.session.add(new_user)
        # Commit the changes to the database
        db.session.commit()

        # Return a success response
        return jsonify({'message': 'ARC_USER created successfully!'}), 201

    except Exception as e:
        # If there is an error, rollback the session and return an error response
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500
    

@app.route('/user_credentials', methods=['POST'])
def create_user_credentials():
    try:
        # Parse data from the request body
        data = request.get_json()
        user_id  = data['user_id']
        password = data['password']

        # Create a new ArcUserCredentials object
        new_credentials = ArcUserCredential(
            user_id  = user_id,
            password = password
        )

        # Add the new credentials to the database session
        db.session.add(new_credentials)
        # Commit the changes to the database
        db.session.commit()

        # Return a success response
        return jsonify({'message': 'User credentials created successfully!'}), 201

    except Exception as e:
        # If there is an error, rollback the session and return an error response
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500


@app.route('/user_profiles', methods=['POST'])
def create_user_profile():
    try:
        # Parse data from the request body
        data = request.get_json()
        user_id      = data['user_id']
        profile_type = data['profile_type']
        profile_name = data['profile_name']

        # Create a new ArcUserProfiles object
        new_profile = ArcUserProfile(
            user_id      = user_id,
            profile_type = profile_type,
            profile_name = profile_name
        )

        # Add the new profile to the database session
        db.session.add(new_profile)
        # Commit the changes to the database
        db.session.commit()

        # Return a success response
        return jsonify({'message': 'User profile created successfully!'}), 201

    except Exception as e:
        # If there is an error, rollback the session and return an error response
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500
    

@app.route('/arcpersons', methods=['GET'])
def get_users():
    try:
        users = ArcPerson.query.all()
        return make_response(jsonify([user.json() for user in users]), 200)
    except:
        return make_response(jsonify({'message': 'Error getting users'}), 500)


@app.route('/users', methods=['POST'])
def register():
    try:
        data            = request.get_json()
        user_id         = data['user_id']
        first_name      = data['first_name']
        middle_name     = data['middle_name']
        last_name       = data['last_name']
        job_title       = data['job_title']
        created_by      = data['created_by']
        created_on      = data['created_on']
        last_updated_by = data['last_updated_by']
        last_updated_on = data['last_updated_on']
        tenant_id       = data['tenant_id']
        profile_type    = data['profile_type']
        profile_name    = data['profile_name']
        password        = data['password']
        privilege_names = data.get('privilege_names', [])  # Get privilege names from the registration data, default to an empty list
        role_names = data.get('role_names', []) # Get role names from the registration data, default to an empty list
    
        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        # Create a new user instance
        new_user = ArcPerson(
            user_id     = user_id,
            first_name  = first_name,
            middle_name = middle_name,
            last_name   = last_name,
            job_title   = job_title
        )

        db.session.add(new_user)
        db.session.commit()

        arc_user_data = {
            "user_id": user_id,
            "created_by": created_by,
            "created_on": created_on,
            "last_updated_by": last_updated_by,
            "last_updated_on": last_updated_on,
            "tenant_id": tenant_id
        }

        arc_user_response = requests.post("http://localhost:5000/arcuser", json=arc_user_data)

        # Check the response from create_arc_user API
        if arc_user_response.status_code != 201:
            return jsonify({'message': 'ARC_USER creation failed'}), 500

        # Create user credentials
        user_credentials_data = {
            "user_id": user_id,
            "password": hashed_password
        }
        user_credentials_response = requests.post("http://localhost:5000/user_credentials", json=user_credentials_data)
        
        # Check the response from user_credentials API
        if user_credentials_response.status_code != 201:
            db.session.rollback()
            return jsonify({'message': 'User credentials creation failed'}), 500

        # Create user profile
        user_profile_data = {
            "user_id"     : user_id,
            "profile_type": profile_type,  # You might want to adjust this based on your use case
            "profile_name": profile_name
        }
        user_profile_response = requests.post("http://localhost:5000/user_profiles", json=user_profile_data)

        # Check the response from user_profiles API
        if user_profile_response.status_code != 201:
            db.session.rollback()
            return jsonify({'message': 'User profile creation failed'}), 500

        # Assign privileges to the user
        user_privileges_data = {
            "user_id": user_id,
            "privilege_names": privilege_names
        }
        user_privileges_response = requests.post("http://localhost:5000/user_granted_privileges", json=user_privileges_data)

        if user_privileges_response.status_code != 201:
            db.session.rollback()
            return jsonify({'message': 'User privileges assignment failed'}), 500

        # Assign roles to the user
        user_roles_data = {
            "user_id": user_id,
            "role_names": role_names
        }
        user_roles_response = requests.post("http://localhost:5000/user_granted_roles", json=user_roles_data)

        if user_roles_response.status_code != 201:
            db.session.rollback()
            return jsonify({'message': 'User roles assignment failed'}), 500

        db.session.commit()

        return jsonify({'message': 'User created successfully with assigned credentials, profile, privileges, and roles'}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        profile_type = data['profile_type']
        profile_name = data['profile_name']
        password = data['password']

        if not profile_name or not profile_type or not password:
            return jsonify({'message': 'Invalid request. Please provide both profile_name, profile_type, and password.'}), 400

        user_profile = ArcUserProfile.query.filter_by(profile_name=profile_name, profile_type=profile_type).first()

        if user_profile and user_profile.user_id:
            user_credentials = ArcUserCredential.query.filter_by(user_id=user_profile.user_id).first()

            if user_credentials and check_password_hash(user_credentials.password, password):
                access_token = create_access_token(identity=user_profile.user_id)
                return jsonify({'access_token': access_token}), 200
            else:
                return jsonify({'message': 'Invalid username or password'}), 401
        else:
            return jsonify({'message': 'User not found'}), 404

    except Exception as e:
     return make_response(jsonify({'message': f'Error: {str(e)}'}), 500)

if __name__ == '__main__':
    app.run(debug=True)