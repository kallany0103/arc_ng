from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid

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
    ##roles = db.relationship('Role', secondary='user_roles', backref='users')

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
    privileges = db.Column(db.String(30))

    # Define a unique constraint on api_endpoint, parameter, and method
    __table_args__ = (
        db.UniqueConstraint('api_endpoint', 'parameter', 'method', name='uq_api_endpoint_parameters_method'),
    )
    def json(self):
        return {'api_endpoint': self.api_endpoint, 'parameter': self.parameter, 'role': self.role, 'method': self.method, 'privileges': self.privileges, 'role': self.role }

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
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id'), primary_key=True)
    privilege_id = db.Column(db.Integer(), db.ForeignKey('privileges.privilege_id'), primary_key=True)

    def json(self):
        return {'user_id': self.user_id, 'role_id': self.role_id, 'privilege_id': self.privilege_id }


@app.route('/register', methods=['POST'])
@jwt_required()
def register():
    data = request.get_json()
    user_name = data['user_name']
    first_name = data['first_name']
    last_name = data['last_name']
    email_address = data['email_address']
    password = data['password']
    role_name = data['role_name']  # Get the desired role name from the registration data

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

    # Retrieve the specified role from the database
    role = Role.query.filter_by(name=role_name).first()

    if role:
        new_user.roles.append(role)  # Assign the retrieved role to the user
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully'}), 201
    else:
        return jsonify({'message': 'Role not found'}), 400

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

@app.route('/users', methods=['GET'])
def get_users():
    try:
        users = Users.query.all()
        return make_response(jsonify([user.json() for user in users]), 200)
    except:
        return make_response(jsonify({'message': 'Error getting users'}), 500)
    
# get a user by id
@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        user = Users.query.filter_by(user_id=user_id).first()
        if user:
            return make_response(jsonify({'user': user.json()}), 200)
        return make_response(jsonify({'message': 'user not found'}), 404)
    except Exception as e:
        return make_response(jsonify({'message': 'Error getting user', 'error': str(e)}), 500)

@app.route('/get_current_user', methods=['GET'])
@jwt_required()  # This route requires authentication
def get_current_user():
        current_user_id = get_jwt_identity()
        return jsonify({'current_user_id': current_user_id})

@app.route('/get_current_user_roles', methods=['GET'])
@jwt_required()  # This route requires authentication
def get_current_user_roles():
    try:
        current_user_id = get_jwt_identity()

        # Query the UserRole model to get the associated role IDs
        user_roles = UserRole.query.filter_by(user_id=current_user_id).all()
        role_ids = [user_role.role_id for user_role in user_roles]
        # Retrieve role names based on role IDs
        role_names = Role.query.filter(Role.id.in_(role_ids)).all()
        role_names = [role.name for role in role_names]

        return jsonify({'role_names': role_names})
    except Exception as e:
        return make_response(jsonify({'message': 'Error getting user roles', 'error': str(e)}), 500)

# update a user
@app.route('/update_users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    try:
        user = Users.query.filter_by(user_id=user_id).first()
        if user:
            data = request.get_json()
            user.user_name      = data['user_name']
            user.first_name    = data['first_name']
            user.last_name     = data['last_name']
            user.email_address = data['email_address']
            db.session.commit()
            return make_response(jsonify({'message': 'user updated'}), 200)
        return make_response(jsonify({'message': 'user not found'}), 404)
    except Exception as e:
        return make_response(jsonify({'message': 'error updating user', 'error': str(e)}), 500)

# delete a user
@app.route('/delete_users/<int:user_id>', methods=['DELETE'])
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


@app.route('/create_author', methods=['POST'])
@jwt_required()  # This route requires authentication
def create_author():
    try:
        current_user_id = get_jwt_identity()
        #print(current_user_id)
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
    

@app.route('/api_endpoints', methods=['GET'])
@jwt_required()
def get_api_endpoints():
    try:
        api_endpoints = ApiEndpoints.query.all()
        return make_response(jsonify([api_endpoint.json() for api_endpoint in api_endpoints]), 200)
    except:
        return make_response(jsonify({'message': 'error getting api endpoints'}), 500)
    

@app.route('/api_endpoint_roles', methods=['GET'])
@jwt_required()
def get_api_endpoint_roles():
    try:
        api_endpoint_roles = ApiEndpointRoles.query.all()
        return make_response(jsonify([api_endpoint_role.json() for api_endpoint_role in api_endpoint_roles]), 200)
    except:
        return make_response(jsonify({'message': 'error getting api endpoint roles'}), 500)
    
    
@app.route('/api_endpoint_role', methods=['GET'])
@jwt_required()
def get_api_endpoint_role():
    api_endpoint = request.args.get('api_endpoint')
    method = request.args.get('method')

    if not api_endpoint or not method:
        return jsonify({'message': 'Both "api_endpoint" and "method" parameters are required'}), 400

    # Query the ApiEndpoints table to get the specific API endpoint information
    api_endpoint_info = ApiEndpoints.query.filter_by(api_endpoint=api_endpoint, method=method).first()

    if not api_endpoint_info:
        return jsonify({'message': 'API endpoint not found or method not supported'}), 404

    # Get the associated API endpoint ID
    api_endpoint_id = api_endpoint_info.api_endpoint_id

    # Query the ApiEndpointRoles table to get role IDs associated with the API endpoint
    api_endpoint_roles = ApiEndpointRoles.query.filter_by(api_endpoint_id=api_endpoint_id).all()
    role_ids = [api_endpoint_role.role_id for api_endpoint_role in api_endpoint_roles]

    # Query the Role table to get the role names based on role IDs
    role_names = Role.query.filter(Role.id.in_(role_ids)).all()
    role_names = [role.name for role in role_names]

    return jsonify(role_names), 200
    


@app.route('/privileges', methods=['GET'])
def get_privileges():
    try:
        privileges = Privileges.query.all()
        return make_response(jsonify([privilege.json() for privilege in privileges]), 200)
    except:
        return make_response(jsonify({'message': 'Error getting privileges'}), 500)
    
@app.route('/get_current_user_privileges', methods=['GET'])
@jwt_required()  # This route requires authentication
def get_current_user_privileges():
    try:
        current_user_id = get_jwt_identity()

        # Query the UserPrivileges model to get the associated privilege IDs
        user_privileges = UserPrivileges.query.filter_by(user_id=current_user_id).all()
        privilege_ids = [user_privilege.privilege_id for user_privilege in user_privileges]

        # Retrieve privilege names based on privilege IDs
        privilege_names = Privileges.query.filter(Privileges.privilege_id.in_(privilege_ids)).all()
        privilege_names = [privilege.privilege_name for privilege in privilege_names]

        return jsonify({'privilege_names': privilege_names}), 200
    except Exception as e:
        return make_response(jsonify({'message': 'Error getting user privileges', 'error': str(e)}), 500)


@app.route('/current_user_info', methods=['GET'])
@jwt_required()
def get_current_user_info():
    try:
        current_user_id = get_jwt_identity()

        # Query the User model to get the user's information
        user = Users.query.get(current_user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Query the UserRole model to get the associated role IDs
        user_roles = UserRole.query.filter_by(user_id=current_user_id).all()
        role_ids = [user_role.role_id for user_role in user_roles]

        # Retrieve role names based on role IDs
        role_names = Role.query.filter(Role.id.in_(role_ids)).all()
        role_names = [role.name for role in role_names]

        # Query the ApiEndpointRoles model to get the associated API endpoint IDs
        api_endpoint_roles = ApiEndpointRoles.query.filter(ApiEndpointRoles.role_id.in_(role_ids)).all()
        api_endpoint_ids = [api_endpoint_role.api_endpoint_id for api_endpoint_role in api_endpoint_roles]

        # Query the ApiEndpoints model to get the API endpoints matching the user's roles
        endpoints = ApiEndpoints.query.filter(ApiEndpoints.api_endpoint_id.in_(api_endpoint_ids)).all()

        # Convert the endpoints to a list of dictionaries
        endpoint_list = [
            {
                'api_endpoint': endpoint.api_endpoint,
                'parameter': endpoint.parameter,
                'method': endpoint.method,
                'privileges': endpoint.privileges
            }
            for endpoint in endpoints
        ]

        # Create the response JSON
        response_json = {
            'user_id': user.user_id,
            'user_name': user.user_name,
            'user_roles': role_names,
            'user_endpoints': endpoint_list
        }
        return jsonify(response_json), 200
    except Exception as e:
        return jsonify({'message': 'Error getting user information', 'error': str(e)}), 500

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
