from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin, Security, SQLAlchemySessionUserDatastore, login_user
from flask_login import LoginManager

app = Flask(__name__)

db_file = "F:\\SQLite\\Databases\\test3.db"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///" + db_file
app.config['SECRET_KEY'] = 'MY_SECRET'
app.config['SECURITY_PASSWORD_SALT'] = "MY_SECRET"
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False

db = SQLAlchemy(app)

roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String(255), nullable=False, server_default='')
    active = db.Column(db.Boolean())
    roles = db.relationship('Role', secondary=roles_users, backref='roled')

class Role(db.Model, RoleMixin):
    __tablename__ = 'role'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)

login_manager = LoginManager()
login_manager.init_app(app)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data['email']
    password = data['password']
    role_name = data['role']

    new_user = User(
        email=email,
        password=password
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

if __name__ == '__main__':
    app.run(debug=True)