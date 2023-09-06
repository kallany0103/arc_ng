import os
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy

db_file = os.getenv('DB_FILE_PATH')
print(db_file)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///" + db_file
db = SQLAlchemy(app)

class Tenants(db.Model):
    __tablename__ = 'arc_tenants'

    tenant_id = db.Column(db.Integer, primary_key=True)
    tenant_name = db.Column(db.String(20), unique=True, nullable=False)

    def json(self):
        return {'tenant_id': self.tenant_id, 'tenant_name': self.tenant_name}

# get all tenants
@app.route('/tenants', methods=['GET'])
def get_tenants():
    try:
        tenants = Tenants.query.all()
        return make_response(jsonify([tenant.json() for tenant in tenants]), 200)
    except Exception as e:
        return make_response(jsonify({'message': 'error getting tenants', 'error': str(e)}), 500)
    
# get tenant by tenant_id
@app.route('/tenants/<int:tenant_id>', methods=['GET'])
def get_tenant(tenant_id):
    try:
        tenant = Tenants.query.filter_by(tenant_id=tenant_id).first()
        if tenant:
            return make_response(jsonify({'tenant': tenant.json()}), 200)
        return make_response(jsonify({'message': 'tenant not found'}), 404)
    except Exception as e:
        return make_response(jsonify({'message': 'error getting tenant', 'error': str(e)}), 500)
    
# create a tenant
@app.route('/tenants', methods=['POST'])
def create_tenant():
    try:
        data = request.get_json()
        new_tenant = Tenants(
                      tenant_id         = data['tenant_id'],
                      tenant_name       = data['tenant_name']
                    )
        db.session.add(new_tenant)
        db.session.commit()
        return make_response(jsonify({'message': 'tenant created'}), 201)
    except Exception as e:
        return make_response(jsonify({'message': 'error creating tenant', 'error': str(e)}), 500)
    
# update a tenant
@app.route('/tenants/<int:tenant_id>', methods=['PUT'])
def update_tenant(tenant_id):
    try:
        tenant = Tenants.query.filter_by(tenant_id=tenant_id).first()
        if tenant:
            data = request.get_json()
            tenant.tenant_name = data['tenant_name']
            db.session.commit()
            return make_response(jsonify({'message': 'Tenant updated'}), 200)
        return make_response(jsonify({'message': 'Tenant not found'}), 404)
    except Exception as e:
        return make_response(jsonify({'message': 'error updating tenant', 'error': str(e)}), 500)

# delete a tenant
@app.route('/tenants/<int:tenant_id>', methods=['DELETE'])
def delete_tenant(tenant_id):
    try:
        tenant = Tenants.query.filter_by(tenant_id=tenant_id).first()
        if tenant:
            db.session.delete(tenant)
            db.session.commit()
            return make_response(jsonify({'message': 'tenant deleted'}), 200)
        return make_response(jsonify({'message': 'tenant not found'}), 404)
    except:
        return make_response(jsonify({'message': 'error deleting tenant'}), 500)

    
if __name__ == '__main__':
    app.run()
