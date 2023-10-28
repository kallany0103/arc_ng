from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson import ObjectId

app = Flask(__name__)

# Configure PyMongo
mongo_uri = "mongodb+srv://kchakma:12345@cluster0.ludm1hq.mongodb.net/?retryWrites=true&w=majority"
mongo_client = MongoClient(mongo_uri)
db = mongo_client["arc_ng2"]
users_collection = db["arc_persons"]

try:
    mongo_client.admin.command('ping')
    print("Pinged your MongoDB deployment. You successfully connected to MongoDB!")
except Exception as e:
    print("Error connecting to MongoDB:", e)

# API to create a new user
@app.route("/users", methods=["POST"])
def create_user():
    data = request.json
    user_id = data["user_id"]
    user_name = data["user_name"]
    first_name = data["first_name"]
    last_name = data["last_name"]
    email_address = data["email_address"]
    password = data["password"]

    user_data = {
        "user_id": user_id,  # Use the specified user_id
        "user_name": user_name,
        "first_name": first_name,
        "last_name": last_name,
        "email_address": email_address,
        "password": password
    }
    if user_data:
        user_id = user_data["user_id"]
        user_name = user_data["user_name"]
        email_address = user_data["email_address"]

        print(f"user_id: {type(user_id)}")
        print(f"user_name: {type(user_name)}")
        print(f"email_address: {type(email_address)}")
    else:
        print("User not found")
        
    result = users_collection.insert_one(user_data)

    return jsonify({"message": "User created successfully", "user_id": str(result.inserted_id)})

# API to get a user by ID
@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user_data = users_collection.find_one({"user_id": user_id})
    if user_data:
        # Convert ObjectId to string for JSON serialization
        user_data["_id"] = str(user_data["_id"])

        return jsonify(user_data)
    return jsonify({"message": "User not found"}), 404

# API to get all users
@app.route("/users", methods=["GET"])
def get_all_users():
    user_data = list(users_collection.find({}))
    # Convert ObjectId to string for JSON serialization for each user
    for user in user_data:
        user["_id"] = str(user["_id"])

    return jsonify(user_data)


# API to update a user by ID
@app.route("/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    data = request.json
    updated_data = {
        "user_name": data.get("user_name"),
        "password": data.get("password")
    }

    # Find the user by user_id and update their data
    user = users_collection.update_one({"user_id": user_id}, {"$set": updated_data})
    if user:
      return jsonify({"message": "User updated successfully"})
    else:
        return jsonify({"message": "User not found"}), 404
    

# API to delete a user by ID
@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    user = users_collection.delete_one({"user_id": user_id})
    if user:
      return jsonify({"message": "User deleted successfully"})
    else:
        return jsonify({"message": "User not found"}), 404

if __name__ == "__main__":
    app.run(debug=True)
