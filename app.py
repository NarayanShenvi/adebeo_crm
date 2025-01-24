from flask import Flask, request, jsonify
from flask_pymongo import PyMongo, ObjectId
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity,create_access_token,verify_jwt_in_request
from datetime import timedelta
from flask_cors import CORS
from datetime import datetime
from functools import wraps
import logging
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError, InvalidAlgorithmError,InvalidSignatureError

#logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = 'your_strong_secret_key'  # Replace with a secure key
app.config['JWT_ALGORITHM'] = 'HS256'
jwt = JWTManager(app)
#app.config["MONGO_URI"] = "mongodb://localhost/crudapp"
# Replace <connection_string> with your MongoDB Atlas URI
# client = "mongodb+srv://narayan:<9OfgyQys5pZ4kGfW>@adebeocrm.rgook.mongodb.net/?retryWrites=true&w=majority&appName=adebeoCrm"
MONGODB_URI = "mongodb+srv://narayan:9OfgyQys5pZ4kGfW@adebeocrm.rgook.mongodb.net/?retryWrites=true&w=majority&appName=adebeoCrm"
# Connect to MongoDB
client = MongoClient(MONGODB_URI)

CORS(app)
#mongo = PyMongo(client)
db = client["adebeocrm"]

users_collection = db['users'] # this is a temp dataset
comment_collection = db['comments'] # this is a temp dataset

adebeo_users_collection = db['adebeo_users']
adebeo_customer_collection=db['adebeo_customers']
CORS(app)

# Decorator to protect routes and extract user info
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            logging.info("Starting JWT verification...")
            auth_header = request.headers.get("Authorization", "")
            logging.info(f"Authorization Header: {auth_header}")
            # Step 1: Verify the JWT token
            verify_jwt_in_request()
            logging.info("JWT verification successful.")

            # Step 2: Get the user's identity from the token
            current_user = get_jwt_identity()
            logging.info(f"User identity extracted: {current_user}")

            # Step 3: Store user info in the request context (optional)
            request.user = current_user
            logging.info("User information added to request context.")

        except Exception as e:
            # Log where the error occurred
            logging.error(f"Authentication error at {request.path}: {str(e)}")

            # Handle JWT-specific exceptions (optional, for better debugging)
            if isinstance(e, ExpiredSignatureError):
                return jsonify({"error": "Token has expired", "message": str(e)}), 401
            elif isinstance(e, InvalidTokenError):
                return jsonify({"error": "Invalid token", "message": str(e)}), 401
            elif isinstance(e, DecodeError):
                return jsonify({"error": "Token decode error", "message": str(e)}), 401
            elif isinstance(e, InvalidAlgorithmError):
                return jsonify({"error": "Invalid algorithm", "message": str(e)}), 401

            # Catch all other exceptions
            return jsonify({"error": "Authentication required", "message": str(e)}), 401

        return f(*args, **kwargs)

    return decorated_function

# app = Flask(__name__)
# app.config["MONGO_URI"] = "mongodb://localhost/crudapp"
# mongo = PyMongo(app)
#users_collection = db.users
#comment_collection = db.comments

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()  # Decoded token payload
    return jsonify({"message": f"Welcome {current_user['username']}!"})


#add new login's
@app.route("/addusers", methods=["POST"])
def add_user():
    data = request.json
    username = data['username'].lower()
    password = data['password']
    role = data['role']

    if adebeo_users_collection.find_one({"username": username}):
        return jsonify({"error": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = {"username": username, "password": hashed_password, "role": role}
    adebeo_users_collection.insert_one(user)
    return jsonify({"message": "User registered successfully"}), 201
    # user = adebeo_users_collection.insert_one({
    #     "name": request.json["name"],
    #     "email": request.json["email"],
    #     "password": request.json["password"],
    #     "role":request.json["role"]
    # })
    # return jsonify(id=str(user.inserted_id), message="user created sucessfully.")

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username'].lower()
    password = data['password']

    user = adebeo_users_collection.find_one({"username": username})
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid credentials"}), 401

    #access_token = create_access_token(identity={"username": username, "role": user['role']}, expires_delta=timedelta(hours=10))
    access_token = create_access_token(identity=username, expires_delta=timedelta(hours=10))
    return jsonify({"access_token": access_token,"role":user['role']}), 200


#get all users, used only for initial samples
@app.route("/users", methods=["GET"])
def get_users():
    users = []
    for user in users_collection.find():
        users.append({
            "_id": str(user["_id"]),
            "name": user["name"],
            "email": user["email"],
            "password": user["password"],
        })
    return jsonify(users)

#search all users, used only for initial samples
@app.route("/allusers/<search_text>", methods=["GET"])
def get_filtered_users(search_text):
    # Convert search text to lowercase to make the search case-insensitive
    search_text = search_text.lower()
    # Initialize an empty list to store the filtered users
    users = []
    # Loop through users fetched from the database
    for user in users_collection.find():
        # Check if the search text is in the user's name (case-insensitive)
        if search_text in user["name"].lower():
            users.append({
                "_id": str(user["_id"]),  # Convert ObjectId to string if using MongoDB
                "name": user["name"],
                "email": user["email"],
                "password": user["password"]
                # Exclude password for security reasons
            })

    # If no users are found, return an empty list
    if not users:
        return jsonify([])  # Empty list in JSON format

    # Return filtered users
    return jsonify(users)

     
     
#get user, used only for initial samples
@app.route("/users/<id>", methods=["GET"])
def get_user(id):
    user = users_collection.find_one({"_id": ObjectId(id)})
    if user is not None:
        user["_id"] = str(user["_id"])
    else:
        user = {}
    return jsonify(user=user)

#add adebeo_customers if the email id are unique, else send message ID already exist, protected route needs authentication
@app.route("/create_adebeo_customers", methods=["POST"])
@login_required
def create_adebeo_customers():
    auth_header = request.headers.get("Authorization")
    if auth_header:
        print(f"Authorization Header: {auth_header}")
    else:
        print("Authorization header is missing in the request.")

    #print(f"Authorization Header: {auth_header}")  # For debugging 
    # Get the email from the request body
    email = request.json.get("primaryEmail")
    current_user = request.user
    # Use current_user['username'] and current_user['role'] as needed
    username = current_user #.get("username")
    #role = current_user.get("role")

    if not email:
        return jsonify({"error": "Primary email is required"}), 400

    # Check if the email already exists
    existing_user = adebeo_customer_collection.find_one({"primaryEmail": {"$regex": f"^{email}$", "$options": "i"}})
    #existing_user = adebeo_customer_collection.find_one({"primaryEmail": email})

    if existing_user:
        return jsonify({"exists": True, "message": "Email already exists!"}), 409
    else:
        # Insert the new user
        new_user = {
            "companyName": request.json.get("companyName"),
            "companyType": request.json.get("companyType"),
            "ownerName": request.json.get("ownerName"),
            "mobileNumber": request.json.get("mobileNumber"),
            "primaryEmail": email,
            "altemail": request.json.get("altemail"),
            "gstin": request.json.get("gstin"),
            "address": request.json.get("address"),
            "primaryLocality": request.json.get("primaryLocality"),
            "secondaryLocality": request.json.get("secondaryLocality"),
            "city": request.json.get("city"),
            "state": request.json.get("state"),
            "pincode": request.json.get("pincode"),
            "products": request.json.get("products"),
            "website": request.json.get("website"),
            "linkedin": request.json.get("linkedin"),
            "insta": request.json.get("insta"),
            "funnelType": request.json.get("funnelType"),
            "insertDate": datetime.now(),
            "insertBy": username
        }

        result = adebeo_customer_collection.insert_one(new_user)

        return jsonify(id=str(result.inserted_id), message="User created successfully.")

# @app.route("/create_adebeo_customers", methods=["POST"])
# @login_required
# def create_adebeo_customers():
#     try:
#         auth_header = request.headers.get("Authorization")
#         print(f"Authorization Header: {auth_header}")

#         email = request.json.get("primaryEmail")
#         if not email:
#             return jsonify({"error": "Primary email is required"}), 400

#         current_user = request.user
#         username = current_user #.get("username")

#         new_user = {
#             "companyName": request.json.get("companyName"),
#             "companyType": request.json.get("companyType"),
#             "ownerName": request.json.get("ownerName"),
#             "mobileNumber": request.json.get("mobileNumber"),
#             "primaryEmail": email,
#             "altemail": request.json.get("altemail"),
#             "gstin": request.json.get("gstin"),
#             "address": request.json.get("address"),
#             "primaryLocality": request.json.get("primaryLocality"),
#             "secondaryLocality": request.json.get("secondaryLocality"),
#             "city": request.json.get("city"),
#             "state": request.json.get("state"),
#             "pincode": request.json.get("pincode"),
#             "products": request.json.get("products"),
#             "website": request.json.get("website"),
#             "linkedin": request.json.get("linkedin"),
#             "insta": request.json.get("insta"),
#             "funnelType": request.json.get("funnelType"),
#             "insertDate": datetime.utcnow(),
#             "insertBy": username,  # Replace with the actual logged-in user ID
#         }
#         result = adebeo_customer_collection.insert_one(new_user)
#         return jsonify({"id": str(result.inserted_id), "message": "User created successfully."})

#     except Exception as e:
#         logging.error(f"Error in /create_adebeo_customers: {str(e)}")
#         return jsonify({"error": "Internal server error", "message": str(e)}), 500
 

#add user, used only for initial samples
@app.route("/users", methods=["POST"])
def create_user():
    user = users_collection.insert_one({
        "name": request.json["name"],
        "email": request.json["email"],
        "password": request.json["password"]
    })
    return jsonify(id=str(user.inserted_id), message="user created sucessfully.")


@app.route("/users/<id>", methods=["DELETE"])
def delete_user(id: str):
    users_collection.delete_one({'_id': ObjectId(id)})
    return jsonify(message="user deleted", id=id)


@app.route("/users/<id>", methods=["PUT"])
def update_user(id: str):
    users_collection.update_one({'_id': ObjectId(id)}, {
        "$set" : {
            'name': request.json["name"],
            'email': request.json["email"],
            'password': request.json["password"]
        }
    })
    return jsonify(message="user updated", id=id)

# @app.route("/merged/<email>", methods=["GET"])
# def merged_users_comments():
#     merged_data = []

#     # Fetch all users
#     user = users_collection.find_one({"email": ObjectId(email)})
#     for user in users_collection.find():
#         user_id = str(user["_id"])

#         # Fetch comments made by this user
#         user_comments = []
#         for comment in comment_collection.find({"user_id": user_id}):
#             user_comments.append({
#                 "_id": str(comment["_id"]),
#                 "comment": comment["comment"]
#             })

#         # Combine user data with their comments
#         merged_data.append({
#             "_id": user_id,
#             "name": user["name"],
#             "email": user["email"],
#             "comments": user_comments
#         })

#     return jsonify(merged_data)

@app.route("/merged_customer_comments", methods=["POST"])
def merged_users_comments():
    data = request.json
    email = data.get("email")  # Get email from request body

    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Fetch user by email
    customer = users_collection.find_one({"email": email})
    if not customer:
        return jsonify({"error": "User not found"}), 404

    # Fetch comments matching the email
    comments = [
        {
            "_id": str(comment["_id"]),
            "comment": comment["comment"]
        }
        for comment in comment_collection.find({"email": email})  # Match by email
    ]

    # Merge user and comments
    merged_data = {
        "_id": str(customer["_id"]),
        "name": customer["name"],
        "email": customer["email"],
        "comment": comments
    }
    return jsonify(merged_data)


@app.route("/comments", methods=["POST"])
def add_comments():
    comment = comment_collection.insert_one({
        "name": request.json["name"],
        "email": request.json["email"],
        "comment": request.json["comment"]
    })
    return jsonify(id=str(comment.inserted_id), message="user comment added sucessfully.")



if __name__ == "__main__":
    app.run(debug=True)