from flask import Flask, request, jsonify
from flask_pymongo import PyMongo, ObjectId
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity,create_access_token,verify_jwt_in_request,get_jwt
from datetime import timedelta
from flask_cors import CORS, cross_origin
from datetime import datetime, timezone
from functools import wraps
import logging
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError, InvalidAlgorithmError,InvalidSignatureError
from bson import ObjectId, json_util
import re
from flask import render_template, send_file
from weasyprint import HTML
import os
from bson.errors import InvalidId
import logging
from zoneinfo import ZoneInfo
import pytz
from flask import send_from_directory

persistent_disk_path = '/mnt/render/persistent/pdf/'  # Directory to store PDFs
# Set up logging before creating the app or defining routes
logging.basicConfig(
    level=logging.DEBUG,  # Make sure the level is DEBUG
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]  # Outputs logs to the console
) 

# app = Flask(__name__)
app = Flask(__name__, static_folder='static')
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
#CORS(app, origins="http://localhost:3000", allow_headers=["Authorization", "Content-Type", "X-Requested-With"])
#mongo = PyMongo(client)
db = client["adebeocrm"]

users_collection = db['users'] # this is a temp dataset
comment_collection = db['comments'] # this is a temp dataset

adebeo_users_collection = db['adebeo_users']
adebeo_customer_collection=db['adebeo_customers']
adebeo_user_funnel=db['adebeo_funnel']
adebeo_customer_comments=db['adebeo_customer_comments']
adebeo_products=db['adebeo_products']
adebeo_quotes_collection=db['adebeo_quotes']

# Configure logging
# logging.basicConfig(
#     filename='app.log',  # File to store logs
#     level=logging.INFO,  # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
#     format='%(asctime)s - %(levelname)s - %(message)s'
# )


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


#adebeo add new login's manually
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

# adebeo Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username'].lower()
    password = data['password']

    user = adebeo_users_collection.find_one({"username": username})
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid credentials"}), 401

    #access_token = create_access_token(identity={"username": username, "role": user['role']}, expires_delta=timedelta(hours=10))
    #access_token = create_access_token(identity=username, expires_delta=timedelta(hours=10))
    access_token = create_access_token(
            identity=username,  # Primary identifier
            additional_claims={"role": user['role']},  # Add the user's role
            expires_delta=timedelta(hours=10)  # Token expiration time
        )
    db['login_logs'].insert_one({
            "username": username,
            "user_role": user['role'],
            "login_time": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S"),  # Set to IST,
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get("User-Agent")
        })

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

# get adebeo user connected funnel data with pagination 
# Helper function to recursively convert ObjectId to string
def convert_objectid_to_str(data):
    if isinstance(data, list):
        return [convert_objectid_to_str(item) for item in data]
    elif isinstance(data, dict):
        return {key: convert_objectid_to_str(value) for key, value in data.items()}
    elif isinstance(data, ObjectId):
        return str(data)
    else:
        return data


@app.route("/funnel_users", methods=["GET"])
@login_required
# example http://127.0.0.1:5000/funnel_users?page=1&limit=6&companyName=abc
def get_funnel_users():
    try:
        username = request.user

        # Query params for pagination and search
        page = int(request.args.get('page', 1))  # Get the page number from URL query param
        limit = int(request.args.get('limit', 10))  # Get the number of items per page from URL query param
        company_name = request.args.get('companyName', None)  # Get the company name for searching

        # Calculate the skip for pagination
        skip = (page - 1) * limit

        # Fetch funnel data assigned to the current user
        funnel_data_cursor = db['adebeo_funnel'].find({"assigned_to": username}).skip(skip).limit(limit)
        funnel_data = list(funnel_data_cursor)
        if not funnel_data:
            return jsonify({"message": "No funnel data found"}), 404

        # Extract customer_ids from funnel data
        customer_ids = [entry['customer_id'] for entry in funnel_data]
        if not customer_ids:
            return jsonify({"message": "No customer IDs found"}), 404

        # Convert customer_ids to ObjectId if needed
        customer_ids = [ObjectId(cid) for cid in customer_ids]

        # Build the query for fetching customers
        customer_query = {"_id": {"$in": customer_ids}}
        if company_name:
            # Add case-insensitive partial-text search for companyName
            customer_query["companyName"] = {"$regex": f".*{re.escape(company_name)}.*", "$options": "i"}

        # Fetch customer data using the query
        customer_data_cursor = db['adebeo_customers'].find(customer_query)
        customer_data = list(customer_data_cursor)
        if not customer_data:
            return jsonify({"message": "No customer data found"}), 404

        # Fetch comments for each customer
        customer_with_comments = []
        for customer in customer_data:
            print(f"Fetching comments for customer: {customer['_id']}")  # Log which customer is being processed
            comments_cursor = db['adebeo_customer_comments'].find({"customer_id": str(customer['_id'])})
            comments = list(comments_cursor)
            print(f"Comments found: {comments}")  # Log the comments found
            customer['comments'] = comments
            customer_with_comments.append(customer)

        # Convert ObjectId fields to strings
        customer_with_comments = convert_objectid_to_str(customer_with_comments)

        # Paginate results
        total_records = len(customer_with_comments)
        total_pages = (total_records // limit) + (1 if total_records % limit else 0)

        # Return the response
        return jsonify({
            "data": customer_with_comments,
            "limit": limit,
            "page": page,
            "total_pages": total_pages,
            "total_records": total_records
        })

    except Exception as e:
        # Log the error
        print(f"Error occurred: {str(e)}")
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

@app.route("/create_adebeo_customer_comments", methods=["POST"])
@login_required
def create_adebeo_customer_comments():
    auth_header = request.headers.get("Authorization")
    username = request.user

    comment = adebeo_customer_comments.insert_one({
        "comment": request.json["comment"],
        "customer_id":request.json["customer_id"],
        "insertDate": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S"),  # Set to IST,
        "insertBy": username
    })
    return jsonify(id=str(comment.inserted_id), message="user comment added sucessfully.")

#App route to get the Selected Customer comments
@app.route("/get_adebeo_customer_comments/<id>", methods=["GET"])
@login_required
def get_adebeo_customer_comments(id):
    auth_header = request.headers.get("Authorization")
    username = request.user
    
    # Print the received customer_id for debugging
    print(f"Received customer_id: {id}")

    try:
        # Query to match customer_id with the string version of id
        comments_cursor = db['adebeo_customer_comments'].find({"customer_id": str(id)})
        
        # Print the raw result to check what is returned from the query
        comments_list = list(comments_cursor)
        print(f"Comments found: {comments_list}")
        
        # If there are no comments found, log that and return an appropriate message
        if not comments_list:
            return jsonify({
                "comments": [],
                "message": "No comments found for the given customer ID."
            })
        
        # Process the comments to return the necessary data
        response_comments = []
        for comment in comments_list:
            comment_data = {
                "date": comment.get("insertDate", ""),
                "comment": comment.get("comment", ""),
                "name": comment.get("insertBy", "")
            }
            response_comments.append(comment_data)

        # Return the comments as a JSON response
        return jsonify({
            "comments": response_comments,
            "message": "Comments retrieved successfully."
        })
    except Exception as e:
        print(f"Error retrieving comments: {e}")
        return jsonify({
            "comments": [],
            "message": "An error occurred while retrieving comments."
        })

#update single customer after edit
@app.route("/update_adebeo_customer/<id>", methods=["PUT"])
@login_required
def update_adebeo_customer(id: str):
    try:
        # Get the username from the JWT token
        username = request.user  

        # Parse JSON request body
        data = request.json
        if not data:
            return jsonify({"message": "No input data provided"}), 400

        # Validate the ObjectId
        try:
            customer_id = ObjectId(id)
        except Exception:
            return jsonify({"message": "Invalid customer ID"}), 400

        # Prepare update fields
        update_fields = {
            "companyName": data.get("companyName"),
            "companyType": data.get("companyType"),
            "ownerName": data.get("ownerName"),
            "mobileNumber": data.get("mobileNumber"),
            "primaryEmail": data.get("primaryEmail"),
            "altemail": data.get("altemail"),
            "gstin": data.get("gstin"),
            "address": data.get("address"),
            "primaryLocality": data.get("primaryLocality"),
            "secondaryLocality": data.get("secondaryLocality"),
            "city": data.get("city"),
            "state": data.get("state"),
            "pincode": data.get("pincode"),
            "products": data.get("products"),
            "website": data.get("website"),
            "linkedin": data.get("linkedin"),
            "insta": data.get("insta"),
            "funnelType": data.get("funnelType"),
            "modifiedDate": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S"),  # Set to IST,
            "modifiedBy": username
        }

        # Remove fields that are None
        update_fields = {key: value for key, value in update_fields.items() if value is not None}

        # Perform the update operation
        result = adebeo_customer_collection.update_one({'_id': customer_id}, {"$set": update_fields})
        
        if result.matched_count == 0:
            return jsonify({"message": "Customer not found"}), 404

        return jsonify({"message": "Customer updated successfully", "id": id}), 200

    except Exception as e:
        # Log the error
        print(f"Error occurred: {str(e)}")
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


#get customers data for the edit
@app.route("/edit_adebeo_customer", methods=["GET"])
@login_required
# Example: http://127.0.0.1:5000/edit_adebeo_customer?companyName=abc
def get_adebeo_customer():
    try:
        username = request.user  # Get the username from the JWT token
        
        # Initialize the customer query
        customer_query = {}
        
        # Get the companyName query parameter
        company_name = request.args.get('companyName', None)  # Get the company name for searching
        
        if company_name:
            # Add case-insensitive partial-text search for companyName
            customer_query["companyName"] = {"$regex": f".*{re.escape(company_name)}.*", "$options": "i"}

        # Fetch customer data using the query
        customer_data_cursor = db['adebeo_customers'].find(customer_query)
        customer_data = list(customer_data_cursor)
        if not customer_data:
            return jsonify({"message": "No customer data found"}), 404

        # Fetch comments for each customer
        customer_with_comments = []
        for customer in customer_data:
            print(f"Fetching comments for customer: {customer['_id']}")  # Log which customer is being processed
            comments_cursor = db['adebeo_customer_comments'].find({"customer_id": str(customer['_id'])})
            comments = list(comments_cursor)
            print(f"Comments found: {comments}")  # Log the comments found
            customer['comments'] = comments
            customer_with_comments.append(customer)

        # Convert ObjectId fields to strings
        customer_with_comments = convert_objectid_to_str(customer_with_comments)
         
        return jsonify({"data": customer_with_comments})
    
    except Exception as e:
        # Log the error
        print(f"Error occurred: {str(e)}")
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

@app.route("/getall_adebeo_products", methods=["GET"]) #maintain lowercase at the route levels
# @cross_origin(origins="http://localhost:3000", allow_headers=["Authorization", "Content-Type", "X-Requested-With"])
@login_required
def getAll_adebeo_products():
    # if request.method == "OPTIONS":
    #     print("Received OPTIONS request for /getAll_adebeo_products")
    #     # Handle OPTIONS request (preflight request)
    #     response = app.make_response(('', 200))  # Status 200 OK
    #     response.headers['Access-Control-Allow-Origin'] = "http://localhost:3000"
    #     response.headers['Access-Control-Allow-Headers'] = "Authorization, Content-Type, X-Requested-With"
    #     response.headers['Access-Control-Allow-Methods'] = "GET, OPTIONS"
    #     response.headers['Allow'] = "HEAD, OPTIONS, GET"  # This line is important
    #     return response

    # GET request logic (for product fetching)
    try:
        username = request.user
        products_cursor = db['adebeo_products'].find()
        valid_products = [product for product in products_cursor if product.get("prodisEnabled")]
        valid_products = convert_objectid_to_str(valid_products)
        return jsonify({"data": valid_products, "total": len(valid_products)})
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


#add new adebeo_products, check for unique product code
@app.route("/create_adebeo_products", methods=["POST"])
@login_required
@jwt_required()
def create_adebeo_products():
    auth_header = request.headers.get("Authorization")
    pcode = request.json.get("productCode")
    username = request.user

    claims = get_jwt()
    user_role = claims.get("role") 
    #user_role = request.role  # Assuming `request.role` holds the user's role from the JWT

    # Ensure the user is an admin
    if user_role != "admin":
        return jsonify({"error": "Access denied. Admin privileges are required."}), 403

    if not pcode:
        return jsonify({"error": "ProductCode is required"}), 400

    existing_product = adebeo_products.find_one({"productCode": {"$regex": f"^{pcode}$", "$options": "i"}})

    if existing_product:
        return jsonify({"exists": True, "message": "ProductCode already exists!"}), 409
    else:
         # Insert the new product
        new_product = {
          	"productName":  request.json.get("productName"), 
	        "productCode": request.json.get("productCode"),
	        "ProductDisplay": request.json.get("ProductDisplay"),
	        "ProductCompanyName":request.json.get("ProductCompanyName"),
	        "Contact": request.json.get("Contact"),
	        "address": request.json.get("address"),
	        "companyGstin": request.json.get("companyGstin"),
	        "primaryLocality": request.json.get("primaryLocality"),
	        "secondaryLocality": request.json.get("secondaryLocality"),
	        "city":request.json.get("city"),
	        "state":request.json.get("state"),
	        "pincode":request.json.get("pincode"),
	        "email":request.json.get("email"),
	        "salesCode":request.json.get("salesCode"),
	        "purchaseCost":request.json.get("purchaseCost"),
	        "salesCost":request.json.get("salesCost"),
	        "maxDiscount":request.json.get("maxDiscount"),
	        "prodisEnabled":request.json.get("prodisEnabled"),
	        "insertBy": username,
	        "insertDate":datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S"),  # Set to IST
	     #   "modifiedBy":request.json.get("productName")
	     #   "modifiedDate":request.json.get("productName")
        }

        result = adebeo_products.insert_one(new_product)
        return jsonify(id=str(result.inserted_id), message="New Product added successfully.")

#load existing products to editor
@app.route("/load_edit_adebeo_products", methods=["GET"])
@login_required
@jwt_required()
def load_edit_adebeo_products():
    try:
        # Get the user's role from JWT
        claims = get_jwt()
        user_role = claims.get("role")
        
        # Ensure the user is an admin
        if user_role != "admin":
            return jsonify({"error": "Access denied. Admin privileges are required."}), 403

        # Get product name from query params for partial-text search
        product_name = request.args.get('productName', None)

        # Build the query dynamically based on the search
        product_query = {}
        if product_name:
            # Add case-insensitive partial-text search for productName
            product_query["productName"] = {"$regex": f".*{re.escape(product_name)}.*", "$options": "i"}

        # Fetch matching product data from the database
        product_data_cursor = db['adebeo_products'].find(product_query)
        product_data = list(product_data_cursor)

        if not product_data:
            return jsonify({"message": "No matching products found"}), 404

        # Convert ObjectId fields to strings for JSON serialization
        return jsonify({"data": convert_objectid_to_str(product_data)})

    except Exception as e:
        # Log the error
        print(f"Error occurred: {str(e)}")
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

#update product_update after edit
@app.route("/update_adebeo_product/<id>", methods=["PUT"])
@login_required
@jwt_required()
def update_adebeo_product(id: str):
    try:
        # Get the username from the JWT token
        username = request.user  
        claims = get_jwt()
        user_role = claims.get("role")
        
        # Ensure the user is an admin
        if user_role != "admin":
            return jsonify({"error": "Access denied. Admin privileges are required."}), 403

        # Parse JSON request body
        data = request.json
        if not data:
            return jsonify({"message": "No input data provided"}), 400

        # Validate the ObjectId
        try:
            product_id = ObjectId(id)
        except Exception:
            return jsonify({"message": "Invalid Product ID"}), 400

        # Prepare update fields
        update_fields = {
            "productName":  request.json.get("productName"), 
	        "productCode": request.json.get("productCode"),
	        "ProductDisplay": request.json.get("ProductDisplay"),
	        "ProductCompanyName":request.json.get("ProductCompanyName"),
	        "Contact": request.json.get("Contact"),
	        "address": request.json.get("address"),
	        "companyGstin": request.json.get("companyGstin"),
	        "primaryLocality": request.json.get("primaryLocality"),
	        "secondaryLocality": request.json.get("secondaryLocality"),
	        "city":request.json.get("city"),
	        "state":request.json.get("state"),
	        "pincode":request.json.get("pincode"),
	        "email":request.json.get("email"),
	        "salesCode":request.json.get("salesCode"),
	        "purchaseCost":request.json.get("purchaseCost"),
	        "salesCost":request.json.get("salesCost"),
	        "maxDiscount":request.json.get("maxDiscount"),
	        "prodisEnabled":request.json.get("prodisEnabled"),
	    #   "insertBy": username,
	    #   "insertDate":datetime.utcnow()
	        "modifiedBy":username,
	        "modifiedDate":datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S"),  # Set to IST
        }

        # Remove fields that are None
        update_fields = {key: value for key, value in update_fields.items() if value is not None}

        # Perform the update operation
        result = adebeo_products.update_one({'_id': product_id}, {"$set": update_fields})
        
        if result.matched_count == 0:
            return jsonify({"message": "Product not found"}), 404

        return jsonify({"message": "Product updated successfully", "id": id}), 200

    except Exception as e:
        # Log the error
        print(f"Error occurred: {str(e)}")
        return jsonify({"message": "An error occurred", "error": str(e)}), 500




#add adebeo_customers if the email id are unique, else send message ID already exist, protected route needs authentication
@app.route("/create_adebeo_customers", methods=["POST"])
@login_required
def create_adebeo_customers():
    auth_header = request.headers.get("Authorization")
    # if auth_header:
    #     print(f"Authorization Header: {auth_header}")
    # else:
    #     print("Authorization header is missing in the request.")


    # Get the email from the request body
    email = request.json.get("primaryEmail")
    username = request.user
    # Use current_user['username'] and current_user['role'] as needed
    #role = current_user.get("role")

    if not email:
        return jsonify({"error": "Primary email is required"}), 400

    # Check if the email already exists
    existing_user = adebeo_customer_collection.find_one({"primaryEmail": {"$regex": f"^{email}$", "$options": "i"}})
    #existing_user = adebeo_customer_collection.find_one({"primaryEmail": email})

    if existing_user:
        return jsonify({"exists": True, "message": "Email already exists!"}), 409
    else:
        # Insert the new customer
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
            "insertDate": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S"),  # Set to IST
            "insertBy": username
        }
        result = adebeo_customer_collection.insert_one(new_user)

         # Add the _id and username to the my_funnel collection
    funnel_entry = {
        "customer_id": str(result.inserted_id),  # Convert ObjectId to string
        "assigned_to": username,
        "assigned_date": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")  # Set to IST
    }

    adebeo_user_funnel.insert_one(funnel_entry)
 
    return jsonify(id=str(result.inserted_id), message="New Customer added successfully.")

 

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

# Function to generate quote number
def generate_quote_number():
    current_year = datetime.now().year
    year_str = str(current_year)
    prefix = "AD"
    
    # Query to find the last quote number for the current year
    last_quote_cursor = adebeo_quotes_collection.find({"quote_number": {"$regex": f"^{prefix}{year_str}Q"}}).sort("quote_number", -1).limit(1)

    # Convert the cursor to a list and check the length
    last_quote = list(last_quote_cursor)

    if len(last_quote) > 0:
        last_quote_number = last_quote[0]['quote_number']
        last_num = int(last_quote_number[-2:])  # Extract the last two digits (QXX format)
    else:
        last_num = 0  # If no quotes exist, start from 0
    
    # Increment and pad the number
    new_quote_number = f"{prefix}{year_str}Q{str(last_num + 1).zfill(2)}"
    return new_quote_number


#################################### this section is for PDF generation ###########################################
# Endpoint to create and store quote
# @app.route('/adebeo_create_quotes', methods=['POST'])
# @login_required
# def adebeo_create_quotes():
#     try:
#         # Getting the username of the logged-in user
#         username = request.user

#         # Ensure required fields are present in the incoming request
#         required_fields = ["customer_id", "quoteTag", "items", "gross_total"]
#         missing_fields = [field for field in required_fields if not request.json.get(field)]
#         if missing_fields:
#             return jsonify({"error": f"Missing fields: {', '.join(missing_fields)}"}), 400

#     # Get customer details
#         customer_id = request.json.get("customer_id")
#         try:
#             # Attempt to match customer_id as ObjectId
#             customer = adebeo_customer_collection.find_one({"_id": ObjectId(customer_id)})
#         except InvalidId:
#             # Fallback to string-based match
#             customer = adebeo_customer_collection.find_one({"_id": customer_id})

#         if not customer:
#             return jsonify({"error": "Customer not found"}), 404

#         # Convert ObjectId fields to strings for the response
#         customer = convert_objectid_to_str(customer)

#          # Generate the quote number (e.g., AD2024Q01)
#         quote_number = generate_quote_number()

#         # Prepare the quote data to insert into the database and send to the template
#         quote = {
#              "quote_number": quote_number,  # Add the generated quote number
#             "customer_id": request.json.get("customer_id"),
#             "insertDate":datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S"),  # Set to IST
#             "insertBy": username,
#             "quoteTag": request.json.get("quoteTag"),
#             "company_description": "Our company ABC Solutions specializes in delivering top-quality products and services tailored to your needs.",
#             "product_description": "This product is designed to enhance your business operations with cutting-edge technology and ease of use.",
#             "items": request.json.get("items"),
#             "total_amount": request.json.get("gross_total"),
#             "terms": request.json.get("terms")
#         }

#         # Log the data being received and the quote being created
#         logging.debug("Received quote data: %s", quote)

#         # Extract relevant fields to pass to the template

#         quote_data = {
#             "quote_number": quote["quote_number"],
#             "date": quote["insertDate"].strftime('%Y-%m-%d'),
#             "company_description": quote["company_description"],
#             "customer_name": customer.get("companyName", "N/A"),
#             "customer_address": customer.get("address", "N/A"),
#             "customer_email": customer.get("primaryEmail", "N/A"),
#             "customer_phone": customer.get("mobileNumber", "N/A"),
#             "products": quote["items"],
#             "terms": quote["terms"]
#         }

#         # Log the final data being passed to the template
#         #logging.debug("Data passed to template: %s", quote_data)

#         # Insert the quote into the database
#         result = adebeo_quotes_collection.insert_one(quote)
#         if not result.inserted_id:
#             return jsonify({"error": "Quote not Generated"}), 404

#         # Render the HTML for the quote using the template
#         rendered_html = render_template(
#             "quote_template2.html",
#             quote_number=quote_data["quote_number"],
#             date=quote_data["date"],
#             company_description= quote_data["company_description"],
#             customer_name=quote_data["customer_name"],
#             customer_address=quote_data["customer_address"],
#             customer_email=quote_data["customer_email"],
#             customer_phone=quote_data["customer_phone"],
#             products=quote_data["products"],
#             terms=quote_data["terms"]
#         )

#         # # Log the HTML that will be converted to PDF
#         # #logging.debug("Rendered HTML: %s", rendered_html[:500])  # Print first 500 chars of HTML for debugging

#         # # Ensure the PDF folder exists
#         # pdf_folder = os.path.join(os.getcwd(), 'static', 'pdf')
#         # os.makedirs(pdf_folder, exist_ok=True)

#         # # Save the generated PDF in the static folder
#         # pdf_file_path = os.path.join(pdf_folder, f"quote_{quote_data['quote_number']}.pdf")
#         # HTML(string=rendered_html).write_pdf(pdf_file_path)

#         # # Respond with success message and link to the generated PDF
#         # response = {
#         #     "message": "Quote successfully created!",
#         #     "quote_id": str(result.inserted_id),
#         #     "pdf_link": f"/static/pdf/quote_{quote_data['quote_number']}.pdf"
#         # }

#         # # Log the response data
#         # #logging.debug("Response: %s", response)

#         # return jsonify(response), 201

#         # Log the HTML that will be converted to PDF
#         logging.debug("Rendered HTML: %s", rendered_html[:500])  # Print first 500 chars of HTML for debugging

#         # Define the path to save the PDF on the Render persistent disk
#         pdf_folder = '/mnt/render/persistent/pdf'  # Use persistent disk folder
#         os.makedirs(pdf_folder, exist_ok=True)

#         # Save the generated PDF in the persistent folder
#         pdf_file_path = os.path.join(pdf_folder, f"quote_{quote_data['quote_number']}.pdf")
#         HTML(string=rendered_html).write_pdf(pdf_file_path)

#         # Respond with success message and link to the generated PDF
#         response = {
#             "message": "Quote successfully created!",
#             "quote_id": str(result.inserted_id),
#             "pdf_link": f"/static/pdf/quote_{quote_data['quote_number']}.pdf"
#         }

#         # Log the response data
#         logging.debug("Response: %s", response)

#         return jsonify(response), 201

#     except Exception as e:
#         # Log the error for troubleshooting
#         logging.error("Error creating quote: %s", str(e))
#         return jsonify({"error": str(e)}), 500

@app.route('/adebeo_create_quotes', methods=['POST'])
@login_required
def adebeo_create_quotes():
    try:
        # Getting the username of the logged-in user
        username = request.user

        # Ensure required fields are present in the incoming request
        required_fields = ["customer_id", "quoteTag", "items", "gross_total"]
        missing_fields = [field for field in required_fields if not request.json.get(field)]
        if missing_fields:
            return jsonify({"error": f"Missing fields: {', '.join(missing_fields)}"}), 400

        # Get customer details
        customer_id = request.json.get("customer_id")
        try:
            customer = adebeo_customer_collection.find_one({"_id": ObjectId(customer_id)})
        except InvalidId:
            customer = adebeo_customer_collection.find_one({"_id": customer_id})

        if not customer:
            return jsonify({"error": "Customer not found"}), 404

        customer = convert_objectid_to_str(customer)

        # Generate the quote number
        quote_number = generate_quote_number()

        # Prepare the quote data
        quote = {
            "quote_number": quote_number,
            "customer_id": request.json.get("customer_id"),
            "insertDate": datetime.now(ZoneInfo("Asia/Kolkata")),
            "insertBy": username,
            "quoteTag": request.json.get("quoteTag"),
            "company_description": "Our company ABC Solutions specializes in delivering top-quality products and services tailored to your needs.",
            "product_description": "This product is designed to enhance your business operations with cutting-edge technology and ease of use.",
            "items": request.json.get("items"),
            "total_amount": request.json.get("gross_total"),
            "terms": request.json.get("terms")
        }

        logging.debug("Received quote data: %s", quote)

        # Extract relevant fields
        quote_data = {
            "quote_number": quote["quote_number"],
            "date": quote["insertDate"].strftime('%Y-%m-%d'),
            "company_description": quote["company_description"],
            "customer_name": customer.get("companyName", "N/A"),
            "customer_address": customer.get("address", "N/A"),
            "customer_email": customer.get("primaryEmail", "N/A"),
            "customer_phone": customer.get("mobileNumber", "N/A"),
            "products": quote["items"],
            "terms": quote["terms"]
        }

        logging.debug("Data passed to template: %s", quote_data)

        # Insert the quote into the database
        result = adebeo_quotes_collection.insert_one(quote)
        if not result.inserted_id:
            return jsonify({"error": "Quote not Generated"}), 404

        # Generate the HTML for the quote using the template
        rendered_html = render_template(
            "quote_template2.html",
            quote_number=quote_data["quote_number"],
            date=quote_data["date"],
            company_description=quote_data["company_description"],
            customer_name=quote_data["customer_name"],
            customer_address=quote_data["customer_address"],
            customer_email=quote_data["customer_email"],
            customer_phone=quote_data["customer_phone"],
            products=quote_data["products"],
            terms=quote_data["terms"]
        )

        logging.debug("Rendered HTML: %s", rendered_html[:500])

        # Local file save (for testing)
        #local_pdf_folder = './static/pdf'
        #os.makedirs(local_pdf_folder, exist_ok=True)
        #local_pdf_file_path = os.path.join(local_pdf_folder, f"quote_{quote_data['quote_number']}.pdf")
        #try:
        #    HTML(string=rendered_html).write_pdf(local_pdf_file_path)
        #    logging.debug(f"Local PDF successfully saved at: {local_pdf_file_path}")
        #except Exception as e:
        #    logging.error(f"Error saving local PDF: {str(e)}")

        # Remote file save (on Render persistent disk)
        remote_pdf_folder = '/mnt/render/persistent/pdf'
        os.makedirs(remote_pdf_folder, exist_ok=True)
        remote_pdf_file_path = os.path.join(remote_pdf_folder, f"quote_{quote_data['quote_number']}.pdf")

        # Log the file path to ensure it's correct
        logging.debug(f"Attempting to save remote PDF to: {remote_pdf_file_path}")

        try:
            HTML(string=rendered_html).write_pdf(remote_pdf_file_path)
            if os.path.exists(remote_pdf_file_path):
                logging.debug(f"Remote PDF successfully saved at: {remote_pdf_file_path}")
            else:
                logging.error(f"Failed to save remote PDF at: {remote_pdf_file_path}")
        except Exception as e:
            logging.error(f"Error saving remote PDF to persistent disk: {str(e)}")

        # Respond with success message and link to the generated PDF
        response = {
            "message": "Quote successfully created!",
            "quote_id": str(result.inserted_id),
            "pdf_link": f"/static/pdf/quote_{quote_data['quote_number']}.pdf"
        }

        logging.debug("Response: %s", response)

        return jsonify(response), 201

    except Exception as e:
        logging.error("Error creating quote: %s", str(e))
        return jsonify({"error": str(e)}), 500



@app.route('/static/pdf/<filename>')
def serve_pdf(filename):
    return send_from_directory('/mnt/render/persistent/pdf', filename)


# Endpoint to generate a PDF for a specific quote
# @app.route('/quotes/<quote_id>/pdf', methods=['GET'])
# def generate_quote_pdf(quote_id):
# @login_required    
#     # Fetch quote data from MongoDB
#     quote = adebeo_quotes_collection.find_one({"_id": quote_id})
#     if not quote:
#         return jsonify({"error": "Quote not found"}), 404

#     # Render the HTML template with the data
#     rendered_html = render_template("quote_template.html", **quote)

#     # Generate PDF using WeasyPrint
#     pdf_file_path = f"quote_{quote_id}.pdf"
#     HTML(string=rendered_html).write_pdf(pdf_file_path)

#     # Return the PDF file
#     return send_file(pdf_file_path, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)