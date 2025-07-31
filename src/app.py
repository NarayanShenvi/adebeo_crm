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
from flask import render_template, send_file,url_for
from weasyprint import HTML
import os
from bson.errors import InvalidId
import logging
from zoneinfo import ZoneInfo
import pytz
from flask import send_from_directory
import uuid
from urllib.parse import unquote
from num2words import num2words
import requests
import asyncio
import pprint
#from flask_login import current_user
#from motor.motor_asyncio import AsyncIOMotorClient

# Set pymongo's log level to WARNING to avoid DEBUG logs from MongoDB
logging.getLogger('pymongo').setLevel(logging.WARNING)


# Now you can set up your app logging
logging.basicConfig(
    level=logging.DEBUG,  # Make sure the level is DEBUG for your app logs
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
#MONGODB_URI = "mongodb+srv://narayan:9OfgyQys5pZ4kGfW@adebeocrm.rgook.mongodb.net/?retryWrites=true&w=majority&appName=adebeoCrm" #this was free trail
MONGODB_URI = "mongodb+srv://narayan:9OfgyQys5pZ4kGfW@adebeocrm.rgook.mongodb.net/?retryWrites=true&w=majority&appName=adebeoCrm"
# Connect to MongoDB

client = MongoClient(MONGODB_URI)
#client = AsyncIOMotorClient(MONGODB_URI)
#db = client['your_database']

CORS(app)
#CORS(app, origins="http://localhost:5000", allow_headers=["Authorization", "Content-Type", "X-Requested-With"])
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
adebeo_invoice_collection=db['adebeo_invoices']
adebeo_performa_collection=db['adebeo_performas']
adebeo_purchase_order_collection =db['adebeo_purchaseOrders']
invoice_collection = db['adebeo_invoices']
orders_collection =db['adebeo_orders']
customer_payments_collection = db['adebeo_payments']
vendor_payments_collection =db['adebeo_vendor_payments']
company_datas = db['adebeo_company_datas']
adebeo_categories_collection =db['adebeo_product_categories']

adebeo_customer_collection.create_index([("companyName", "text")])

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
def get_funnel_users():
    username = request.user
    claims = get_jwt()
    user_role = claims.get("role")

    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        company_name = request.args.get('companyName', None)
        skip = (page - 1) * limit

        # Filter assigned_to if not admin or tech
        match_filter = {}
        if user_role not in ['admin', 'tech']:
            match_filter["assigned_to"] = username

        # Prepare company name regex
        company_name_regex = None
        if company_name:
            company_name_decoded = unquote(company_name).strip()
            company_name_regex = re.escape(company_name_decoded)

        pipeline = []

        if match_filter:
            pipeline.append({ "$match": match_filter })

        # Lookup customers (customer_id is string)
        pipeline.append({
            "$lookup": {
                "from": "adebeo_customers",
                "let": { "cust_id_str": "$customer_id" },
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {
                                "$eq": ["$_id", { "$toObjectId": "$$cust_id_str" }]
                            }
                        }
                    }
                ],
                "as": "customer"
            }
        })

        # Unwind customer array
        pipeline.append({
            "$unwind": {
                "path": "$customer",
                "preserveNullAndEmptyArrays": False
            }
        })

        # Optional company name filter
        if company_name_regex:
            pipeline.append({
                "$match": {
                    "customer.companyName": {
                        "$regex": company_name_regex,
                        "$options": "i"
                    }
                }
            })

        # Count total records
        count_pipeline = pipeline + [{ "$count": "total" }]
        count_result = list(db.adebeo_funnel.aggregate(count_pipeline))
        total_records = count_result[0]["total"] if count_result else 0
        total_pages = (total_records // limit) + (1 if total_records % limit else 0)

        # Pagination
        pipeline.extend([
            { "$skip": skip },
            { "$limit": limit }
        ])

        # Lookup comments
        pipeline.append({
            "$lookup": {
                "from": "adebeo_customer_comments",
                "let": { "customer_id_str": { "$toString": "$customer._id" } },
                "pipeline": [
                    {
                        "$match": {
                            "$expr": { "$eq": ["$customer_id", "$$customer_id_str"] }
                        }
                    }
                ],
                "as": "comments"
            }
        })

        # Final projection — flatten customer and merge comments
        pipeline.append({
            "$replaceRoot": {
                "newRoot": {
                    "$mergeObjects": ["$customer", { "comments": "$comments" }]
                }
            }
        })

        # Execute final pipeline
        results = list(db.adebeo_funnel.aggregate(pipeline))

        # Convert ObjectIds to strings
        for r in results:
            r["_id"] = str(r["_id"])
            for comment in r.get("comments", []):
                comment["_id"] = str(comment["_id"])
                comment["customer_id"] = str(comment["customer_id"])

        # Return response
        return jsonify({
            "data": results,
            "limit": limit,
            "page": page,
            "total_pages": total_pages,
            "total_records": total_records
        })

    except Exception as e:
        return jsonify({ "message": "An error occurred", "error": str(e) }), 500



# # Route to handle funnel users 
# @app.route("/funnel_users", methods=["GET"])
# @login_required
# def get_funnel_users():
#     username = request.user
    
#     claims = get_jwt()
#     user_role = claims.get("role") 

#     try:
#         # Get query params for pagination and search
#         page = int(request.args.get('page', 1))  # Page number from URL query param
#         limit = int(request.args.get('limit', 10))  # Number of items per page from URL query param
#         company_name = request.args.get('companyName', None)  # Company name for search

#         # Log the received parameters
#         logging.info(f"Received parameters - page: {page}, limit: {limit}, company_name: {company_name}")

#         # Fetch all funnel data assigned to the current user (no pagination yet)
#         # funnel_data_cursor = adebeo_user_funnel.find({"assigned_to": username})
#         # funnel_data = list(funnel_data_cursor)
#           # If the user is an 'admin' or 'tech', fetch all users' funnel data
#         if user_role in ['admin', 'tech']:
#             funnel_data_cursor = adebeo_user_funnel.find()  # No user-specific filtering
#         else:
#             # For a regular 'user', filter by their username
#             funnel_data_cursor = adebeo_user_funnel.find({"assigned_to": username})
        
#         funnel_data = list(funnel_data_cursor)

#         # Log all the fetched funnel data (can be a large amount, be careful with logging it in production)
#         logging.info(f"Funnel data fetched for user '{username}': {len(funnel_data)} records")

#         # Log each funnel entry to verify the data (for debugging purposes)
#         for entry in funnel_data:
#             logging.debug(f"Funnel entry: {entry}")

#         # Check if funnel data is found
#         if not funnel_data:
#             logging.warning("No funnel data found")
#             return jsonify({"message": "No funnel data found"}), 404

#         # If company_name is provided, filter customers based on it (case-insensitive fuzzy matching)
#         if company_name:
#             company_name_decoded = unquote(company_name).strip().lower()
#             logging.info(f"Decoded company_name for filtering: {company_name_decoded}")

#             # Create a regex pattern for fuzzy and case-insensitive matching
#             pattern = re.compile(re.escape(company_name_decoded), re.IGNORECASE)
#             logging.info(f"Regex pattern for matching: {pattern}")

#             funnel_data_filtered = []
#             for funnel_entry in funnel_data:
#                 customer_id = funnel_entry.get('customer_id')
#                 if not customer_id:
#                     logging.warning(f"Funnel entry missing customer_id: {funnel_entry}")
#                     continue

#                 # Fetch the customer data for each funnel entry
#                 customer = db['adebeo_customers'].find_one({"_id": ObjectId(customer_id)})
#                 if customer:
#                     company_name_in_customer = customer.get('companyName', '').lower()
#                     logging.info(f"Comparing '{company_name_in_customer}' with '{company_name_decoded}'")

#                     if pattern.search(company_name_in_customer):
#                         funnel_data_filtered.append(funnel_entry)
#                         logging.info(f"Match found for customer: {company_name_in_customer}")
#                     else:
#                         logging.info(f"No match for customer: {company_name_in_customer}")
#                 else:
#                     logging.warning(f"Customer with ID {customer_id} not found in 'adebeo_customers'")

#             # Log the filtered data
#             logging.info(f"Filtered funnel data: {len(funnel_data_filtered)} records matching company_name")

#             # Update the funnel data with the filtered list
#             funnel_data = funnel_data_filtered

#         # If no customers matched the company_name filter (if provided)
#         if not funnel_data:
#             logging.warning(f"No customers found matching the company name '{company_name}'")
#             return jsonify({"message": f"No customers found matching the company name '{company_name}'"}), 404

#         # Apply pagination now (after filtering)
#         total_records = len(funnel_data)
#         total_pages = (total_records // limit) + (1 if total_records % limit else 0)
#         logging.info(f"Total records after filtering: {total_records}, Total pages: {total_pages}, Pagination skip: {(page - 1) * limit}, limit: {limit}")

#         # Calculate the skip value and apply it to the filtered funnel data
#         skip = (page - 1) * limit
#         paginated_data = funnel_data[skip:skip+limit]

#         # Log paginated data
#         logging.info(f"Paginated funnel data: {len(paginated_data)} records for page {page}")

#         # Add comments for each customer in the paginated data
#         customer_with_comments = []
#         for funnel_entry in paginated_data:
#             customer_id = funnel_entry.get('customer_id')
#             customer = db['adebeo_customers'].find_one({"_id": ObjectId(customer_id)})
#             if customer:
#                 comments_cursor = db['adebeo_customer_comments'].find({"customer_id": str(customer['_id'])})
#                 comments = list(comments_cursor)
#                 customer['comments'] = comments
#                 customer_with_comments.append(customer)
#                 logging.info(f"Added comments for customer: {customer.get('companyName', 'Unknown Company')}")
#             else:
#                 logging.warning(f"Customer with ID {customer_id} not found in 'adebeo_customers'")

#         # Convert ObjectId fields to strings
#         customer_with_comments = convert_objectid_to_str(customer_with_comments)

#         # Log the final customer data with comments
#         logging.info(f"Customer data with comments: {len(customer_with_comments)} records")

#         # Return the response with pagination data
#         response_data = {
#             "data": customer_with_comments,
#             "limit": limit,
#             "page": page,
#             "total_pages": total_pages,
#             "total_records": total_records
#         }

#         logging.info(f"Returning response: {response_data}")
#         return jsonify(response_data)

#     except ValueError as ve:
#         logging.error(f"ValueError occurred: {str(ve)}")
#         return jsonify({"message": "Validation error", "error": str(ve)}), 400
    
#     except Exception as e:
#         logging.error(f"Error occurred: {str(e)}")
#         return jsonify({"message": "An error occurred", "error": str(e)}), 500



@app.route("/create_adebeo_customer_comments", methods=["POST"])
@login_required
def create_adebeo_customer_comments():
    #auth_header = request.headers.get("Authorization")
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
            "modifiedBy": username,
            "area":data.get("area"),
            "subArea":data.get("subArea")
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

#add product categoy
@app.route("/addcategory", methods=["POST"])
@login_required
@jwt_required()
def add_category():
    auth_header = request.headers.get("Authorization")
    pcode = request.json.get("productCode")
    username = request.user

    claims = get_jwt()
    user_role = claims.get("role") 
    #user_role = request.role  # Assuming `request.role` holds the user's role from the JWT

    # Ensure the user is an admin
    if user_role != "admin":
        return jsonify({"error": "Access denied. Admin privileges are required."}), 403

    data = request.json

    # Extract and validate required fields
    category_name = data.get("Category_Name", "").strip()
    category_code = data.get("Category_Code", "").strip()
    category_description = data.get("Category_description", "").strip()
    is_enabled = data.get("isEnabled", True)  # Default to True if not provided

    if not category_name or not category_code:
        return jsonify({"error": "Category_Name and Category_Code are required"}), 400

    # Check for existing category by name or code (assuming code should be unique too)
    if adebeo_categories_collection.find_one({
        "$or": [
            {"Category_Name": category_name},
            {"Category_Code": category_code}
        ]
    }):
        return jsonify({"error": "Category with this name or code already exists"}), 400

    category = {
        "Category_Name": category_name,
        "Category_Code": category_code,
        "Category_description": category_description,
        "isEnabled": bool(is_enabled)
    }

    adebeo_categories_collection.insert_one(category)

    return jsonify({"message": "Category added successfully"}), 201

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
            "subscriptionDuration":request.json.get("subscriptionDuration")
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
            "subscriptionDuration":request.json.get("subscriptionDuration")
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




# #add adebeo_customers if the email id are unique, else send message ID already exist, protected route needs authentication
@app.route("/create_adebeo_customers", methods=["POST"])
@login_required
def create_adebeo_customers():
    auth_header = request.headers.get("Authorization")
    
    # Get the email from the request body
    email = request.json.get("primaryEmail")
    username = request.user

    if not email:
        return jsonify({"success": False, "message": "Primary email is required"}), 400

    # Check if the email already exists
    existing_user = adebeo_customer_collection.find_one({"primaryEmail": {"$regex": f"^{email}$", "$options": "i"}})

    if existing_user:
        return jsonify({"success": False, "exists": True, "message": "Email already exists!"}), 409
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
            "insertBy": username,
            "area":request.json.get("area"),
            "subArea":request.json.get("subArea")
        }
        
        # Insert the new user into the database
        result = adebeo_customer_collection.insert_one(new_user)

        # Add the _id and username to the my_funnel collection
        funnel_entry = {
            "customer_id": str(result.inserted_id),  # Convert ObjectId to string
            "assigned_to": username,
            "assigned_date": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")  # Set to IST

        }

        adebeo_user_funnel.insert_one(funnel_entry)
        
        # Return the success response with the message
        return jsonify({
            "success": True, 
            "id": str(result.inserted_id), 
            "message": "New Customer added successfully."
        })

# @app.route("/create_adebeo_customers", methods=["POST"])
# @login_required
# def create_adebeo_customers():
#     auth_header = request.headers.get("Authorization")
#     # if auth_header:
#     #     print(f"Authorization Header: {auth_header}")
#     # else:
#     #     print("Authorization header is missing in the request.")


#     # Get the email from the request body
#     email = request.json.get("primaryEmail")
#     username = request.user
#     # Use current_user['username'] and current_user['role'] as needed
#     #role = current_user.get("role")

#     if not email:
#         return jsonify({"error": "Primary email is required"}), 400

#     # Check if the email already exists
#     existing_user = adebeo_customer_collection.find_one({"primaryEmail": {"$regex": f"^{email}$", "$options": "i"}})
#     #existing_user = adebeo_customer_collection.find_one({"primaryEmail": email})

#     if existing_user:
#         return jsonify({"exists": True, "message": "Email already exists!"}), 409
#     else:
#         # Insert the new customer
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
#             "insertDate": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S"),  # Set to IST
#             "insertBy": username
#         }
#         result = adebeo_customer_collection.insert_one(new_user)

#          # Add the _id and username to the my_funnel collection
#     funnel_entry = {
#         "customer_id": str(result.inserted_id),  # Convert ObjectId to string
#         "assigned_to": username,
#         "assigned_date": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")  # Set to IST
#     }

#     adebeo_user_funnel.insert_one(funnel_entry)
 
#     return jsonify(id=str(result.inserted_id), message="New Customer added successfully.")

 

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
# def generate_quote_number():
#     current_year = datetime.now().year
#     year_str = str(current_year)
#     prefix = "AD"
    
#     # Query to find the last quote number for the current year
#     last_quote_cursor = adebeo_quotes_collection.find({"quote_number": {"$regex": f"^{prefix}{year_str}Q"}}).sort("quote_number", -1).limit(1)

#     # Convert the cursor to a list and check the length
#     last_quote = list(last_quote_cursor)

#     if len(last_quote) > 0:
#         last_quote_number = last_quote[0]['quote_number']
#         last_num = int(last_quote_number[-2:])  # Extract the last two digits (QXX format)
#     else:
#         last_num = 0  # If no quotes exist, start from 0
    
#     # Increment and pad the number
#     new_quote_number = f"{prefix}{year_str}Q{str(last_num + 1).zfill(2)}"
#     return new_quote_number
def generate_quote_number():
    current_year = datetime.now().year
    year_str = str(current_year)
    prefix = "AD"

    # Get all quotes matching the year
    matching_quotes_cursor = adebeo_quotes_collection.find({
        "quote_number": {"$regex": f"^{prefix}{year_str}Q\\d+$"}
    })

    max_num = 0

    for doc in matching_quotes_cursor:
        match = re.search(rf"{prefix}{year_str}Q(\d+)", doc["quote_number"])
        if match:
            num = int(match.group(1))
            max_num = max(max_num, num)

    new_num = max_num + 1
    new_quote_number = f"{prefix}{year_str}Q{str(new_num).zfill(3)}"
    return new_quote_number


#################################### this section is for PDF generation ###########################################

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

#         # Get customer details
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

#         # Generate the quote number (e.g., AD2024Q01)
#         quote_number = generate_quote_number()

#         # Prepare the quote data to insert into the database and send to the template
#         quote = {
#             "quote_number": quote_number,  # Add the generated quote number
#             "customer_id": request.json.get("customer_id"),
#             "insertDate": datetime.now(ZoneInfo("Asia/Kolkata")),  # Make sure this is a datetime object
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
#             "date": quote["insertDate"].strftime('%Y-%m-%d'),  # Ensure this is a datetime object
#             "company_description": quote["company_description"],
#             "customer_name": customer.get("companyName", "N/A"),
#             "customer_address": customer.get("address", "N/A"),
#             "customer_email": customer.get("primaryEmail", "N/A"),
#             "customer_phone": customer.get("mobileNumber", "N/A"),
#             "products": quote["items"],
#             "terms": quote["terms"]
#         }

#         # Log the final data being passed to the template
#         logging.debug("Data passed to template: %s", quote_data)

#         # Insert the quote into the database
#         result = adebeo_quotes_collection.insert_one(quote)
#         if not result.inserted_id:
#             return jsonify({"error": "Quote not Generated"}), 404

#         # Generate the HTML for the quote using the template
#         rendered_html = render_template(
#             "quote_template2.html",
#             quote_number=quote_data["quote_number"],
#             date=quote_data["date"],
#             company_description=quote_data["company_description"],
#             customer_name=quote_data["customer_name"],
#             customer_address=quote_data["customer_address"],
#             customer_email=quote_data["customer_email"],
#             customer_phone=quote_data["customer_phone"],
#             products=quote_data["products"],
#             terms=quote_data["terms"]
#         )

#         # Log the HTML that will be converted to PDF
#         logging.debug("Rendered HTML: %s", rendered_html[:500])  # Print first 500 chars of HTML for debugging

#         # Generate a random UUID for the file name
#         pdf_filename = f"quote_{uuid.uuid4()}.pdf"

#         # Local file save (for debugging purposes)
#         local_pdf_folder = './static/pdf'  # Local folder for testing
#         os.makedirs(local_pdf_folder, exist_ok=True)  # Create the folder if it doesn't exist
#         local_pdf_file_path = os.path.join(local_pdf_folder, pdf_filename)
#         try:
#             HTML(string=rendered_html).write_pdf(local_pdf_file_path)
#             logging.debug(f"Local PDF successfully saved at: {local_pdf_file_path}")
#         except Exception as e:
#             logging.error(f"Error saving local PDF: {str(e)}")

#         # Remote file save (on Render persistent disk)
#         remote_pdf_folder = '/mnt/render/persistent/pdf'  # Render persistent disk folder
#         os.makedirs(remote_pdf_folder, exist_ok=True)  # Ensure the remote folder exists
#         remote_pdf_file_path = os.path.join(remote_pdf_folder, pdf_filename)

#         try:
#             HTML(string=rendered_html).write_pdf(remote_pdf_file_path)
#             # Check if the file was saved successfully
#             if os.path.exists(remote_pdf_file_path):
#                 logging.debug(f"Remote PDF successfully saved at: {remote_pdf_file_path}")
#             else:
#                 logging.error(f"Failed to save remote PDF at: {remote_pdf_file_path}")
#         except Exception as e:
#             logging.error(f"Error saving remote PDF to persistent disk: {str(e)}")

#         # Respond with success message and link to the generated PDF
#         response = {
#             "message": "Quote successfully created!",
#             "quote_id": str(result.inserted_id),
#             "pdf_link": f"/static/pdf/{pdf_filename}"  # Local path for now
#         }

#         # Log the response data
#         logging.debug("Response: %s", response)

#         return jsonify(response), 201

#     except Exception as e:
#         # Log the error for troubleshooting
#         logging.error("Error creating quote: %s", str(e))
#         return jsonify({"error": str(e)}), 500

# @app.route('/get_quotes', methods=['GET'])
# @login_required
# def get_quotes():
#     try:
#         # Get pagination parameters from the request (default to page 1, 10 quotes per page)
#         page = int(request.args.get('page', 1))
#         per_page = int(request.args.get('per_page', 10))

#         # Query the quotes from the database, ordered by insertDate descending
#         quotes_cursor = adebeo_quotes_collection.find().sort("insertDate", -1)
        
#         # Paginate the quotes
#         quotes_cursor = quotes_cursor.skip((page - 1) * per_page).limit(per_page)

#         # Convert ObjectId fields to strings and prepare the quote data
#         quotes = []
#         for quote in quotes_cursor:
#             quote_data = {
#                 "quote_id": str(quote["_id"]),
#                 "quote_date": quote["insertDate"].strftime('%Y-%m-%d'),
#                 "quote_tag": quote["quoteTag"],
#                 "total_price": quote["total_amount"],
#                 "pdf_link": f"/static/pdf/quote_{quote['quote_number']}.pdf"
#             }
#             quotes.append(quote_data)

#         # Get total count of quotes for pagination (use to calculate number of pages)
#         total_quotes = adebeo_quotes_collection.count_documents({})
#         total_pages = (total_quotes + per_page - 1) // per_page  # ceiling division for pages

#         # Prepare the response
#         response = {
#             "quotes": quotes,
#             "total_pages": total_pages,
#             "current_page": page
#         }

#         # Return quotes with pagination info
#         return jsonify(response), 200

#     except Exception as e:
#         logging.error("Error fetching quotes: %s", str(e))
#         return jsonify({"error": "Error fetching quotes"}), 500        



# @app.route('/static/pdf/<filename>')
# def serve_pdf(filename):
#     return send_from_directory('/mnt/render/persistent/pdf', filename)

@app.route('/adebeo_create_quotes', methods=['POST'])
@login_required
def adebeo_create_quotes():
    try:
        # Getting the username of the logged-in user
        username = request.user
        base_url = 'https://adebeo-crm1.onrender.com' 
        
        # Image URL
        local_image_path ='https://www.adebeo.co.in/wp-content/themes/adebeo5/img/logo.png' #https://adebeo-crm1.onrender.com/static/logo.png' # modified

        # Step 1: Download the image and save it locally
        # image_response = requests.get(logo_url, timeout=60)  # Timeout to handle slow network
        # if image_response.status_code == 200:
        #     # Save the image locally in a 'static' folder
        #     local_image_path = os.path.join('static', 'logo.png')
        #     with open(local_image_path, 'wb') as f:
        #         f.write(image_response.content)
        # else:
        #     logging.error("Failed to fetch logo image.")
        #     local_image_path = None
    #try:
        # Getting the username of the logged-in user
        username = request.user
        #base_url = 'https://adebeo-crm1.onrender.com' 
        # Ensure required fields are present in the incoming request
        required_fields = ["customer_id", "quoteTag", "items", "gross_total"]
        missing_fields = [field for field in required_fields if not request.json.get(field)]
        if missing_fields:
            return jsonify({"error": f"Missing fields: {', '.join(missing_fields)}"}), 400

        # Get customer details
        customer_id = request.json.get("customer_id")
        try:
            # Attempt to match customer_id as ObjectId
            customer = adebeo_customer_collection.find_one({"_id": ObjectId(customer_id)})
        except InvalidId:
            # Fallback to string-based match
            customer = adebeo_customer_collection.find_one({"_id": customer_id})

        if not customer:
            return jsonify({"error": "Customer not found"}), 404

        # Convert ObjectId fields to strings for the response
        customer = convert_objectid_to_str(customer)

        # Generate the quote number (e.g., AD2024Q01)
        quote_number = generate_quote_number()
        company_document = company_datas.find_one({})

        # Check if the document exists and contains the required fields
        if company_document:
            # Clean the keys by removing extra quotes around the field names
            cleaned_document = {key.strip('\"'): value for key, value in company_document.items()}

            # Now, you can safely access the fields without the extra quotes
            about_us = cleaned_document.get("about_us", "No information available.")
            terms1 = cleaned_document.get("terms1", "No terms available.")
            products = cleaned_document.get("products", "No products information available.")
            company_name = cleaned_document.get("company_name","Adebeo")
            company_address = cleaned_document.get("company_address", "Bangalore")
            company_contact = cleaned_document.get("company_contact", "9008513444")
            company_email = cleaned_document.get("company_email", "narayan@adebeo.co.in")
        # Prepare the quote data to insert into the database and send to the template
        quote = {
            "quote_number": quote_number,  # Add the generated quote number
            "customer_id": request.json.get("customer_id"),
            "insertDate": datetime.now(ZoneInfo("Asia/Kolkata")),  # Make sure this is a datetime object
            "insertBy": username,
            "quoteTag": request.json.get("quoteTag"),
            "company_description": about_us,#"Our company ABC Solutions specializes in delivering top-quality products and services tailored to your needs.",
            "product_description": products,#"This product is designed to enhance your business operations with cutting-edge technology and ease of use.",
            "items": request.json.get("items"),
            "total_amount": request.json.get("gross_total"),
            "terms": terms1,
            "base_url":base_url,
            "company_name":company_name,
            "company_address":company_address,
            "company_contact":company_contact,
            "company_email":company_email,
            "overall_discount":request.json.get("overall_discount","0"),
            "tax_amount":request.json.get("tax_amount","0"),
            "customer_name": customer.get("companyName", "N/A"),
            "customer_address": customer.get("address", "N/A"),
            "customer_email": customer.get("primaryEmail", "N/A"),
            "customer_phone": customer.get("mobileNumber", "N/A"),
        }

        # Log the data being received and the quote being created
        logging.debug("Received quote data: %s", quote)

        # Extract relevant fields to pass to the template
        quote_data = {
            "quote_number": quote["quote_number"],
            "date": quote["insertDate"].strftime('%Y-%m-%d'),  # Ensure this is a datetime object
            "company_description": quote["company_description"],
            "product_description":quote["product_description"],
            "customer_name": customer.get("companyName", "N/A"),
            "customer_address": customer.get("address", "N/A"),
            "customer_email": customer.get("primaryEmail", "N/A"),
            "customer_phone": customer.get("mobileNumber", "N/A"),
            "products": quote["items"],
            "terms": quote["terms"],
            "company_name":quote["company_name"],
            "company_address":quote["company_address"],
            "company_contact":quote["company_contact"],
            "company_email":quote["company_email"],
            "total_amount" : quote["total_amount"],
            "overall_discount":quote["overall_discount"],
            "tax_amount":quote["tax_amount"]
        }

        # Log the final data being passed to the template
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
            product_description=quote_data["product_description"],
            customer_name=quote_data["customer_name"],
            customer_address=quote_data["customer_address"],
            customer_email=quote_data["customer_email"],
            customer_phone=quote_data["customer_phone"],
            products=quote_data["products"],
            terms=quote_data["terms"],
            gross_total = quote_data["total_amount"],
            company_name = "Adebeo",
            company_email = quote_data["company_email"],
            company_address = "J.P Nagar, Bangalore",
            company_contact = quote_data["company_contact"],
            base_url = base_url, #'http://127.0.0.1:5000'
            logo_image =  local_image_path,
            overall_discount= quote_data["overall_discount"],
            tax_amount=quote_data["tax_amount"]
        )

        # Log the HTML that will be converted to PDF
        logging.debug("Rendered HTML: %s", rendered_html[:500])  # Print first 500 chars of HTML for debugging

        # Generate a random UUID for the file name
        pdf_filename = f"quote_{uuid.uuid4()}.pdf"

        # Local file save (for debugging purposes)
        local_pdf_folder = './static/pdf'  # Local folder for testing
        os.makedirs(local_pdf_folder, exist_ok=True)  # Create the folder if it doesn't exist
        local_pdf_file_path = os.path.join(local_pdf_folder, pdf_filename)
        try:
            HTML(string=rendered_html).write_pdf(local_pdf_file_path, timeout=60)
            logging.debug(f"Local PDF successfully saved at: {local_pdf_file_path}")
        except Exception as e:
            logging.error(f"Error saving local PDF: {str(e)}")

        # Remote file save (on Render persistent disk)
        remote_pdf_folder = '/mnt/render/persistent/pdf'  # Render persistent disk folder
        os.makedirs(remote_pdf_folder, exist_ok=True)  # Ensure the remote folder exists
        remote_pdf_file_path = os.path.join(remote_pdf_folder, pdf_filename)

        try:
            HTML(string=rendered_html).write_pdf(remote_pdf_file_path)
            # Check if the file was saved successfully
            if os.path.exists(remote_pdf_file_path):
                logging.debug(f"Remote PDF successfully saved at: {remote_pdf_file_path}")
            else:
                logging.error(f"Failed to save remote PDF at: {remote_pdf_file_path}")
        except Exception as e:
            logging.error(f"Error saving remote PDF to persistent disk: {str(e)}")

        # Add the pdf_filename to the quote data before inserting into the database
        adebeo_quotes_collection.update_one(
            {"_id": result.inserted_id},
            {"$set": {"pdf_filename": pdf_filename}}
        )

        # Respond with success message and link to the generated PDF
        response = {
            "message": "Quote successfully created!",
            "quote_id": str(result.inserted_id),
            "pdf_link": f"/static/pdf/{pdf_filename}" if pdf_filename else "",
            "base_url": base_url  # Ensure this is never None
        }

        # Log the response data
        logging.debug("Response: %s", response)

        return jsonify(response), 201

    except Exception as e:
        # Log the error for troubleshooting
        logging.error("Error creating quote: %s", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/get_quotes', methods=['GET'])
@login_required
def get_quotes():
    try:
        # Get pagination parameters from the request (default to page 1, 10 quotes per page)
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 5))
        
        # Get customer_id from the request args (make sure it's provided)
        customer_id = request.args.get('customer_id')
        if not customer_id:
            return jsonify({"error": "customer_id is required"}), 400

        # Log pagination and customer_id values
        logging.debug(f"Pagination - Page: {page}, Per Page: {per_page}, Customer ID: {customer_id}")

        # Query the quotes from the database, filtered by customer_id, ordered by insertDate descending
        logging.debug("Querying quotes collection")
        quotes_cursor = adebeo_quotes_collection.find({"customer_id": customer_id}).sort("insertDate", -1)

        # Paginate the quotes
        quotes_cursor = quotes_cursor.skip((page - 1) * per_page).limit(per_page)

        # Convert ObjectId fields to strings and prepare the quote data
        quotes = []
        for quote in quotes_cursor:
            logging.debug(f"Quote data: {quote}")  # Log each quote data
            
            # Ensure pdf_filename and base_url are handled safely
            pdf_filename = quote.get("pdf_filename", "")  # Default to empty string if not found
            base_url = quote.get("base_url", "")  # Default to empty string if not found
            
            quote_data = {
                "quote_id": str(quote["_id"]),
                "quote_number":str(quote["quote_number"]),
                "quote_date": quote["insertDate"].strftime('%Y-%m-%d'),
                "quote_tag": quote.get("quoteTag", ""),
                "total_price": quote.get("total_amount", 0),
                "tax_amount": quote.get("tax_amount", 0),
                "overall_discount":quote.get("overall_discount", 0),
                "items":quote.get("items",""),
                "pdf_link": f"/static/pdf/{pdf_filename}" if pdf_filename else "",
                "base_url": base_url  # Ensure this is never None
            }
            quotes.append(quote_data)

        # Get total count of quotes for this customer (use to calculate number of pages)
        total_quotes = adebeo_quotes_collection.count_documents({"customer_id": customer_id})
        total_pages = (total_quotes + per_page - 1) // per_page  # ceiling division for pages

        # Prepare the response
        response = {
            "quotes": quotes,
            "total_pages": total_pages,
            "current_page": page
        }

        # Return quotes with pagination info
        return jsonify(response), 200

    except Exception as e:
        logging.error("Error fetching quotes: %s", str(e))  # Log error
        return jsonify({"error": "Error fetching quotes"}), 500


@app.route('/static/pdf/<filename>')
def serve_pdf(filename):
    try:
        logging.debug(f"Attempting to serve file: {filename}")
        return send_from_directory('/mnt/render/persistent/pdf', filename)
    except FileNotFoundError:
        logging.error(f"File {filename} not found in /mnt/render/persistent/pdf.")
        return jsonify({"error": f"File {filename} not found"}), 404
    except Exception as e:
        logging.error(f"Error serving file {filename}: {str(e)}")
        return jsonify({"error": f"Failed to serve file: {str(e)}"}), 500
#############  this section for Invoices ###################
# Function to generate a unique invoice number
# def generate_invoice_number():
#     current_year = datetime.now().year
#     year_str = str(current_year)
#     prefix = "AD"
    
#     # Query to find the last invoice number for the current year
#     last_invoice_cursor = adebeo_invoice_collection.find({"invoice_number": {"$regex": f"^{prefix}{year_str}I"}}).sort("invoice_number", -1).limit(1)
    
#     # Convert the cursor to a list and check the length
#     last_invoice = list(last_invoice_cursor)

#     if len(last_invoice) > 0:
#         last_invoice_number = last_invoice[0]['invoice_number']
        
#         # Extract the part after 'I' and ensure it contains only digits
#         last_num_str = last_invoice_number[-4:]  # Extract the last 4 characters (after 'I')
        
#         # Ensure it's numeric before converting
#         if last_num_str.isdigit():
#             last_num = int(last_num_str)  # Convert to integer
#         else:
#             last_num = 0  # Fallback in case the last number part is not valid
#     else:
#         last_num = 0  # If no invoice exists, start from 0
    
#     # Increment the last number and format it properly (up to 9999 invoices)
#     new_invoice_number = f"{prefix}{year_str}I{str(last_num + 1).zfill(4)}"  # Padding to 4 digits
    
#     return new_invoice_number

# Function to generate a unique performa number
def generate_performa_number():
    current_year = datetime.now().year
    year_str = str(current_year)
    prefix = "AD"
    
    # Query to find the last invoice number for the current year
    last_performa_cursor = adebeo_performa_collection.find({"performa_number": {"$regex": f"^{prefix}{year_str}P"}}).sort("performa_number", -1).limit(1)
    
    # Convert the cursor to a list and check the length
    last_performa = list(last_performa_cursor)

    if len(last_performa) > 0:
        last_performa_number = last_performa[0]['performa_number']
        
        # Extract the part after 'I' and ensure it contains only digits
        last_num_str = last_performa_number[-4:]  # Extract the last 4 characters (after 'I')
        
        # Ensure it's numeric before converting
        if last_num_str.isdigit():
            last_num = int(last_num_str)  # Convert to integer
        else:
            last_num = 0  # Fallback in case the last number part is not valid
    else:
        last_num = 0  # If no invoice exists, start from 0
    
    # Increment the last number and format it properly (up to 9999 invoices)
    new_performa_number = f"{prefix}{year_str}P{str(last_num + 1).zfill(4)}"  # Padding to 4 digits
    
    return new_performa_number    

@app.route('/create_performa', methods=['POST'])
@login_required
def create_performa():
    try:
        # Getting the username of the logged-in user
        username = request.user
        base_url = 'https://adebeo-crm1.onrender.com'

        # Get the quote_number and quote_tag from the request (if any)
        quote_number = request.json.get("quote_number")
        quote_tag = request.json.get("quote_tag")
        
        # If no quote_number and quote_tag are provided, check for required fields (manual invoice creation)
        if not quote_number or not quote_tag:
            required_fields = ["customer_id", "items", "gross_total"]
            missing_fields = [field for field in required_fields if not request.json.get(field)]
            if missing_fields:
                return jsonify({"error": f"Missing fields: {', '.join(missing_fields)}"}), 400

        # If quote_number and quote_tag are provided, fetch the quote details
        if quote_number and quote_tag:
            quote = adebeo_quotes_collection.find_one({
                "quote_number": quote_number,
                "quoteTag": quote_tag
            })

            if not quote:
                return jsonify({"error": "Quote not found"}), 404
            # Extract relevant fields from the quote
            customer_id = quote["customer_id"]
            items = quote["items"]
            total_amount = quote["total_amount"]
            terms = quote["terms"]
            preformaTag = quote["quoteTag"]
            refPoValue = request.json.get("refPoValue")
            overall_discount = request.json.get("overall_discount")
            tax_amount = request.json.get("tax_amount")
        else:
            # If no quote_number or quote_tag, fetch the invoice details from the payload
            customer_id = request.json.get("customer_id")
            items = request.json.get("items")
            total_amount = request.json.get("gross_total")
            terms = request.json.get("terms")
            preformaTag = request.json.get("preformaTag")
            refPoValue = request.json.get("refPoValue")
            overall_discount = request.json.get("overall_discount")
            tax_amount = request.json.get("tax_amount")
        # Get customer details
        try:
            # Attempt to match customer_id as ObjectId
            customer = adebeo_customer_collection.find_one({"_id": ObjectId(customer_id)})
        except InvalidId:
            # Fallback to string-based match
            customer = adebeo_customer_collection.find_one({"_id": customer_id})

        if not customer:
            return jsonify({"error": "Customer not found"}), 404

        # Convert ObjectId fields to strings for the response
        customer = convert_objectid_to_str(customer)

        # Generate the invoice number (e.g., AD2025I01)
        performa_number = generate_performa_number()
        company_document = company_datas.find_one({})

        # Check if the document exists and contains the required fields
        if company_document:
            # Clean the keys by removing extra quotes around the field names
            cleaned_document = {key.strip('\"'): value for key, value in company_document.items()}

            # Now, you can safely access the fields without the extra quotes
            about_us = cleaned_document.get("about_us", "No information available.")
            terms1 = cleaned_document.get("terms1", "No terms available.")
            products = cleaned_document.get("products", "No products information available.")
            company_name = cleaned_document.get("company_name", "Adebeo")
            company_address = cleaned_document.get("company_address", "Bangalore")
            company_contact = cleaned_document.get("company_contact", "9008513444")
            company_email = cleaned_document.get("company_email", "narayan@adebeo.co.in")
            company_gstin = cleaned_document.get("company_gstin", "-")
            company_account_no1 =cleaned_document.get("company_account1", " ")
            company_bankbranch1 =cleaned_document.get("company_bankbranch1", " ")
            company_bank =cleaned_document.get("company_bank", " ")
            company_ifsc1 = cleaned_document.get("company_ifsc1", "-")
            company_swift1 = cleaned_document.get("company_swift1", "-")
            company_pan = cleaned_document.get("company_pan", "-")
            invoice_note1= cleaned_document.get("invoice_note1", " ")
            company_payee= cleaned_document.get("company_payee", " ")


     
        # Prepare the invoice data to insert into the database and send to the template
        performa = {
            "performa_number": performa_number,
            "customer_id": customer_id,
            "insertDate": datetime.now(ZoneInfo("Asia/Kolkata")),
            "insertBy": username,
            "items": items,
            "total_amount": total_amount,
            "terms": terms,
            "base_url": base_url,
            "preformaTag": preformaTag,
            "refPoValue" : refPoValue,
            "tax_amount": tax_amount,
            "overall_discount":overall_discount
            
        }

        # Log the data being received and the invoice being created
        logging.debug("Received performa data: %s", performa)

        # Extract relevant fields to pass to the template
        po_invoice = {
            "performa_number": performa["performa_number"],
            "date": performa["insertDate"].strftime('%Y-%m-%d'),
            "company_description": "Our company ABC Solutions specializes in delivering top-quality products and services tailored to your needs.",
            "customer_name": customer.get("companyName", "N/A"),
            "customer_address": customer.get("address", "N/A"),
            "customer_email": customer.get("primaryEmail", "N/A"),
            "customer_phone": customer.get("mobileNumber", "N/A"),
            "customer_gstin": customer.get("gstin",'-'),
            "products": performa["items"],
            "terms": performa["terms"],
            "preformaTag": preformaTag,
            "refPoValue" :refPoValue
        }

        # Log the final data being passed to the template
        logging.debug("Data passed to template: %s", po_invoice)

        # Insert the invoice into the database
        result = adebeo_performa_collection.insert_one(performa)
        if not result.inserted_id:
            return jsonify({"error": "Invoice not generated"}), 404

        # Generate the HTML for the invoice using the template
        preformaTag = preformaTag.replace('-', '')  # Remove dashes or handle other problematic characters
        rendered_html = render_template(
            "profoma_template.html",  # Create a similar template like "quote_template2.html"
            po_invoice = po_invoice,
            performa_number=po_invoice["performa_number"],
            date=po_invoice["date"],
            company_description=po_invoice["company_description"],
            customer_name=po_invoice["customer_name"],
            customer_address=po_invoice["customer_address"],
            customer_email=po_invoice["customer_email"],
            customer_phone=po_invoice["customer_phone"],
            customer_gstin ="GSTIN: "+po_invoice["customer_gstin"],
            company_name = company_name,
            company_address=company_address,
            products=po_invoice["products"],
            terms=po_invoice["terms"],
            preformaTag=po_invoice["preformaTag"],
            base_url= base_url,
            total_sum = sum(item.get('sub_total', 0) for item in request.json['items']),
            amount_in_words  = num2words(total_amount),
            gross_total = total_amount,
            addl_discount = overall_discount,
            company_gstin = company_gstin,
            company_account_no1 =company_account_no1,
            company_bankbranch1 =company_bankbranch1,
            company_bank =company_bank,
            company_ifsc1 = company_ifsc1,
            company_swift1 = company_swift1,
            company_pan = company_pan,
            notes = invoice_note1,
            company_payee= company_payee,
            company_email= company_email,
            company_contact=company_contact,
            logo_image ='https://www.adebeo.co.in/wp-content/themes/adebeo5/img/logo.png',
            po_ref = refPoValue 
           
            #customer_name = po_invoice["customer_name"]+" \n"+po_invoice["customer_address"]
        )

        # Log the HTML that will be converted to PDF
        logging.debug("Rendered HTML: %s", rendered_html[:500])  # Print first 500 chars of HTML for debugging

        # Generate a random UUID for the file name
        pdf_filename = f"performa_{uuid.uuid4()}.pdf"

        # Local file save (for debugging purposes)
        local_pdf_folder = './static/pdf'  # Local folder for testing
        os.makedirs(local_pdf_folder, exist_ok=True)  # Create the folder if it doesn't exist
        local_pdf_file_path = os.path.join(local_pdf_folder, pdf_filename)

        try:
            logging.debug("Attempting to save PDF locally at: %s", local_pdf_file_path)
            HTML(string=rendered_html).write_pdf(local_pdf_file_path)
            logging.debug(f"Local PDF successfully saved at: {local_pdf_file_path}")
        except Exception as e:
            logging.error(f"Error saving local PDF: {str(e)}")

        # Remote file save (on Render persistent disk)
        remote_pdf_folder = '/mnt/render/persistent/pdf'  # Render persistent disk folder
        os.makedirs(remote_pdf_folder, exist_ok=True)  # Ensure the remote folder exists
        remote_pdf_file_path = os.path.join(remote_pdf_folder, pdf_filename)

        try:
            logging.debug("Attempting to save PDF remotely at: %s", remote_pdf_file_path)
            HTML(string=rendered_html).write_pdf(remote_pdf_file_path)
            # Check if the file was saved successfully
            if os.path.exists(remote_pdf_file_path):
                logging.debug(f"Remote PDF successfully saved at: {remote_pdf_file_path}")
            else:
                logging.error(f"Failed to save remote PDF at: {remote_pdf_file_path}")
        except Exception as e:
            logging.error(f"Error saving remote PDF to persistent disk: {str(e)}")

        # Add the pdf_filename to the invoice data before inserting into the database
        logging.debug("Attempting to update database with PDF filename: %s", pdf_filename)
        try:
            adebeo_performa_collection.update_one(
                {"_id": result.inserted_id},
                {"$set": {"pdf_filename": pdf_filename}}
            )
            logging.debug("Database updated with PDF filename successfully.")
        except Exception as e:
            logging.error(f"Error updating database with PDF filename: {str(e)}")

        # Respond with success message and link to the generated PDF
        response = {
            "message": "Performa successfully created!",
            "performa_id": str(result.inserted_id),
            "pdf_link": f"/static/pdf/{pdf_filename}" if pdf_filename else "",
            "base_url": base_url  # Ensure this is never None
        }

        # Log the response data
        logging.debug("Response: %s", response)

        return jsonify(response), 201

    except Exception as e:
        # Log the error for troubleshooting
        logging.error("Error creating Performa invoice: %s", str(e))
        return jsonify({"error": str(e)}), 500



@app.route('/create_invoice', methods=['POST']) 
@login_required
def create_invoice():
    try:
        # Getting the username of the logged-in user
        username = request.user
        base_url = 'https://adebeo-crm1.onrender.com'

        # Get the proforma_id and proforma_tag from the request (these are required for invoice creation)
        proforma_id = request.json.get("proforma_id")
        proforma_tag = request.json.get("proforma_tag")

        # Ensure proforma_id and proforma_tag are provided
        if not proforma_id or not proforma_tag:
            return jsonify({"error": "Proforma ID and Proforma Tag are required to create an invoice."}), 400

        # Fetch the proforma details using proforma_id and proforma_tag  
        proforma = adebeo_performa_collection.find_one({
            "proforma_number": proforma_id,
            "proforma_tag": proforma_tag
        })

        if not proforma:
            return jsonify({"error": "Proforma not found. Invoice cannot be created."}), 404

        # Extract customer_id, items, total_amount, and terms from the Proforma
        customer_id = proforma["customer_id"]
        items = proforma["items"]
        total_amount = proforma["total_amount"]
        terms = proforma["terms"]

        # Get customer details from the customer_id
        try:
            customer = adebeo_customer_collection.find_one({"_id": ObjectId(customer_id)})
        except InvalidId:
            customer = adebeo_customer_collection.find_one({"_id": customer_id})

        if not customer:
            return jsonify({"error": "Customer not found"}), 404

        # Convert ObjectId fields to strings for the response
        customer = convert_objectid_to_str(customer)

        # Generate the invoice number (e.g., AD2025I01)
        invoice_number = generate_invoice_number()

        # Prepare the invoice data to insert into the database
        invoice = {
            "invoice_number": invoice_number,
            "customer_id": customer_id,
            "insertDate": datetime.now(ZoneInfo("Asia/Kolkata")),
            "insertBy": username,
            "items": items,
            "total_amount": total_amount,
            "terms": terms,
            "base_url": base_url
        }

        # Log the data being received and the invoice being created
        logging.debug("Received invoice data: %s", invoice)

        # Extract relevant fields to pass to the template
        invoice_data = {
            "invoice_number": invoice["invoice_number"],
            "date": invoice["insertDate"].strftime('%Y-%m-%d'),
            "company_description": "Our company ABC Solutions specializes in delivering top-quality products and services tailored to your needs.",
            "customer_name": customer.get("companyName", "N/A"),
            "customer_address": customer.get("address", "N/A"),
            "customer_email": customer.get("primaryEmail", "N/A"),
            "customer_phone": customer.get("mobileNumber", "N/A"),
            "products": invoice["items"],
            "terms": invoice["terms"]
        }

        # Log the final data being passed to the template
        logging.debug("Data passed to template: %s", invoice_data)

        # Insert the invoice into the database
        result = adebeo_invoice_collection.insert_one(invoice)
        if not result.inserted_id:
            return jsonify({"error": "Invoice not generated"}), 404

        # Generate the HTML for the invoice using the template
        rendered_html = render_template(
            "invoice_template.html",  # Create a similar template like "quote_template2.html"
            invoice_number=invoice_data["invoice_number"],
            date=invoice_data["date"],
            company_description=invoice_data["company_description"],
            customer_name=invoice_data["customer_name"],
            customer_address=invoice_data["customer_address"],
            customer_email=invoice_data["customer_email"],
            customer_phone=invoice_data["customer_phone"],
            products=invoice_data["products"],
            terms=invoice_data["terms"]
        )

        # Log the HTML that will be converted to PDF
        logging.debug("Rendered HTML: %s", rendered_html[:500])  # Print first 500 chars of HTML for debugging

        # Generate a random UUID for the file name
        pdf_filename = f"invoice_{uuid.uuid4()}.pdf"

        # Local file save (for debugging purposes)
        local_pdf_folder = './static/pdf'  # Local folder for testing
        os.makedirs(local_pdf_folder, exist_ok=True)  # Create the folder if it doesn't exist
        local_pdf_file_path = os.path.join(local_pdf_folder, pdf_filename)
        try:
            HTML(string=rendered_html).write_pdf(local_pdf_file_path)
            logging.debug(f"Local PDF successfully saved at: {local_pdf_file_path}")
        except Exception as e:
            logging.error(f"Error saving local PDF: {str(e)}")

        # Remote file save (on Render persistent disk)
        remote_pdf_folder = '/mnt/render/persistent/pdf'  # Render persistent disk folder
        os.makedirs(remote_pdf_folder, exist_ok=True)  # Ensure the remote folder exists
        remote_pdf_file_path = os.path.join(remote_pdf_folder, pdf_filename)

        try:
            HTML(string=rendered_html).write_pdf(remote_pdf_file_path)
            # Check if the file was saved successfully
            if os.path.exists(remote_pdf_file_path):
                logging.debug(f"Remote PDF successfully saved at: {remote_pdf_file_path}")
            else:
                logging.error(f"Failed to save remote PDF at: {remote_pdf_file_path}")
        except Exception as e:
            logging.error(f"Error saving remote PDF to persistent disk: {str(e)}")

        # Add the pdf_filename to the invoice data before inserting into the database
        adebeo_invoice_collection.update_one(
            {"_id": result.inserted_id},
            {"$set": {"pdf_filename": pdf_filename}}
        )

        # Respond with success message and link to the generated PDF
        response = {
            "message": "Invoice successfully created!",
            "invoice_id": str(result.inserted_id),
            "pdf_link": f"/static/pdf/{pdf_filename}" if pdf_filename else "",
            "base_url": base_url  # Ensure this is never None
        }

        # Log the response data
        logging.debug("Response: %s", response)

        return jsonify(response), 201

    except Exception as e:
        # Log the error for troubleshooting
        logging.error("Error creating invoice: %s", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/get_performas', methods=['GET'])
def get_performas():
    try:
        base_url = 'https://adebeo-crm1.onrender.com'
        # Get query parameters: customer_id, page, per_page
        customer_id = request.args.get("customer_id")
        page = int(request.args.get("page", 1))  # Default to page 1 if not provided
        limit = int(request.args.get("per_page", 5))  # Default to 10 performas per page

        # Ensure pagination values are valid
        if page < 1 or limit < 1:
            return jsonify({"error": "Invalid page or per_page value"}), 400

        # Calculate the skip value for MongoDB query (pagination offset)
        skip = (page - 1) * limit

        # Query to find performas for the given customer_id, sorted by insertDate in descending order (latest first)
        query = {"customer_id": customer_id}
        performas_cursor = adebeo_performa_collection.find(query) \
            .sort("insertDate", -1) \
            .skip(skip) \
            .limit(limit)

        # Convert the cursor to a list of performas and apply the conversion of ObjectIds to strings
        performas = []
        for performa in performas_cursor:
            # Construct PDF link
            pdf_filename = performa.get("pdf_filename", "")  # Default to empty string if not found
            #base_url = performa.get("base_url", "")  # Default to empty string if not found

            # Build performa data
            performa_data = {
                "performa_id": str(performa["_id"]),
                "performa_number": str(performa.get("performa_number", "")),
                "performa_date": performa.get("insertDate", "").strftime('%Y-%m-%d') if performa.get("insertDate") else "",
                "total_amount": performa.get("total_amount", 0),
                "items": performa.get("items", ""),
                "preformaTag":performa.get("preformaTag"),
                "pdf_link": f"/static/pdf/{pdf_filename}" if pdf_filename else "",
                "base_url": base_url
            }
            performas.append(performa_data)

        # Count total performas for the customer to calculate total pages
        total_performas = adebeo_performa_collection.count_documents(query)
        total_pages = (total_performas + limit - 1) // limit  # Ceiling division to calculate total pages

        # Return the performas with pagination info
        return jsonify({
            "performas": performas,
            "pagination": {
                "page": page,
                "per_page": limit,
                "total_performas": total_performas,
                "total_pages": total_pages
            }
        }), 200

    except Exception as e:
        logging.error("Error fetching performas: %s", str(e))  # Log error
        return jsonify({"error": "Error fetching performas"}), 500

# @app.route('/get_performas', methods=['GET'])
# def get_performas():
#     try:
#         # Get query parameters: customer_id, page, per_page
#         customer_id = request.args.get("customer_id")
#         page = int(request.args.get("page", 1))  # Default to page 1 if not provided
#         limit = int(request.args.get("per_page", 10))  # Default to 10 performas per page

#         # Ensure pagination values are valid
#         if page < 1 or limit < 1:
#             return jsonify({"error": "Invalid page or per_page value"}), 400

#         # Calculate the skip value for MongoDB query (pagination offset)
#         skip = (page - 1) * limit

#         # Query to find performas for the given customer_id, sorted by insertDate in descending order (latest first)
#         query = {"customer_id": customer_id}
#         performas_cursor = adebeo_performa_collection.find(query) \
#             .sort("insertDate", -1) \
#             .skip(skip) \
#             .limit(limit)

#         # Convert the cursor to a list of performas and apply the conversion of ObjectIds to strings
#         performas = [convert_objectid_to_str(performa) for performa in performas_cursor]

#         # Count total performas for the customer to calculate total pages
#         total_performas = adebeo_performa_collection.count_documents(query)
#         total_pages = (total_performas + limit - 1) // limit  # Ceiling division to calculate total pages

#         # Return the performas with pagination info
#         return jsonify({
#             "performas": performas,
#             "pagination": {
#                 "page": page,
#                 "per_page": limit,
#                 "total_performas": total_performas,
#                 "total_pages": total_pages
#             }
#         }), 200

#     except Exception as e:
#         logging.error(f"Error fetching performas: {str(e)}")
#         return jsonify({"error": str(e)}), 500

@app.route('/get_invoices', methods=['GET'])
@login_required
def get_invoices():
    try:
        # Get the customer ID from the request parameters
        base_url = 'https://adebeo-crm1.onrender.com'
        customer_id = request.args.get("customer_id")
        
        # Pagination parameters (page and limit)
        page = int(request.args.get("page", 1))  # Default to page 1 if not provided
        limit = int(request.args.get("limit", 10))  # Default to 10 invoices per page

        # Ensure pagination values are valid
        if page < 1 or limit < 1:
            return jsonify({"error": "Invalid page or limit"}), 400

        # Calculate the skip value for MongoDB query (pagination offset)
        skip = (page - 1) * limit

        # Query to find invoices for the given customer_id, sorted by insertDate in descending order (latest first)
        invoices_cursor = adebeo_invoice_collection.find({"customer_id": customer_id}) \
            .sort("insertDate", -1) \
            .skip(skip) \
            .limit(limit)

        # Convert the cursor to a list of invoices and handle PDF link
        invoices = []
        for invoice in invoices_cursor:
            # Extract PDF filename and base_url (adjust field names based on your schema)
            pdf_filename = invoice.get("pdf_filename", "")  # Default to empty string if not found
            #base_url = invoice.get("base_url", "")  # Default to empty string if not found

            # Construct PDF link
            pdf_link = f"/static/pdf/{pdf_filename}" if pdf_filename else ""

            # Build invoice data
            invoice_data = {
                "invoice_id": str(invoice["_id"]),
                "invoice_number": str(invoice.get("invoice_number", "")),
                "invoice_date": invoice.get("insertDate", "").strftime('%Y-%m-%d') if invoice.get("insertDate") else "",
                "total_amount": invoice.get("total_amount", 0),
                "items": invoice.get("items", ""),
                "pdf_link": pdf_link,
                "base_url": base_url
            }
            invoices.append(invoice_data)

        # Count total invoices for the customer to calculate total pages
        total_invoices = adebeo_invoice_collection.count_documents({"customer_id": customer_id})
        total_pages = (total_invoices + limit - 1) // limit  # Ceiling division to calculate total pages

        # Return the invoices with pagination info
        return jsonify({
            "invoices": invoices,
            "pagination": {
                "page": page,
                "limit": limit,
                "total_invoices": total_invoices,
                "total_pages": total_pages
            }
        }), 200

    except Exception as e:
        logging.error(f"Error fetching invoices: {str(e)}")
        return jsonify({"error": f"An error occurred while fetching invoices: {str(e)}"}), 500


# @app.route('/get_invoices', methods=['GET'])
# @login_required
# def get_invoices():
#     # Get the customer ID from the request parameters
#     customer_id = request.args.get("customer_id")
    
#     # Pagination parameters (page and limit)
#     page = int(request.args.get("page", 1))  # Default to page 1 if not provided
#     limit = int(request.args.get("limit", 10))  # Default to 10 invoices per page

#     # Ensure pagination values are valid
#     if page < 1 or limit < 1:
#         return jsonify({"error": "Invalid page or limit"}), 400

#     # Calculate the skip value for MongoDB query (pagination offset)
#     skip = (page - 1) * limit

#     # Query to find invoices for the given customer_id, sorted by insertDate in descending order (latest first)
#     invoices_cursor = adebeo_invoice_collection.find({"customer_id": customer_id}) \
#         .sort("insertDate", -1) \
#         .skip(skip) \
#         .limit(limit)

#     # Convert the cursor to a list of invoices
#     invoices = list(invoices_cursor)

#     # Count total invoices for the customer to calculate total pages
#     total_invoices = adebeo_invoice_collection.count_documents({"customer_id": customer_id})
#     total_pages = (total_invoices + limit - 1) // limit  # Ceiling division to calculate total pages

#     # Return the invoices with pagination info
#     return jsonify({
#         "invoices": invoices,
#         "pagination": {
#             "page": page,
#             "limit": limit,
#             "total_invoices": total_invoices,
#             "total_pages": total_pages
#         }
#     }), 200


############################## Purchase Order Preparation ####################
def generate_purchase_order_number():
    current_year = datetime.now().year
    year_str = str(current_year)
    prefix = "AD"

    # Query to find the last po_number for the current year
    last_performa_cursor = adebeo_purchase_order_collection.find({
        "po_number": {"$regex": f"^{prefix}{year_str}PO"}
    }).sort("po_number", -1).limit(1)

    # Convert the cursor to a list and check the length
    last_performa = list(last_performa_cursor)

    if len(last_performa) > 0:
        last_performa_number = last_performa[0]['po_number']
        
        # Extract the last 4 digits part after "PO" (e.g., 0001 from AD2025PO0001)
        last_num_str = last_performa_number[-4:]  # Extract the last 4 characters
        
        # Ensure it's numeric before converting
        if last_num_str.isdigit():
            last_num = int(last_num_str)  # Convert to integer
        else:
            last_num = 0  # Fallback in case the last number part is not valid
    else:
        last_num = 0  # If no purchase order exists, start from 0

    # Increment the last number and format it properly (up to 9999 orders)
    new_po_number = f"{prefix}{year_str}PO{str(last_num + 1).zfill(4)}"  # Padding to 4 digits

    return new_po_number

def generate_invoice_number():
    current_year = datetime.now().year
    year_str = str(current_year)
    prefix = "AD"

    # Query to find the last po_number for the current year
    last_invoice_cursor = invoice_collection.find({
        "invoice_number": {"$regex": f"^{prefix}{year_str}IN"}
    }).sort("invoice_number", -1).limit(1)

    # Convert the cursor to a list and check the length
    last_invoice = list(last_invoice_cursor)

    if len(last_invoice) > 0:
        last_invoice_number = last_invoice[0]['invoice_number']
        
        # Extract the last 4 digits part after "PO" (e.g., 0001 from AD2025PO0001)
        last_num_str = last_invoice_number[-4:]  # Extract the last 4 characters
        
        # Ensure it's numeric before converting
        if last_num_str.isdigit():
            last_num = int(last_num_str)  # Convert to integer
        else:
            last_num = 0  # Fallback in case the last number part is not valid
    else:
        last_num = 0  # If no purchase order exists, start from 0

    # Increment the last number and format it properly (up to 9999 orders)
    new_invoice_number = f"{prefix}{year_str}IN{str(last_num + 1).zfill(4)}"  # Padding to 4 digits
    return new_invoice_number    
 

def extract_proforma_num(proforma_id):
    try:
        idx = proforma_id.index("P")
        return int(proforma_id[idx+1:])
    except Exception:
        return 0

@app.route("/get_proformas_for_purchase_order", methods=["GET"])
@login_required
def get_proformas():
    username = request.user
    claims = get_jwt()
    user_role = claims.get("role") 
    #user_role = request.role  # Assuming `request.role` holds the user's role from the JWT

    # Ensure the user is an admin
    if user_role != "admin":
        return jsonify({"error": "Access denied. Admin privileges are required."}), 403

    try:
        pipeline = [
            {
                "$match": {
                    "$and": [
                        {
                            "$or": [
                                {"purchase_status": False},
                                {"purchase_status": {"$exists": False}}
                            ]
                        },
                        {
                            "$or": [
                                {"isDisabled": {"$exists": False}},
                                {"isDisabled": False}
                            ]
                        }
                    ]
                }
            },
            {
                "$lookup": {
                    "from": "adebeo_customers",
                    "let": {"cust_id": {"$toObjectId": "$customer_id"}},
                    "pipeline": [
                        {"$match": {"$expr": {"$eq": ["$_id", "$$cust_id"]}}}
                    ],
                    "as": "customer"
                }
            },
            {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
            {"$unwind": {"path": "$items", "preserveNullAndEmptyArrays": True}},
            {
                "$lookup": {
                    "from": "adebeo_products",
                    "let": {"prod_id": {"$toObjectId": "$items.product_id"}},
                    "pipeline": [
                        {"$match": {"$expr": {"$eq": ["$_id", "$$prod_id"]}}}
                    ],
                    "as": "product"
                }
            },
            {"$unwind": {"path": "$product", "preserveNullAndEmptyArrays": True}},
            {
                "$addFields": {
                    "item_info": {
                        "description": {"$ifNull": ["$product.ProductDisplay", "No description"]},
                        "product_name": {"$ifNull": ["$product.productName", "Unknown Product"]},
                        "product_code": {"$ifNull": ["$product.productCode", "Unknown Code"]},
                        "company_name": {"$ifNull": ["$product.ProductCompanyName", "Unknown Company"]},
                        "contact": {"$ifNull": ["$product.Contact", "-"]},
                        "telephone": {"$ifNull": ["$product.telephone", "-"]},
                        "address": {"$ifNull": ["$product.address", "No address"]},
                        "company_gstin": {"$ifNull": ["$product.companyGstin", "No GSTIN"]},
                        "primary_locality": {"$ifNull": ["$product.primaryLocality", "No locality"]},
                        "secondary_locality": {"$ifNull": ["$product.secondaryLocality", "No locality"]},
                        "city": {"$ifNull": ["$product.city", "Unknown City"]},
                        "state": {"$ifNull": ["$product.state", "Unknown State"]},
                        "pincode": {"$ifNull": ["$product.pincode", "No Pincode"]},
                        "email": {"$ifNull": ["$product.email", "No email"]},
                        "sales_code": {"$ifNull": ["$product.salesCode", "No sales code"]},
                        "purchase_cost": {"$ifNull": ["$product.purchaseCost", 0]},
                        "quantity": {"$ifNull": ["$items.quantity", 0]},
                        "sub_total": {"$ifNull": ["$items.sub_total", 0]},
                        "unit_price": {"$ifNull": ["$items.unit_price", 0]},
                        "discount": {"$ifNull": ["$items.discount", 0]},
                        "dr_status": {"$ifNull": ["$items.dr_status", ""]},
                        "subscriptionDuration": {"$ifNull": ["$product.subscriptionDuration", "1 Year"]}
                    }
                }
            },
            {
                "$group": {
                    "_id": {
                        "number": "$performa_number",
                        "tag": "$preformaTag"
                    },
                    "customer_name": {"$first": {"$ifNull": ["$customer.companyName", "Unknown"]}},
                    "items": {"$push": "$item_info"}
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "proforma_id": "$_id.number",
                    "proforma_tag": "$_id.tag",
                    "customer_name": 1,
                    "items": 1
                }
            }
        ]

        results = list(adebeo_performa_collection.aggregate(pipeline))

        # Python-side sort descending by numeric suffix after "P"
        results.sort(key=lambda x: extract_proforma_num(x.get("proforma_id", "")), reverse=True)

        # Convert ObjectIds in nested dicts to strings if any
        def convert_ids(obj):
            if isinstance(obj, list):
                return [convert_ids(i) for i in obj]
            elif isinstance(obj, dict):
                return {
                    k: str(v) if isinstance(v, ObjectId) else convert_ids(v)
                    for k, v in obj.items()
                }
            return obj

        results = convert_ids(results)

        return jsonify(results)

    except Exception as e:
        logging.error(f"Error in get_proformas: {e}")
        return jsonify({"error": "Internal Server Error"}), 500



# @app.route("/get_proformas_for_purchase_order", methods=["GET"])
# @login_required
# def get_proformas():
#     username = request.user

#     claims = get_jwt()
#     user_role = claims.get("role") 
#     #user_role = request.role  # Assuming `request.role` holds the user's role from the JWT

#     # Ensure the user is an admin
#     if user_role != "admin":
#         return jsonify({"error": "Access denied. Admin privileges are required."}), 403

#     try:
#         # Fetch Proformas where Purchase_status is False or missing
#         proformas = adebeo_performa_collection.find({
#             "$or": [{"purchase_status": False}, {"purchase_status": {"$exists": False}}]
#         })

#         if not proformas:
#             logging.error("No proformas found in the collection.")
        
#         proforma_list = []

#         # Loop through each proforma to get the associated customer name
#         for proforma in proformas:
#             customer_id = proforma.get("customer_id")
#             if not customer_id:
#                 logging.warning(f"Proforma {proforma.get('performa_number')} is missing 'customer_id'. Skipping this proforma.")
#                 continue

#             try:
#                 # Convert customer_id to ObjectId before querying the customer collection
#                 customer = adebeo_customer_collection.find_one({"_id": ObjectId(customer_id)})

#                 if customer is None:
#                     logging.warning(f"Customer with ID {customer_id} not found for proforma {proforma.get('performa_number')}.")
#                     continue

#             except Exception as e:
#                 logging.error(f"Error converting customer_id '{customer_id}' to ObjectId or fetching customer: {e}")
#                 continue  # Skip this proforma on error

#             # Initialize proforma info
#             proforma_info = {
#                 "proforma_id": proforma.get("performa_number", "Unknown"),
#                 "proforma_tag": proforma.get("preformaTag", "Unknown"),
#                 "customer_name": customer.get("companyName", "Unknown"),
#                 "items": []
#             }

#             # Loop through items in the proforma to fetch product details
#             for item in proforma.get("items", []):
#                 # Get the product_id, which corresponds to the product's _id in the product collection
#                 product_id = item.get("product_id")
#                 if not product_id:
#                     logging.warning(f"Item in proforma {proforma.get('performa_number')} is missing 'product_id'. Skipping this item.")
#                     continue

#                 try:
#                     # Fetch the product from the adebeo_products collection using the ObjectId
#                     product = adebeo_products.find_one({"_id": ObjectId(product_id)})

#                     if product is None:
#                         logging.warning(f"Product with ID {product_id} not found for item in proforma {proforma.get('performa_number')}.")
#                         continue

#                     # Add product details to the item
#                     item_info = {
#                         "description": product.get("ProductDisplay", "No description"),  # Product display name
#                         "product_name": product.get("productName", "Unknown Product"),
#                         "product_code": product.get("productCode", "Unknown Code"),
#                         "company_name": product.get("ProductCompanyName", "Unknown Company"),
#                         "contact": product.get("Contact", "-"),
#                         "telephone": product.get("telephone", "-"),
#                         "address": product.get("address", "No address"),
#                         "company_gstin": product.get("companyGstin", "No GSTIN"),
#                         "primary_locality": product.get("primaryLocality", "No locality"),
#                         "secondary_locality": product.get("secondaryLocality", "No locality"),
#                         "city": product.get("city", "Unknown City"),
#                         "state": product.get("state", "Unknown State"),
#                         "pincode": product.get("pincode", "No Pincode"),
#                         "email": product.get("email", "No email"),
#                         "sales_code": product.get("salesCode", "No sales code"),
#                         "purchase_cost": product.get("purchaseCost", 0),  # purchaseCost field from the product
#                         "quantity": item.get("quantity", 0),
#                         "sub_total": item.get("sub_total", 0),
#                         "unit_price": item.get("unit_price", 0),
#                         "discount": item.get("discount", 0),
#                         "dr_status": item.get("dr_status", ""),
#                         "subscriptionDuration":product.get("subscriptionDuration","1 Year")
                    
#                     }

#                     # Append item with full product details to the proforma's items list
#                     proforma_info["items"].append(item_info)

#                 except Exception as e:
#                     logging.error(f"Error fetching product with ID '{product_id}' for item in proforma {proforma.get('performa_number')}: {e}")
#                     continue  # Skip this item if there’s an error fetching the product

#             # Append this proforma's details to the result list
#             proforma_list.append(proforma_info)

#         # If no proformas were found, log the info
#         if not proforma_list:
#             logging.info("No proformas with valid items and products were found.")

#         return jsonify(proforma_list)

#     except Exception as e:
#         logging.error(f"An error occurred while fetching proformas: {e}")
#         return jsonify({"error": "Internal Server Error. Please try again later."}), 500

DURATION_TO_DAYS = {
    "1 Month": 30,
    "3 Months": 90,
    "6 Months": 180,
    "1 Year": 365,
    "2 Years": 730,
    "3 Years": 1095,
    "Perpetual": -1  # Perpetual doesn't expire
}

def calculate_validity_date(duration: str):
    # Get the number of days corresponding to the selected duration
    days = DURATION_TO_DAYS.get(duration)

    # Check if the duration is valid
    if days is None:
        raise ValueError(f"Invalid subscription duration: {duration}")

    # If it's perpetual, there's no expiration
    if days == -1:
        return "Perpetual (No expiration)"
    
    # Calculate expiration date based on duration (add days to current date)
    expiration_date = datetime.now() + timedelta(days=days)
    return expiration_date.strftime('%Y-%m-%d')  # Format as 'YYYY-MM-DD'

@app.route("/create_purchase_orders", methods=["POST"])
@login_required
def create_purchase_orders():
    username = request.user
    
    claims = get_jwt()
    user_role = claims.get("role") 
    #user_role = request.role  # Assuming `request.role` holds the user's role from the JWT

    # Ensure the user is an admin
    if user_role != "admin":
        return jsonify({"error": "Access denied. Admin privileges are required."}), 403

    try:
        username = request.user
        base_url = 'https://adebeo-crm1.onrender.com'

        # Get the proforma_id and items from the request
        performa_number = request.json.get("proforma_id")
        items = request.json.get("items")  # List of items with productID

        if not performa_number:
            return jsonify({"error": "Proforma ID is required"}), 400

        if not items:
            return jsonify({"error": "Items list is empty or missing"}), 400

        # Fetch Proforma from the database
        proforma = adebeo_performa_collection.find_one({"performa_number": performa_number})

        if not proforma:
            return jsonify({"error": "Proforma not found"}), 404

        # Fetch customer details
        customer_id = proforma.get("customer_id", "0")
        customer = None

        if customer_id != "0":
            customer = adebeo_customer_collection.find_one({"_id": ObjectId(customer_id)})

        if not customer:
            return jsonify({"error": "Customer not found"}), 404

        # Generate Purchase Orders for each item in the Proforma
        created_pois = []
        for item in items:
            # Extract required product information
            product_name = item.get("description", "Unknown")
            vendor = item.get("company_name", "Unknown Vendor")
            vendor_address = item.get("address", "Unknown Address")
            purchase_price = float(item.get("purchase_cost", 0))
            contact =  item.get("contact", "-")
            telephone = item.get("telephone","-")
            email = item.get("email","-")
            gstin = item.get("company_gstin","-")
            # Calculate the total amount (assuming the discount field is already available)
            discount = float(item.get("discount", 0))
            tax_amount = float(item.get("tax_amount",0))
            revised_purchase_price = purchase_price - discount
            quantity = int(item.get("quantity", 0))
            total_amount = quantity * revised_purchase_price
            mode = item.get("mode","-")
            business_type = item.get("business_type","-")
            subscriptionDuration = item.get("subscriptionDuration", "1 Year")
            unit_price = item.get("unit_price",0)

             # Calculate validity date from the selected duration
            validity_date = calculate_validity_date(subscriptionDuration)
    
            po_number = generate_purchase_order_number()  # Implement your PO number generation logic
            company_document = company_datas.find_one({})

            # Check if the document exists and contains the required fields
            if company_document:
                # Clean the keys by removing extra quotes around the field names
                cleaned_document = {key.strip('\"'): value for key, value in company_document.items()}

                # Now, you can safely access the fields without the extra quotes
                about_us = cleaned_document.get("about_us", "No information available.")
                terms1 = cleaned_document.get("terms1", "No terms available.")
                products = cleaned_document.get("products", "No products information available.")
                company_name = cleaned_document.get("company_name", "Adebeo")
                company_address = cleaned_document.get("company_address", "Bangalore")
                company_contact = cleaned_document.get("company_contact", "9008513444")
                company_email = cleaned_document.get("company_email", "narayan@adebeo.co.in")
                company_gstin = cleaned_document.get("company_gstin", "-")
                company_account_no1 =cleaned_document.get("company_account1", " ")
                company_bankbranch1 =cleaned_document.get("company_bankbranch1", " ")
                company_ifsc1 = cleaned_document.get("company_ifsc1", "-")
                company_swift1 = cleaned_document.get("company_swift1", "-")
                company_pan = cleaned_document.get("company_pan", "-")
                invoice_note1= cleaned_document.get("invoice_note1", " ")
                company_payee= cleaned_document.get("company_payee", " ")
                po_note1=cleaned_document.get("po_note1","")


            po_data = {
                "po_number": po_number,
                "customer_id": customer_id,
                "customer_name": customer["companyName"],
                "product_name": product_name,
                "vendor": vendor,
                "vendor_address": vendor_address,
                "quantity": quantity,
                "purchase_price": revised_purchase_price,
                "total_amount": total_amount*1.18,
                "date": datetime.now(ZoneInfo("Asia/Kolkata")),
                "status": "Pending",  # Or set an initial status
                "proforma_id": performa_number,
                "discount": discount,
                "mode":mode,
                "business_type":business_type,
                "tax_amount":tax_amount
            }

            # Save Purchase Order to the database
            result = adebeo_purchase_order_collection.insert_one(po_data)

            if not result.inserted_id:
                return jsonify({"error": f"Failed to create Purchase Order for {product_name}"}), 500

            # Generate PDF for each PO using the HTML template
            po_pdf_data = {
                "po_number": po_data["po_number"],
                "customer_name": po_data["customer_name"],
                "product_name": po_data["product_name"],
                "vendor": po_data["vendor"],
                "vendor_address": po_data["vendor_address"],
                "quantity": po_data["quantity"],
                "purchase_price": po_data["purchase_price"],
                "discount": po_data["discount"],
                "total_amount": po_data["total_amount"],
                "date": po_data["date"].strftime('%Y-%m-%d'),
                "proforma_id": performa_number,
            }
            
            #rendered_html = render_template("purchase_order_template.html", **po_pdf_data)
            
            # Generate the HTML
            rendered_html = render_template(
            "purchase_order_template.html",  # Create a similar template like "quote_template2.html"
            po_number = po_data["po_number"],
            customer_name = po_data["customer_name"],
            product_name = po_data["product_name"],
            vendor = po_data["vendor"],
            vendor_address = po_data["vendor_address"],
            quantity = po_data["quantity"],
            purchase_price= revised_purchase_price,
            discount = po_data["discount"],
            tax_amount = po_data["tax_amount"],
            total_amount = po_data["total_amount"],
            date= po_data["date"].strftime('%Y-%m-%d'),
            proforma_id= performa_number,
            po_pdf_data = po_pdf_data,
            contact_name = contact,
            email = email,
            #customer_name = customer.get("companyName", "N/A"),
            client_ref_po = proforma["refPoValue"],
            company_name = company_name,
            company_address = company_address,
            company_contact = company_contact,
            company_email = company_email,
            net_total_words = num2words((revised_purchase_price * quantity) + tax_amount),
            base_url = base_url,
            logo_image ='https://www.adebeo.co.in/wp-content/themes/adebeo5/img/logo.png',   
            gstin = gstin,
            notes = po_note1,
            )

             # Log the HTML that will be converted to PDF
            #logging.debug("Rendered HTML: %s", rendered_html[:500])  # Print first 500 chars of HTML for debugging

             # Generate a random UUID for the file name
            pdf_filename = f"purchase_order_{po_number}.pdf"

            # Generate PDF and save it
            # local_pdf_folder = './static/pdf'
            # os.makedirs(local_pdf_folder, exist_ok=True)
            # local_pdf_file_path = os.path.join(local_pdf_folder, pdf_filename)

            # HTML(string=rendered_html).write_pdf(local_pdf_file_path)

            # Local file save (for debugging purposes)
            # local_pdf_folder = './static/pdf'  # Local folder for testing
            # os.makedirs(local_pdf_folder, exist_ok=True)  # Create the folder if it doesn't exist
            # local_pdf_file_path = os.path.join(local_pdf_folder, pdf_filename)
            # try:
            #     HTML(string=rendered_html).write_pdf(local_pdf_file_path)
            #     logging.debug(f"Local PDF successfully saved at: {local_pdf_file_path}")
            # except Exception as e:
            #    logging.error(f"Error saving local PDF: {str(e)}")

            # Remote file save (on Render persistent disk)
            remote_pdf_folder = '/mnt/render/persistent/pdf'  # Render persistent disk folder
            os.makedirs(remote_pdf_folder, exist_ok=True)  # Ensure the remote folder exists
            remote_pdf_file_path = os.path.join(remote_pdf_folder, pdf_filename)

            try:
                HTML(string=rendered_html).write_pdf(remote_pdf_file_path)
                # Check if the file was saved successfully
                if os.path.exists(remote_pdf_file_path):
                    logging.debug(f"Remote PDF successfully saved at: {remote_pdf_file_path}")
                else:
                    logging.error(f"Failed to save remote PDF at: {remote_pdf_file_path}")
            except Exception as e:
                logging.error(f"Error saving remote PDF to persistent disk: {str(e)}")

            # Update the PO document with the PDF file path
            adebeo_purchase_order_collection.update_one(
                {"_id": result.inserted_id},
                {"$set": {"pdf_filename": pdf_filename}}
            )

            # Collect the generated POs for response
            created_pois.append({
                "po_number": po_number,
                "pdf_link": f"/static/pdf/{pdf_filename}"
            })

            # this section is OrderBD this should be update at item level------------------------------------------
            order_data = {
                "order_number": po_number,
                "customer_id": customer_id,
                "vendor_name": po_data["vendor"],  # Assuming vendor_id is provided
               # "product_id": item.get("product_id", "Unknown Product ID"),  # Assuming product_id is provided
                "product_name":product_name,
                "quantity": quantity,
                "adebeo_purchase_price": revised_purchase_price,
                "adebeo_total_amount": total_amount,
                "status": "Pending",
                "order_date": datetime.now(),
                "expiry" :"", # Need to update
                "payment_status": "Pending",  # Will be updated when payment happens
                "mode" :"regular", #should come from PO
                "type" : "new", #should come from PO 
                "proforma_id": performa_number,
                "mode":mode,
                "business_type":business_type,
                "validity": validity_date,
                "total_amount":unit_price*quantity,
                "purchase_price":unit_price,
            }
            orders_collection.insert_one(order_data)
            # this section is OrderBD this should be update at item level------------------------------------------  
            # this section is vendorPayment this should be update at item level------------------------------------------ 
            vendor_payment_data = {
                "order_number": po_number,
                "vendor_name": po_data["vendor"],
                "customer_id": customer_id,
                "product_name":product_name,
                "total_amount": total_amount,
                "payment_date": datetime.now(),
                "status": "Pending",
                "proforma_id": performa_number
            }
            vendor_payments_collection.insert_one(vendor_payment_data)
            # this section is vendorPayment this should be update at item level------------------------------------------
        # this section is for generating Invoices--------------------------------------------------
        invoice_number = generate_invoice_number()  # Implement your own invoice number generator
        invoice_data = {
            "invoice_number": invoice_number,
            "customer_id": customer_id,
            "customer_name": customer["companyName"],
            "proforma_id": performa_number,  
            "total_amount": proforma["total_amount"],
            "amount_due": proforma["total_amount"],
            "payment_status": "Pending",
            "items":proforma["items"],
            "invoice_date": datetime.now(),
            "payment_method": "",  # You can update this when the payment is made
            "payment_reference": "",
            "due_date": None,  # Set the due date if necessary
            "po_number":po_number,
            "po_ref": proforma["refPoValue"]
        }
        # Save to Invoice DB
        invoice_collection.insert_one(invoice_data)

        invoice_pdf_data = {
            "invoice_number": invoice_number,
            "customer_name": customer["companyName"],
            "invoice_date": datetime.now().strftime('%Y-%m-%d'),
            "total_amount": total_amount,
            "amount_due": total_amount,
            "items": items  # Use all items from the proforma for the invoice
        }

        # Generate the HTML
        # rendered_html = render_template(
        #     "invoice_template.html",  # Create a similar template like "quote_template2.html"
        #     invoice_number = invoice_number,
        #     customer_name = customer["companyName"],
        #     invoice_date = datetime.now().strftime('%Y-%m-%d'),
        #     total_amount = total_amount,
        #     amount_due = total_amount,
        #     items = items,  # Use all items from the proforma for the invoice
        #    # invoice = invoice_pdf_data,

        #     po_invoice = " ",
        #     # performa_number=po_invoice["performa_number"],
        #     date= datetime.now().strftime('%Y-%m-%d'),
        #     #customer_name= customer.get("companyName", "N/A"),
        #     customer_address=customer.get("address", "N/A"),
        #     customer_email=customer.get("primaryEmail", "N/A"),
        #     customer_phone=customer.get("mobileNumber", "N/A"),
        #     customer_gstin = customer.get("companyGstin",'-'),
        #     company_name = company_name,
        #     company_address=company_address,
        #     products=proforma["items"],
        #   #  preformaTag=po_invoice["preformaTag"],
        #     base_url= base_url,
        #     total_sum = sum(item.get('sub_total', 0) for item in request.json['items']),
        #     amount_in_words  = num2words(total_amount),
        #     gross_total = total_amount,
        #     addl_discount = 0,
        #     company_gstin = company_gstin,
        #     company_account_no1 =company_account_no1,
        #     company_bankbranch1 =company_bankbranch1,
        #     company_ifsc1 = company_ifsc1,
        #     company_swift1 = company_swift1,
        #     company_pan = company_pan,
        #     notes = invoice_note1,
        #     company_payee= company_payee,
        #     company_email= company_email,
        #     company_contact=company_contact

        #     )

             # Log the HTML that will be converted to PDF
        #logging.debug("Rendered HTML: %s", rendered_html[:500])  # Print first 500 chars of HTML for debugging

             # Generate a random UUID for the file name
       
        # Define PDF output path
        #local_pdf_folder = './static/pdf'
        #os.makedirs(local_pdf_folder, exist_ok=True)
        # commented to check the speed issue
        ##pdf_filename = f"invoice_{invoice_number}.pdf"
        #local_pdf_folder = './static/pdf'  # Local folder for testing
        #os.makedirs(local_pdf_folder, exist_ok=True)  # Create the folder if it doesn't exist
        #local_pdf_file_path = os.path.join(local_pdf_folder, pdf_filename)
        
        #try:
        #    HTML(string=rendered_html).write_pdf(local_pdf_file_path)
        #    logging.debug(f"Local PDF successfully saved at: {local_pdf_file_path}")
        #except Exception as e:
        #    logging.error(f"Error saving local PDF: {str(e)}")

        # Remote file save (on Render persistent disk)
        ##remote_pdf_folder = '/mnt/render/persistent/pdf'  # Render persistent disk folder
        ##os.makedirs(remote_pdf_folder, exist_ok=True)  # Ensure the remote folder exists
        ##remote_pdf_file_path = os.path.join(remote_pdf_folder, pdf_filename)

        ##try:
        ##    HTML(string=rendered_html).write_pdf(remote_pdf_file_path)
        ##    # Check if the file was saved successfully
        ##    if os.path.exists(remote_pdf_file_path):
        ##        logging.debug(f"Remote PDF successfully saved at: {remote_pdf_file_path}")
        ##    else:
        ##        logging.error(f"Failed to save remote PDF at: {remote_pdf_file_path}")
        ##except Exception as e:
        ##    logging.error(f"Error saving remote PDF to persistent disk: {str(e)}")
        
        # Update the invoice record in DB with the path to the saved PDF
        ##invoice_collection.update_one(
        ##    {"invoice_number": invoice_number},
        ##    {"$set": {"pdf_filename": pdf_filename}}
        ##)
        # this section is for generating Invoices--------------------------------------------------
        ### customer Payment Initiate =========================================
            # For customer payments
        customer_payment_data = {
            "customer_id": customer_id,
            "customer_name":customer["companyName"],
            "invoice_number": invoice_number,
            "total_amount":  proforma["total_amount"],
            "paid_amount": 0,
            "remaining_amount":  proforma["total_amount"],
            "invoice_date": datetime.now().strftime('%Y-%m-%d'),
            "status": "inprog"
            }
        customer_payments_collection.insert_one(customer_payment_data)
         ### customer Payment Initiate =========================================
        
        # Update the Proforma collection (purchase_status to True)
        adebeo_performa_collection.update_one(
            {"performa_number": performa_number},  # Find Proforma by ID
            {"$set": {"purchase_status": True}}   # Set purchase_status to True
        )
        # Respond with the created POs and their download links
        return jsonify({
            "status": "success",
            "message": "Purchase Orders created successfully!",
            "purchase_orders": created_pois
        }), 201

    except Exception as e:
        logging.error(f"Error creating Purchase Orders: {str(e)}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/generate_invoice_pdf/<invoice_number>', methods=["POST"])
@login_required
def generate_invoice_pdf(invoice_number):
    try:
        base_url = 'https://adebeo-crm1.onrender.com'
        # Fetch the invoice data
        invoice = adebeo_invoice_collection.find_one({"invoice_number": invoice_number})
        if not invoice:
            return jsonify({"error": "Invoice not found"}), 404
        
        # Fetch customer information using customer_id from the invoice
        customer_id = invoice.get("customer_id", "0")
        customer = None

        if customer_id != "0":
            customer = adebeo_customer_collection.find_one({"_id": ObjectId(customer_id)})

        if not customer:
            return jsonify({"error": "Customer not found"}), 404

        # Fetch company information
        company_document = company_datas.find_one({})
        if company_document:
            # Clean the company data
            cleaned_document = {key.strip('\"'): value for key, value in company_document.items()}

            about_us = cleaned_document.get("about_us", "No information available.")
            terms1 = cleaned_document.get("terms1", "No terms available.")
            products = cleaned_document.get("products", "No products information available.")
            company_name = cleaned_document.get("company_name", "Adebeo")
            company_address = cleaned_document.get("company_address", "Bangalore")
            company_contact = cleaned_document.get("company_contact", "9008513444")
            company_email = cleaned_document.get("company_email", "narayan@adebeo.co.in")
            company_gstin = cleaned_document.get("company_gstin", "-")
            company_account_no1 = cleaned_document.get("company_account1", " ")
            company_bankbranch1 = cleaned_document.get("company_bankbranch1", " ")
            company_bank = cleaned_document.get("company_bank", " ")
            company_ifsc1 = cleaned_document.get("company_ifsc1", "-")
            company_swift1 = cleaned_document.get("company_swift1", "-")
            company_pan = cleaned_document.get("company_pan", "-")
            invoice_note1 = cleaned_document.get("invoice_note1", " ")
            company_payee = cleaned_document.get("company_payee", " ")
        else:
            return jsonify({"error": "Company details not found"}), 404

        # Prepare invoice details (items, total amounts, etc.)
        total_amount = invoice["total_amount"]
        items = invoice["items"]

        # Render the HTML template with dynamic data
        rendered_html = render_template(
            "invoice_template.html", 
            performa_number=invoice_number,
            customer_name=customer.get("companyName", "N/A"),
            date=datetime.now().strftime('%Y-%m-%d'),
            total_sum=sum(item.get('sub_total', 0) for item in items),
            products=items,  # Use all items from the invoice
            company_name=company_name,
            company_address=company_address,
            company_contact=company_contact,
            company_email=company_email,
            company_gstin=company_gstin,
            company_account_no1=company_account_no1,
            company_bank = company_bank,
            company_bankbranch1=company_bankbranch1,
            company_ifsc1=company_ifsc1,
            company_swift1=company_swift1,
            company_pan=company_pan,
            notes=invoice_note1,
            company_payee=company_payee,
            base_url =base_url,
            po_invoice = invoice,
            addl_discount = 0, #just added
            gross_total = total_amount,
            logo_image ='https://www.adebeo.co.in/wp-content/themes/adebeo5/img/logo.png',
            po_ref = invoice["po_ref"],
            customer_gstin = "GSTIN: "+customer.get("gstin", "N/A"),
            customer_address = customer.get("address", "N/A"),

        )
        pdf_filename = f"invoice_{uuid.uuid4()}.pdf"

         # Local file save (for debugging purposes)
        local_pdf_folder = './static/pdf'  # Local folder for testing
        os.makedirs(local_pdf_folder, exist_ok=True)  # Create the folder if it doesn't exist
        local_pdf_file_path = os.path.join(local_pdf_folder, pdf_filename)
        try:
            HTML(string=rendered_html).write_pdf(local_pdf_file_path)
            logging.debug(f"Local PDF successfully saved at: {local_pdf_file_path}")
        except Exception as e:
            logging.error(f"Error saving local PDF: {str(e)}")

        # Remote file save (on Render persistent disk)
        remote_pdf_folder = '/mnt/render/persistent/pdf'  # Render persistent disk folder
        os.makedirs(remote_pdf_folder, exist_ok=True)  # Ensure the remote folder exists
        remote_pdf_file_path = os.path.join(remote_pdf_folder, pdf_filename)

        try:
            HTML(string=rendered_html).write_pdf(remote_pdf_file_path)
                # Check if the file was saved successfully
            if os.path.exists(remote_pdf_file_path):
                logging.debug(f"Remote PDF successfully saved at: {remote_pdf_file_path}")
            else:
               logging.error(f"Failed to save remote PDF at: {remote_pdf_file_path}")
        except Exception as e:
                logging.error(f"Error saving remote PDF to persistent disk: {str(e)}")

        # Update the PO document with the PDF file path
        adebeo_invoice_collection.update_one(
            {"invoice_number": invoice_number},  # Match by invoice_number
                {
                    "$set": {  # Use $set to specify the fields to update
                        "pdf_filename": pdf_filename,  # Update pdf_filename field
                        "invoiced_date": datetime.now().strftime('%Y-%m-%d')  # Update invoiced_date field
                    }
                }    
        )
        return jsonify({"message": "PDF generated successfully", "file_path": local_pdf_file_path}), 200

    except Exception as e:
        logging.error(f"Error generating PDF: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/get_purchase_orders", methods=["GET"])
@login_required
def get_purchase_orders():
    username = request.user
    
    claims = get_jwt()
    user_role = claims.get("role") 
    # user_role = request.role  # Assuming `request.role` holds the user's role from the JWT

    # Ensure the user is an admin
    if user_role != "admin":
        return jsonify({"error": "Access denied. Admin privileges are required."}), 403

    try:
        base_url = 'https://adebeo-crm1.onrender.com'
        # Get query parameters
        page = int(request.args.get('page', 1))
        rows_per_page = int(request.args.get('rows_per_page', 10))

        # Validate the parameters
        if page < 1 or rows_per_page < 1:
            return jsonify({"error": "Invalid page or rows per page"}), 400

        # Query to fetch purchase orders with pagination
        skip = (page - 1) * rows_per_page
        #orders_cursor = adebeo_purchase_order_collection.find().skip(skip).limit(rows_per_page)
        orders_cursor = adebeo_purchase_order_collection.find().sort("date", -1)  # Sort by insertDate, descending
        orders_cursor = orders_cursor.skip(skip).limit(rows_per_page)

        total_orders = adebeo_purchase_order_collection.count_documents({})
        total_pages = (total_orders + rows_per_page - 1) // rows_per_page  # Calculate total pages

        # Convert orders to a list and serialize ObjectIds as strings
        orders_list = []
        for order in orders_cursor:
            # Extract PDF filename (you may need to adjust field names based on your schema)
            pdf_filename = order.get("pdf_filename", "")  # Default to empty string if not found
            #base_url = order.get("base_url", "")  # Default to empty string if not found

            # Construct PDF link
            pdf_link = f"/static/pdf/{pdf_filename}" if pdf_filename else ""

            # Build order data
            order_data = {
                "_id": str(order["_id"]),
                "po_number": str(order.get("po_number", "")),
                "date": order.get("date", "").strftime('%Y-%m-%d') if order.get("insertDate") else "",
                "total_amount": order.get("total_amount", 0),
                "items": order.get("items", ""),
                "product_name": order.get("product_name",""),
                "vendor":order.get("vendor",""),
                "status":order.get("status",""),
                "customer_name":order.get("customer_name",""),
                "pdf_link": pdf_link,
                "base_url": base_url
            }
            orders_list.append(order_data)

        return jsonify({
            "orders": orders_list,
            "page": page,
            "total_orders": total_orders,
            "total_pages": total_pages
        }), 200

    except Exception as e:
        logging.error(f"Error fetching purchase orders: {str(e)}")
        return jsonify({"error": f"An error occurred while fetching purchase orders: {str(e)}"}), 500


# @app.route("/get_purchase_orders", methods=["GET"])
# @login_required
# def get_purchase_orders():
#     username = request.user
    
#     claims = get_jwt()
#     user_role = claims.get("role") 
#     #user_role = request.role  # Assuming `request.role` holds the user's role from the JWT

#     # Ensure the user is an admin
#     if user_role != "admin":
#         return jsonify({"error": "Access denied. Admin privileges are required."}), 403

#     try:
#         # Get query parameters
#         page = int(request.args.get('page', 1))
#         rows_per_page = int(request.args.get('rows_per_page', 10))

#         # Validate the parameters
#         if page < 1 or rows_per_page < 1:
#             return jsonify({"error": "Invalid page or rows per page"}), 400

#         # Query to fetch purchase orders with pagination
#         skip = (page - 1) * rows_per_page
#         orders = adebeo_purchase_order_collection.find().skip(skip).limit(rows_per_page)
#         total_orders = adebeo_purchase_order_collection.count_documents({})
#         total_pages = (total_orders + rows_per_page - 1) // rows_per_page

#         # Convert orders to a list and serialize ObjectIds as strings
#         orders_list = []
#         for order in orders:
#             # Convert ObjectId fields to strings
#             order['_id'] = str(order['_id'])  # Convert ObjectId to string
#             orders_list.append(order)

#         return jsonify({
#             "orders": orders_list,
#             "page": page,
#             "total_orders": total_orders,
#             "total_pages": total_pages
#         }), 200

#     except Exception as e:
#         logging.error(f"Error fetching purchase orders: {str(e)}")
#         return jsonify({"error": f"An error occurred while fetching purchase orders: {str(e)}"}), 500
#-----------------------------------------------------------------------------------------------------

@app.route('/get_adebeo_orders', methods=['GET'])
@login_required
def get_adebeo_orders():
    customer_id = request.args.get('customer_ID')  # Get customer_ID from query parameter

    if not customer_id:
        return jsonify({"error": "customer_ID is required"}), 400

    try:
        base_url = 'https://adebeo-crm1.onrender.com'
        # Query the 'orders_collection' using the customer_ID and sort by product_name
        orders_data = orders_collection.find({"customer_id": customer_id}).sort("product_name", 1)

        # Convert Mongo cursor to list and group orders
        orders_list = []

        for order in orders_data:
            # Convert _id (ObjectId) to string for serialization
            order['_id'] = str(order['_id'])
            orders_list.append(order)

        if not orders_list:
            return jsonify({"message": "No orders found for this customer"}), 200

        # Group orders by product_name
        grouped_orders = {}

        for order in orders_list:
            product_name = order.get('product_name')

            # If the product_name is not in the grouped_orders dictionary, create a new list for it
            if product_name not in grouped_orders:
                grouped_orders[product_name] = []

            # Add the order to the corresponding product_name group
            proforma_id = order.get('proforma_id')

            # Get Invoice PDF link if the proforma_id is available
            if proforma_id:
                # Query the invoice_collection with proforma_id to get the pdf_filename (Invoice PDF link)
                invoice_data = invoice_collection.find_one({"proforma_id": proforma_id})

                if invoice_data and 'pdf_filename' in invoice_data:  # Use pdf_filename from invoice collection
                    order['pdf_link'] = f"/static/pdf/{invoice_data['pdf_filename']}" #invoice_data['pdf_filename']
                    order['base_url'] = base_url
                else:
                    order['pdf_link'] = None
            else:
                order['pdf_link'] = None

            # Add the order to the group for that product_name
            grouped_orders[product_name].append(order)

        # Return the grouped orders as a JSON response
        return jsonify(grouped_orders)

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500


# @app.route('/get_adebeo_orders', methods=['GET'])
# @login_required
# def get_adebeo_orders():
#     customer_id = request.args.get('customer_ID')  # Get customer_ID from query parameter

#     if not customer_id:
#         return jsonify({"error": "customer_ID is required"}), 400

#     try:
#         # Query the 'orders_collection' using the customer_ID and sort by product_name
#         orders_data = orders_collection.find({"customer_id": customer_id}).sort("product_name", 1)
        
#         # Convert Mongo cursor to list and group orders
#         orders_list = []

#         for order in orders_data:
#             # Convert _id (ObjectId) to string for serialization
#             order['_id'] = str(order['_id'])
#             orders_list.append(order)

#         if not orders_list:
#             return jsonify({"message": "No orders found for this customer"}), 200
        
#         # Group orders by product_name
#         grouped_orders = {}

#         for order in orders_list:
#             product_name = order.get('product_name')

#             # If the product_name is not in the grouped_orders dictionary, create a new list for it
#             if product_name not in grouped_orders:
#                 grouped_orders[product_name] = []

#             # Add the order to the corresponding product_name group
#             proforma_id = order.get('proforma_id')

#             # Get Invoice PDF link if the proforma_id is available
#             if proforma_id:
#                 # Query the invoice_collection with proforma_id to get the pdf_filename (Invoice PDF link)
#                 invoice_data = invoice_collection.find_one({"proforma_id": proforma_id})

#                 if invoice_data and 'pdf_filename' in invoice_data:  # Use pdf_filename from invoice collection
#                     order['Invoice_PDF_link'] = invoice_data['pdf_filename']
#                 else:
#                     order['Invoice_PDF_link'] = None
#             else:
#                 order['Invoice_PDF_link'] = None

#             # Add the order to the group for that product_name
#             grouped_orders[product_name].append(order)

#         # Return the grouped orders as a JSON response
#         return Response (json_util.dumps(grouped_orders), mimetype='application/json')

#     except Exception as e:
#         print(f"Error: {str(e)}")
#         return jsonify({"error": str(e)}), 500


############################ CxPayment DB ############################


@app.route('/get_cxpayment', methods=['GET'])
@login_required
def get_cxpayment():
    try:
        # Get the customer ID from the request parameters
        base_url = 'https://adebeo-crm1.onrender.com'
        customer_id = request.args.get("customer_id")
        
        # Pagination parameters (page and limit)
        #page = int(request.args.get("page", 1))  # Default to page 1 if not provided
        #limit = int(request.args.get("limit", 10))  # Default to 10 invoices per page
         # Pagination logic remains
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        skip = (page - 1) * per_page

        # Ensure pagination values are valid
        #if page < 1 or limit < 1:
         #   return jsonify({"error": "Invalid page or limit"}), 400

        # Calculate the skip value for MongoDB query (pagination offset)
        #skip = (page - 1) * limit

        # Query to find invoices for the given customer_id, sorted by insertDate in descending order (latest first)
        # invoices_cursor = adebeo_invoice_collection.find({"customer_id": customer_id}) \
        #     .sort("insertDate", -1) \
        #     .skip(skip) \
        #     .limit(limit)
        #invoices_cursor = list(invoice_collection.find().skip(skip).limit(per_page))
        invoices_cursor = list(invoice_collection.find()
                       .sort("invoice_date", -1)  # or use "insertDate", depending on your schema
                       .skip(skip)
                       .limit(per_page))
                       
        if not invoices_cursor:
            return jsonify({"message": "No payment data found."}), 404

        # Convert the cursor to a list of invoices and handle PDF link
        invoices = []
        for invoice in invoices_cursor:
            # Extract PDF filename and base_url (adjust field names based on your schema)
            pdf_filename = invoice.get("pdf_filename", "")  # Default to empty string if not found
            #base_url = invoice.get("base_url", "")  # Default to empty string if not found

            # Construct PDF link
            pdf_link = f"/static/pdf/{pdf_filename}" if pdf_filename else ""

            # Build invoice data
            invoice_data = {
                "invoice_id": str(invoice["_id"]),
                "invoice_number": str(invoice.get("invoice_number", "")),
                "customer_name":invoice.get("customer_name",""),
                "customer_id":invoice.get("customer_id",""),
                "invoice_date": invoice.get("invoice_date", "").strftime('%Y-%m-%d') if invoice.get("invoice_date") else "",
                "total_amount": invoice.get("total_amount", 0),
                "items": invoice.get("items", ""),
                "payment_status":invoice.get("payment_status",""),
                "amount_due":invoice.get("amount_due",0),
                "pdf_link": pdf_link,
                "base_url": base_url
            }
            invoices.append(invoice_data)

        # Count total invoices for the customer to calculate total pages
        #total_invoices = adebeo_invoice_collection.count_documents({"customer_id": customer_id})
        # total_pages = (total_invoices + limit - 1) // limit  # Ceiling division to calculate total pages
        total_count = invoice_collection.count_documents({})
        total_pages = (total_count + per_page - 1) // per_page

        # Return the invoices with pagination info
        return jsonify({
            "payments": invoices,
            "current_page": page,
            "per_page": per_page,
            "total_count": total_count,
            "total_pages": total_pages
        }), 200

    except Exception as e:
        logging.error(f"Error fetching invoices: {str(e)}")
        return jsonify({"error": f"An error occurred while fetching invoices: {str(e)}"}), 500


# @app.route('/get_cxpayment', methods=['GET'])
# @login_required
# def get_cxpayment():
#     # Claims and role checking logic stays the same
#     claims = get_jwt()
#     user_role = claims.get("role") 

#     if user_role != "admin":
#         return jsonify({"error": "Access denied. Admin privileges are required."}), 403

#     try:
#         # Pagination logic remains
#         page = int(request.args.get('page', 1))
#         per_page = int(request.args.get('per_page', 10))
#         skip = (page - 1) * per_page
        
#         # Fetch records from the 'invoice_collection' without customer_id filter
#         payments = list(invoice_collection.find().skip(skip).limit(per_page))

#         # If no payments are found, return a message
#         if not payments:
#             return jsonify({"message": "No payment data found."}), 404

#         # Calculate total pages based on total record count and per_page
#         total_count = invoice_collection.count_documents({})
#         total_pages = (total_count + per_page - 1) // per_page

#         # Clean up documents and remove '_id'
#         for payment in payments:
#             payment.pop('_id', None)

#         # Return payments with pagination metadata
#         return jsonify({
#             "current_page": page,
#             "payments": payments,
#             "per_page": per_page,
#             "total_count": total_count,
#             "total_pages": total_pages
#         }), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

########################## Payment collection DB ###########################

@app.route('/process_payment', methods=['POST'])
@login_required
def process_payment():
    # Retrieve user info from JWT claims
    claims = get_jwt()
    user_role = claims.get("role")  # Assuming role comes from JWT claims

    # Ensure the user is an admin
    if user_role != "admin":
        return jsonify({"error": "Access denied. Admin privileges are required."}), 403

    try:
        # Get the payment data from the request body (assuming JSON format)
        data = request.json

        # Extract values from the request
        customer_id = data.get('customer_id')
        invoice_number = data.get('invoice_number')
        invoice_date = data.get('invoice_date')  # ISODate string or date object
        total_amount = data.get('total_amount')
        paid_amount = data.get('paid_amount')
        payment_status = data.get('payment_status')
        remaining_amount = data.get('remaining_amount', total_amount - paid_amount)  # Default calculation
        comments = data.get('comment')

        # Ensure the required fields are present
        required_fields = ['customer_id','invoice_number', 'total_amount', 'paid_amount', 'payment_status']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400

        # Calculate payment status based on remaining amount
        new_status = "completed" if remaining_amount <= 0 else "inprog"

       # Convert dates to datetime objects (if necessary)
        if invoice_date:
            try:
                # Try parsing the date string using the verbose format first
                try:
                    invoice_date = datetime.strptime(invoice_date, "%a, %d %b %Y %H:%M:%S GMT")
                except ValueError:
                    # If that fails, try parsing using the "YYYY-MM-DD" format
                    invoice_date = datetime.strptime(invoice_date, "%Y-%m-%d")
            except ValueError:
                return jsonify({"error": f"Invalid date format. Expected format: 'Thu, 06 Mar 2025 11:41:42 GMT' or '2025-03-29', but received: {invoice_date}"}), 400
        else:
            invoice_date = None

        current_date = datetime.utcnow()  # Ensure current_date is UTC for consistency

        # Step 1: Insert the full payment record into customer_payments_collection
        payment_data = {
            "customer_id": customer_id,
            "invoice_number": invoice_number,
            "invoice_date": invoice_date,
            "total_amount": total_amount,
            "paid_amount": paid_amount,
            "remaining_amount": remaining_amount,
            "payment_date": current_date,
            "updated_at": datetime.utcnow(),
            "comments": comments,
            "payment_status": new_status,
        }

        # Insert the payment record into customer_payments_collection
        customer_payments_collection.insert_one(payment_data)

        # Step 2: Update the pending_due in invoice_collection based on the invoice_number
        invoice_record = invoice_collection.find_one({"invoice_number": invoice_number})

        if invoice_record:
            # Retrieve the current amount_due from the invoice record
            pending_due = invoice_record.get('amount_due', 0)

            # Calculate the new pending_due after the payment
            new_pending_due = pending_due - paid_amount

            # Update the invoice record in invoice_collection
            invoice_collection.update_one(
                {"invoice_number": invoice_number},
                {
                    "$set": {
                        "amount_due": new_pending_due,  # Update the pending due amount
                        "updated_at": datetime.utcnow(),  # Set the updated timestamp
                    }
                }
            )

        else:
            return jsonify({"error": "Invoice not found"}), 404

        return jsonify({"message": "Payment processed successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


########################### Report for user #############################

# Helper functions to fetch data based on the report type
def get_comment_activity(company_filter, start_date,end_date, skip, limit,user=None):
    
    date_filter = {
        'insertDate': {
            '$gte': start_date,
            '$lte': end_date
        }
    }

      # Add the user filter if the user is provided
    if user:
        company_filter['insertBy'] = user

    # Combine company filter, date filter, and user filter
    #filters = {**company_filter, **date_filter}

    comments = adebeo_customer_comments.find({**company_filter,**date_filter}).skip(skip).limit(limit).sort("insertDate", 1)
    activities = []
    
    for comment in comments:
        customer_id = comment.get('customer_id')  # Fetch customer_id from the comment
        customer_name = get_customer_name_by_id(customer_id) if customer_id else 'Unknown'  # Fetch customer_name
        
        activity = {
            "activity_type": "Comment",
            "insertDate": comment['insertDate'],
            "insertBy": comment['insertBy'],
            "details": comment['comment'],
            "company_name": customer_name  # Return customer_name instead of company_name
        }
        
        activities.append(activity)
    
    return activities
    

def get_quote_activity(company_filter, start_date,end_date, skip, limit,user=None):
    if user:
        company_filter['insertBy'] = user

    date_filter = {
        'insertDate': {
            '$gte': start_date,
            '$lte': end_date
        }
    }
    if user:
        company_filter['insertBy'] = user

    quotes = list(adebeo_quotes_collection.find({**company_filter, **date_filter}).skip(skip).limit(limit).sort("insertDate", 1))
    activities = []
    
    for quote in quotes:
        customer_id = quote.get('customer_id')  # Fetch customer_id from the quote
        customer_name = get_customer_name_by_id(customer_id) if customer_id else 'Unknown'  # Fetch customer_name
        
        activity = {
            "activity_type": "Quote",
            "insertDate": quote['insertDate'],
            "insertBy": quote['insertBy'],
            "details": f"Quote ID: {quote['quote_number']}, Quote Tag: {quote.get('quoteTag', '')}",
            "company_name": customer_name  # Return customer_name instead of company_name
        }
        
        activities.append(activity)
    
    return activities

def get_proforma_activity(company_filter, start_date,end_date, skip, limit,user=None):
    if user:
        company_filter['insertBy'] = user

    date_filter = {
        'insertDate': {
            '$gte': start_date,
            '$lte': end_date
        }
    }
    proformas = adebeo_performa_collection.find({**company_filter, **date_filter}).skip(skip).limit(limit).sort("insertDate", 1)
    activities = []
    
    for proforma in proformas:
        customer_id = proforma.get('customer_id')  # Fetch customer_id from the proforma
        customer_name = get_customer_name_by_id(customer_id) if customer_id else 'Unknown'  # Fetch customer_name
        
        activity = {
            "activity_type": "Proforma",
            "insertDate": proforma['insertDate'],
            "insertBy": proforma['insertBy'],
            "details": f"Proforma Number: {proforma['performa_number']}, Proforma Tag: {proforma.get('preformaTag', '')}",
            "company_name": customer_name  # Return customer_name instead of company_name
        }
        
        activities.append(activity)
    
    return activities

def get_invoice_activity(company_filter, start_date,end_date, skip, limit):
    date_filter = {
        'insertDate': {
            '$gte': start_date,
            '$lte': end_date
        }
    }    
    invoices = adebeo_invoice_collection.find({**company_filter, **date_filter}).skip(skip).limit(limit).sort("insertDate", 1)
    activities = []
    
    for invoice in invoices:
        customer_id = invoice.get('customer_id')  # Fetch customer_id from the invoice
        customer_name = get_customer_name_by_id(customer_id) if customer_id else 'Unknown'  # Fetch customer_name
        
        activity = {
            "activity_type": "Invoice",
            "insertDate": invoice['insertDate'],
            "insertBy": invoice['insertBy'],
            "details": f"Invoice Number: {invoice.get('invoice_number', '')}, Invoice Status: {invoice.get('status', '')}",
            "company_name": customer_name  # Return customer_name instead of company_name
        }
        
        activities.append(activity)
    
    return activities


def convert_to_datetime(date_str):
    # Check if it's a string and convert it
    if isinstance(date_str, str):
        try:
            # Assuming the format is like "2025-04-08 16:09:40"
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None  # Handle invalid format if needed
    return date_str  # Return datetime if already in datetime format

def get_customer_activity(start_date_str, end_date_str, company_filter=None, skip=0, limit=10):
    """Fetch customer activity data based on a date range and optional company filter."""

    # Convert date strings to datetime objects
    start_date = convert_to_datetime(start_date_str)
    end_date = convert_to_datetime(end_date_str)
    
    if not start_date or not end_date:
        logging.error("Invalid date format. Cannot proceed.")
        return []

    # Log the date range being used
    logging.debug(f"Using start_date: {start_date} and end_date: {end_date}")

    # Set up the date filter for aggregation
    date_filter = {
        '$gte': start_date,
        '$lte': end_date
    }

    # Aggregate pipeline to convert insertDate (string) to datetime and filter by the range
    pipeline = [
        {
            '$addFields': {
                'insertDate': {
                    '$dateFromString': {
                        'dateString': '$insertDate',  # Assuming 'insertDate' is a string field
                        'format': "%Y-%m-%d %H:%M:%S"  # Adjust the format as needed
                    }
                }
            }
        },
        {
            '$match': {
                'insertDate': date_filter,
                **(company_filter if company_filter else {})  # Add company filters if provided
            }
        },
        {
            '$sort': {
                'insertDate': 1  # Sorting by insertDate in ascending order
            }
        },
        {
            '$skip': skip
        },
        {
            '$limit': limit
        }
    ]

    # Run the aggregation pipeline
    customer_activities = adebeo_customer_collection.aggregate(pipeline)

    # Log the number of activities fetched
    activities_list = list(customer_activities)
    logging.debug(f"Fetched customer activities: {activities_list}")

    # Process the activities
    activities = []
    for activity in activities_list:
        customer_id = activity.get('_id')
        logging.debug(f"Processing customer_id: {customer_id}")

        if '_id' not in activity:
            logging.warning("Missing _id in the activity. Skipping this entry.")
            continue
        
        if 'companyName' not in activity:
            logging.warning("Missing companyName in the activity. Skipping this entry.")
            continue
        
        # Fetch customer name (example method, customize as per your requirements)
        customer_name = get_customer_name_by_id(customer_id) if customer_id else 'Unknown'

        # Prepare the activity data to be returned
        activity_data = {
            "activity_type": "Customer",
            "insertDate": activity['insertDate'],
            "insertBy": activity.get('insertBy', 'Unknown'),
            "details": f"Activity Type: Customer Add/ Edit, Details: {activity.get('primaryEmail', 'No details available')}",
            "company_name": activity.get('companyName', 'Unknown')
        }
        activities.append(activity_data)

    return activities

    
# Helper function to sort activities by timestamp (insertDate)
def sort_activities(activities):
    return sorted(activities, key=lambda x: x['insertDate'])

# Route to fetch the activity report with pagination and report type
@app.route('/activity_report', methods=['GET'])
def get_activity_report():
    # Get parameters from the request
    start_date = request.args.get('startDate', None)
    end_date = request.args.get('endDate', None)
    company_name = request.args.get('companyName', None)
    user = request.args.get('user', None)
    page = int(request.args.get('page', 1))  # Default page 1
    per_page = int(request.args.get('per_page', 10))  # Default per page 10

    # Debug: Print the received parameters
    print(f"Received Parameters - Start Date: {start_date}, End Date: {end_date}, Company Name: {company_name}, User: {user}, Page: {page}, Per Page: {per_page}")
    
    # Validate per_page is positive
    if per_page <= 0:
        return jsonify({"error": "'per_page' must be a positive number"}), 400

    # Calculate skip value for pagination
    skip = (page - 1) * per_page

    # If start date or end date is not provided, set default values for the current date
    if not start_date:
        start_date = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        if 'T' not in start_date:
            start_date += 'T00:00:00'
        start_date = datetime.fromisoformat(start_date)

    if not end_date:
        end_date = datetime.today().replace(hour=23, minute=59, second=59, microsecond=999999)
    else:
        if 'T' not in end_date:
            end_date += 'T23:59:59'
        end_date = datetime.fromisoformat(end_date)

    company_filter = {}
    if company_name:
        company_filter['company_name'] = company_name

    # Debug: Print the final filters
    print(f"Company Filter: {company_filter}, Start Date: {start_date}, End Date: {end_date}")

    try:
        # Get filtered activities with pagination for each type of activity
        comment_activity = get_comment_activity(company_filter, start_date, end_date, skip, per_page, user)
        quote_activity = get_quote_activity(company_filter, start_date, end_date, skip, per_page, user)
        proforma_activity = get_proforma_activity(company_filter, start_date, end_date, skip, per_page)
        invoice_activity = get_invoice_activity(company_filter, start_date, end_date, skip, per_page)
        customer_activity = get_customer_activity(start_date, end_date, company_filter, skip, per_page)

        # Debug: Print number of activities retrieved for each type
        print(f"Fetched Activities: Comment: {len(comment_activity)}, Quote: {len(quote_activity)}, Proforma: {len(proforma_activity)}, Invoice: {len(invoice_activity)}, Customer: {len(customer_activity)}")

        # Merge all activities
        activities = comment_activity + quote_activity + proforma_activity + invoice_activity + customer_activity

        # Debug: Print total activities before sorting
        print(f"Total Activities (before sorting): {len(activities)}")

        # Sort activities by insertDate (timestamp)
        activities = sorted(activities, key=lambda x: x['insertDate'], reverse=True)

        # Debug: Print total activities after sorting
        print(f"Total Activities (after sorting): {len(activities)}")

        # Calculate total count for each collection and print them
        comment_count = get_comment_activity_count(company_filter, start_date, end_date, user)
        quote_count = get_quote_activity_count(company_filter, start_date, end_date, user)
        proforma_count = get_proforma_activity_count(company_filter, start_date, end_date)
        invoice_count = get_invoice_activity_count(company_filter, start_date, end_date)
        customer_count = get_customer_activity_count(company_filter, start_date, end_date)

        # Debug: Print individual counts
        print(f"Individual Counts - Comment: {comment_count}, Quote: {quote_count}, Proforma: {proforma_count}, Invoice: {invoice_count}, Customer: {customer_count}")

        # Total count is the sum of individual counts
        total_count = comment_count + quote_count + proforma_count + invoice_count + customer_count

        # Debug: Print total count
        print(f"Total Count (after summing individual counts): {total_count}")

        # Calculate total pages based on the filtered total count
        total_pages = (total_count + per_page - 1) // per_page

        # Debug: Print total pages
        print(f"Total Pages: {total_pages}")

        # Apply pagination to the merged activities
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_activities = activities[start_idx:end_idx]

        # Return paginated response with metadata
        return jsonify({
            "currentPage": page,
            "totalPages": total_pages,
            "totalCount": total_count,
            "activities": paginated_activities
        })

    except Exception as e:
        # Debug: Print error message
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500



def get_comment_activity_count(company_filter, start_date, end_date, user=None):
    # Filter based on date range and company filter
    query = {"insertDate": {"$gte": start_date, "$lte": end_date}}
    if company_filter:
        query.update(company_filter)
    if user:
        query["insertBy"] = user
    
    # Return the count of comment activities that match the filter
    return adebeo_customer_comments.count_documents(query)

def get_quote_activity_count(company_filter, start_date, end_date, user=None):
    query = {"insertDate": {"$gte": start_date, "$lte": end_date}}
    if company_filter:
        query.update(company_filter)
    if user:
        query["insertBy"] = user
    
    return adebeo_quotes_collection.count_documents(query)

def get_proforma_activity_count(company_filter, start_date, end_date):
    query = {"insertDate": {"$gte": start_date, "$lte": end_date}}
    if company_filter:
        query.update(company_filter)
    
    return adebeo_performa_collection.count_documents(query)

def get_invoice_activity_count(company_filter, start_date, end_date):
    query = {"insertDate": {"$gte": start_date, "$lte": end_date}}
    if company_filter:
        query.update(company_filter)
    
    return adebeo_invoice_collection.count_documents(query)

def get_customer_activity_count(company_filter, start_date, end_date):
    query = {"insertDate": {"$gte": start_date, "$lte": end_date}}
    if company_filter:
        query.update(company_filter)
    
    return adebeo_customer_collection.count_documents(query)

# Function to format the date with default times (00:00:00 for start and 23:59:59 for end)
def format_datetime_for_query(date_str, default_time):
    if not date_str:
        return None
    try:
        parsed_date = datetime.fromisoformat(date_str)
        if not parsed_date.time():  # If time is not provided, apply the default time
            return parsed_date.replace(hour=default_time[0], minute=default_time[1], second=default_time[2]).strftime('%Y-%m-%dT%H:%M:%S')
        return parsed_date.strftime('%Y-%m-%dT%H:%M:%S')
    except ValueError:
            return None        

def get_customer_name_by_id(customer_id):
    try:
        # If customer_id is a string, convert it to ObjectId
        if isinstance(customer_id, str):
            customer_id = ObjectId(customer_id)

        # Query the customer collection using _id (customer_id should be of type ObjectId)
        customer = adebeo_customer_collection.find_one({"_id": customer_id})
        
        if customer:
            return customer.get('companyName', 'Unknown')  # You can use 'ownerName' or other fields as needed
        else:
            return 'Unknown'  # If no customer found, return 'Unknown'
    except Exception as e:
        print(f"Error while fetching customer name: {e}")
        return 'Unknown'  # Return 'Unknown' in case of errors
# def get_customer_name_by_id(customer_id):
#     try:
#         # Convert string customer_id to ObjectId
#         customer_id_object = ObjectId(customer_id)
        
#         # Query the customer collection using the ObjectId
#         customer = adebeo_customer_collection.find_one({"_id": customer_id_object})
        
#         # If the customer is found, return the companyName or ownerName
#         if customer:
#             return customer.get('companyName', 'Unknown')  # Or use ownerName or another field if needed
#         else:
#             return 'Unknown'  # Return 'Unknown' if no matching customer is found
#     except Exception as e:
#         print(f"Error while fetching customer name: {e}")
#         return 'Unknown'  # Return 'Unknown' in case of any errors


# Example function to get customer data by customer_id
def get_customer_data_by_id(customer_id):
    # Assuming there's a collection or database where customer details are stored
    customer = adebeo_customer_collection.find_one({"_id": customer_id})
    return customer if customer else {}

@app.route('/current_adebeo_users', methods=['GET'])
@login_required
def current_adebeo_users():
    claims = get_jwt()
    user_role = claims.get("role")
    username = request.user
    #user_username = claims.get("username")  # Assuming you also store the username in the claims

    try:
        # If the user is an admin, show all users
        users_list = []
        if user_role == "admin":
            # Assuming your MongoDB collection is named `adebeo_users_collection`
            users = adebeo_users_collection.find({}, {'password': 0, '__v': 0})  # Excluding password and other sensitive fields
            
            # Mapping the result to a cleaner format (removing _id and renaming if necessary)
            users_list = []
            for user in users:
                user_data = {
                    'username': user['username'],
                    'role': user['role']
                }
                users_list.append(user_data)
            
            return jsonify(users_list)
        
        # If the user is not an admin, show only their own information
        else:
            user = adebeo_users_collection.find_one({"username": username}, {'password': 0, '__v': 0})
            
            if not user:
                return jsonify({"error": "User not found"}), 404
            
            user_data = {
                'username': user['username'],
                'role': user['role']
            }
            users_list.append(user_data)
            return jsonify(users_list)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# @app.route('/current_adebeo_users', methods=['GET'])
# def current_adebeo_users():
#     try:
#         # Assuming your MongoDB collection is named `adebeo_users_collection`
#         users = adebeo_users_collection.find({}, {'password': 0, '__v': 0})  # Excluding password and other sensitive fields
        
#         # Mapping the result to a cleaner format (removing _id and renaming if necessary)
#         users_list = []
#         for user in users:
#             user_data = {
#                 'username': user['username'],
#                 'role': user['role']
#             }
#             users_list.append(user_data)
        
#         return jsonify(users_list)
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500



if __name__ == "__main__":
    app.run(debug=True)