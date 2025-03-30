from flask import Flask, jsonify
from flask import request
from flask import make_response
import bson
import json
import time
import jwt
from dotenv import load_dotenv
import os
from pymongo import MongoClient
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import unset_jwt_cookies
from datetime import datetime
from datetime import timedelta


load_dotenv()

app = Flask(__name__)
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_TOKEN_LOCATION"] = ["cookies"] 
app.config["JWT_SECRET_KEY"] = os.getenv('SIGN_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

jwt = JWTManager(app)

sign_key = os.getenv('SIGN_KEY')
print("sign key", sign_key)
dbname=None
jobsCollection = None

def get_database():
   # Provide the mongodb atlas url to connect python to mongodb using pymongo
   CONNECTION_STRING = os.getenv('MONGO_STRING')
 
   # Create a connection using MongoClient. You can import MongoClient or use pymongo.MongoClient
   client = MongoClient(CONNECTION_STRING)
 
   # Create the database for our example (we will use the same database throughout the tutorial
   return client['test']
  
# This is added so that many files can reuse the function get_database()



if __name__ == "__main__":   
  
   # Get the database
   dbname = get_database()
   jobsCollection = dbname['jobs']

@app.route("/login", methods=['POST'])
def login():
    user_name = request.form.get('username')
    password = request.form.get('password')
    print("received user name:", user_name)
    print("received pass:", password)
    print("is matching", user_name=='admin-sava' and password == 'abc')
    resp = make_response(jsonify({"message":"howdi partner..."}))
    if user_name=='admin-sava' and password == 'abc':
        access_token = create_access_token(identity=user_name)
        print("encoded jwt", access_token)
        set_access_cookies(resp, access_token)
        return resp, 200
    else:
        error_resp = make_response("",401)
        return error_resp
    
@app.route("/logout", methods=['POST'])
@jwt_required()
def logout():
    resp = make_response(jsonify({"message":"howdi partner..."}))
    unset_jwt_cookies(resp)
    return resp, 200


@app.route("/jobs", methods=['POST'])
@jwt_required()
def add_job():
    location = request.form.get('location')
    role = request.form.get('role')
    description = request.form.get('description')
    date = request.form.get('date')
    status = request.form.get('status')
    try:
        if(jobsCollection is not None):
            jobsCollection.insert_one(
               {
                    "location":location,
                    "role":role,
                    "description":description,
                    "date":date,
                    "status":status
                }
            )
    except Exception as e:
        print("error in adding", e)
        return '500'
    return '200'

@app.route("/jobs", methods=['DELETE'])
@jwt_required()
def delete_job():
    idd = request.args.get('id')
    try:
        if(jobsCollection is not None):
            jobsCollection.delete_one(
               {
                    "_id":idd,
                }
            )
    except Exception as e:
        print("error in deleting", e)
        return '500'
    return '200'



@app.route("/jobs", methods=['GET'])
def get_jobs():
    item_details = jobsCollection.find({},{ "description": 0, }) #exclued description
    l_cursor = list(item_details)
    temp_outp = map(lambda x:{**x, "id":str(x.get('_id'))}, l_cursor)
    outp = list(map(lambda x:{k:v for k,v in x.items() if k!='_id'}, temp_outp))
    print("item details", outp)
    print(request.cookies)
    print("formdata", request.headers.get('X-CSRF-TOKEN'))
    return  json.dumps(bson.json_util.dumps(outp)), '200'

@app.route("/job/<id>", methods=['GET'])
def get_job():
    return {}, '200'






if __name__ == "__main__":
    app.run(debug=True)