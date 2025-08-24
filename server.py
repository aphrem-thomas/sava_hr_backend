import base64
from flask import Flask, jsonify
from flask import request
from flask import make_response
import bson
import json
import time
import jwt
from dotenv import load_dotenv
import os
import bcrypt
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
from flask_mail import Mail, Message 


load_dotenv()

app = Flask(__name__)
mail = Mail(app) # instantiate the mail class 
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_TOKEN_LOCATION"] = ["cookies"] 
app.config["JWT_SECRET_KEY"] = os.getenv('SIGN_KEY')
app.config['JWT_ALGORITHM'] = 'HS256'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'jobs4ottawa@gmail.com'
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASS")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'None'
mail = Mail(app) 

jwt = JWTManager(app)

encodedSalt = os.getenv("SALT")
salt = base64.b64decode(encodedSalt)

# Handle unauthorized access by unsetting JWT cookies
@jwt.unauthorized_loader
def unauthorized_callback(callback):
    print("unauthorized callback called")
    resp = make_response(jsonify({"msg": "Missing or invalid token"}), 401)
    unset_jwt_cookies(resp)
    return resp

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

ALLOWED_EXTENSIONS = {'pdf'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

   
# Get the database
dbname = get_database()
jobsCollection = dbname['jobs']
userColection = dbname['users']


@app.before_request
def before_request():
    print("Request Headers:", request.headers)
    print("Request Cookies:", request.cookies)
    print('Request formdata', request.form)

@app.route("/login", methods=['POST'])
def login():
    user_name = request.form.get('username')
    password = request.form.get('password')
    resp = make_response(jsonify({"message":"howdi partner..."}))
    hash_pass = bcrypt.hashpw(password.encode('utf-8'),salt)
    user = userColection.find_one({"username": user_name})
    user_password = user.get('password', b'') if user else b''
    # Ensure user_password is bytes
    if isinstance(user_password, str):
        user_password = user_password.encode('utf-8')
    if user is None or not bcrypt.checkpw(password.encode('utf-8'), user_password):
        error_resp = make_response("", 401)
        return error_resp
    if user is not None and bcrypt.checkpw(password.encode('utf-8'), user_password):
        print("User found and password matched", user.get('username'))
        access_token = create_access_token(identity=user_name)
        print("encoded jwt", access_token)
        set_access_cookies(resp, access_token)
        return resp, 200
    else:
        error_resp = make_response("",401)
        return error_resp
    
@app.route("/register", methods=['POST'])
def register():
    user_name = request.form.get('username')
    password = request.form.get('password')
    resp = make_response(jsonify({"message":"howdi partner..."}))
    hash_pass = bcrypt.hashpw(password.encode('utf-8'),salt)
    user = userColection.find_one({"username": user_name})
    if user is not None:
        print("user already exists")
        error_resp = make_response("", 409)
        return error_resp
    try:
        if(userColection is not None):
            userColection.insert_one(
               {
                    "username":user_name,
                    "password":hash_pass,
                }
            )
    except Exception as e:
        print("error in adding", e)
        return '500'
    resp.status_code = 200
    resp.headers['Location'] = '/login'
    return resp

@app.route("/change_password", methods=['POST'])
def change_password():
    user_name = request.form.get('username')
    password = request.form.get('oldPassword')
    new_password = request.form.get('newPassword')
    resp = make_response(jsonify({"message":"howdi partner..."}))
    hash_pass = bcrypt.hashpw(password.encode('utf-8'),salt)
    user = userColection.find_one({"username": user_name})
    if user is None:
        error_resp = make_response("", 401)
        return error_resp
    try:
        if(userColection is not None and user is not None and bcrypt.checkpw(password.encode('utf-8'), user.get('password'))):
            userColection.update_one(
               {"username":user_name},
               {"$set": {"password":bcrypt.hashpw(new_password.encode('utf-8'),salt)}}
            )
        else:
            error_resp = make_response("", 401)
            return error_resp
    except Exception as e:
        print("error in updating", e)
        return '500'
    resp.status_code = 200
    resp.headers['Location'] = '/login'
    return resp

    
    
@app.route("/logout", methods=['POST'])
@jwt_required()
def logout():
    resp = make_response(jsonify({"message":"howdi partner..."}))
    unset_jwt_cookies(resp)
    return resp, 200


@app.route("/jobs", methods=['POST'])
@jwt_required()
def add_job():
    print("req-->",request.form)
    print(request.cookies)
    location = request.form.get('location')
    role = request.form.get('role')
    description = request.form.get('description')
    date = request.form.get('date')
    status = request.form.get('status')
    title = request.form.get('title')
    company = request.form.get('company')
    requirements = request.form.get('requirements').split(';')
    try:
        if(jobsCollection is not None):
            jobsCollection.insert_one(
               {
                    "location":location,
                    "role":role,
                    "description":description,
                    "date":date,
                    "status":status,
                    "title":title,
                    "company":company,
                    "requirements":requirements,
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
def get_job(id):
    jobDetail = jobsCollection.find_one({'_id': bson.ObjectId(id)})
    return json.dumps(bson.json_util.dumps(jobDetail)), '200'

@app.route("/job/<id>", methods=['DELETE'])
@jwt_required()
def delete_job_by_id(id):
    print("deleting job with id", id)
    try:
        if(jobsCollection is not None):
            jobsCollection.delete_one(
               {
                    "_id":bson.ObjectId(id),
                }
            )
    except Exception as e:
        print("error in deleting", e)
        return '500'
    return '200'

#this route for applying for job and submitting resume
@app.route("/apply", methods=['POST'])
def apply_job():
    fname = request.form.get('fname')
    lname = request.form.get('lname')
    email = request.form.get('email')
    jobtitle = request.form.get('jobtitle') #current job title of the applicant.
    status = request.form.get('status')
    experience = request.form.get('experience')
    jobid = request.form.get('jobid') #job id to which he is applying
    job_name = getattr(jobsCollection.find_one({'_id':bson.ObjectId(jobid)},{"title":1}),'title', None) #name of job which he is applying
    print("jobname",job_name, jobid)
    print("fileee", request.files)
    if (jobid is not None and job_name is None):
        return {"message":"invalid job id"}, '404'
    if 'resume' not in request.files:
        return {"message":"no files attached"}, '404'
    file = request.files['resume']
    # If the user does not select a file, the browser submits an
    # empty file without a filename.
    if file.filename == '':
        return {"message":"no files attached"}, '404'
    if jobid is None:
        msg = Message( 
                    f"Resume of {fname+ ' ' + lname}", 
                    sender ='jobs4ottawa@gmail.com', 
                    recipients = ['jobs4ottawa@gmail.com'] 
                    
                ) 
        msg.html = f"<h3>Resume of {fname+ ' ' + lname}.</h3><br/> Contact email: {email}<br/> Current job title: {jobtitle} <br/> Status: {status}"
        msg.attach(file.filename,None,file.read())
        mail.send(msg) 
        return {}, '200'
    if file and allowed_file(file.filename):
        msg = Message( 
                    f"Job application of {fname+ ' ' + lname} for {job_name}", 
                    sender ='jobs4ottawa@gmail.com', 
                    recipients = ['jobs4ottawa@gmail.com'] 
                    
                ) 
        msg.html = f"<h3>Job application of {fname+ ' ' + lname} for {job_name}.</h3><br/> Contact email: {email}<br/> Current job title: {jobtitle} <br/> Status: {status} <br/> Experience: {experience}"
        msg.attach(file.filename,None,file.read())
        mail.send(msg) 
        return {}, '200'
    return '500'

