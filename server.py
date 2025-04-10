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
from flask_mail import Mail, Message 


load_dotenv()

app = Flask(__name__)
mail = Mail(app) # instantiate the mail class 
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_TOKEN_LOCATION"] = ["cookies"] 
app.config["JWT_SECRET_KEY"] = os.getenv('SIGN_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'jobs4ottawa@gmail.com'
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASS")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app) 

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

ALLOWED_EXTENSIONS = {'pdf'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



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
    title = request.form.get('title')
    try:
        if(jobsCollection is not None):
            jobsCollection.insert_one(
               {
                    "location":location,
                    "role":role,
                    "description":description,
                    "date":date,
                    "status":status,
                    "title":title
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

@app.route("/apply", methods=['POST'])
def apply_job():
    fname = request.form.get('fname')
    lname = request.form.get('lname')
    email = request.form.get('email')
    jobtitle = request.form.get('jobtitle')
    status = request.form.get('status')
    jobid = request.form.get('jobid')
    job_name = getattr(jobsCollection.find_one({'_id':bson.ObjectId(jobid)},{"title":1}),'title', None)
    print("jobname",job_name, jobid)
    if (job_name is None):
        return {"message":"invalid job id"}, '404'
    if 'file' not in request.files:
        return {"message":"no files attached"}, '404'
    file = request.files['file']
    # If the user does not select a file, the browser submits an
    # empty file without a filename.
    if file.filename == '':
        return {"message":"no files attached"}, '404'
    if file and allowed_file(file.filename):
        msg = Message( 
                    f"Job application of {fname+ ' ' + lname} for {job_name}", 
                    sender ='jobs4ottawa@gmail.com', 
                    recipients = ['jobs4ottawa@gmail.com'] 
                    
                ) 
        msg.html = f"<h3>Job application of {fname+ ' ' + lname} for {job_name}.</h3><br/> Contact email: {email}<br/> Current job title: {jobtitle} <br/> Status: {status}"
        msg.attach(file.filename,None,file.read())
        mail.send(msg) 
        return {}, '200'
    return '500'






if __name__ == "__main__":
    app.run(debug=True)