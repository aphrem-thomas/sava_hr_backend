from flask import Flask, jsonify
from flask import request
from flask import make_response
import time
import jwt

app = Flask(__name__)

@app.route("/login", methods=['POST'])
def login():
    user_name = request.form.get('username')
    password = request.form.get('password')
    print("received user name:", user_name)
    print("received pass:", password)
    print("is matching", user_name=='admin-sava' and password == 'abc')
    resp = make_response(jsonify({"message":"howdi partner..."}))
    if user_name=='admin-sava' and password == 'abc':
        encoded_jwt = jwt.encode({"userId":user_name}, "dkfalkdfjalkdfjlakdjfldjflkd", algorithm="HS256")
        print("encoded jwt", encoded_jwt)
        resp.set_cookie('session', encoded_jwt,
                         expires=time.time()+ 24 * 60 * 60 * 1000,
                         path='/')
        return resp, 200
    else:
        error_resp = make_response("",401)
        return error_resp
    
@app.route("/logout", methods=['POST'])
def logout():
    resp = make_response(jsonify({"message":"howdi partner..."}))
    resp.delete_cookie('session')
    return resp, 200



if __name__ == "__main__":
    app.run(debug=True)