from flask import Flask, request, make_response, jsonify
from flask_cors import CORS, cross_origin
import hashlib
import jwt
import datetime
import os


app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

users = {}
usersTokens = {}

SECRET = 'superSecret'


def validateRegisterBody(body):
    if(body is None):
        raise Exception("Invalid body")
    if(body["userName"] in users):
        raise Exception("This user name is already taken")


def hashPassword(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def registerUser(user):
    users[user["userName"]] = hashPassword(user["password"])


@app.route('/register', methods=['POST'])
@cross_origin()
def register():
    post_data = request.get_json()
    try:
        validateRegisterBody(post_data)
        registerUser(post_data)
        return make_response("ok"), 200
    except Exception as err:
        return make_response({"error": str(err)}), 400


def validateLoginBody(body):
    if(body is None):
        raise Exception("Invalid body")
    if not userExists(body["userName"]):
        raise Exception("Invalid username or password")


def userExists(userName):
    return userName in users


def loginUser(user):
    validPassoword = users[user["userName"]]
    if validPassoword == hashPassword(user["password"]):
        token = jwt.encode(
            {"user": user["userName"], "iat": datetime.datetime.now()}, SECRET)
        usersTokens[user["userName"]] = token
        return make_response({"token": token}), 200

    else:
        raise Exception("Invalid username or password.")


@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    post_data = request.get_json()
    try:
        validateLoginBody(post_data)
        return loginUser(post_data)
    except Exception as err:
        print(err)
        return make_response({"error": str(err)}), 400


@app.route('/verify', methods=['POST'])
@cross_origin()
def verify():
    token = request.headers['token']
    try:
        decoded = jwt.decode(token, SECRET, 'HS256')
        currentToken = usersTokens[decoded["user"]]
        if(token != currentToken):
            return make_response("invalid token"), 400
        return make_response(), 200
    except Exception as err:
        return make_response("unathorized"), 400


@app.route('/users', methods=['GET'])
@cross_origin()
def getUsers():
    userNames = []
    for key in users.keys():
        userNames.append(key)
    return make_response(jsonify(userNames)), 200


if __name__ == '__main__':
    port = os.environ.get('PORT', 5000)
    app.run(debug=False, host='0.0.0.0', port=port)
