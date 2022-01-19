from flask import Flask, request, make_response, jsonify
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
import hashlib
import jwt
from datetime import datetime
import os
from dotenv import load_dotenv
import os

load_dotenv('./.env')

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class Users(db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True)
    userName = db.Column(db.String(200))
    password = db.Column(db.String(200))
    createdAt = db.Column(db.String(200))

    def __init__(self, userName, password):
        time = datetime.today()
        self.userName = userName
        self.password = password
        self.createdAt = str(str(time.day) + "-" +
                             str(time.month) + "-" + str(time.year))


class ValidTokens(db.Model):
    __tablename__ = 'Tokens'
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer)
    token = db.Column(db.String(200))

    def __init__(self, userId, token):
        self.userId = userId
        self.token = token


SECRET = 'superSecret'


def validateRegisterBody(body):
    if(body is None):
        raise Exception("Invalid body")
    if db.session.query(Users).filter(Users.userName == body["userName"]).count() != 0:
        raise Exception("This user name is already taken")


def hashPassword(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def registerUser(user):
    password = hashPassword(user["password"])
    userName = user["userName"]
    data = Users(userName, password)
    db.session.add(data)
    db.session.commit()


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
    if db.session.query(Users).filter(Users.userName == body["userName"]).count() == 0:
        raise Exception("This username doesn't exist")


def loginUser(user):
    password = Users.query.filter_by(
        userName=user['userName']).first().password
    id = Users.query.filter_by(
        userName=user['userName']).first().id
    if password == hashPassword(user["password"]):
        token = jwt.encode(
            {"user": user["userName"], "iat": datetime.now()}, SECRET)
        if db.session.query(ValidTokens).filter(ValidTokens.userId == id).count() != 0:
            obj = db.session.query(ValidTokens).filter(
                ValidTokens.userId == id).first()
            db.session.delete(obj)
            db.session.commit()

        data = ValidTokens(id, token)
        db.session.add(data)
        db.session.commit()
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
        return make_response({"error": str(err)}), 400


@app.route('/verify', methods=['POST'])
@cross_origin()
def verify():
    token = request.headers['token']
    try:
        if db.session.query(ValidTokens).filter(ValidTokens.token == token).count() == 1:
            return make_response(), 200
        return make_response("invalid token"), 400
    except Exception as err:
        return make_response("unathorized"), 400


@app.route('/users', methods=['GET'])
@cross_origin()
def getUsers():
    userNames = []
    users = Users.query.all()
    for user in users:
        userNames.append([user.userName, user.createdAt])
    return make_response(jsonify(userNames)), 200


if __name__ == '__main__':
    port = os.environ.get('PORT', 5000)
    app.run(debug=False, host='0.0.0.0', port=port)
