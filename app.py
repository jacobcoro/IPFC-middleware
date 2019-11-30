from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import BIGINT, JSONB, VARCHAR
import psycopg2
import uuid
import bcrypt
import jwt
import datetime
from functools import wraps
import os
import uwsgi
from flask_cors import CORS, cross_origin

app = Flask(__name__)
CORS(app)
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SECRET_KEY'] = 'totally%@#$%^T@#Secure!'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Users(db.Model):
    __table_args__ = {'schema':'admin'}
    user_id = db.Column(VARCHAR, primary_key=True)
    email = db.Column(VARCHAR)
    password_hash = db.Column(VARCHAR)
    pinata_api = db.Column(VARCHAR)
    pinata_key = db.Column(VARCHAR)

    def __init__(self, user_id, email, password_hash, pinata_api, pinata_key):
        self.user_id = user_id
        self.email = email
        self.password_hash = password_hash
        self.pinata_api = pinata_api
        self.pinata_key = pinata_key

class UserCollections(db.Model):
    deck_id = db.Column(VARCHAR, primary_key=True)
    sr_id = db.Column(VARCHAR)
    deck_ids =  db.Column(JSONB)
    all_deck_cids = db.Column(JSONB)
    def __init__(self, deck_id, sr_id, deck_ids, all_deck_cids):
        self.deck_id = deck_id
        self.sr_id = sr_id
        self.deck_ids =  deck_ids
        self.all_deck_cids = all_deck_cids

class Decks(db.Model):
    deck_id = db.Column(VARCHAR, primary_key=True)
    edited = db.Column(BIGINT)
    deck_cid = db.Column(VARCHAR)
    deck = db.Column(JSONB)
    title = db.Column(VARCHAR)
    def __init__(self, deck_id, edited, deck_cid, deck, title):
        self.deck_id = deck_id
        self.edited = edited
        self.deck_cid = deck_cid
        self.deck = deck
        self.title = title


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/sign_up', methods=['POST'])
def sign_up():
    data = request.get_json()
    hashed_password = bcrypt.hashpw(data['password'].encode('utf8'), bcrypt.gensalt())
    new_user = Users(user_id=str(uuid.uuid4()), email=data['email'],
                     password_hash=hashed_password.decode('utf8'), pinata_api=data['pinata_api'],
                     pinata_key=data['pinata_key'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'New user created!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    user = Users.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
                                        #
    if bcrypt.checkpw(auth.password.encode('utf8'), user.password_hash.encode('utf8')):
        token = jwt.encode({'user_id': user.user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)},
                           app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})





if __name__ == '__main__':
    app.run(debug=True)
