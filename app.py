from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import BIGINT, JSONB, VARCHAR
from flask_marshmallow import Marshmallow
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
ma = Marshmallow(app)
CORS(app)
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SECRET_KEY'] = 'totally%@#$%^T@#Secure!'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


### Models ###

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
    user_id = db.Column(VARCHAR, primary_key=True)
    sr_id = db.Column(VARCHAR)
    deck_ids = db.Column(JSONB)
    all_deck_cids = db.Column(JSONB)

    def __init__(self, user_id, sr_id, deck_ids, all_deck_cids):
        self.user_id = user_id
        self.sr_id = sr_id
        self.deck_ids = deck_ids
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


### Schemas ###

class UserCollectionsSchema(ma.Schema):
    class Meta:
        fields = ("user_id", "sr_id", "deck_ids", "all_deck_cids")


user_collection_schema = UserCollectionsSchema()

class DecksSchema(ma.Schema):
    class Meta:
        fields = ("deck_id", "edited", "deck_cid", "deck", "title")

deck_schema = DecksSchema()
decks_schema = DecksSchema(many=True)


### JWT token checker ###

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
            current_user = Users.query.filter_by(user_id=data['user_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


### API call routes ###

@app.route('/sign_up', methods=['POST'])
# @cross_origin(origin='*')
def sign_up():

    data = request.get_json()
    exists = Users.query.filter_by(email=data['email']).first()
    if exists is not None:
        return jsonify({"error": "email already exists"})
    else:
        hashed_password = bcrypt.hashpw(data['password'].encode('utf8'), bcrypt.gensalt())
        new_user = Users(user_id=str(uuid.uuid4()),
                         email=data['email'],
                         password_hash=hashed_password.decode('utf8'),
                         pinata_api=data['pinata_api'],
                         pinata_key=data['pinata_key'])
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'New user created!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    user = Users.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    if bcrypt.checkpw(auth.password.encode('utf8'), user.password_hash.encode('utf8')):
        token = jwt.encode({'user_id': user.user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)},
                           app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

@app.route('/post_user_collection', methods=['POST'])
@token_required
def post_user_collection(current_user):
    data = request.get_json()

    new_collection = UserCollections(user_id=current_user.user_id,
                                     sr_id=str(uuid.uuid4()),
                                     all_deck_cids=data['all_deck_cids'],
                                     deck_ids=data['deck_ids'],)
    db.session.add(new_collection)
    db.session.commit()

    return user_collection_schema.dump(new_collection)

@app.route('/get_user_collection', methods=['GET'])
@token_required
def get_user_collection(current_user):

    user_collection = UserCollections.query.filter_by(user_id=current_user.user_id).first()
    return user_collection_schema.dump(user_collection)

@app.route('/put_user_collection', methods=['PUT'])
@token_required
def put_user_collection(current_user):
    data = request.get_json()
    user_collection = UserCollections.query.filter_by(user_id=current_user.user_id).first()
    if 'sr_id' in data:
        user_collection.sr_id = data['sr_id']
    if 'deck_ids' in data:
        user_collection.deck_ids = data['deck_ids']
    if 'all_deck_cids' in data:
        user_collection.all_deck_cids = data['all_deck_cids']

    db.session.commit()
    return user_collection_schema.dump(user_collection)


@app.route('/post_deck', methods=['POST'])
@token_required
def post_deck(current_user):
    data = request.get_json()
    exists = Decks.query.filter_by(deck_id=data['deck_id']).first()
    if exists is not None:
        return jsonify({"error": "deck already exists"})
    else:
        new_deck = Decks(
            deck_id=data['deck_id'],
            deck=data['deck'],
            # these echo 'deck' internal info to allow for less expensive database metadata queries
            title=data['title'],
            edited=data['edited'],
            deck_cid=data['deck_cid']
        )
        db.session.add(new_deck)
        db.session.commit()
        return deck_schema.dump(new_deck)


@app.route('/get_deck', methods=['GET'])
@token_required
def get_deck(current_user):
    data = request.get_json()
    deck_id = data['deck_id']
    dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
    return dump['deck']

@app.route('/get_decks', methods=['GET'])
@token_required
def get_decks(current_user):
    data = request.get_json()
    deck_ids = data['deck_ids']
    decks = []
    for deck_id in deck_ids:
        dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
        if 'deck' in dump:
            decks.append(dump['deck'])
    return jsonify(decks)


@app.route('/put_deck', methods=['PUT'])
@token_required
def put_deck(current_user):
    data = request.get_json()
    deck_update = Decks.query.filter_by(deck_id=data['deck_id']).first()

    if 'deck' in data:
        deck_update.deck = data['deck']
    # If the deck is changed server-side remember to change edited and title in deck itself !!!
    if 'title' in data:
        deck_update.title = data['title']
    if 'edited' in data:
        deck_update.edited = data['edited']
    if 'deck_cid' in data:
        deck_update.deck_cid = data['deck_cid']

    db.session.commit()
    return deck_schema.dump(deck_update)

@app.route('/get_deck_meta', methods=['GET'])
@token_required
def get_deck_meta(current_user):
    data = request.get_json()
    deck_id = data['deck_id']
    dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
    deck_meta = {
    'title' : dump['title'],
    'edited' : dump['edited'],
    'deck_cid' : dump['deck_cid'],
    'deck_id' : dump['deck_id']
    }
    return jsonify(deck_meta)

@app.route('/get_decks_meta', methods=['GET'])
@token_required
def get_decks_meta(current_user):
    data = request.get_json()
    deck_ids = data['deck_ids']
    decks_meta = []
    for deck_id in deck_ids:
        dump = deck_schema.dump(Decks.query.filter_by(deck_id=deck_id).first())
        deck_meta = {
        'title' : dump['title'],
        'edited' : dump['edited'],
        'deck_cid' : dump['deck_cid'],
        'deck_id' : dump['deck_id']
        }
        decks_meta.append(deck_meta)
    return jsonify(decks_meta)

if __name__ == '__main__':
    app.run(debug=True)
