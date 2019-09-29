from flask import Flask, request
from flask_restful import Resource, Api
import sys
import os
import glob
from pathlib import Path
import json
import random
import psycopg2
import uuid
import argon2
import secrets
import requests
import shutil

app = Flask(__name__)
api = Api(app)

def media_downloader(deck_file_path):
    with open(deck_file_path) as fileobj:
        deck = json.loads(fileobj.read())
    title = deck['title']
    for card in deck['cards']:
        for item in card.items():
            if 'http' in item[1]:
                url = item[1]
                response = requests.get(url, stream=True)
                write_file_path = str(decks_dir) + '/' + 'media_' + title + '/' + card['card_id'] + ';' + item[0] + '.jpg'
                with open(write_file_path, 'wb') as out_file:
                    shutil.copyfileobj(response.raw, out_file)
                del response

# login procedure:
# app - email and password entered, app queries middleware for salt,
# middleware queries database, gives email, gets salt, returns it to app.

# app hashes user entered password with retrieved salt
# app queries middleware with hash key
# middleware queries database, checks if queried key matches stored key,
# returns true to app, also returns userID. if wrong replies 'incorrect'

# app
def get_salt(self):
    entered_email = self.ui.lineEditEmail.text()
#   salt_query = an API request to the middleware offering email, asking for salt
    return salt

def get_userid(self):
    # user_id_query = an API request to the middleware offering email and password key
    global user_id
    user_id = user_id_query_result

def verify_login(self):
    entered_email = self.ui.lineEditEmail.text()
    entered_password = self.ui.lineEditPassword.text()
    stored_salt = get_salt()
    trial_key = argon2.argon2_hash(password=entered_password, salt=stored_salt, t=16, m=512, p=2, buflen=64).hex()
#   Send trial key, email to API. get back login confirm bool
    if verify_login():
        self.ui.labelResponse.setText('Incorrect login information.')
        return
    if not verify_login():
        self.open_start_menu()
        get_userid()
        return

# middleware, takes email
def get_salt(self):
    try:
        conn = psycopg2.connect(IPFCdatabase_login)
        cursor = conn.cursor()
    except:
        self.ui.labelResponse.setText("Unable to connect to the database")
    if self.ui.labelResponse.text() == "Unable to connect to the database":
        return
    else:
        # entered email = API requests arg entered email
        entered_password = self.ui.lineEditPassword.text()
        salt_query = "SELECT salt FROM admin.users WHERE email = %s"
        cursor.execute(salt_query, (entered_email,))
        stored_salt = cursor.fetchone()[0]
        # return stored_salt through API

def get_userid(self):
    user_id_query = "SELECT user_id FROM admin.users WHERE email = %s"
    cursor.execute(user_id_query, (entered_email,))
    user_id = cursor.fetchone()[0]
    return user_id

def verify_key(self):
    try:
        conn = psycopg2.connect(IPFCdatabase_login)
        cursor = conn.cursor()
    except:
        self.ui.labelResponse.setText("Unable to connect to the database")
    if self.ui.labelResponse.text() == "Unable to connect to the database":
        return
    else:
        # entered email = API requests arg entered email
        key_query = "SELECT key FROM admin.users WHERE email = %s"
        cursor.execute(key_query, (entered_email,))
        stored_key = cursor.fetchone()[0]
        # trial_key = API requests arg entered key
        if trial_key != stored_key:
            conn.close()
            return False
            # API return False
        if trial_key == stored_key:
            conn.close()
            return True
            # API return True
        # if enter wrong three times, wait 5 minutes. only one trial per minute. over 9 times, lock for a day





def verify_signup(self):
    # midware
    try:
        conn = psycopg2.connect(IPFCdatabase_login)
        cursor = conn.cursor()
    except:
        self.ui.labelResponse.setText("Unable to connect to the database")
    if self.ui.labelResponse.text() == "Unable to connect to the database":
        return
    else:
        # app
        new_user_id = uuid.uuid4().hex
        new_email = self.ui.lineEditEmail.text()
        password = self.ui.lineEditPassword.text()
        repeat_password = self.ui.lineEditPassword.text()
        pinata_api = self.ui.lineEditPinataAPI.text()
        pinata_key = self.ui.lineEditPinataKey.text()
        new_salt = secrets.token_hex(32)
        key = argon2.argon2_hash(password=password, salt=new_salt, t=16, m=512, p=2, buflen=64).hex()
        if new_email == "" or password == "" or repeat_password == "" or pinata_api == "" or pinata_key == "":
            self.ui.labelResponse.setText("All fields are required")
            return
        elif "@" not in new_email and "." not in new_email:
            self.ui.labelResponse.setText("Please input a valid email address")
            return
        elif len(password) < 8 :
            self.ui.labelResponse.setText("Password must be more than 8 characters long")
            return
        elif password != repeat_password:
            self.ui.labelResponse.setText("Passwords did not match")
            return

        else:
            # app to midware to db
            email_exists_query = "SELECT EXISTS (SELECT * FROM admin.users WHERE email = %s)"
            cursor.execute(email_exists_query, (new_email,))
            exists = cursor.fetchone()[0]
            if exists:
                self.ui.labelResponse.setText("Email already already in database.")
                conn.close()
                return
            else:
                cursor.execute('''INSERT INTO admin.users(user_id, email, key, salt, pinata_api, pinata_key) 
                               VALUES (%s, %s, %s, %s, %s, %s)''',
                               (new_user_id, new_email, key, new_salt, pinata_api, pinata_key))
                conn.commit()
                self.ui.labelResponse.setText("Sign up successful! After signing up for "
                                              "Pinata, press back and sign in")
                # add something here to query database and see if values are all there properly?
                conn.close()
                return

"""need to create a deck downloader here, and an uploader where? at program and and at any edits place"""
#def deck_downloader(self):

user_id = ""

IPFCdatabase_login = """
dbname='IPFCdatabase' 
user='jacob' 
password='5w42bjnscjny8ufy'
host='165.22.144.86'
port='5432'
"""

class TodoSimple(Resource):
    def get(self, todo_id):
        return {todo_id: todos[todo_id]}

    def put(self, todo_id):
        todos[todo_id] = request.form['data']
        return {todo_id: todos[todo_id]}

api.add_resource(TodoSimple, '/<string:todo_id>')

if __name__ == '__main__':
    app.run(debug=True)