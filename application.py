from flask import Flask, request
from flask_restful import Resource, Api
import psycopg2
import uwsgi

app = Flask(__name__)
api = Api(app)

# IPFCdatabase_login = """
# dbname='IPFCdatabase'
# user='jacob'
# password='5w42bjnscjny8ufy'
# host='165.22.144.86'
# port='5432'
# """

IPFCdatabase_login = """
dbname='d8psd9fqa0qh2b' 
user='gvzzuizrbhvhan' 
password='47efd6af45d4c4d3736d06c2922cf00d17682c237ed8763d0d8b901d9449d169'
host='ec2-107-22-160-185.compute-1.amazonaws.com'
port='5432'
"""


# class UploadDeck(Resource):
#     def put(self):
#         try:
#             conn = psycopg2.connect(IPFCdatabase_login)
#             cursor = conn.cursor()
#         except:
#             result = "Unable to connect to the database"
#             return result
#         else:


class GetSalt(Resource):
    def get(self):
        try:
            conn = psycopg2.connect(IPFCdatabase_login)
            cursor = conn.cursor()
        except:
            result = "Unable to connect to the database"
            return result
        else:
            email = request.form['email']
            salt_query = "SELECT salt FROM admin.users WHERE email = %s"
            cursor.execute(salt_query, (email,))
            stored_salt = cursor.fetchone()[0]
            return stored_salt

class GetUserID(Resource):
    def get(self):
        try:
            conn = psycopg2.connect(IPFCdatabase_login)
            cursor = conn.cursor()
        except:
            result = "Unable to connect to the database"
            return result
        else:
            email = request.form['email']
            user_id_query = "SELECT user_id FROM admin.users WHERE email = %s"
            cursor.execute(user_id_query, (email,))
            user_id = cursor.fetchone()[0]
            return user_id


class VerifyLogin(Resource):
    def get(self):
        try:
            conn = psycopg2.connect(IPFCdatabase_login)
            cursor = conn.cursor()
        except:
            result = "Unable to connect to the database"
            return result
        else:
            email = request.form['email']
            trial_key = request.form['key']
            key_query = "SELECT key FROM admin.users WHERE email = %s"
            cursor.execute(key_query, (email,))
            stored_key = cursor.fetchone()[0]
            if trial_key != stored_key:
                conn.close()
                return False
            if trial_key == stored_key:
                conn.close()
                return True
            # if enter wrong three times, wait 5 minutes. only one trial per minute.
            # over 9 times, lock for a day


class VerifySignup(Resource):
    def get(self):
        try:
            conn = psycopg2.connect(IPFCdatabase_login)
            cursor = conn.cursor()
        except:
            result = "Unable to connect to the database"
            return result
        else:
            new_user_id = request.form['new_user_id']
            new_email = request.form['new_email']
            key = request.form['key']
            new_salt = request.form['new_salt']
            pinata_api = request.form['pinata_api']
            pinata_key = request.form['pinata_key']
            email_exists_query = "SELECT EXISTS (SELECT * FROM admin.users WHERE email = %s)"
            cursor.execute(email_exists_query, (new_email,))
            exists = cursor.fetchone()[0]
            if exists:
                conn.close()
                result = "email_exists"
                return result
            else:
                cursor.execute('''INSERT INTO admin.users(user_id, email, key, salt, pinata_api, pinata_key) 
                               VALUES (%s, %s, %s, %s, %s, %s)''',
                               (new_user_id, new_email, key, new_salt, pinata_api, pinata_key))
                conn.commit()
                conn.close()
                result = "success"
                return result


class GetUserCollection(Resource):
    def get(self):
        try:
            conn = psycopg2.connect(IPFCdatabase_login)
            cursor = conn.cursor()
        except:
            result = "Unable to connect to the database"
            return result
        else:
            user_id = request.form['user_id']
            query = "SELECT * FROM public.user_collections WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()
            return result

api.add_resource(GetSalt, '/getsalt')
api.add_resource(GetUserID, '/getuserid')
api.add_resource(VerifyLogin, '/verifylogin')
api.add_resource(VerifySignup, '/verifysignup')
api.add_resource(GetUserCollection, '/getusercollection')

if __name__ == '__main__':
    app.run(debug=True)
