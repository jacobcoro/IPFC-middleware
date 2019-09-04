from flask import Flask, request
from flask_restful import Resource, Api
import psycopg2

app = Flask(__name__)
api = Api(app)

IPFCdatabase_login = """
dbname='IPFCdatabase' 
user='jacob' 
password='5w42bjnscjny8ufy'
host='165.22.144.86'
port='5432'
"""


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


api.add_resource(GetSalt, '/getsalt')
api.add_resource(GetUserID, '/getuserid')
api.add_resource(VerifyLogin, '/verifylogin')

if __name__ == '__main__':
    app.run(debug=True)
