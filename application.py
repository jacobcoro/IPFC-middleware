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


api.add_resource(GetSalt, '/')

if __name__ == '__main__':
    app.run(debug=True)
