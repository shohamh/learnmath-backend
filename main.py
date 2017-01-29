import datetime
import hashlib
import os
import re
import sqlite3
import uuid

from flask import Flask, jsonify, _app_ctx_stack, request, g

DATABASE = 'db.db'

app = Flask(__name__)


def get_db():
    db = getattr(_app_ctx_stack.top, '_database', None)
    if db is None:
        db = _app_ctx_stack.top._database = sqlite3.connect(DATABASE)

    db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(_app_ctx_stack.top, '_database', None)
    if db is not None:
        db.close()


def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def checkmail(email):
    EMAIL_REGEX = re.compile(r"'\w+[.|\w]\w+@\w+[.]\w+[.|\w+]\w+'")
    if not EMAIL_REGEX.match(email):
        return False
    return True




@app.route('/')
def homepage():
    return '<h2 color="green">  ברוכים הבאים לאתר מתמטיקל </h2>'


# @app.route('/getuser')

@app.route('/register', methods=["POST"])
def register():
 try:
    registerdata = request.get_json(force=True)
    username = registerdata["username"]
    password = registerdata["password"]
    email = registerdata["email"]
    salt = os.urandom(64)
    user_id = str(uuid.uuid4())
    registration_date = datetime.datetime.utcnow().isoformat()
    last_login_date = registration_date
    password_hashed = hashlib.pbkdf2_hmac('sha256', password.encode("utf-8"), salt, 100000)  # and salted
    if checkmail(email) == True:

        cursor = get_db().execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                                  [user_id, username, password_hashed, salt, email, registration_date, last_login_date])
        g.db.commit()

        if cursor:
            result = {
                "success": True,
                "error_message": None
            }

        else:
            result = {
                "success": False,
                "error_message": "registration failed!"
            }
        cursor.close()
        return jsonify(result)
    else:
        result = {
            "success": False,
            "error_message": "registratiion failed!"
        }
 except:
        result = {
            "success": False,
            "error_message": "registratiion failed!"
        }
 return jsonify(result)



@app.route('/login', methods=["POST", "GET"])
def login():
    logindata = request.get_json(force=True)
    username = logindata["username"]
    password = logindata["password"]
    salt = query_db('SELECT salt FROM users WHERE username=?', (username))
    query = query_db('SELECT * FROM users WHERE username=? AND password=?',
                     (username, hashlib.pbkdf2_hmac('sha256', password, salt, 100000)))
    if query is None:
        print('Your username or password were incorrect.')
        result = {
            "success": False,
            "error_message": 'Your username or password were incorrect.'
        }

    else:
        print('Successful login.')
        result = {
        "success": True,
        "error_message": None
        }
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
