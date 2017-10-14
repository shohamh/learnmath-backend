import datetime
import hashlib
import os
import re
import sqlite3
import uuid

from flask import Flask, jsonify, _app_ctx_stack, request
from flask_cors import CORS, cross_origin

DATABASE = 'db.db'
app = Flask(__name__)
CORS(app)


# ---------------------------------------------------------------------
# Function that prepers the DataBase in order to execute a query.
# ---------------------------------------------------------------------
def get_db():
    db = getattr(_app_ctx_stack.top, '_database', None)
    if db is None:
        db = _app_ctx_stack.top._database = sqlite3.connect(DATABASE)

    db.row_factory = sqlite3.Row
    return db


# -----------------------------------------------
# Function that closes a connection to DataBase.
# -----------------------------------------------
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(_app_ctx_stack.top, '_database', None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------
# Function that convert the result of a query into a dictionary.
# ---------------------------------------------------------------
def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))


# -------------------------------------------------------------------------
# Function that executes a query and returns the result(might be empty).
# -------------------------------------------------------------------------
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


# -----------------------------------------------------------------------------
# Function that checks the validity of an email.
# This function gets an email string as an input and returns a boolean value.
# -----------------------------------------------------------------------------
def checkmail(email):
    EMAIL_REGEX = re.compile(r"\w+[.|\w]\w+@\w+[.]\w+[.|\w+]\w+")
    if not email or not EMAIL_REGEX.match(email):
        return False
    return True


# -----------------------------------------------------------------------------
# Function that checks if an email is unique.
# This function gets an email string as an input,and returns a boolean value.
# -----------------------------------------------------------------------------
def is_unique_email(email):
    cur = query_db('SELECT username FROM users WHERE email=?', (email,))
    if not cur:
        return True
    else:
        return False


# @app.route('/DBcheck')
# @cross_origin()
# def DBcheck():
# res=''
# c=get_db().cursor()
# c.execute('SELECT username FROM users')
# for user in c.fetchall():
#  res=res+' '+user+'\n'
# return res
#


@app.route('/users', methods=["POST", "GET"])
@cross_origin()
def users():
    for user in query_db('SELECT * FROM users'):
        print(user['username'], 'has the id', user['user_id'])


@app.route('/')
@cross_origin()
def homepage():
    return '<html><body><h2 color="green">  ברוכים הבאים לאתר אינטיליגנציה מתמטית </h2></body></html>'


# @app.route('/getuser')

@app.route('/register', methods=["POST", "GET"])
@cross_origin()
# -------------------------------------------------------------------------------------------------
# Function that adds a new user to the system.
# This function returns an object that shows wheter the user succeeded in registration or not.
# -------------------------------------------------------------------------------------------------
def register():
    result = {
        "success": False,
        "error_messages": []
    }

    # try:

    registerdata = request.get_json(force=True)
    username = registerdata["username"] if "username" in registerdata else None
    password = registerdata["password"] if "password" in registerdata else None
    email = registerdata["email"] if "email" in registerdata else None

    salt = os.urandom(64)
    user_id = str(uuid.uuid4())
    registration_date = datetime.datetime.utcnow().isoformat()
    last_login_date = registration_date
    password_hashed = hashlib.pbkdf2_hmac('sha256', password.encode("utf-8"), salt, 100000)
    if not checkmail(email):
        result["error_messages"].append("Email not valid.")
        return jsonify(result)
    if not is_unique_email(email):
        result["error_messages"].append("Email already taken.")
        return jsonify(result)

   # checkUsername = get_db().execute('SELECT * FROM users WHERE username=?',(username,))
    #if checkUsername:
     #   result["error_messages"].append("Username is already taken.")
      #  return jsonify(result)

    #cursor = get_db().execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
    #                          [user_id, username, password_hashed, salt, email, registration_date,
    #                           last_login_date])

    #get_db().commit()
    cursor = query_db('INSERT INTO users VALUES(?,?,?,?,?,?,?)',(user_id,username,password_hashed,salt,email,registration_date,last_login_date))
    if not cursor:
        result["error_messages"].append("Failed to register, the username/email may be taken.")
#        cursor.close()
    else:
        result["success"] = True

    return jsonify(result)


@app.route('/login', methods=["POST", "GET"])
@cross_origin()
# --------------------------------------------------------------------------------
# Function that checks if the username and password are existed in the database.
# This function returns an object that shows wheter the user exist or not.
# --------------------------------------------------------------------------------
def login():
    result = {
        "success": False,
        "session_key":"",
        "error_messages": []
    }
    logindata = request.get_json(force=True)
    username = logindata["username"] if "username" in logindata else None
    password = logindata["password"] if "password" in logindata else None

    salt_rows = query_db('SELECT salt FROM users WHERE username=?', (username,))
    if not salt_rows:
        result["error_messages"].append("Username does not exist.")
        return jsonify(result)
    user_salt = salt_rows[0]["salt"]  # try and catch sqlite3.IntegrityError: UNIQUE constraint failed: users.email

    #a = username.encode("utf-8")
    b = hashlib.pbkdf2_hmac('sha256', password.encode("utf-8"), user_salt, 100000)
    query = query_db('SELECT * FROM users WHERE username=? AND password=?',
                     [username,
                      b])
    if not query:
        result["error_messages"].append("Your username or password were incorrect.")
        return jsonify(result)

    session_key = uuid.uuid1()
    cur = query_db('SELECT last_login FROM sessions WHERE username=?', (username,))
    if cur :
        get_db().execute('DELETE FROM sessions WHERE username=?', [username, ])
        get_db().commit()

    #cursor = get_db().execute('INSERT INTO sessions VALUES(?,?,?,?)',
    #               [username, session_key, datetime.datetime.utcnow().isoformat(),30])
    #get_db().commit()
    #if not cursor:
     #   result["error_messages"].append("Failed to login.Problem with the session key")
      #  cursor.close()
       # result["success"] = False
        #return jsonify(result)

    result["session_key"] = session_key

    result["success"] = True

    return jsonify(result)


@app.route('/question', methods=["POST", "GET"])
def question():
    result = {
        "success": True,
        "error_messages": [],
        "problem": "9x^2+8x+79-3x+11=0"
    }
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)