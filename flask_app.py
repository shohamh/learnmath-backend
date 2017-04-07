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
    EMAIL_REGEX = re.compile(r"\w+[.|\w]\w+@\w+[.]\w+[.|\w+]\w+")
    if not EMAIL_REGEX.match(email):
        return False
    return True
def is_unique_email(email):
 cur=query_db('SELECT salt FROM users WHERE email=?', (email,))
 if len(cur)>0:
  return False
 else:
      return True

# @app.route('/DBcheck')
# @cross_origin()
# def DBcheck():
# res=''
# c=get_db().cursor()
# c.execute('SELECT username FROM users')
# for user in c.fetchall():
#  res=res+' '+user+'\n'
# return res




@app.route('/')
@cross_origin()
def homepage():
    return '<h2 color="green">  ברוכים הבאים לאתר אינטיליגציה מתמטית </h2>'


# @app.route('/getuser')

@app.route('/register', methods=["POST", "GET"])
@cross_origin()
def register():
    result = {
        "success": False,
        "error_messages": []
    }

    # try:

    registerdata = request.get_json(force=True)
    username = registerdata["username"]
    password = registerdata["password"]
    email = registerdata["email"]
    salt = os.urandom(64)
    user_id = str(uuid.uuid4())
    registration_date = datetime.datetime.utcnow().isoformat()
    last_login_date = registration_date
    password_hashed = hashlib.pbkdf2_hmac('sha256', password.encode("utf-8"), salt, 100000)  # and salted
    if checkmail(email) and is_unique_email(email):

        cursor = get_db().execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                                  [user_id, username, password_hashed, salt, email, registration_date,
                                   last_login_date])

        get_db().commit()

        if cursor is None:
         result["error_messages"].append("Failed to register, the username/email may be taken.")
         cursor.close()
        else:
            result["success"] = True

    else:
        result["error_messages"].append("Email not valid.")


    return jsonify(result)


@app.route('/login', methods=["POST", "GET"])
@cross_origin()
def login():
    result = {
        "success": False,
        "error_messages": []
    }
    logindata = request.get_json(force=True)
    username = logindata["username"]
    password = logindata["password"]
    salt_rows = query_db('SELECT salt FROM users WHERE username=?', (username, ))
    if salt_rows and len(salt_rows)>0:
        salt = salt_rows[0]['salt'] #try and catch sqlite3.IntegrityError: UNIQUE constraint failed: users.email
        query = query_db('SELECT * FROM users WHERE username=? AND password=?',
                         [username.encode("utf_8"), hashlib.pbkdf2_hmac('sha256', password.encode("utf_8"), salt, 100000)])
        if query is None:

            result["error_messages"].append("Your username or password were incorrect.")



        else:

            session_key = uuid.uuid1()
            get_db().execute('DELETE from sessions where username=?',[username,])
            get_db().commit()
            get_db().execute('INSERT into sessions values(?,?,?,?)',[username,session_key,datetime.datetime.utcnow().isoformat(),30])
            get_db().commit()
            result["session_key"] = session_key


            result["success"] = True
    else:
        result["error_messages"].append("Username does not exist.")

    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)
