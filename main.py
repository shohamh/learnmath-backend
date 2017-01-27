import sqlite3

from flask import Flask, jsonify, request, _app_ctx_stack

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


@app.route('/homepage')
def homepage():
    return '<h2 color="green">  ברוכים הבאים לאתר מתמטיקל </h2>'


@app.route('/getuser')
@app.route('/register')
def register():
    registerdata = request.get_json(force=True)
    username = registerdata["username"]
    password = registerdata["password"]
    email = registerdata["email"]
    query = query_db('INSERT INTO users VALUES(?,?,?)', [username, password, email])
    result = {
        "success": True if query else False,
        "error_message": None
    }
    return jsonify(result)


@app.route('/login')
def login():
    logindata = request.get_json(force=True)
    username = logindata["username"]
    password = logindata["password"]
    query = query_db('SELECT * FROM users WHERE username=? AND password=?', [username, password])
    if query is None:
        print('Your username or password were incorrect.')
    else:
        print('Successful login.')
    result = {
        "success": True,
        "error_message": None
    }
    return jsonify(result)

if __name__ == '__main__':
    app.run()
