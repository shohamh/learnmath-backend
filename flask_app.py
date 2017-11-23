import datetime
import hashlib
import os
import random
import re
import sqlite3
import ssl
import subprocess
import sys
import uuid

import lxml.etree as ET
import xmltodict
from flask import Flask, jsonify, _app_ctx_stack, request
from flask_cors import CORS, cross_origin

from wolframalpha import wap

apb_exec = "algebra-problem-generator"

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain(certfile="certs/cert.pem", keyfile="certs/key.pem")

wa_server = 'http://api.wolframalpha.com/v2/query'

wa_appid = 'LH259U-2X7QT3WQP4'

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


# -------------------------------------------------------------------------
# Function that executes a query that changes the db and commits (doesn't return anything, TODO: maybe it should?).
# -------------------------------------------------------------------------
def execute_query_db(query, args=()):
    db = get_db()
    db.execute(query, args)
    db.commit()


# -----------------------------------------------------------------------------
# Function that checks the validity of an email.
# This function gets an email string as an input and returns a boolean value.
# -----------------------------------------------------------------------------
def is_email_valid(email):
    email_regex = re.compile(r"\w+[.|\w]\w+@\w+[.]\w+[.|\w+]\w+")
    if not email or not email_regex.match(email):
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


@app.route('/all_users', methods=["POST", "GET"])
@cross_origin()
def all_users():
    result = "<html><body><table border=\"1\">"
    result += "<tr><th>user_id</th><th>username</th><th>password</th><th>salt</th><th>email</th><th>registration_date</th><th>last_login_date</th></tr>"
    user_rows = query_db('SELECT * FROM users')
    for user in user_rows:
        result += "<tr>"
        result += "<td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>".format(
            user["user_id"], user["username"], user["password"], user["salt"], user["email"], user["registration_date"],
            user["last_login_date"])
        result += "</tr>"
    result += "</table></body></html>"
    return result


@app.route('/all_sessions', methods=["POST", "GET"])
@cross_origin()
def all_sessions():
    result = "<html><body><table border=\"1\">"
    result += "<tr><th>user_id</th><th>session_key</th><th>last_login</th><th>max_session_length</th></tr>"
    session_rows = query_db('SELECT * FROM sessions')
    for session in session_rows:
        result += "<tr>"
        result += "<td>{}</td><td>{}</td><td>{}</td><td>{}</td>".format(session["user_id"], session["session_key"],
                                                                        session["last_login"],
                                                                        session["max_session_length"])
        result += "</tr>"
    result += "</table></body></html>"
    return result


@app.route('/all_student_solutions', methods=["POST", "GET"])
@cross_origin()
def all_student_solutions():
    result = "<html><body><table border=\"1\">"
    result += "<tr><th>user_id</th><th>question_id</th><th>solution_time</th><th>answer</th><th>correct_answer</th><th>datetime</th></tr>"
    student_solutions_rows = query_db('SELECT * FROM student_solutions')
    for student_solution in student_solutions_rows:
        result += "<tr>"
        result += "<td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>".format(
            student_solution["user_id"], student_solution["question_id"], student_solution["solution_time"],
            student_solution["answer"], student_solution["correct_answer"], student_solution["datetime"])
        result += "</tr>"
    result += "</table></body></html>"
    return result


@app.route('/')
@cross_origin()
def homepage():
    return '<html><body><h2 color="green">LearnMath backend server</h2></body></html>'


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

    data = request.get_json(force=True)
    username, password, email, role = data.get("username"), data.get("password"), data.get("email"), data.get("role")
    if role not in ["Student", "Teacher"]:
        role = "Student"
    salt = os.urandom(64)
    user_id = str(uuid.uuid4())
    registration_date = datetime.datetime.utcnow().isoformat()
    last_login_date = registration_date
    hashed_salted_password = hashlib.pbkdf2_hmac('sha256', password.encode("utf-8"), salt, 100000)

    if not is_email_valid(email):
        result["error_messages"].append("Email not valid.")
        return jsonify(result)

    try:
        execute_query_db('INSERT INTO users VALUES(?,?,?,?,?,?,?,?)',
                         (user_id, username, email, hashed_salted_password, salt, role, registration_date,
                          last_login_date))
    except sqlite3.Error as e:
        if e.args[0] == "UNIQUE constraint failed: users.email":
            result["error_messages"].append("Email already taken.")

        elif e.args[0] == "UNIQUE constraint failed: users.username":
            result["error_messages"].append("Username already taken.")

        else:
            result["error_messages"].append(e.args[0])

        return jsonify(result)

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
        "user": None,
        "error_messages": []
    }
    data = request.get_json(force=True)
    username, password = data.get("username"), data.get("password")

    salt_rows = query_db('SELECT salt FROM users WHERE username=?', (username,))
    if not salt_rows:
        result["error_messages"].append("Username does not exist.")
        return jsonify(result)
    user_salt = salt_rows[0]["salt"]
    hashed_salted_password = hashlib.pbkdf2_hmac('sha256', password.encode("utf-8"), user_salt, 100000)

    row = query_db('SELECT * FROM users WHERE username=? AND password=?', [username, hashed_salted_password], one=True)
    if not row:
        result["error_messages"].append("Your username/password were incorrect.")
        return jsonify(result)

    user_id = row["user_id"]
    # removing last session token
    execute_query_db("DELETE FROM sessions WHERE user_id=?", [user_id, ])

    new_session_key = str(uuid.uuid1())

    try:
        execute_query_db('INSERT INTO sessions VALUES(?,?,?,?)',
                         (user_id, new_session_key, datetime.datetime.utcnow().isoformat(), 30))
    except sqlite3.Error as e:
        result["error_messages"].append(e.args[0])
        return jsonify(result)

    result["user"] = {
        "username": row["username"],
        "role": row["role"],
        "email": row["email"],
        "token": new_session_key
    }
    result["success"] = True

    return jsonify(result)


@app.route('/student_solution', methods=["GET", "POST"])
@cross_origin()
# -----------------------------------------------------------------------------------------
# Function that saves the student's answer for a question,including the time and the date.
# -----------------------------------------------------------------------------------------
def student_solution():
    result = {
        "success": False,
        "error_messages": []
    }

    data = request.get_json(force=True)
    user_id, question_id, answer, correct_answer, solution_time = data.get("user_id"), data.get("question_id"), \
                                                                  data.get("answer"), data.get("correct_answer"), \
                                                                  data.get("solution_time")
    date_time = datetime.datetime.utcnow().isoformat()

    try:
        execute_query_db('INSERT INTO student_solutions VALUES(?,?,?,?,?,?)',
                         (user_id, question_id, solution_time, answer, correct_answer, date_time))
    except sqlite3.Error as e:
        # TO DO: probably not good with new primary key tuple
        if e.args[0] == "UNIQUE constraint failed: student_solutions.user_id, student_solutions.question_id":
            result["error_messages"].append("The user already had this question.")

        else:
            result["error_messages"].append(e.args[0])

        return jsonify(result)

    result["success"] = True

    return jsonify(result)


@app.route('/question', methods=["POST", "GET"])
@cross_origin()
# ----------------------------------------------------------------------------
# Function that returns a question for the user(student).
# ----------------------------------------------------------------------------
def question():
    data = request.get_json(force=True)

    # running f# executable
    out = ""

    source_problem_mml = "<math xmlns='http://www.w3.org/1998/Math/MathML'><mn>0</mn></math>"

    rows = query_db('SELECT * FROM question_templates')

    source_problem_mml = rows[random.randrange(0, len(rows))]["template_mathml"]

    similar_problem_mathml = source_problem_mml
    try:
        similar_problem_mathml = subprocess.check_output(
            ["dotnet", "run", "--project", apb_exec, source_problem_mml]).decode('utf-8')
        if not similar_problem_mathml.strip():
            similar_problem_mathml = source_problem_mml
        print(similar_problem_mathml)
    except subprocess.CalledProcessError as e:
        print("algebra-problem-generator failed. " + str(e), file=sys.stderr)

    latex = ""
    try:
        mathml = ET.fromstring(similar_problem_mathml)
        xslt = ET.parse("web-xslt/pmml2tex/mmltex.xsl")
        transform = ET.XSLT(xslt)
        latex_tree = transform(mathml)
        latex = str(latex_tree).replace('$', '').strip()
        print(latex)
    except ET.XSLTParseError as e:
        print(e)
        print(similar_problem_mathml)
        print(latex)

    problem = latex
    result = {
        "success": True,
        "error_messages": [],
        "problem": problem
    }
    return jsonify(result)


@app.route('/add_question', methods=["POST", "GET"])
@cross_origin()
# -----------------------------------------------------------------------------------
# Function that gives the teacher permission to add a question to the database,
# so the system will generate exercises similarly to this specific question.
# -----------------------------------------------------------------------------------
def add_question():
    result = {
        "success": True,
        "error_messages": []
    }
    data = request.get_json(force=True)
    question = data.get("question")
    question_mathml = question.get("mathml") if question is not None else None
    # question_subject = question.get("subject") if question is not None else None
    user = data.get("user")
    if not user:
        result["error_messages"].append("No user given, cannot validate creator is a teacher.")
        return jsonify(result)

    row = query_db('SELECT * FROM users WHERE username=?', [user.get("username")], one=True)
    if not row:
        result["error_messages"].append("No such user in database.")
        return jsonify(result)
    if row["role"] != "Teacher":
        result["error_messages"].append("Permission error, user is not a teacher.")
        return jsonify(result)
    user_id = row["user_id"]

    template_id = str(uuid.uuid4())
    date_time = datetime.datetime.utcnow().isoformat()

    try:
        execute_query_db('INSERT INTO question_templates VALUES(?,?,?,?)',
                         (template_id, question_mathml, user_id, date_time))
    except sqlite3.Error as e:
        result["error_messages"].append(e.args[0])
        return jsonify(result)

    result["success"] = True

    return jsonify(result)


def dicttoxml(dict):
    res = xmltodict.unparse(dict)
    xml_prefix = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    if xml_prefix in res:
        res = res[len(xml_prefix):]
    return res


def get_wolfram_solutions(input):
    waeo = wap.WolframAlphaEngine(wa_appid, wa_server)
    query = waeo.CreateQuery(input)
    res = waeo.PerformQuery(query)
    waeqr = wap.WolframAlphaQueryResult(res)
    jsonresult = waeqr.JsonResult()

    wa_solutions = []

    for pod in jsonresult["pod"]:
        if "solution" in pod["title"].lower():
            if isinstance(pod["subpod"], dict):
                subpod = pod["subpod"]
                try:
                    actual_answer = subpod["mathml"]["math"]["mtable"]["mtr"]["mtd"]
                except KeyError:
                    actual_answer = subpod["mathml"]["math"]
                mathml = dicttoxml(actual_answer)
                wa_solutions.append(mathml)
            else:  # list
                for subpod in pod["subpod"]:
                    try:
                        actual_answer = subpod["mathml"]["math"]["mtable"]["mtr"]["mtd"]
                    except KeyError:
                        actual_answer = subpod["mathml"]["math"]
                    mathml = dicttoxml(actual_answer)
                    wa_solutions.append(mathml)
    return wa_solutions


def check_solutions_equality(solution1, solution2):
    try:
        out = subprocess.check_output(
            ["dotnet", "run", "--project", apb_exec, "--checkequality", solution1, solution2]).decode('utf-8')
        print(out)
        bool = out.strip()[:-5].strip()
        if bool == "true":
            return True
        elif bool == "false":
            return False
        else:
            return False

    except subprocess.CalledProcessError as e:
        print("algebra-problem-generator failed. " + str(e), file=sys.stderr)


@app.route("/check_solution", methods=["POST"])
@cross_origin()
# ---------------------------------------------------------------------------------------------
# This function checks the student answer for the question.
# This function gets the question,the subject of the question and the students solutions.
# ---------------------------------------------------------------------------------------------
def check_solution():
    data = request.get_json(force=True)

    student_solutions = data.get("solutions")
    question = data.get("question")  # TODO: INSECURE FIX LATER, make question come from server&session
    if isinstance(student_solutions, str):
        student_solutions = [student_solutions]

    result = {
        "success": True,
        "error_messages": [],
        "correct": False

    }

    wa_solutions = get_wolfram_solutions(question)

    input = "<math>"
    for i, sol in enumerate(wa_solutions + student_solutions):
        if isinstance(sol, bytes):
            sol = sol.decode('utf-8')
        input += sol
        if i != len(wa_solutions + student_solutions) - 1:
            input += "<mo>,</mo>"
    input += "</math>"

    wa_verify_solutions = get_wolfram_solutions(input)

    # it means the student didnt fuck up the expression (taut hishuv), but might not have finished solving yet (not checking if their solution is of form: x=3)
    if wa_verify_solutions != wa_solutions:
        result["correct"] = False

    if len(student_solutions) != len(wa_solutions):
        result["error_messages"].append("There are " + ("more" if len(wa_solutions) > len(
            student_solutions) else "less") + "solutions to the problem than what you said.")  # TODO: add a "tips" key where to put different tips like this
        result["correct"] = False
    else:
        amount_of_correct_solutions = 0
        for wa_sol in wa_solutions:
            for stu_sol in student_solutions:
                if check_solutions_equality(wa_sol, stu_sol):
                    amount_of_correct_solutions += 1
        if amount_of_correct_solutions == len(wa_solutions):
            result["correct"] = True

    print("Question: " + question)
    print("Wolfram solutions for question: " + str(wa_solutions))
    print("Student solutions: " + str(student_solutions))
    print("Wolfram comparison of solutions: " + str(wa_verify_solutions))

    return jsonify(result)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True, ssl_context=context)
