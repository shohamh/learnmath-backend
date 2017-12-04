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


# -------------------------------------------------------------------------------------------------------------------
# Function that prepers the DataBase in order to execute a query.
# -------------------------------------------------------------------------------------------------------------------
def get_db():
    db = getattr(_app_ctx_stack.top, '_database', None)
    if db is None:
        db = _app_ctx_stack.top._database = sqlite3.connect(DATABASE)

    db.row_factory = sqlite3.Row
    return db


# -------------------------------------------------------------------------------------------------------------------
# Function that closes a connection to DataBase.
# -------------------------------------------------------------------------------------------------------------------
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(_app_ctx_stack.top, '_database', None)
    if db is not None:
        db.close()


# -------------------------------------------------------------------------------------------------------------------
# Function that convert the result of a query into a dictionary.
# -------------------------------------------------------------------------------------------------------------------
def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))


# -------------------------------------------------------------------------------------------------------------------
# Function that executes a query and returns the result(might be empty).
# -------------------------------------------------------------------------------------------------------------------
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


# -----------------------------------------------------------------------------------------------------------------
# Function that executes a query that changes the db and commits (doesn't return anything, TODO: maybe it should?).
# -----------------------------------------------------------------------------------------------------------------
def execute_query_db(query, args=()):
    db = get_db()
    db.execute(query, args)
    db.commit()


# --------------------------------------------------------------------------------------------------------------------
# Function that checks the validity of an email.
# This function gets an email string as an input and returns a boolean value.
# -------------------------------------------------------------------------------------------------------------------
def is_email_valid(email):
    email_regex = re.compile(r"\w+[.|\w]\w+@\w+[.]\w+[.|\w+]\w+")
    if not email or not email_regex.match(email):
        return False
    return True


# --------------------------------------------------------------------------------------------------------------------
# Function that checks if an email is unique.
# This function gets an email string as an input,and returns a boolean value.
# -------------------------------------------------------------------------------------------------------------------
def is_unique_email(email):
    cur = query_db('SELECT username FROM users WHERE email=?', (email,))
    if not cur:
        return True
    else:
        return False


@app.route('/all_users', methods=["POST", "GET"])
@cross_origin()
# ---------------------------------------------------------------------------------------------------------------------
# Function that shows all users
# --------------------------------------------------------------------------------------------------------------------
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
# --------------------------------------------------------------------------------------------------------------------
# Function that shows all user sessions.
# --------------------------------------------------------------------------------------------------------------------
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
# --------------------------------------------------------------------------------------------------------------------
# Function that shows all of students solutions.
# --------------------------------------------------------------------------------------------------------------------
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
# -------------------------------------------------------------------------------------------------------------------
# Server's home page.
# -------------------------------------------------------------------------------------------------------------------
def homepage():
    return '<html><body><h2 color="green">LearnMath backend server</h2></body></html>'


@app.route('/register', methods=["POST", "GET"])
@cross_origin()
# ------------------------------------------------------------------------------------------------------------------
# Function that adds a new user to the system.
# This function returns an object that shows wheter the user succeeded in registration or not.
# ------------------------------------------------------------------------------------------------------------------
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
# ------------------------------------------------------------------------------------------------------------------
# Function that checks if the username and password are existed in the database.
# This function returns an object that shows wheter the user exist or not.
# ------------------------------------------------------------------------------------------------------------------
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
# ------------------------------------------------------------------------------------------------------------------
# Function that saves the student's answer for a question,including the time and the date.
# -------------------------------------------------------------------------------------------------------------------
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
# -------------------------------------------------------------------------------------------------------------------
# Function that returns a question for the user(student).
# -------------------------------------------------------------------------------------------------------------------
def question():
    result = {
        "success": False,
        "error_messages": [],
        "problem": ""
    }
    data = request.get_json(force=True)
    sid = data.get("sid")
    user = user_from_sid(sid)

    if not sid:
        result["error_messages"].append("No session id given.")
        return jsonify(result)
    if not user:
        result["error_messages"].append("Invalid session_id.")
        return jsonify(result)

    # running f# executable
    out = ""

    source_problem_mml = "<math xmlns='http://www.w3.org/1998/Math/MathML'><mn>0</mn></math>"

    rows = query_db('SELECT * FROM question_templates')
    #
    # template_id = rows[0]["template_id"]
    # check = query_db('SELECT subject_id FROM template_in_subject WHERE template_id=?'(template_id, ))
    # if not check:
    #     result["error_messages"].append("template without a subject..")
    #     return jsonify(result)
    # subject_id = check[0]["subject_id"]
    #
    # is_first_time_in_subject = False
    # first = query_db(
    #     'SELECT * FROM students_feedback_in_subject WHERE student_id=? AND subject_id=?'(user_id, subject_id))
    # if not first:
    #     is_first_time_in_subject = True
    #     execute_query_db('INSERT INTO students_feedback_in_subject VALUES(?,?,?,?,?)'(user_id, subject_id, 1, 0, 0))
    random_index = random.randrange(0, len(rows))
    source_problem_mml = rows[random_index]["template_mathml"]
    template_id = rows[random_index]["template_id"]

    subject_ids_row = query_db('SELECT subject_id FROM template_in_subject WHERE template_id=?',
                               [template_id])
    # if not subject_ids_row:
    #     #result["error_messages"].append("No subjects for template.")
    #     return jsonify(result)
    subject_ids = [x["subject_id"] for x in subject_ids_row]
    subjects_row = query_db(
        'SELECT * FROM subjects WHERE subject_id IN ({})'.format(','.join('?' * len(subject_ids))), subject_ids)
    subjects = [x["subject_name"] for x in subjects_row]

    similar_problem_mathml = source_problem_mml
    try:
        similar_problem_mathml = subprocess.check_output(
            ["dotnet", "run", "--project", apb_exec, "--generatesimilarterm", source_problem_mml]).decode('utf-8')
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

    result["problem"] = problem
    result["subjects"] = subjects
    result["success"] = True
    # if is_first_time_in_subject == False:
    #     execute_query_db(
    #         'UPDATE students_feedback_in_subject SET number_of_questions=number_of_questions+1 WHERE student_id=? AND subject_id=?',
    #         (user_id, subject_id))

    return jsonify(result)


@app.route('/add_question', methods=["POST", "GET"])
@cross_origin()
# ----------------------------------------------------------------------------------------------------------------
# This function adds a question to the templates stock.
# ----------------------------------------------------------------------------------------------------------------
def add_question():
    result = {
        "success": False,
        "error_messages": []
    }
    data = request.get_json(force=True)
    question = data.get("question")
    question_mathml = question.get("mathml") if question is not None else None
    subject_names = data.get("subjects") if question is not None else None

    sid = data.get("sid")
    user = user_from_sid(sid)

    if not sid:
        result["error_messages"].append("No session id given.")
        return jsonify(result)
    if not user:
        result["error_messages"].append("Invalid session_id.")
        return jsonify(result)

    if user["role"] != "Teacher":
        result["error_messages"].append("Permission error, user is not a teacher.")
        return jsonify(result)

    user_id = user["user_id"]

    template_id = str(uuid.uuid4())
    date_time = datetime.datetime.utcnow().isoformat()
    try:
        execute_query_db('INSERT INTO question_templates VALUES(?,?,?,?)',
                         (template_id, question_mathml, user_id, date_time))

        for subject_name in subject_names:
            row = query_db('SELECT subject_id FROM subjects WHERE subject_name=?', [subject_name], one=True)
            if not row:
                result["error_messages"].append("No such subject exists.")
                return jsonify(result)
            subject_id = row["subject_id"]
            execute_query_db('INSERT INTO template_in_subject VALUES (?,?)', [template_id, subject_id])
    except sqlite3.Error as e:
        result["error_messages"].append(e.args[0])
        return jsonify(result)

    result["success"] = True

    return jsonify(result)


# ----------------------------------------------------------------------
# Inner function that converts dictionary representation to xml format.
# ----------------------------------------------------------------------

def dicttoxml(dict):
    res = xmltodict.unparse(dict)
    xml_prefix = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    if xml_prefix in res:
        res = res[len(xml_prefix):]
    return res


# --------------------------------------------------------------
# Inner function that returns solution/s for a question.
# --------------------------------------------------------------

def get_wolfram_solutions(input, mathml=True, rerun_mathml=True):
    waeo = wap.WolframAlphaEngine(wa_appid, wa_server)
    query = waeo.CreateQuery(input)
    res = waeo.PerformQuery(query, mathml=mathml)
    waeqr = wap.WolframAlphaQueryResult(res)
    jsonresult = waeqr.JsonResult()

    wa_solutions = []
    solution_pod_found = False
    for pod in jsonresult["pod"]:
        if "solution" in pod["title"].lower():
            solution_pod_found = True
            if isinstance(pod["subpod"], dict):
                subpod = pod["subpod"]
                try:
                    actual_answer = subpod["mathml"]["math"]["mtable"]["mtr"]["mtd"]
                except KeyError:
                    actual_answer = subpod["mathml"]["math"]
                try:
                    mathml = dicttoxml(actual_answer)
                    wa_solutions.append(mathml)
                except ValueError:
                    if ("no solution" in x for x in actual_answer["mrow"]["mtext"]):
                        pass
                    else:
                        print("Malformed answer from Wolfram|Alpha we don't know how to handle", file=sys.stderr)

            else:  # list
                for subpod in pod["subpod"]:
                    try:
                        actual_answer = subpod["mathml"]["math"]["mtable"]["mtr"]["mtd"]
                    except KeyError:
                        actual_answer = subpod["mathml"]["math"]
                    try:
                        mathml = dicttoxml(actual_answer)
                        wa_solutions.append(mathml)
                    except ValueError:
                        if ("no solution" in x for x in actual_answer["mrow"]["mtext"]):
                            pass
                        else:
                            print("Malformed answer from Wolfram|Alpha we don't know how to handle", file=sys.stderr)
    if not solution_pod_found:
        for pod in jsonresult["pod"]:
            if "result" in pod["title"].lower():
                if isinstance(pod["subpod"], dict):
                    subpod = pod["subpod"]
                    try:
                        actual_answer = subpod["mathml"]["math"]["mtable"]["mtr"]["mtd"]
                    except KeyError:
                        actual_answer = subpod["mathml"]["math"]
                    try:
                        mathml = dicttoxml(actual_answer)
                        wa_solutions += get_wolfram_solutions(mathml)
                    except ValueError:
                        if ("no solution" in x for x in actual_answer["mrow"]["mtext"]):
                            pass
                        else:
                            print("Malformed answer from Wolfram|Alpha we don't know how to handle", file=sys.stderr)
                else:  # list
                    for subpod in pod["subpod"]:
                        try:
                            actual_answer = subpod["mathml"]["math"]["mtable"]["mtr"]["mtd"]
                        except KeyError:
                            actual_answer = subpod["mathml"]["math"]
                        try:
                            mathml = dicttoxml(actual_answer)
                            wa_solutions += get_wolfram_solutions(mathml)
                        except ValueError:
                            if ("no solution" in x for x in actual_answer["mrow"]["mtext"]):
                                pass
                            else:
                                print("Malformed answer from Wolfram|Alpha we don't know how to handle",
                                      file=sys.stderr)
    return wa_solutions


# --------------------------------------------------------------------------------------------------------------------
# Inner function that checks if student's solution is correct or not.
# --------------------------------------------------------------------------------------------------------------------
def check_solutions_equality(solution1, solution2):
    try:
        out = subprocess.check_output(
            ["dotnet", "run", "--project", apb_exec, "--checkequality", solution1, solution2]).decode('utf-8')
        print(out)
        bool = out.strip()[-5:].strip()
        if bool == "true":
            return True
        elif bool == "false":
            return False
        else:
            return False

    except subprocess.CalledProcessError as e:
        print("algebra-problem-generator failed. " + str(e), file=sys.stderr)


# ------------------------------------------------------------------------------------------------------------------
# Inner function that checks if student's solution is in final form like x=number.
# -------------------------------------------------------------------------------------------------------------------
def is_final_answer_form(answer):
    try:
        out = subprocess.check_output(
            ["dotnet", "run", "--project", apb_exec, "--isfinalanswerform", answer]).decode('utf-8')
        print(out)
        bool = out.strip()[-5:].strip()
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
# ----------------------------------------------------------------------------------------------------------------------
# This function checks the student answer for the question.
# This function gets the question,the subject of the question and the students solutions.
# ----------------------------------------------------------------------------------------------------------------------
def check_solution():
    result = {
        "success": True,
        "error_messages": [],
        "correct": False

    }
    data = request.get_json(force=True)
    sid = data.get("sid")
    user = user_from_sid(sid)

    if not sid:
        result["error_messages"].append("No session id given.")
        return jsonify(result)
    if not user:
        result["error_messages"].append("Invalid session_id.")
        return jsonify(result)

    student_id = user["user_id"]

    student_solutions = data.get("solutions")
    question = data.get("question")  # TODO: INSECURE FIX LATER, make question come from server&session
    subject_names = data.get("subjects")
    if isinstance(student_solutions, str):
        student_solutions = [student_solutions]

    # TODO: [0] is wrong?
    if not is_final_answer_form(student_solutions[0]):
        result["correct"] = False
        result["error_messages"].append("Looks like you haven't finished solving the problem, keep at it!")
        return jsonify(result)

    wa_solutions = get_wolfram_solutions(question)

    input = "<math xmlns='http://www.w3.org/1998/Math/MathML'>"
    for i, sol in enumerate(wa_solutions + student_solutions):
        if isinstance(sol, bytes):
            sol = sol.decode('utf-8')
        input += sol
        if i != len(wa_solutions + student_solutions) - 1:
            input += "<mo>,</mo>"
    input += "</math>"

    wa_verify_solutions = get_wolfram_solutions(input)

    if wa_verify_solutions == wa_solutions:
        result["correct"] = True

    # if len(student_solutions) != len(wa_solutions):
    #     result["error_messages"].append("There are " + ("more" if len(wa_solutions) > len(
    #         student_solutions) else "less") + "solutions to the problem than what you said.")  # TODO: add a "tips" key where to put different tips like this
    #     result["correct"] = False
    # else:
    #     amount_of_correct_solutions = 0
    #     for wa_sol in wa_solutions:
    #         wa_sol = "<math xmlns='http://www.w3.org/1998/Math/MathML'>" + wa_sol + "</math>"
    #         for stu_sol in student_solutions:
    #             if check_solutions_equality(wa_sol, stu_sol):
    #                 amount_of_correct_solutions += 1
    #     if amount_of_correct_solutions == len(wa_solutions):
    #         result["correct"] = True

    print("Question: " + question)
    print("Wolfram solutions for question: " + str(wa_solutions))
    print("Student solutions: " + str(student_solutions))
    print("Wolfram comparison of solutions: " + str(wa_verify_solutions))
    # subject_ids_row = query_db(
    #     'SELECT subject_id FROM subjects WHERE subject_name IN ({})'.format(','.join('?' * len(subject_names))),
    #     subject_names)
    # if not subject_ids_row:
    #     result["error_messages"].append("Curriculum doesn't exist or doesn't have any subjects yet.")
    #     return jsonify(result)
    # subject_ids = [x["subject_id"] for x in subject_ids_row]
    #
    # for subject_id in subject_ids:
    #     row = query_db('SELECT * FROM students_feedback_in_subject WHERE student_id=? AND subject_id=?',
    #                    [student_id, subject_id])
    #
    #     if not row:
    #         try:
    #             execute_query_db("INSERT INTO students_feedback_in_subject VALUES (?,?,?,?,?)",
    #                              [student_id, subject_id, 1, 1 if result["correct"] else 0,
    #                               0 if result["correct"] else 1])
    #         except sqlite3.Error as e:
    #             result["error_messages"].append(e.args[0])
    #             return jsonify(result)
    #     else:
    #         try:
    #             execute_query_db(
    #                 'UPDATE students_feedback_in_subject SET {0}={0}+1 WHERE student_id=? AND subject_id=?'.format(
    #                     "number_of_correct_solutions" if result["correct"] else "number_of_wrong_solutions"),
    #                 [student_id, subject_id])
    #         except sqlite3.Error as e:
    #             result["error_messages"].append(e.args[0])
    #             return jsonify(result)
    template_id = ""
    solution_time = 100
    step_by_step_data = ""
    mistake_type = None
    mistake_step_number = None
    import datetime
    datetime = datetime.datetime.utcnow().isoformat()
    try:
        execute_query_db("INSERT INTO student_solutions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                         [student_id, template_id, question, solution_time, str(student_solutions), str(wa_solutions),
                          int(result["correct"]), step_by_step_data, mistake_type, mistake_step_number, datetime])
    except sqlite3.Error as e:
        result["error_messages"].append(e.args[0])
        return jsonify(result)

    return jsonify(result)


@app.route("/get_feedback", methods=["GET", "POST"])
@cross_origin()
# ------------------------------------------------------------------------------------------------------------------------
# This function returns number of questions that were given for the student,number of mistakes,number of correct answers
# ------------------------------------------------------------------------------------------------------------------------
def get_feedback():
    result = {
        "success": False,
        "student": None,
        "error_messages": []
    }

    data = request.get_json(force=True)

    student_name = data.get("student_name")
    subject_name = data.get("subject_name")

    subject_id_row = query_db('SELECT subject_id FROM subjects WHERE subject_name=?', (subject_name,), one=True)

    if not subject_id_row:
        result["error_messages"].append("This subject does not exist in the system")
        result["success"] = False
        return jsonify(result)
    subject_id = subject_id_row["subject_id"]

    student_id_row = query_db('SELECT user_id FROM users WHERE username=?', (student_name,), one=True)

    if not student_id_row:
        result["success"] = False
        result["error_messages"].append("Student name does not exist...")
        return jsonify(result)

    student_id = student_id_row["user_id"]

    row = query_db(
        'SELECT student_id,subject_name,sf.number_of_correct_solutions,sf.number_of_questions,sf.number_of_wrong_solutions FROM users,students_feedback_in_subject as sf,subjects  WHERE users.user_id=sf.student_id AND subjects.subject_id=? AND sf.subject_id=? AND student_id=?',
        (subject_id, subject_id, student_id), one=True)
    if not row:
        result["error_messages"].append("The student didn't solve any question from this subject.")
        result["success"] = False
        return jsonify(result)

    result["feedback"] = {
        "student_id": row["student_id"],
        "student_name": student_name,
        "subject_name": row["subject_name"],
        "number_of_questions": str(row["number_of_questions"]),
        "number_of_correct_answers": str(row["number_of_correct_solutions"]),
        "number_of_wrong_answers": str(row["number_of_wrong_solutions"])

    }
    result["success"] = True
    return jsonify(result)


# --------------------------------------------------------------------------------------------------------------------
# Inner function that gets as a parameter session id and returns all user properties.
# --------------------------------------------------------------------------------------------------------------------
def user_from_sid(sid):
    row = query_db('SELECT user_id FROM sessions WHERE session_key=?', [sid], one=True)
    if not row:
        return None
    user_id = row["user_id"]
    row = query_db('SELECT * FROM users WHERE user_id=?', [user_id], one=True)
    if not row:
        return None
    return row


@app.route('/add_subject', methods=["POST", "GET"])
@cross_origin()
# -------------------------------------------------------------------------------------------------------------------
# Function that adds a subject to subjects table.
# -------------------------------------------------------------------------------------------------------------------
def add_subject():
    result = {
        "success": False,
        "error_messages": []
    }
    data = request.get_json(force=True)
    subject_name = data.get("name")
    sid = data.get("sid")
    user = user_from_sid(sid)

    if not sid:
        result["error_messages"].append("No session id given.")
        return jsonify(result)
    if not user:
        result["error_messages"].append("Invalid session_id.")
        return jsonify(result)

    if user["role"] != "Teacher":
        result["error_messages"].append("Permission error, user is not a teacher.")
        return jsonify(result)

    subject_id = str(uuid.uuid4())

    try:
        execute_query_db('INSERT INTO subjects VALUES(?,?)', (subject_id, subject_name))
    except sqlite3.Error as e:
        result["error_messages"].append(e.args[0])
        return jsonify(result)

    result["success"] = True

    return jsonify(result)


@app.route('/add_curriculum', methods=["POST", "GET"])
@cross_origin()
# -------------------------------------------------------------------------------------------------------------------
# Function that adds a new curriculum to curriculums table.
# -------------------------------------------------------------------------------------------------------------------
def add_curriculum():
    result = {
        "success": False,
        "error_messages": []
    }
    data = request.get_json(force=True)
    curriculum_name = data.get("name")
    curriculum_description = data.get("description")
    sid = data.get("sid")
    user = user_from_sid(sid)

    if not sid:
        result["error_messages"].append("No session id given.")
        return jsonify(result)
    if not user:
        result["error_messages"].append("Invalid session_id.")
        return jsonify(result)

    if user["role"] != "Teacher":
        result["error_messages"].append("Permission error, user is not a teacher.")
        return jsonify(result)

    curriculum_id = str(uuid.uuid4())

    try:
        execute_query_db('INSERT INTO curriculums VALUES(?,?,?)',
                         (curriculum_id, curriculum_name, curriculum_description))
    except sqlite3.Error as e:
        result["error_messages"].append(e.args[0])
        return jsonify(result)

    result["success"] = True

    return jsonify(result)


@app.route('/add_subject_to_curriculum', methods=["POST", "GET"])
@cross_origin()
# -------------------------------------------------------------------------------------------------------------------
# Function that adds a subject to a specific curriculum.
# -------------------------------------------------------------------------------------------------------------------
def add_subject_to_curriculum():
    result = {
        "success": False,
        "error_messages": []
    }
    data = request.get_json(force=True)
    curriculum_name = data.get("curriculum_name")
    subject_name = data.get("subject_name")

    sid = data.get("sid")
    user = user_from_sid(sid)

    if not sid:
        result["error_messages"].append("No session id given.")
        return jsonify(result)
    if not user:
        result["error_messages"].append("Invalid session_id.")
        return jsonify(result)

    if user["role"] != "Teacher":
        result["error_messages"].append("Permission error, user is not a teacher.")
        return jsonify(result)

    row = query_db('SELECT curriculum_id FROM curriculums WHERE name=?', [curriculum_name], one=True)
    if not row:
        result["error_messages"].append("No such curriculum exists.")
        return jsonify(result)
    curriculum_id = row["curriculum_id"]

    row = query_db('SELECT subject_id FROM subjects WHERE subject_name=?', [subject_name], one=True)
    if not row:
        result["error_messages"].append("No such subject exists.")
        return jsonify(result)
    subject_id = row["subject_id"]

    try:
        execute_query_db('INSERT INTO subject_in_curriculum VALUES(?,?)', (curriculum_id, subject_id))
    except sqlite3.Error as e:
        result["error_messages"].append(e.args[0])
        return jsonify(result)

    result["success"] = True

    return jsonify(result)


@app.route('/curriculums', methods=["POST", "GET"])
@cross_origin()
# -------------------------------------------------------------------------------------------------------------------
# Function that shows all curriculums.
# -------------------------------------------------------------------------------------------------------------------
def curriculums():
    result = {
        "success": True,
        "error_messages": [],
        "curriculums": []
    }

    row = query_db('SELECT * FROM curriculums')
    if not row:
        result["error_messages"].append("No curriculums exist.")

    else:
        result["curriculums"] = [{"name": x["name"], "description": x["description"]} for x in row]
    return jsonify(result)


@app.route('/subjects_in_curriculum', methods=["POST", "GET"])
@cross_origin()
# -------------------------------------------------------------------------------------------------------------------
# Function that shows all the subjects in a specific curriculum.
# -------------------------------------------------------------------------------------------------------------------
def subjects_in_curriculum():
    result = {
        "success": False,
        "error_messages": [],
        "subjects": []
    }
    data = request.get_json(force=True)
    curriculum_name = data.get("curriculum")
    row = query_db('SELECT curriculum_id FROM curriculums WHERE name=?', [curriculum_name], one=True)
    if not row:
        result["error_messages"].append("Curriculum doesn't exist.")
        return jsonify(result)
    curriculum_id = row["curriculum_id"]
    subject_ids_row = query_db('SELECT subject_id FROM subject_in_curriculum WHERE curriculum_id=?', [curriculum_id])
    if not subject_ids_row:
        result["error_messages"].append("Curriculum doesn't exist or doesn't have any subjects yet.")
        return jsonify(result)
    subject_ids = [x["subject_id"] for x in subject_ids_row]
    subjects_row = query_db('SELECT * FROM subjects WHERE subject_id IN ({})'.format(','.join('?' * len(subject_ids))),
                            subject_ids)
    subjects = [{"name": x["subject_name"]} for x in subjects_row]
    result["subjects"] = subjects

    result["success"] = True
    return jsonify(result)


@app.route('/subjects_in_all_curriculums', methods=["POST", "GET"])
@cross_origin()
# ------------------------------------------------------------------------------------------------------------------
# Function that shows all subjects in all curriculums.
# -------------------------------------------------------------------------------------------------------------------
def subjects_in_all_curriculums():
    result = {
        "success": False,
        "error_messages": [],
        "subjects_in_curriculums": {}
    }
    data = request.get_json(force=True)
    sid = data.get("sid")
    user = user_from_sid(sid)

    if not sid:
        result["error_messages"].append("No session id given.")
        return jsonify(result)
    if not user:
        result["error_messages"].append("Invalid session_id.")
        return jsonify(result)

    if user["role"] != "Teacher":
        result["error_messages"].append("Permission error, user is not a teacher.")
        return jsonify(result)

    row = query_db('SELECT * FROM curriculums')
    if not row:
        result["error_messages"].append("Curriculum doesn't exist.")
        return jsonify(result)
    curriculums = {x["curriculum_id"]: {"curriculum_id": x["curriculum_id"], "name": x["name"]} for x in row}
    for curriculum_id in curriculums.keys():
        subject_ids_row = query_db('SELECT subject_id FROM subject_in_curriculum WHERE curriculum_id=?',
                                   [curriculum_id])
        if not subject_ids_row:
            result["error_messages"].append("Curriculum doesn't exist or doesn't have any subjects yet.")
            return jsonify(result)
        subject_ids = [x["subject_id"] for x in subject_ids_row]
        subjects_row = query_db(
            'SELECT * FROM subjects WHERE subject_id IN ({})'.format(','.join('?' * len(subject_ids))), subject_ids)
        # subjects = [{"name": x["subject_name"]} for x in subjects_row]
        subjects = [x["subject_name"] for x in subjects_row]
        result["subjects_in_curriculums"][curriculums[curriculum_id]["name"]] = subjects

    result["success"] = True
    return jsonify(result)


@app.route('/success_rate_stats', methods=["POST", "GET"])
@cross_origin()
# -------------------------------------------------------------------------------------------------------------------
# Function that returns statistics about student's success rate in solving questions.
# -------------------------------------------------------------------------------------------------------------------
def success_rate_stats():
    result = {
        "success": False,
        "error_messages": [],
        "stats": {}
    }
    data = request.get_json(force=True)
    sid = data.get("sid")
    user = user_from_sid(sid)

    if not sid:
        result["error_messages"].append("No session id given.")
        return jsonify(result)
    if not user:
        result["error_messages"].append("Invalid session_id.")
        return jsonify(result)


def generate_similar_question(template_id):
    # running f# executable
    row = query_db('SELECT * FROM question_templates where template_id=?', [template_id], one=True)
    if not row:
        return None
    source_problem_mml = row["template_mathml"]

    similar_problem_mathml = source_problem_mml
    try:
        similar_problem_mathml = subprocess.check_output(
            ["dotnet", "run", "--project", apb_exec, "--generatesimilarterm", source_problem_mml]).decode('utf-8')
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

    return problem


# -------------------------------------------------------------------------------------------------------------------
# Function that creates a practice session for a student.
# -------------------------------------------------------------------------------------------------------------------
@app.route('/create_practice_session', methods=["GET", "POST"])
@cross_origin()
def create_practice_session():
    result = {
        "success": True,
        "Error_messages": []

    }
    index = 0
    practice_id = str(uuid.uuid4())
    student_solution_id = str(uuid.uuid4())
    data = request.get_json(force=True)

    student_id = data.get("student_id")
    if data.get("template_ids") is not None:
     for template_id in data.get("template_ids"):
        question = generate_similar_question(template_id)
        correct_solutions = get_wolfram_solutions(question)
        if question is None:
            result["success"] = False
            return jsonify(result)

        try:
            execute_query_db('INSERT INTO student_solutions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                             (student_solution_id, student_id, practice_id, template_id, question, None, None,
                              correct_solutions,
                              None, None, None, None, None))
            execute_query_db('INSERT INTO practice_session_questions VALUES (?,?,?,?,?, ?)',
                             (practice_id, template_id, question, index, student_solution_id, correct_solutions))

        except sqlite3.Error as e:
            result["Error_messages"].append(e.args[0])
            return jsonify(result)

        index += 1

    try:
        execute_query_db('INSERT INTO practice_sessions VALUES (?,?,?,?)',
                         (practice_id, student_id, datetime.datetime.utcnow().isoformat(), index))
    except sqlite3.Error as e:
        result["Error_messages"].append(e.args[0])
        return jsonify(result)

    return jsonify(result)

#-----------------------------------------------------------------------------------------------------------------------
#Inner function that gets a template_id and returns subject_name.
#-----------------------------------------------------------------------------------------------------------------------
def get_subject_from_template(template_id):

    subject_id = query_db('SELECT subject_id FROM template_in_subject WHERE template_id=?',[template_id])
    if not subject_id:
        return None

    subject_name = query_db('SELECT subject_name FROM subjects WHERE subject_id=?' , [subject_id])

    if not subject_name:
        return None

    return subject_name

#-----------------------------------------------------------------------------------------------------------------------
#Inner function that gets a subject_id and returns curriculum_name.
#-----------------------------------------------------------------------------------------------------------------------
def get_curriculum_from_subject(subject_id):
    curriculum_id = query_db('SELECT curriculum_id FROM subject_in_curriculum WHERE subject_id=?' , [subject_id])
    if not curriculum_id:
        return None
    curriculum_name = query_db('SELECT curriculum_name FROM curriculums WHERE curriculum_id=?' , [curriculum_id])
    if not curriculum_name:
        return None

    return curriculum_name

#-----------------------------------------------------------------------------------------------------------------------
#Inner function that gets subject_name and returns subject_id.
#-----------------------------------------------------------------------------------------------------------------------
def get_subject_id_from_subject_name(subject_name):
    subject_id = query_db('SELECT subject_id FROM subjects WHERE subject_name = ?' , [subject_name])
    if not subject_id:
        return None

    return subject_id


@app.route('/get_practice_session_questions' , methods=["GET" , "POST"])
@cross_origin()
#-----------------------------------------------------------------------------------------------------------------------
#Function that returns a list of questions for a practice session.
#-----------------------------------------------------------------------------------------------------------------------
def get_practice_session_questions():
    result = {
        "success": True,
        "error_messages": [],
        "questions": [],
        "subjects": [],
        "curriculum": ""

    }
    data = request.get_json(force=True)
    sid = data.get("sid")
    user = user_from_sid(sid)

    if not sid:
        result["success"] = False
        result["error_messages"].append("No session id given.")
        return jsonify(result)

    if not user:
        result["success"] = False
        result["error_messages"].append("Invalid session_id.")
        return jsonify(result)

    row = query_db('SELECT * FROM practice_sessions WHERE student_id=? AND time_created = max(time_created)' , [user["user_id"]] , one=True)

    if not row:
        result["success"] = False
        result["error_messages"].append("Sorry, there is no practice session for this user...")
        return jsonify(result)

    questions = query_db('SELECT * FROM practice_session_questions WHERE practice_id=?' , [row["practice_id"]])
    if not questions:
        result["success"] = False
        result["error_messages"].append("")
        return jsonify(result)

    for question in questions["question_mathml"]:
        result["questions"].append(question)

    i = 0

    for template_id in questions["template_id"]:
        subject = get_subject_from_template(template_id)
        if str(subject) == "None":
            result["subjects"].append("subject is not defined...")

        result["subjects"].append(str(subject))

        if i == 0:
            subid = get_subject_id_from_subject_name(str(subject))
            if str(subid) == "None":
                result["error_messages"].append("subject doesn't exist...")
                return jsonify(result)
            curriculum_name = get_curriculum_from_subject(subid)
            if str(curriculum_name) == "None":
                result["curriculum"] = "curriculum doesn't exist..."
                return jsonify(result)

            result["curriculum"] = str(curriculum_name)
            i += 1

    return jsonify(result)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True, ssl_context=context)
