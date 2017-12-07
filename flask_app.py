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


# ----------------------------------------------------------------------------------------------------------------------
# Function that prepers the DataBase in order to execute a query.
# ----------------------------------------------------------------------------------------------------------------------
def get_db():
    db = getattr(_app_ctx_stack.top, '_database', None)
    if db is None:
        db = _app_ctx_stack.top._database = sqlite3.connect(DATABASE)

    db.row_factory = sqlite3.Row
    return db


# ----------------------------------------------------------------------------------------------------------------------
# Function that closes a connection to DataBase.
# ----------------------------------------------------------------------------------------------------------------------
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(_app_ctx_stack.top, '_database', None)
    if db is not None:
        db.close()


# ----------------------------------------------------------------------------------------------------------------------
# Function that convert the result of a query into a dictionary.
# ----------------------------------------------------------------------------------------------------------------------
def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))


# ----------------------------------------------------------------------------------------------------------------------
# Function that executes a query and returns the result(might be empty).
# ----------------------------------------------------------------------------------------------------------------------
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


# ----------------------------------------------------------------------------------------------------------------------
# Function that executes a query that changes the db and commits (doesn't return anything)
# ----------------------------------------------------------------------------------------------------------------------
def execute_query_db(query, args=()):
    db = get_db()
    db.execute(query, args)
    db.commit()


# ----------------------------------------------------------------------------------------------------------------------
# Function that checks the validity of an email.
# This function gets an email string as an input and returns a boolean value.
# ----------------------------------------------------------------------------------------------------------------------
def is_email_valid(email):
    email_regex = re.compile(r"\w+[.|\w]\w+@\w+[.]\w+[.|\w+]\w+")
    if not email or not email_regex.match(email):
        return False
    return True


# ----------------------------------------------------------------------------------------------------------------------
# Function that checks if an email is unique.
# This function gets an email string as an input,and returns a boolean value.
# ----------------------------------------------------------------------------------------------------------------------
def is_unique_email(email):
    cur = query_db('SELECT username FROM users WHERE email=?', (email,))
    if not cur:
        return True
    else:
        return False


@app.route('/all_users', methods=["POST", "GET"])
@cross_origin()
# ----------------------------------------------------------------------------------------------------------------------
# Function that shows all users
# ----------------------------------------------------------------------------------------------------------------------
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
# ----------------------------------------------------------------------------------------------------------------------
# Function that shows all user sessions.
# ----------------------------------------------------------------------------------------------------------------------
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
# ----------------------------------------------------------------------------------------------------------------------
# Function that shows all of students solutions.
# ----------------------------------------------------------------------------------------------------------------------
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
# ----------------------------------------------------------------------------------------------------------------------
# Server's home page.
# ----------------------------------------------------------------------------------------------------------------------
def homepage():
    return '<html><body><h2 color="green">LearnMath backend server</h2></body></html>'


@app.route('/register', methods=["POST", "GET"])
@cross_origin()
# ----------------------------------------------------------------------------------------------------------------------
# Function that adds a new user to the system.
# This function returns an object that shows wheter the user succeeded in registration or not.
# ----------------------------------------------------------------------------------------------------------------------
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
# ----------------------------------------------------------------------------------------------------------------------
# Function that checks if the username and password are existed in the database.
# This function returns an object that shows wheter the user exist or not.
# ----------------------------------------------------------------------------------------------------------------------
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


@app.route('/question', methods=["POST", "GET"])
@cross_origin()
# ----------------------------------------------------------------------------------------------------------------------
# Function that returns a question for the user(student).
# ----------------------------------------------------------------------------------------------------------------------
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
        xslt = ET.parse("pmml2tex/mmltex.xsl")
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
# ----------------------------------------------------------------------------------------------------------------------
# This function adds a question to the templates stock.
# ----------------------------------------------------------------------------------------------------------------------
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
        inferred_subjects = infer_subjects_from_template_id(template_id)
        for subject in inferred_subjects:
            new_subject_id = str(uuid.uuid4())
            try:
                execute_query_db("INSERT INTO subjects VALUES(?,?,?)", [new_subject_id, subject, 1])
            except sqlite3.Error as e:
                print(e.args[0], file=sys.stderr)
                continue

        subject_names += inferred_subjects
        for subject_name in subject_names:
            row = query_db('SELECT subject_id FROM subjects WHERE subject_name=?', [subject_name], one=True)
            if not row:
                result["error_messages"].append("No such subject exists.")
                return jsonify(result)
            subject_id = row["subject_id"]
            execute_query_db('INSERT INTO template_in_subject VALUES (?,?)', [template_id, subject_id])
            curriculums_row = query_db("SELECT curriculum_id FROM curriculums")
            if curriculums_row:
                for curriculum in curriculums_row:
                    try:
                        curriculum_id = curriculum["curriculum_id"]
                        execute_query_db('INSERT INTO subject_in_curriculum VALUES (?,?)', [curriculum_id, subject_id])
                    except sqlite3.Error as e:
                        continue
            try:
                execute_query_db('INSERT INTO template_in_subject VALUES (?,?)', [template_id, subject_id])
            except sqlite3.Error as e:
                continue
    except sqlite3.Error as e:
        result["error_messages"].append(e.args[0])
        return jsonify(result)

    result["success"] = True

    return jsonify(result)


# ----------------------------------------------------------------------------------------------------------------------
# Inner function that converts dictionary representation to xml format.
# ----------------------------------------------------------------------------------------------------------------------

def dicttoxml(dict):
    dict.pop("xmlns", None)
    dict.pop("xmlns:mathematica", None)
    dict.pop("mathematica:form", None)
    res = xmltodict.unparse(dict)
    xml_prefix = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    if xml_prefix in res:
        res = res[len(xml_prefix):]
    return res


# ----------------------------------------------------------------------------------------------------------------------
# Inner function that returns solution/s for a question.
# ----------------------------------------------------------------------------------------------------------------------

def get_wolfram_solutions(input, mathml=True, rerun_mathml=True):
    waeo = wap.WolframAlphaEngine(wa_appid, wa_server)
    query = waeo.CreateQuery(input)
    res = waeo.PerformQuery(query, mathml=mathml)
    waeqr = wap.WolframAlphaQueryResult(res)
    jsonresult = waeqr.JsonResult()

    wa_solutions = []
    solution_pod_found = False
    if jsonresult["success"] == "false":
        return []
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
                        lst = [x for x in actual_answer.get("mrow", {}).get("mtext", [])]
                        found_no_solution = False
                        for x in lst:
                            if "no solution" in x:
                                found_no_solution = True
                                break
                        if found_no_solution:
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


# ----------------------------------------------------------------------------------------------------------------------
# Inner function that checks if student's solution is correct or not.
# ----------------------------------------------------------------------------------------------------------------------
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


# Check @ Wolfram|Alpha if these two equations have the same solutions
def check_equations_have_same_solutions(equation1, equation2):
    if isinstance(equation2, str):
        equation2 = [equation2]
    wa_solutions = get_wolfram_solutions(equation1)

    # input = "<math xmlns='http://www.w3.org/1998/Math/MathML'>"
    # for i, sol in enumerate(wa_solutions + equation2):
    #     if isinstance(sol, bytes):
    #         sol = sol.decode('utf-8')
    #     input += sol
    #     if i != len(wa_solutions + equation2) - 1:
    #         input += "<mo>,</mo>"
    # input += "</math>"

    wa_verify_solutions = get_wolfram_solutions(equation2[0])

    print("Check Equation Equality:")
    print("Equation1: " + str(equation1))
    print("Equation2: " + str(equation2))
    print("Solutions for equation1: " + str(wa_solutions))
    print("Solutions for equation2: " + str(wa_verify_solutions))

    return wa_verify_solutions == wa_solutions


# ----------------------------------------------------------------------------------------------------------------------
# Inner function that checks if student's solution is in final form like x=number.
# ----------------------------------------------------------------------------------------------------------------------
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


def get_student_practice_id(student_id):
    row = query_db(
        'SELECT practice_id FROM practice_sessions WHERE student_id=? ORDER BY time_created DESC LIMIT 1',
        [student_id], one=True)
    if not row:
        return None

    return row["practice_id"]


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
    question_index = data.get("index")
    solution_time = data.get("time")
    practice_id = get_student_practice_id(student_id)

    question_row = query_db(
        "SELECT * FROM practice_session_questions WHERE practice_id=? AND question_index=?",
        [practice_id, question_index], one=True)
    if not question_row:
        result["success"] = False
        result["error_messages"].append("No question found for this index and practice id.")
        return jsonify(result)

    question = question_row["question_mathml"]
    template_id = question_row["template_id"]

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
    else:
        check_equations_have_same_solutions(question, student_solutions)
    print("Question: " + question)
    print("Wolfram solutions for question: " + str(wa_solutions))
    print("Student solutions: " + str(student_solutions))
    print("Wolfram comparison of solutions: " + str(wa_verify_solutions))
    step_by_step_data = ""
    mistake_type = None
    mistake_step_number = None
    import datetime
    datetime = datetime.datetime.utcnow().isoformat()
    try:
        execute_query_db(
            "UPDATE student_solutions SET solution_time=?, final_answer=?, is_correct=?, step_by_step_data=?, mistake_type=?, mistake_step_number=?, datetime=? WHERE practice_id=? AND student_id=? AND template_id=?",
            [solution_time, student_solutions[0],
             int(result["correct"]) if type(result["correct"]) is not None else None,
             step_by_step_data, mistake_type, mistake_step_number, datetime] + [practice_id, student_id, template_id])
    except sqlite3.Error as e:
        result["error_messages"].append(e.args[0])
        return jsonify(result)

    return jsonify(result)

@app.route("/validate_solution", methods=["POST"])
@cross_origin()
# ----------------------------------------------------------------------------------------------------------------------
# This function checks the student answer for the question.
# This function gets the question,the subject of the question and the students solutions.
# ----------------------------------------------------------------------------------------------------------------------
def validate_solution():
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
    question_index = data.get("index")
    solution_time = data.get("time")
    practice_id = get_student_practice_id(student_id)

    question_row = query_db(
        "SELECT * FROM practice_session_questions WHERE practice_id=? AND question_index=?",
        [practice_id, question_index], one=True)
    if not question_row:
        result["success"] = False
        result["error_messages"].append("No question found for this index and practice id.")
        return jsonify(result)

    question = question_row["question_mathml"]
    template_id = question_row["template_id"]

    if isinstance(student_solutions, str):
        student_solutions = [student_solutions]

    # TODO: [0] is wrong?
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
    else:
        check_equations_have_same_solutions(question, student_solutions)
    print("Question: " + question)
    print("Wolfram solutions for question: " + str(wa_solutions))
    print("Student solutions: " + str(student_solutions))
    print("Wolfram comparison of solutions: " + str(wa_verify_solutions))
    step_by_step_data = ""
    mistake_type = None
    mistake_step_number = None
    import datetime
    datetime = datetime.datetime.utcnow().isoformat()
    try:
        execute_query_db(
            "UPDATE student_solutions SET solution_time=?, final_answer=?, is_correct=?, step_by_step_data=?, mistake_type=?, mistake_step_number=?, datetime=? WHERE practice_id=? AND student_id=? AND template_id=?",
            [solution_time, student_solutions[0],
             int(result["correct"]) if type(result["correct"]) is not None else None,
             step_by_step_data, mistake_type, mistake_step_number, datetime] + [practice_id, student_id, template_id])
    except sqlite3.Error as e:
        result["error_messages"].append(e.args[0])
        return jsonify(result)

    return jsonify(result)
# @app.route("/validate_solution", methods=["POST"])
# @cross_origin()
# # ----------------------------------------------------------------------------------------------------------------------
# # This function checks the student answer for the question.
# # This function gets the question,the subject of the question and the students solutions.
# # ----------------------------------------------------------------------------------------------------------------------
# def validate_solution():
#     result = {
#         "success": True,
#         "error_messages": [],
#         "correct": False
#
#     }
#     data = request.get_json(force=True)
#     sid = data.get("sid")
#     user = user_from_sid(sid)
#
#     if not sid:
#         result["error_messages"].append("No session id given.")
#         return jsonify(result)
#     if not user:
#         result["error_messages"].append("Invalid session_id.")
#         return jsonify(result)
#
#     student_id = user["user_id"]
#
#     solution_history = data.get("solution_history")
#     question_index = data.get("index")
#     solution_time = data.get("time")
#     practice_id = get_student_practice_id(student_id)
#     student_solutions = solution_history[-1]
#     question_row = query_db(
#         "SELECT * FROM practice_session_questions WHERE practice_id=? AND question_index=?",
#         [practice_id, question_index], one=True)
#     if not question_row:
#         result["success"] = False
#         result["error_messages"].append("No question found for this index and practice id.")
#         return jsonify(result)
#
#     question = question_row["question_mathml"]
#     template_id = question_row["template_id"]
#
#     index = len(solution_history) - 1
#
#     # def binary_search(A, predicate, l, r):
#     #     if r >= l:
#     #         mid = int(l + (r - l) / 2)
#     #         if r - l == 0:
#     #             if not predicate(A[mid]):
#     #                 return mid
#     #             else:
#     #                 return None
#     #         elif predicate(A[mid]):
#     #             return binary_search(A, predicate, mid + 1, r)
#     #         else:
#     #             return binary_search(A, predicate, l, mid - 1)
#     #     else:
#     #         return None
#
#     mistake_step_number = binary_search(solution_history, lambda x: check_equations_have_same_solutions(question, x), 0,
#                   len(solution_history) - 1)
#     if mistake_step_number is None:
#         result["correct"] = True
#     # while not check_equations_have_same_solutions(question, solution_history[index]):
#
#
#
#     step_by_step_data = ""
#     mistake_type = "Invalid transition"
#     import datetime
#     datetime = datetime.datetime.utcnow().isoformat()
#     try:
#         execute_query_db(
#             "UPDATE student_solutions SET solution_time=?, final_answer=?, is_correct=?, step_by_step_data=?, mistake_type=?, mistake_step_number=?, datetime=? WHERE practice_id=? AND student_id=? AND template_id=?",
#             [solution_time, student_solutions[0],
#              int(result["correct"]) if type(result["correct"]) is not None else None,
#              step_by_step_data, mistake_type, mistake_step_number, datetime] + [practice_id, student_id, template_id])
#     except sqlite3.Error as e:
#         result["error_messages"].append(e.args[0])
#         return jsonify(result)
#
#     return jsonify(result)


@app.route("/get_feedback", methods=["GET", "POST"])
@cross_origin()
# ----------------------------------------------------------------------------------------------------------------------
# This function returns number of questions that were given for the student,number of mistakes,number of correct answers
# ----------------------------------------------------------------------------------------------------------------------
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


# ----------------------------------------------------------------------------------------------------------------------
# Inner function that gets as a parameter session id and returns all user properties.
# ----------------------------------------------------------------------------------------------------------------------
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
# ----------------------------------------------------------------------------------------------------------------------
# Function that adds a subject to subjects table.
# ----------------------------------------------------------------------------------------------------------------------
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
        execute_query_db('INSERT INTO subjects VALUES(?,?,?)', (subject_id, subject_name, 0))
    except sqlite3.Error as e:
        result["error_messages"].append(e.args[0])
        return jsonify(result)

    result["success"] = True

    return jsonify(result)


@app.route('/add_curriculum', methods=["POST", "GET"])
@cross_origin()
# ----------------------------------------------------------------------------------------------------------------------
# Function that adds a new curriculum to curriculums table.
# ----------------------------------------------------------------------------------------------------------------------
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
# ----------------------------------------------------------------------------------------------------------------------
# Function that adds a subject to a specific curriculum.
# ----------------------------------------------------------------------------------------------------------------------
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
# ----------------------------------------------------------------------------------------------------------------------
# Function that shows all curriculums.
# ----------------------------------------------------------------------------------------------------------------------
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
# ----------------------------------------------------------------------------------------------------------------------
# Function that shows all the subjects in a specific curriculum.
# ----------------------------------------------------------------------------------------------------------------------
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
# ----------------------------------------------------------------------------------------------------------------------
# Function that shows all subjects in all curriculums.
# ----------------------------------------------------------------------------------------------------------------------
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


# -----------------------------------------------------------------------------------------------------------------------
# Inner function that gets a template_id and generates similar question from it by using F# code.
# -----------------------------------------------------------------------------------------------------------------------
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
        xslt = ET.parse("pmml2tex/mmltex.xsl")
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


def infer_subjects_from_template_id(template_id):
    template_mathml_row = query_db("SELECT template_mathml FROM question_templates WHERE template_id=?", [template_id],
                                   one=True)
    result = []
    if not template_mathml_row:
        return []
    template_mathml = template_mathml_row["template_mathml"]
    try:
        subjects_string = subprocess.check_output(
            ["dotnet", "run", "--project", apb_exec, "--gettermdomains", template_mathml]).decode('utf-8')

        for line in subjects_string.strip().splitlines():
            if line.startswith(";"):
                result.append(line[1:])

        print(subjects_string)

    except subprocess.CalledProcessError as e:
        print("algebra-problem-generator failed. " + str(e), file=sys.stderr)
    return result


# -------------------------------------------------------------------------------------------------------------------
# Function that creates a practice session for a student.
# -------------------------------------------------------------------------------------------------------------------
@app.route('/create_practice_session', methods=["GET", "POST"])
@cross_origin()
def create_practice_session():
    result = {
        "success": True,
        "error_messages": []

    }
    index = 0

    data = request.get_json(force=True)

    student_id = data.get("student_id")
    template_ids = data.get("template_ids")
    question_count = data.get("question_count", 10)
    if not template_ids:
        subjects = data.get("subjects")
        if not data.get("subjects"):
            result["success"] = False
            result["error_messages"].append("No subjects given to generate practice session for.")
            return jsonify(result)
        subjects_row = query_db(
            'SELECT * FROM subjects WHERE subject_name IN ({})'.format(','.join('?' * len(subjects))), subjects)
        subject_ids = [x["subject_id"] for x in subjects_row]
        template_ids_row = query_db(
            "select template_id, count(subject_id) FROM (select * FROM template_in_subject WHERE subject_id IN ({})) GROUP BY template_id order by (count(subject_id)) DESC LIMIT ?".format(
                ','.join('?' * len(subject_ids))), subject_ids + [question_count])
        if not template_ids_row:
            result["success"] = False
            result["error_messages"].append("No question templates for the subjects you chose.")
            return jsonify(result)
        template_ids = [x["template_id"] for x in template_ids_row]

    original_template_ids = template_ids.copy()

    while len(template_ids) < question_count:
        index_to_duplicate = random.randrange(0, len(original_template_ids))
        template_ids.append(original_template_ids[index_to_duplicate])

    template_ids = template_ids[:question_count]

    if student_id:
        student_ids = [student_id]
    else:
        row = query_db("SELECT user_id FROM users")
        student_ids = [x["user_id"] for x in row]

    for student_id in student_ids:
        practice_id = str(uuid.uuid4())
        index = 0
        for template_id in template_ids:
            question = generate_similar_question(template_id)
            correct_solutions = get_wolfram_solutions(question)
            student_solution_id = str(uuid.uuid4())

            if question is None:
                result["success"] = False
                return jsonify(result)

            try:
                execute_query_db('INSERT INTO student_solutions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                                 (student_solution_id, student_id, practice_id, template_id, question, None, None,
                                  str(correct_solutions),
                                  None, None, None, None, None))
                execute_query_db('INSERT INTO practice_session_questions VALUES (?,?,?,?,?, ?)',
                                 [
                                     practice_id, index, template_id, question, str(correct_solutions),
                                     student_solution_id,
                                 ])

            except sqlite3.Error as e:
                result["error_messages"].append(e.args[0])
                return jsonify(result)

            index += 1
        try:
            execute_query_db('INSERT INTO practice_sessions VALUES (?,?,?,?)',
                             (practice_id, student_id, datetime.datetime.utcnow().isoformat(), index))
            print("inserted practice session for" + student_id)
        except sqlite3.Error as e:
            result["error_messages"].append(e.args[0])
            return jsonify(result)
        except Exception as e:
            print("exception adding practice session " + str(e))

    result["success"] = True
    return jsonify(result)


# -----------------------------------------------------------------------------------------------------------------------
# Inner function that gets a template_id and returns subject_name.
# -----------------------------------------------------------------------------------------------------------------------
def get_subjects_from_template(template_id):
    subjects_row = query_db(
        'SELECT template_in_subject.subject_id, subject_name FROM template_in_subject INNER JOIN subjects ON subjects.subject_id=template_in_subject.subject_id WHERE template_id=?',
        [template_id])
    if not subjects_row:
        return None
    subject_names = [x["subject_name"] for x in subjects_row]

    return subject_names


# -----------------------------------------------------------------------------------------------------------------------
# Inner function that gets a subject_id and returns curriculum_name.
# -----------------------------------------------------------------------------------------------------------------------
def get_curriculum_from_subject(subject_id):
    curriculum_id = query_db('SELECT curriculum_id FROM subject_in_curriculum WHERE subject_id=?', [subject_id])
    if not curriculum_id:
        return None
    curriculum_name = query_db('SELECT curriculum_name FROM curriculums WHERE curriculum_id=?', [curriculum_id])
    if not curriculum_name:
        return None

    return curriculum_name


# -----------------------------------------------------------------------------------------------------------------------
# Inner function that gets subject_name and returns subject_id.
# -----------------------------------------------------------------------------------------------------------------------
def get_subject_id_from_subject_name(subject_name):
    subject_id = query_db('SELECT subject_id FROM subjects WHERE subject_name = ?', [subject_name])
    if not subject_id:
        return None

    return subject_id


@app.route('/get_practice_session_questions', methods=["GET", "POST"])
@cross_origin()
# -----------------------------------------------------------------------------------------------------------------------
# Function that returns a list of questions for a practice session.
# -----------------------------------------------------------------------------------------------------------------------
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
    student_id = user["user_id"]
    row = query_db(
        'SELECT practice_id,student_id FROM practice_sessions WHERE student_id=? ORDER BY time_created DESC LIMIT 1',
        [student_id], one=True)

    if not row:
        result["success"] = False
        result["error_messages"].append("No practice sessions available for user.")
        return jsonify(result)
    practice_id = row["practice_id"]
    questions = query_db('SELECT * FROM practice_session_questions WHERE practice_id=?', [practice_id])
    if not questions:
        result["success"] = False
        result["error_messages"].append("No questions in practice session.")
        return jsonify(result)

    for question in questions:
        result["questions"].append(question["question_mathml"])

    template_ids = [x["template_id"] for x in questions]
    for template_id in template_ids:
        subjects = get_subjects_from_template(template_id)
        result["subjects"] += subjects if subjects else []

    result["subjects"] = list(set(result["subjects"]))
    return jsonify(result)


# ----------------------------------------------------------------------------------------------------------------------
# Inner function that gets a student_id and return all subjects in student solutions table.
# ----------------------------------------------------------------------------------------------------------------------
def get_subjects_from_student_id(student_id):
    subjects = []
    row = query_db('SELECT template_id FROM student_solutions WHERE student_id=?', [student_id])
    if row:
        for item in row:
            template_id = item["template_id"]
            subject = get_subjects_from_template(template_id)
            if subject is not None:
                subjects.append(subject)

    return list(set(sum(subjects, [])))


# ----------------------------------------------------------------------------------------------------------------------
# Function that gets a session key and returns correct and wrong counters to each subject in question the student solved
# ----------------------------------------------------------------------------------------------------------------------
@app.route('/get_wrong_right_stats', methods=["GET", "POST"])
@cross_origin()
def get_wrong_right_stats():
    result = {
        "success": True,
        "error_messages": [],
        "result": {}
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
    student_names = []
    student_ids = []
    if user["role"] == "Student":
        student_names = [user["username"]]
        student_ids = [user["user_id"]]
    else:
        students_rows = query_db("SELECT * FROM users")
        student_names = [x["username"] for x in students_rows]
        student_ids = [x["user_id"] for x in students_rows]

    rows = query_db(
        'SELECT * FROM student_solutions WHERE student_id IN ({})'.format(','.join('?' * len(student_ids))),
        student_ids)
    subjects = list(set(sum([get_subjects_from_student_id(student_id) for student_id in student_ids], [])))

    if len(subjects) > 0:
        for subject in subjects:
            correct_count = 0
            wrong_count = 0
            for row in rows:
                subjects_from_template = get_subjects_from_template(row["template_id"])
                if subjects_from_template is not None:
                    for x in subjects_from_template:
                        if x == subject:

                            if row["is_correct"] == 1:
                                correct_count += 1
                            else:
                                wrong_count += 1
            result["result"][subject] = {"wrong": wrong_count, "correct": correct_count}

    return jsonify(result)


# ----------------------------------------------------------------------------------------------------------------------
# Inner function that gets a student_name and returns the number of questions that were given to him.
# ----------------------------------------------------------------------------------------------------------------------
def get_questions_number_from_student_name(student_name):
    student_id_row = query_db('SELECT user_id FROM users WHERE username=?', [student_name], one=True)
    if not student_id_row:
        return None
    student_id = student_id_row["user_id"]
    number_of_questions = query_db(
        'SELECT count(solution_id) FROM student_solutions WHERE student_id=? GROUP BY student_id',
        [student_id], one=True)
    if number_of_questions is None:
        return None
    return number_of_questions[0]


# ----------------------------------------------------------------------------------------------------------------------
# Inner function that gets a student_name and returns the number of his correct answers.
# ----------------------------------------------------------------------------------------------------------------------
def get_correct_answers_count_from_student_name(student_name):
    correct_counter = 0
    student_id_row = query_db('SELECT user_id FROM users WHERE username=?', [student_name], one=True)
    if not student_id_row:
        return None
    student_id = student_id_row["user_id"]
    rows = query_db('SELECT * FROM student_solutions WHERE student_id=?', [student_id])
    for row in rows:
        if row["is_correct"] == 1:
            correct_counter += 1

    return correct_counter


# ----------------------------------------------------------------------------------------------------------------------
# Inner function that gets a student_name and returns the his average solution time.
# ----------------------------------------------------------------------------------------------------------------------
def get_avg_solution_time(student_name):
    student_id_row = query_db('SELECT user_id FROM users WHERE username=?', [student_name], one=True)
    if not student_id_row:
        return None
    student_id = student_id_row["user_id"]
    solutions_time = query_db(
        'SELECT AVG(solution_time) FROM student_solutions WHERE is_correct = 1 AND student_id=?', [student_id],
        one=True)
    if not solutions_time:
        return None
    return solutions_time[0]


@app.route('/get_success_percentage_avg_time_stats', methods=["GET", "POST"])
@cross_origin()
# ----------------------------------------------------------------------------------------------------------------------
# Function that returns success percentage and average time of solution for a specific student or to all of the students.
# ----------------------------------------------------------------------------------------------------------------------
def get_success_percentage_avg_time_stats():
    result = {
        "success": True,
        "error_messages": [],
        "result": {}
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
    student_names = []
    if user["role"] == "Student":
        student_names = [user["username"]]
    else:
        student_names_row = query_db("SELECT * FROM users")
        student_names = [x["username"] for x in student_names_row]

    for student_name in student_names:
        questions_number = get_questions_number_from_student_name(student_name)
        if questions_number is None:
            continue

        correct_answers = get_correct_answers_count_from_student_name(student_name)
        number_of_questions = get_questions_number_from_student_name(student_name)
        avg_solution_time = get_avg_solution_time(student_name)

        if correct_answers is None or number_of_questions is None or avg_solution_time is None:
            # result["success"] = False
            # result["error_messages"].append("There is no such username...")
            # return jsonify(result)
            continue
        result["result"][student_name] = {}
        result["result"][student_name]["success_percentage"] = correct_answers / number_of_questions
        result["result"][student_name]["average_solving_time"] = avg_solution_time
    else:

        return jsonify(result)


# ----------------------------------------------------------------------------------------------------------------------
# Inner function that gets a student_name and returns the number of his wrong answers.
# ----------------------------------------------------------------------------------------------------------------------
def get_wrong_answers_count_from_student_name(student_name):
    wrongs_counter = 0
    student_id_row = query_db('SELECT user_id FROM users WHERE username=?', [student_name], one=True)
    if not student_id_row:
        return None
    student_id = student_id_row["user_id"]
    rows = query_db('SELECT * FROM student_solutions WHERE student_id=?', [student_id])
    for row in rows:
        if row["is_correct"] == 0:
            wrongs_counter += 1

    return wrongs_counter


# -----------------------------------------------------------------------------------------------------------------------
# Inner function that gets a student name and returns his mistakes.
# -----------------------------------------------------------------------------------------------------------------------
def get_all_mistakes_from_student_name(student_name):
    student_id_row = query_db('SELECT user_id FROM users WHERE username=?', [student_name], one=True)
    if not student_id_row:
        return None
    student_id = student_id_row["user_id"]
    mistakes = query_db('SELECT DISTINCT mistake_type FROM student_solutions WHERE student_id=?', [student_id])
    if not mistakes:
        return None
    return list(filter(None.__ne__, [mistake[0] for mistake in mistakes]))


# -----------------------------------------------------------------------------------------------------------------------
# Inner function that gets student_name and mistake_type and returns the number of mistakes from that type the student did.
# -----------------------------------------------------------------------------------------------------------------------
def get_mistake_type_counter_from_student_(student_name, mistake_type):
    student_id_row = query_db('SELECT user_id FROM users WHERE username=?', [student_name], one=True)
    if not student_id_row:
        return None
    student_id = student_id_row["user_id"]
    counter = query_db(
        'SELECT COUNT(student_id,mistake_type) FROM student_solutions WHERE student_id=? AND mistake_type=?',
        [student_id, mistake_type])
    if not counter:
        return None

    return counter[0]


@app.route('/get_mistake_type_stats', methods=["GET", "POST"])
@cross_origin()
# ------------------------------------------------------------------------------------------------------------------------
# Function that returns mistake_type stats of a specific student or all of the students
# ------------------------------------------------------------------------------------------------------------------------
def get_mistake_type_stats():
    result = {
        "success": True,
        "error_messages": [],
        "result": {}

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
    student_names = []
    if user["role"] == "Student":
        student_names = [user["username"]]
    else:
        student_names_row = query_db("SELECT * FROM users")
        student_names = [x["username"] for x in student_names_row]

    all_mistakes = set()
    all_mistakes_counter = 0
    for student_name in student_names:
        wrongs_counter = get_wrong_answers_count_from_student_name(student_name)
        student_mistakes = get_all_mistakes_from_student_name(student_name)
        all_mistakes = set.union(set(student_mistakes))
        if wrongs_counter is None or student_mistakes is None:
            continue

        for mistake in student_mistakes:
            mistake_counter = get_mistake_type_counter_from_student_(student_name, mistake)
            all_mistakes_counter += mistake_counter
            if mistake_counter is None:
                continue

            result["result"][student_name] = {}
            result["result"][student_name][mistake] = mistake_counter / wrongs_counter
    for mistake in all_mistakes:
        result["result"][mistake] = sum(
            (result["result"][student_name].get(mistake, 0) for student_name in student_names))

    return jsonify(result)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True, ssl_context=context)
