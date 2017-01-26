from flask import Flask

app = Flask(__name__)


@app.route('/homepage')
def homepage():
    return '<h2 color="green">  ברוכים הבאים לאתר מתמטיקל </h2>'


if __name__ == '__main__':
    app.run()
