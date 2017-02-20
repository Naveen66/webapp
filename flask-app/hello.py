from flask import Flask
app = Flask(__name__)


@app.route("/")
def hello():
    return "Hey Naveen..First Flask Program..!!"


@app.route("/test")
def test():
    return "This is test function...!!"

if __name__ == "__main__":
    app.run()

