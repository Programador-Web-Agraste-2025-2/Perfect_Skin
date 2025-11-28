from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/quiz2")
def quiz2():
    return render_template("quiz2.html")

@app.route("/quiz3")
def quiz3():
    return render_template("quiz3.html")

@app.route("/quiz4")
def quiz4():
    return render_template("quiz4.html")

@app.route("/quiz5")
def quiz5():
    return render_template("quiz5.html")

@app.route("/quiz6")
def quiz6():
    return render_template("quiz6.html")

@app.route("/quiz7")
def quiz7():
    return render_template("quiz7.html")

if __name__ == "__main__":
    app.run(debug=True)
