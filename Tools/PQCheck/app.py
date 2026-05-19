from flask import Flask, render_template

from crypto import crypto_bp
from dependency import dependency_bp
from ai_chat import ai_chat_bp

app = Flask(__name__)

app.register_blueprint(crypto_bp)
app.register_blueprint(dependency_bp)
app.register_blueprint(ai_chat_bp)


@app.route("/")
def home():
    return render_template("home.html")


if __name__ == "__main__":
    app.run(debug=False)
