from flask import Blueprint, render_template, request, jsonify

from crypto import ask_ai


ai_chat_bp = Blueprint("ai_chat_bp", __name__)


@ai_chat_bp.route("/ai", methods=["GET"])
def ai_chat_page():
    return render_template("ai_chat.html")


@ai_chat_bp.route("/chat", methods=["POST"])
def chat():
    data = request.get_json() or {}

    repo = (data.get("repo") or "").strip()
    msg = (data.get("message") or "").strip()

    if not repo:
        return jsonify({"reply": "Repository is required (owner/repo)."}), 400

    if not msg:
        return jsonify({"reply": "Message is required."}), 400

    # Normalize common GitHub URL paste format.
    repo = repo.replace("https://github.com/", "")
    repo = repo.replace("http://github.com/", "")
    repo = repo.replace("github.com/", "")

    if "/" not in repo:
        return jsonify({"reply": "Invalid repository format. Use owner/repo."}), 400

    reply = ask_ai(repo, msg)
    return jsonify({"reply": reply})
