#
#              Copyright 2026 Comcast Cable Communications Management, LLC
#
#              Licensed under the Apache License, Version 2.0 (the "License");
#              you may not use this file except in compliance with the License.
#              You may obtain a copy of the License at
#
#              http://www.apache.org/licenses/LICENSE-2.0
#
#              Unless required by applicable law or agreed to in writing, software
#              distributed under the License is distributed on an "AS IS" BASIS,
#              WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#              See the License for the specific language governing permissions and
#              limitations under the License.
#
#              SPDX-License-Identifier: Apache-2.0
#
#              This product includes software developed at Comcast (https://www.comcast.com/).# 

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
