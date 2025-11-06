from flask import Flask, render_template, request, make_response
import markdown
from collections import deque
import nh3

app = Flask(__name__)

notes = []
recent_users = deque(maxlen=3)

@app.route("/")
def username():
    return render_template("main.html")

@app.route("/hello", methods=['GET', 'POST'])
def hello():
    if request.method == 'POST':
        username = request.form.get("username", "unknown")
        if not username in recent_users:
            recent_users.append(username)
        resp = make_response(render_template("hello.html", username=username, notes=notes, recent_users=list(recent_users)))
        resp.set_cookie("username", username)
        return resp
    if request.method == 'GET':
        username = request.cookies.get("username", "unknown")
        return render_template("hello.html", username=username, notes=notes, recent_users=list(recent_users))

@app.route("/render", methods=['POST'])
def render():
    md = request.form.get("markdown","")
    html = markdown.markdown(md, extensions=['extra', 'sane_lists', 'nl2br'])
    
    allowed_tags = {'a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul',
                    'p', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'img'}
    allowed_attrs = {
        'a': {'href', 'title'},
        'img': {'src', 'alt', 'title'}
    }
    allowed_protocols = {'http', 'https', 'mailto'}
    
    cleaned = nh3.clean(html,
                        tags=allowed_tags,
                        attributes=allowed_attrs,
                        url_schemes=allowed_protocols,
                        link_rel=None)
    notes.append(cleaned)
    return render_template("markdown.html", rendered=cleaned)

@app.route("/render/<rendered_id>")
def render_old(rendered_id):
    if int(rendered_id) > len(notes):
        return "Wrong note id", 404

    rendered = notes[int(rendered_id) - 1]
    return render_template("markdown.html", rendered=rendered)

app.run(debug=True)