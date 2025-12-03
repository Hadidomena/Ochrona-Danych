import os
import getpass
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, request, jsonify
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

@app.route("/status", methods=["GET"])
def status():
    try:
        uid = os.getuid()
        gid = os.getgid()
    except AttributeError:
        uid = None
        gid = None
    user = getpass.getuser()
    return jsonify({"uid": uid, "gid": gid, "user": user})
    

@app.route("/ip", methods=["GET"])
def ip():
    x_real = request.headers.get('X-Real-IP')
    xfwd = request.headers.get("X-Forwarded-For")
    remote = request.remote_addr
    return jsonify({"X-Real-IP": x_real, "X-Forwarded-For": xfwd, "remote_addr": remote})

if __name__ == "__main__":
    app.run(debug=False)