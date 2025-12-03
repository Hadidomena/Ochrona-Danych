#flask app configuration
from flask import Flask, request
app = Flask(__name__)

@app.route("/status", methods=["GET"])
def status():
    # wyświetla UID, GID i nazwę użytkownika procesu którym jest aplikacja
    return "Ok"
    

@app.route("/ip", methods=["GET"])
def ip():
    X_Real_IP = request.headers.get('X-Real-IP')
    if X_Real_IP:
        return X_Real_IP
    else:
        return request.remote_addr


if __name__ == "__main__":
    app.run(debug=True)