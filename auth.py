from flask import (
	Flask,
	request,
	render_template,
	flash,
	redirect,
	url_for,
	make_response,
)
import hashlib
import os
from config import *
import time
import jwt
from cryptography.fernet import Fernet
import json
import base64
import sqlite3

f = Fernet(KEY)

with open("private.pem", "rb") as file:
	private_key = file.read()


def dict_factory(cursor, row):
	d = {}
	for i, col in enumerate(cursor.description):
		d[col[0]] = row[i]
	return d


def get_db():
	con = sqlite3.connect("database.db")
	con.row_factory = dict_factory
	cur = con.cursor()
	return con, cur


# def generate_access_token():
#     payload = {"iss": ISSUER, "exp": time.time() + JWT_LIFE_SPAN}

#     access_token = jwt.encode(payload, private_key, algorithm="RS256")

#     return access_token


# def generate_authorization_code(client_id, redirect_uri):
#     authorization_code = f.encrypt(
#         json.dumps(
#             {
#                 "client_id": client_id,
#                 "redirect_uri": redirect_uri,
#             }
#         ).encode()
#     )

#     authorization_code = (
#         base64.b64encode(authorization_code, b"-_").decode().replace("=", "")
#     )

#     expiration_date = time.time() + CODE_LIFE_SPAN

#     authorization_codes[authorization_code] = {
#         "client_id": client_id,
#         "redirect_uri": redirect_uri,
#         "exp": expiration_date,
#     }

#     return authorization_code


# def verify_authorization_code(authorization_code, client_id, redirect_uri):
#     record = authorization_codes.get(authorization_code)
#     if not record:
#         return False

#     client_id_in_record = record.get("client_id")
#     redirect_uri_in_record = record.get("redirect_uri")
#     exp = record.get("exp")

#     if client_id != client_id_in_record or redirect_uri != redirect_uri_in_record:
#         return False

#     if exp < time.time():
#         return False

#     del authorization_codes[authorization_code]

#     return True


app = Flask(__name__)
app.secret_key = os.urandom(64)


@app.route("/")
def index():
	return "/"


@app.route("/login", methods=["GET", "POST"])
def login():
	if request.method == "GET":
		client_id = request.args.get("client_id")
		redirect_uri = request.args.get("redirect_uri")
		state = request.args.get("state")
		return render_template("login.html", title="Login", client_id=client_id, redirect_uri=redirect_uri, state=state)

	elif request.method == "POST":
		con, cur = get_db()
		res = cur.execute(
			"SELECT * FROM users WHERE username=?", (request.form.get("username"),)
		)
		user = res.fetchone()
		if user is None:
			flash("Username does not exist", "error")
			return redirect(url_for("login"))

		hasher = hashlib.sha512()
		hasher.update(bytes(request.form.get("password"), "ascii"))
		passhash = hasher.hexdigest()

		if passhash != user.get("passhash"):
			flash("Incorrect password", "error")
			return redirect(url_for("login"))
		
		client_id = request.form.get('client_id')
		redirect_uri = request.form.get('redirect_uri')
		state = request.form.get('state')

		code = f"testcode.{user['id']}"

		res = make_response(redirect(f"{redirect_uri}?state={state}&code={code}"))
		return res


@app.route("/token", methods=['POST'])
def token():
	code = request.form['code']
	user_id = code.split('.')[1]

	body = json.dumps({
		"access_token": f"Atza|{user_id}",
		"token_type": "bearer",
		"expires_in": 3600,
		"refresh_token": f"Atzr|{user_id}"
	})
	res = make_response(body)
	res.headers['Content-Type'] = 'application/json; charset UTF-8'
	res.headers['Cache-Control'] = 'no-store'
	res.headers['Pragma'] = 'no-cache'

	return user_id


@app.route("/register", methods=["GET", "POST"])
def register():
	if request.method == "GET":
		return render_template("register.html", title="Register")

	elif request.method == "POST":
		if request.form.get("username") == "":
			flash("Username cannot be empty", "error")
			return redirect(url_for("register"))

		if request.form.get("password") == "":
			flash("Password cannot be empty", "error")
			return redirect(url_for("register"))

		if request.form.get("password") != request.form.get("confirm-password"):
			flash("Passwords do not match", "error")
			return redirect(url_for("register"))

		con, cur = get_db()
		res = cur.execute(
			"SELECT * FROM users WHERE username=?", (request.form.get("username"),)
		)
		user = res.fetchone()
		if user is not None:
			flash("Username already exists", "error")
			return redirect(url_for("register"))

		hasher = hashlib.sha512()
		hasher.update(bytes(request.form.get("password"), "ascii"))
		passhash = hasher.hexdigest()

		cur.execute(
			"INSERT INTO users (username, passhash) VALUES (?, ?)",
			(request.form.get("username"), passhash),
		)
		con.commit()

		res = make_response(redirect(url_for("login")))
		return res


# @app.route("/auth")
# def auth():
#     # Describe the access request of the client and ask user for approval
#     client_id = request.args.get("client_id")
#     redirect_uri = request.args.get("redirect_uri")

#     if None in [client_id, redirect_uri]:
#         return json.dumps({"error": "invalid_request"}), 400

#     if not verify_client_info(client_id, redirect_uri):
#         return json.dumps({"error": "invalid_client"})

#     return render_template(
#         "AC_grant_access.html", client_id=client_id, redirect_uri=redirect_uri
#     )


# def process_redirect_uri(redirect_uri, authorization_code):
#     # Prepare the redirect URL
#     url_parts = list(urlparse.urlparse(redirect_uri))
#     queries = dict(urlparse.parse_qsl(url_parts[4]))
#     queries.update({"authorization_code": authorization_code})
#     url_parts[4] = urlencode(queries)
#     url = urlparse.urlunparse(url_parts)
#     return url


# @app.route("/signin", methods=["POST"])
# def signin():
#     # Issues authorization code
#     username = request.form.get("username")
#     password = request.form.get("password")
#     client_id = request.form.get("client_id")
#     redirect_uri = request.form.get("redirect_uri")

#     if None in [username, password, client_id, redirect_uri]:
#         return json.dumps({"error": "invalid_request"}), 400

#     if not verify_client_info(client_id, redirect_uri):
#         return json.dumps({"error": "invalid_client"})

#     if not authenticate_user_credentials(username, password):
#         return json.dumps({"error": "access_denied"}), 401

#     authorization_code = generate_authorization_code(client_id, redirect_uri)

#     url = process_redirect_uri(redirect_uri, authorization_code)

#     return redirect(url, code=303)


# @app.route("/token", methods=["POST"])
# def exchange_for_token():
#     # Issues access token
#     authorization_code = request.form.get("authorization_code")
#     client_id = request.form.get("client_id")
#     client_secret = request.form.get("client_secret")
#     redirect_uri = request.form.get("redirect_uri")

#     if None in [authorization_code, client_id, client_secret, redirect_uri]:
#         return json.dumps({"error": "invalid_request"}), 400

#     if not authenticate_client(client_id, client_secret):
#         return json.dumps({"error": "invalid_client"}), 400

#     if not verify_authorization_code(authorization_code, client_id, redirect_uri):
#         return json.dumps({"error": "access_denied"}), 400

#     access_token = generate_access_token()

#     return json.dumps(
#         {
#             "access_token": access_token.decode(),
#             "token_type": "JWT",
#             "expires_in": JWT_LIFE_SPAN,
#         }
#     )

if __name__ == "__main__":
	app.run(debug=True)
