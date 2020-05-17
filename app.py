from flask import Flask, render_template, redirect, request

import flask

import google.oauth2.credentials
import google_auth_oauthlib.flow

import datetime
import json

import os
import ast
import string

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
import random

from flask_cors import CORS

oauth_scopes = [
"https://www.googleapis.com/auth/userinfo.email", #gets google profile
"openid",
"https://www.googleapis.com/auth/userinfo.profile", #gets google email adress
]


admins=[
	"acanberk21@lawrenceville.org",
	"ahasan20@lawrenceville.org",
	"ekosoff@lawrenceville.org",
	"tgachuega20@lawrenceville.org",
]


def email_to_school(email):
    special_indexes = []
    for x in range(0, len(email)):
        if email[x] == "." or email[x] == "@":
            special_indexes.append(x)
    return email[special_indexes[-2]+1:special_indexes[-1]]

def ran_gen(size, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

def gtd(generator):
    list = []
    for element in generator:
        n_dict = element.to_dict()
        n_dict['id'] = element.id
        list.append(n_dict)
    return list


firebase_credentials = ast.literal_eval(os.environ['FIREBASE_CREDENTIALS'])
cred = credentials.Certificate(firebase_credentials)
firebase_admin.initialize_app(cred)
db = firestore.client()

users_ref = db.collection('users')
connect_ref = db.collection('connect')
pinner_ref = db.collection('pinner_requests')


app = Flask(__name__)
CORS(app)
app.secret_key = os.environ['SECRET_KEY']

@app.route('/')
def index():
	if("user_info" in flask.session.keys()):
		return render_template("index.html", logged_in = True)
	else:
		return render_template("index.html", logged_in = False)

@app.route('/why-nexus')
def why_nexus():
	return render_template("why-nexus.html")

@app.route('/connect')
def connect():
    return render_template("connect.html")

@app.route('/set_pinner', methods=['POST'])
def setpinner():

	print(json.loads(request.data))

	pinner_email = json.loads(request.data)["pinner_email"]
	pinner_name = json.loads(request.data)["pinner_name"]

	if(pinner_email == "" or pinner_name == ""):
		return "Email name or email field, try again."

	found_by_email = gtd(users_ref.where('email', '==', pinner_email).get())
	found_by_name = gtd(users_ref.where('name', '==', pinner_email).get())

	if(len(found_by_name) or len(found_by_email)):
		found_by_name[0].update({
				"pinner_name":pinner_name,
				"pinner_email":pinner_email
			})
		return "Pinner set!"

	return "Pinner could not be found. Are you sure your pinner has signed up yet?"

@app.route('/receive_connect', methods=['POST'])
def receiveconnect():
	data = request.form
	connect_ref.document(ran_gen(8)).set({
		        'email': data["email"],
		        'name': data["name"],
		        'last_name': data["surname"],
		        'need':data["need"],
		        'message':data["message"],
		    })

	return redirect('/')

@app.route('/register')
def register():
	return render_template("register.html")

@app.route('/access')
def access():
	if("user_info" in flask.session.keys()):
		user = users_ref.where('email','==', flask.session["user_info"]["email"])
		if(len(gtd(user.stream()))):
			password = gtd(user.stream())[0]["password"]
			return render_template("portals/"+email_to_school(flask.session["user_info"]["email"])+".html", user_info=flask.session["user_info"], isStudent = ('2' in flask.session["user_info"]["email"]) )
		users_ref.document(ran_gen(6)).set({
	        'email': flask.session["user_info"]["email"],
	        'password': "",
	        'name': flask.session["user_info"]["name"],
	        'school':email_to_school(flask.session["user_info"]["email"]),
	        'isStudent':('2' in flask.session["user_info"]["email"]),
	    })
		return redirect('/register')
	return redirect('/')

@app.route('/auth/google')
def auth():

    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow stepsself.
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
      json.loads(os.environ['CLIENT_SECRET']),#os.environ['CLIENT_SECRET']
      scopes=oauth_scopes,
      redirect_uri= flask.request.url_root + 'oauth2callback'
    )

    authorization_url, state = flow.authorization_url(
      prompt='consent',
      include_granted_scopes='true')

    flask.session['state'] = state

    return redirect(authorization_url)

@app.route('/changepass', methods=['POST'])
def changepass():
	if(request.method == 'POST'):
		user_id = gtd(users_ref.where('email','==', flask.session["user_info"]["email"]).stream())[0]["id"]
		users_ref.document(user_id).update({'password':request.json["pass"]})
		return redirect("/access")
	else:
		return "sneaky sneaky"


@app.route('/authenticate_with_unity', methods=['POST'])
def authenticate_with_unity():
	if(request.method == 'POST'):

		print("second line")

		data = request.form
		user = gtd(users_ref.where('email','==', data["email"]).stream())

		print(type(data["email"]))

		if(len(user) != 0):
			print("user")
			print(gtd(users_ref.where('email','==', request.form["email"]).stream())[0])
			user = user[0]
			print("comparing passwords")
			print(user["password"])
			print(data["password"])
			if(user["password"] == data["password"]):
				print("right password")
				return json.dumps({
					"code":0,
					"admin":(True if data["email"] in admins else False),
					"name":user["name"],
					"isStudent":(user["isStudent"])
				})
			return json.dumps({
				"code":403,
				"admin":False,
				"name":""
			})
		return json.dumps({
			"code":404,
			"admin":False,
			"name":""
		})
	else:
		print("method not post")
		return "sneaky sneaky"

def credentials_to_dict(credentials):
    return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

@app.route('/oauth2callback')
def oauth2callback():
    state = flask.session['state']
    flow = google_auth_oauthlib.flow.Flow.from_client_config(json.loads(os.environ['CLIENT_SECRET']), scopes=oauth_scopes, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    print(credentials_to_dict(credentials))
    flask.session['credentials'] = credentials_to_dict(credentials)

    if flask.session['credentials']['refresh_token'] == None:
        flask.session['credentials']['refresh_token'] = "1/NWvP0mjD4Vp3xs22FkvdqWHw-_7VUyC2VN7zcsthHcw"

    session = flow.authorized_session()
    user_info = session.get('https://www.googleapis.com/userinfo/v2/me').json()

    flask.session["user_info"] = user_info

    return redirect("/access")

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    flask.session.pop('credentials', None)
    flask.session.pop('state', None)
    flask.session.pop('user_info', None)
    return redirect('/access')

if __name__ == "__main__":
	app.config['SESSION_TYPE'] = 'filesystem'
	app.run()
