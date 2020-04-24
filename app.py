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

oauth_scopes = [
"https://www.googleapis.com/auth/userinfo.email", #gets google profile
"openid",
"https://www.googleapis.com/auth/userinfo.profile", #gets google email adress
]

app.secret_key = os.environ['SECRET_KEY']

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



app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/access')
def access():
	# docs = users_ref.stream()
	# for doc in docs:
	#     print(u'{} => {}'.format(doc.id, doc.to_dict()))
	if("user_info" in flask.session.keys()):
		print("user coming in")
		user = users_ref.where('email','==', flask.session["user_info"]["email"])
		password = gtd(user.get())[0]["password"]
		if(len(gtd(user.get()))):
			return render_template("access.html", logged_in = True, user_info=flask.session["user_info"], password=password)
		users_ref.document(ran_gen(6)).set({
	        'email': flask.session["user_info"]["email"],
	        'password': "",
	    })
		return render_template("access.html", logged_in = True, user_info=flask.session["user_info"], password=password)
	return render_template("access.html", logged_in = False)


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
		user_id = gtd(users_ref.where('email','==', flask.session["user_info"]["email"]).get())[0]["id"]
		users_ref.document(user_id).update({'password':request.json["pass"]})
		return redirect("/access")
	else:
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
