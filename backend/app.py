from __future__ import absolute_import

import json
import os
from urlparse import urlparse
from datetime import timedelta
from functools import update_wrapper

from flask import Flask, render_template, request, redirect, session,jsonify, make_response,url_for
from flask.ext.login import LoginManager, login_required, login_user, \
    logout_user, current_user, UserMixin
from flask_sslify import SSLify
from flask_oauth import OAuth
import requests
from requests.exceptions import HTTPError
import urllib, urllib2

from model import db
from model import User
from model import CreateDB
from model import app as application
from sqlalchemy.exc import IntegrityError,SQLAlchemyError
import os

app = Flask(__name__)
app.requests_session = requests.Session()
app.secret_key = os.urandom(24)

sslify = SSLify(app)

GOOGLE_CLIENT_ID = '786919166452-v1h1kp81u4h1bsrhf1fp9eibt8ree1of.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '_Cbad7k6yXdmSnSDF9NHPt1f'
REDIRECT_URI = '/gCallback'

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

oauth = OAuth()
 
google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)


def crossdomain(origin=None, methods=None, headers=None,
                max_age=21600, attach_to_all=True,
                automatic_options=True):
    if methods is not None:
        methods = ', '.join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, basestring):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, basestring):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods

        options_resp = app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if automatic_options and request.method == 'OPTIONS':
                resp = app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))
            if not attach_to_all and request.method != 'OPTIONS':
                return resp

            h = resp.headers

            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator
 
@app.route('/')
@login_required
def index():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))
 
    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError
 
    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            return redirect(url_for('login'))
        return res.read()
 
    return res.read()
 
 
@app.route('/login')
def login():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)
 
 
 
@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('index'))
 
 
@google.tokengetter
def get_access_token():
    return session.get('access_token')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


#Location API's
@app.route('/locations', methods=['GET'])
def show_addresses():
  all_addresses = g.db.execute('select id, nickname, location, latitude, longitude from addresses').fetchall()
  entries = [dict(id=address[0], nickname=address[1], location=address[2], latitude=address[3], longitude=address[4]) for address in all_addresses]
  return json.dumps(entries)
	
@app.route('/locations', methods=['POST'])
@crossdomain(origin='*')
def create_address():
    try:
        print request
        name = request.json['name']
        address = request.json['address']
        city = request.json['city']
        state = request.json['state']
        zip = request.json['zip']
        params = {
                'address' : address+city+state,
                'sensor' : 'false',
        }  

        url = 'http://maps.google.com/maps/api/geocode/json?' + urllib.urlencode(params)
        response = urllib2.urlopen(url)
        result = json.load(response)
        
        place = result['results'][0]['geometry']['location']

        database = CreateDB(hostname='127.0.0.1')
        db.create_all()
        user = User(name,address,city,state,zip,place['lat'],place['lng'])
        db.session.add(user)
        db.session.commit()

        response = jsonify({'id':user.id,'name':request.json['name'], 'address':request.json['address'],'city':request.json['city'],'state':request.json['state'],'zip':request.json['zip'],
        'coordinates':place})
        response.status_code = 201
        return response
    except IntegrityError as e:
                db.session.rollback()
                resp = jsonify({"IntegrityError": str(e)})
                resp.status_code = 403
                return resp
    except SQLAlchemyError as e:
                db.session.rollback()
                resp = jsonify({"error": str(e)})
                resp.status_code = 403
                return resp

@app.route('/locations/<address_id>')
@crossdomain(origin='*')
@login_required
def show_address(address_id):
    try:
        user = User.query.filter_by(id=address_id).first_or_404()
        return jsonify({'id':user.id, 'name':user.name, 'address':user.address,'city':user.city,'state':user.state,'zip':user.zip,'coordinates':{'lat':user.lat,'lng':user.lng}})
    except IntegrityError:
        resp = jsonify({"IntegrityError": str(e)})
        resp.status_code = 404
        return resp

@app.route('/locations/<int:address_id>', methods=['PUT'])
@crossdomain(origin='*')
def edit_address(address_id):
	try:
		user = User.query.get(address_id)
		data = json.loads(request.data)
		user.name = data['name']
		db.session.commit()
		resp = jsonify({"result":True})
		resp.status_code = 202
		return resp

	except IntegrityError as e:
                db.session.rollback()
                resp = jsonify({"IntegrityError": str(e)})
                resp.status_code = 403
                return resp

@app.route('/locations/<int:address_id>', methods=['DELETE'])
@crossdomain(origin='*')
def delete_address(address_id):
    try:
        db.session.delete(User.query.get(address_id))
        db.session.commit()
        resp = jsonify({"result":True})
        resp.status_code = 204
        return resp

    except IntegrityError as e:
        resp = jsonify({"IntegrityError": str(e)})
        resp.status_code = 404
        return resp


if __name__ == '__main__':
    app.debug = os.environ.get('FLASK_DEBUG', True)
    app.run(port=7000)
