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

END_LATITUDE=0
END_LONGITUDE=0
USER_EMAIL='none'


UBER_CLIENT_ID = 'YO5_U3M_6NJFHjCrTYjq8Cv-HRHeK0St'
UBER_SERVER_TOKEN = 'BA5f0EmvAeZsZCwayyrS2LpjEJreWdp8kHifJktD'

with open('config.json') as f:
    config = json.load(f)

app = Flask(__name__)
app.secret_key = 'iwonttellyou'
app.requests_session = requests.Session()
 
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
 
#GOOGLE AUTHENTICATION CALLS###########################################################
redirect_uri = 'http://localhost:7000/gCallback'
client_id = '786919166452-v1h1kp81u4h1bsrhf1fp9eibt8ree1of.apps.googleusercontent.com'  # get from https://code.google.com/apis/console
client_secret = '_Cbad7k6yXdmSnSDF9NHPt1f'

auth_uri = 'https://accounts.google.com/o/oauth2/auth'
token_uri = 'https://accounts.google.com/o/oauth2/token'
scope = ('https://www.googleapis.com/auth/userinfo.profile',
         'https://www.googleapis.com/auth/userinfo.email')
profile_uri = 'https://www.googleapis.com/oauth2/v1/userinfo'


@app.route('/')
def index():
    if 'email' not in session:
        return render_template(
        'index.html',
    )
    else:
        return render_template(
        'maps.html',
    )


@app.route('/logout')
def logout():
    session.pop('email', '')
    return redirect(url_for('index'))


@app.route('/login')
def login():
    # Step 1
    params = dict(response_type='code',
                  scope=' '.join(scope),
                  client_id=client_id,
                  approval_prompt='force',  # or 'auto'
                  redirect_uri=redirect_uri)
    url = auth_uri + '?' + urllib.urlencode(params)
    return redirect(url)


@app.route('/gCallback')
def callback():
    if 'code' in request.args:
        # Step 2
        code = request.args.get('code')
        data = dict(code=code,
                    client_id=client_id,
                    client_secret=client_secret,
                    redirect_uri=redirect_uri,
                    grant_type='authorization_code')
        r = requests.post(token_uri, data=data)
        # Step 3
        access_token = r.json()['access_token']
        r = requests.get(profile_uri, params={'access_token': access_token})
        session['email'] = r.json()['email']
        USER_EMAIL = r.json()['email']
        return redirect(url_for('index'))
    else:
        return 'ERROR'


#Location API's
@app.route('/locations', methods=['GET'])
def show_addresses():
        all_addresses = User.query.with_entities(User.id, User.name)
        entries = [dict(id=address[0], name=address[1]) for address in all_addresses]
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
            user = User(name,address,city,state,zip,place['lat'],place['lng'],USER_EMAIL)
            db.session.add(user)
            db.session.commit()

            response = jsonify({'id':user.id,'name':request.json['name'], 'address':request.json['address'],'city':request.json['city'],'state':request.json['state'],'zip':request.json['zip'],
            'coordinates':place,'email':USER_EMAIL})
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
def show_address(address_id):
    if 'email' not in session:
        return 'Please <a href="/login">login</a>'
    else:
        try:
            user = User.query.filter_by(id=address_id).first_or_404()
            return jsonify({'id':user.id, 'name':user.name, 'address':user.address,'city':user.city,'state':user.state,'zip':user.zip,'email':user.email,'coordinates':{'lat':user.lat,'lng':user.lng}})
        except IntegrityError:
            resp = jsonify({"IntegrityError": str(e)})
            resp.status_code = 404
            return resp

@app.route('/locations/<int:address_id>', methods=['PUT'])
@crossdomain(origin='*')
def edit_address(address_id):
    if 'email' not in session:
        return 'Please <a href="/login">login</a>'
    else:
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
    if 'email' not in session:
        return 'Please <a href="/login">login</a>'
    else:
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



####################################################################################################################################
##UBER APIS##


def generate_ride_headers(token):
    """Generate the header object that is used to make api requests."""
    return {
        'Authorization': 'Token %s' % token,
        'Content-Type': 'application/json',
    }


@app.route('/health', methods=['GET'])
def health():
    """Check the status of this application."""
    return ';-)'


@app.route('/', methods=['GET'])
def signup():
    """The first step in the three-legged OAuth handshake.

    You should navigate here first. It will redirect to login.uber.com.
    
    params = {
        'response_type': 'code',
        'redirect_uri': get_redirect_uri(request),
        'scopes': ','.join(config.get('scopes')),
    }
    url = generate_oauth_service().get_authorize_url(**params)
    return redirect(url)"""
    return "The app is working"


@app.route('/submit', methods=['GET'])
def submit():
    """The other two steps in the three-legged Oauth handshake.

    Your redirect uri will redirect you here, where you will exchange
    a code that can be used to obtain an access token for the logged-in use.
    """
    params = {
        'redirect_uri': get_redirect_uri(request),
        'code': request.args.get('code'),
        'grant_type': 'authorization_code'
    }
    response = app.requests_session.post(
        config.get('access_token_url'),
        auth=(
            os.environ.get('UBER_CLIENT_ID'),
            os.environ.get('UBER_CLIENT_SECRET')
        ),
        data=params,
    )
    session['access_token'] = response.json().get('access_token')

    return render_template(
        'success.html',
        token=response.json().get('access_token')
    )


@app.route('/demo', methods=['GET'])
def demo():
    """Demo.html is a template that calls the other routes in this example."""
    return render_template('demo.html', token=session.get('access_token'))



@app.route('/trips', methods=['POST'])
def trip():
    try:
        id_start=request.json['start']
        id_end = request.json['end']
        user1 = User.query.filter_by(id=id_start).first_or_404()
            #return jsonify({'id':user.id, 'name':user.name, 'address':user.address,'city':user.city,'state':user.state,'zip':user.zip,'email':user.email,'coordinates':{'lat':user.lat,'lng':user.lng}})
        user2 = User.query.filter_by(id=id_end).first_or_404()

    except IntegrityError:
        resp = jsonify({"IntegrityError": str(e)})
        resp.status_code = 404
        return resp


    url = config.get('base_uber_url') + 'estimates/price'
    params = {
        'start_latitude': user1.lat,
        'start_longitude': user1.lng,
        'end_latitude': user2.lat,
        'end_longitude': user2.lng,
    }

    response = requests.get(
        url,
        headers=generate_ride_headers(UBER_SERVER_TOKEN),
        params=params,
    )

    data = json.loads(response.text)

    #string = json.dumps(response.text).read().decode('utf-8')
    #json_obj = json.loads(string)

    price = data['prices'][1]['estimate']
    currency = data['prices'][1]['currency_code']
    time = data['prices'][1]['duration']
    distance = data['prices'][1]['distance']
    res = jsonify({'name':"Uber",'total_costs_by_cheapest_car_type':price, 'currency_code':currency,'total_duration':time,'duration_unit':"seconds",'total_distance':distance,
    'distance_unit':"miles"})

    if response.status_code != 200:
        return 'There was an error', response.status_code
    return res
    """render_template(
        'results.html',
        endpoint='price',
        data=res,
    ) """



@app.route('/me', methods=['GET'])
def me():
    """Return user information including name, picture and email."""
    url = config.get('base_uber_url') + 'me'
    response = app.requests_session.get(
        url,
        headers=generate_ride_headers(session.get('access_token')),
    )

    if response.status_code != 200:
        return 'There was an error', response.status_code
    return render_template(
        'results.html',
        endpoint='me',
        data=response.text,
    )


def get_redirect_uri(request):
    """Return OAuth redirect URI."""
    parsed_url = urlparse(request.url)
    if parsed_url.hostname == 'localhost':
        return 'http://{hostname}:{port}/submit'.format(
            hostname=parsed_url.hostname, port=parsed_url.port
        )
    return 'https://{hostname}/submit'.format(hostname=parsed_url.hostname)




if __name__ == '__main__':
    app.debug = os.environ.get('FLASK_DEBUG', True)
    app.run(port=7000)
