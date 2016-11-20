from __future__ import absolute_import

import json
import os
from urlparse import urlparse

from flask import Flask, render_template, request, redirect, session,jsonify, make_response
from flask_sslify import SSLify
from rauth import OAuth2Service
import requests
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

#Location API's
@app.route('/locations', methods=['GET'])
def show_addresses():
  all_addresses = g.db.execute('select id, nickname, location, latitude, longitude from addresses').fetchall()
  entries = [dict(id=address[0], nickname=address[1], location=address[2], latitude=address[3], longitude=address[4]) for address in all_addresses]
  return json.dumps(entries)
	
@app.route('/locations', methods=['POST'])
def create_address():
    try:
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
def show_address(address_id):
    try:
        user = User.query.filter_by(id=address_id).first_or_404()
        return jsonify({'id':user.id, 'name':user.name, 'address':user.address,'city':user.city,'state':user.state,'zip':user.zip,'coordinates':{'lat':user.lat,'lng':user.lng}})
    except IntegrityError:
        resp = jsonify({"IntegrityError": str(e)})
        resp.status_code = 404
        return resp

@app.route('/locations/<int:address_id>', methods=['PUT'])
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
