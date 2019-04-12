from flask import Flask, jsonify, request, json
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'users'
app.config['MONGO_URI'] = 'mongodb://vbhv98:hovergames69@ds031257.mlab.com:31257/hover-games'
app.config['JWT_SECRET_KEY'] = 'xyzabc'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)


@app.route('/users/reglog', methods=['POST'])
def reg():
    users = mongo.db.users
    userid = request.get_json()['userid']
    password = request.get_json()['password']
    password_bcrypt = bcrypt.generate_password_hash(password).decode('utf-8')
    created = datetime.utcnow()

    if not users.find_one({'user_id': userid}) is None:
        response = users.find_one({'user_id': userid})

        if response:
            if bcrypt.check_password_hash(response['password'], password):
                access_token = create_access_token(
                    identity={'user_id': response['user_id']})
                return jsonify({'token': access_token, 'new': False})
            else:
                return jsonify({'error': 'invalid username and password'})
        else:
            return jsonify({'error': 'no result found'})

    id = users.insert({
        'user_id': userid,
        'password': password_bcrypt,
        'created': created
    })

    new_user = users.find_one({'_id': id})
    access_token = create_access_token(
        identity={'user_id': new_user['user_id']})
    return jsonify({'token': access_token, 'new': True})


@app.route('/users/guest')
def guest():
    users = mongo.db.users
    guest_id = users.insert({
        'user_id': 'guest',
        'password': 'guest',
        'created': datetime.utcnow()
    })
    return jsonify({'guest_id': str(guest_id)})


@app.route('/users/guestLogout/<id>')
def guestLogout(id):
    users = mongo.db.users
    return jsonify({'result': 'success'}) if not users.delete_one({'user_id': id}) is None else jsonify({'result': 'fail'})


if __name__ == '__main__':
    app.run()
