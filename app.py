from flask import Flask, render_template, url_for, request, session, redirect
from flask_pymongo import PyMongo
import bcrypt
import config
import sys
import vt
import util as master

# can grab link, now need to begin implementing apis and stuff to do calculation
app = Flask(__name__)
mongo = config.connect(app)


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('url'))

    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    users = mongo.db.users
    login_user = users.find_one({'name': request.form['username']})

    if login_user:
        # cannot use encode in comparison because the gensalt makes it byte

        if bcrypt.hashpw(request.form['pass'].encode('utf-8'), login_user['password']) == login_user['password']:
            session['username'] = request.form['username']
            return redirect(url_for('index'))

    return 'Invalid username/password combination'


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        users = mongo.db.users
        existing_user = users.find_one({'name': request.form['username']})

        if existing_user is None:
            hashpass = bcrypt.hashpw(request.form['pass'].encode('utf-8'), bcrypt.gensalt())
            users.insert({'name': request.form['username'], 'password': hashpass})
            session['username'] = request.form['username']
            return redirect(url_for('index'))

        return 'That username already exists!'

    return render_template('register.html')

#TODO: fix how the rendering is not actually displaying the message
@app.route('/url', methods=['POST','GET'])
# method name should be same as route name so do not get confused with html
def url():
    if 'username' not in session:
        return redirect(url_for('index'))
    url = mongo.db.urls

    if request.method == 'GET':
        return render_template('url.html')

    if request.method=='POST':
        if request.form['url']:
            if url.find_one({'url': request.form['url']}) is None:
            # check if url exists in url DB, if so report result otherwise send to scan
            # after scans add url user and result
                score = master.performScan(request.form['url'])
                url.insert({'url': request.form['url'], 'user': session["username"], 'score': score })

            score = url.find_one({'url':request.form['url']})["score"]
            if score == 0:
                return redirect(url_for('clean')) #give result based on score entry


            return redirect(url_for('virus'))

@app.route('/virus', methods=['POST','GET'])
def virus():
    return render_template('virus.html')

@app.route('/clean', methods=['POST','GET'])
def clean():
    return render_template('clean.html')





if __name__ == '__main__':
    app.secret_key = 'mysecret'
    app.run(debug=True)
