from flask import Flask, render_template, flash, redirect, url_for, session, request, logging, make_response, send_file, jsonify
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

import json
import random
import string
import httplib2

from oau.flask_oauth import OAuth

# app Init

app = Flask(__name__)
app.debug = True
app.secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in range(32))

# Google Config

GOOGLE_CLIENT_ID = '218171654775-qs4e5i7vb7bljb1k1vls4rdluqbepn2v.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'YzEs7EmNVK4zsTtH36J8m88w'
REDIRECT_URI = '/gCallback'  # one of the Redirect URIs from Google APIs console
SECRET_KEY = app.secret_key

# OAuth Init
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
                          consumer_secret=GOOGLE_CLIENT_SECRET
                        )

### PostGRE Sql for Heroku
# Will add code later

### MySQL for other
# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'abcd1234'
app.config['MYSQL_DB'] = 'test'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)

#Articles = Articles()

# Index
@app.route('/')
def index():
    return render_template('home.html')

@app.route('/google2a51ef9bab7ff250.html')
def googleverify():
    return render_template('google2a51ef9bab7ff250.html')

# About
@app.route('/about')
def about():
    return render_template('about.html')


# Articles
@app.route('/articles')
def articles():
    # Create cursor
    cur = mysql.connection.cursor()
    # Get articles
    result = cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()
    if result > 0:
        return render_template('articles.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('articles.html', msg=msg)
    # Close connection
    cur.close()


#Single Article
@app.route('/article/<string:id>/')
def article(id):
    cur = mysql.connection.cursor()
    # Get article
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article = cur.fetchone()
    return render_template('article.html', article=article)


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Registeration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        cur = mysql.connection.cursor()
        # Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))
        # Commit to DB
        mysql.connection.commit()
        # Close connection
        cur.close()
        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']
        cur = mysql.connection.cursor()
        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])
        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = data['username']

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
#@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    cur = mysql.connection.cursor()
    # Show articles only from the user logged in 
    result = cur.execute("SELECT * FROM articles WHERE author = %s", [session['username']])
    articles = cur.fetchall()
    if result > 0:
        return render_template('dashboard.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('dashboard.html', msg=msg)
    cur.close()

# Article Form Class
class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])

# Add Article
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)",(title, body, session['username']))
        mysql.connection.commit()
        cur.close()

        flash('Article Created', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_article.html', form=form)


# Edit Article
@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article = cur.fetchone()
    cur.close()
    # Get form
    form = ArticleForm(request.form)
    # Populate article form fields
    form.title.data = article['title']
    form.body.data = article['body']
    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']
        # Create Cursor
        cur = mysql.connection.cursor()
        app.logger.info(title)
        # Execute
        cur.execute ("UPDATE articles SET title=%s, body=%s WHERE id=%s",(title, body, id))
        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Article Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form=form)

# Delete Article
@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM articles WHERE id = %s", [id])
    mysql.connection.commit()
    cur.close()
    flash('Article Deleted', 'success')
    return redirect(url_for('dashboard'))

# Google Login

@app.route('/gcheck')
def gcheck():
    access_token = session.get('access_token')
    if access_token is None and 'logged_in' not in session:
        flash('No access token','danger')
        return redirect(url_for('login'))
    access_token = access_token[0]
    from urllib.request import Request, urlopen, URLError
    
    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)
    try:
        res = urlopen(req)
        userData = json.loads(res.read().decode('utf-8'))
        userData = jsonify(userData)
        session['username'] = 'trial'
        session['logged_in'] = True
        return redirect(url_for('index'))
    except URLError as e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            flash(e.code, 'danger')
            return redirect(url_for('login'))
            #return res.read()
        flash('Some error occured', 'error')
        return redirect(url_for('login'))
    
    # If user data exists in Our DB
    """cur = mysql.connection.cursor()
    # Get user by username
    result = cur.execute("SELECT * FROM users WHERE email = %s", [userData['email']])
    if result > 0:
        data = cur.fetchone()
        gid  = data['gid']
        if gid == userData['id']:
            session['id'] = data['id']
        else:
            session.pop('access_token', None)
            return redirect(url_for('login'))
    else:
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (userData['given_name'], userData['email'], userData['email'], None))
        mysql.connection.commit()
        cur.close()
        flash('You are now registered and logged in', 'success')"""
    flash ('Something went wrong','danger')
    return redirect(url_for('login'))
    

@app.route('/glogin')
def glogin():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)

@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('gcheck'))


@google.tokengetter
def get_access_token():
    return session.get('access_token')


if __name__ == '__main__':
    #app.secret_key='secret123456'
    app.run(debug=True)
