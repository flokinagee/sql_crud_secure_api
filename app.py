import sys
sys.path.insert(0, '/Users/mahaakutty/Library/homebrew/lib/python3.7/site-packages')
from flask import Flask, render_template, url_for, flash, redirect, session, logging, request, jsonify
import mysql.connector
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

# Define JWT
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

app = Flask(__name__)
# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'nagarajans'  # Change this!
jwt = JWTManager(app)

# Config MySQL
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="naga1234",
    database="myflaskapp"
)

# Index
@app.route('/')
def index():
    return render_template('home.html')

# About
@app.route('/about')
def about():
    return render_template('about.html')

# Articles
@app.route('/articles')
def articles():
    mycursor = mydb.cursor(dictionary=True)
    mycursor.execute("SELECT * FROM articles")
    result = mycursor.fetchall()
    if result:
        return render_template('articles.html', articles=result)
    else:
        msg = 'No Articles Found'
        return render_template('articles.html', msg=msg)
    mycursor.close()

#Single Article
@app.route('/find_article/<string:id>/')
def find_article(id):
    mycursor = mydb.cursor(dictionary=True)
    mycursor.execute("SELECT * FROM articles WHERE id = %s", [id])
    result = mycursor.fetchone()
    return render_template('find_article.html', article=result)
    mycursor.close()

# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [validators.DataRequired(),validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password')

# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        mycursor = mydb.cursor()
        mycursor.execute("INSERT INTO users (name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))
        mydb.commit()
        mycursor.close()

        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        mycursor = mydb.cursor(dictionary=True)
        mycursor.execute("SELECT * FROM users WHERE username = %s", [username])
        result = mycursor.fetchone()
        if result:
            password = result['password']
            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            mycursor.close()
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
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    mycursor = mydb.cursor(dictionary=True)
    mycursor.execute("SELECT * FROM articles WHERE author = %s", [session['username']])
    result = mycursor.fetchall()
    if result:
        return render_template('dashboard.html', articles=result)
    else:
        msg = 'No Articles Found'
        return render_template('dashboard.html', msg=msg)
    mycursor.close()

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

        mycursor = mydb.cursor()
        mycursor.execute("INSERT INTO articles (title, body, author) VALUES (%s, %s, %s)",(title, body, session['username']))
        mydb.commit()
        mycursor.close()

        flash('Article Created', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)

# Edit Article
@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    mycursor = mydb.cursor(dictionary=True)
    mycursor.execute("SELECT * FROM articles WHERE id = %s", [id])
    result = mycursor.fetchone()
    mycursor.close()

    form = ArticleForm(request.form)
    form.title.data = result['title']
    form.body.data = result['body']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']

        mycursor = mydb.cursor()
        app.logger.info(title)
        mycursor.execute("UPDATE articles SET title=%s, body=%s WHERE id=%s",(title, body, id))
        mydb.commit()
        mycursor.close()

        flash('Article Updated', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form=form)

# Delete Article
@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    mycursor = mydb.cursor()
    mycursor.execute("DELETE FROM articles WHERE id = %s", [id])
    mydb.commit()
    mycursor.close()

    flash('Article Deleted', 'success')
    return redirect(url_for('dashboard'))

# API SECTION
@app.route('/api/v1/login', methods=['GET', 'POST'])
def api_login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        mycursor = mydb.cursor(dictionary=True)
        mycursor.execute("SELECT * FROM users WHERE username = %s", [username])
        result = mycursor.fetchone()
        if result:
            password = result['password']
            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = username

                # flash('You are now logged in', 'success')
                # return redirect(url_for('dashboard'))
                # Identity can be any data that is json serializable
                access_token = create_access_token(identity=username)
                return jsonify(access_token=access_token), 200
            else:
                error = 'Invalid login'
                return jsonify(error), 403
            mycursor.close()
        else:
            error = 'Username not found'
            return jsonify(error), 403
    return jsonify("username not found"), 403

# Dashboard API
@app.route('/api/v1/dashboard')
@jwt_required
def api_dashboard():
    mycursor = mydb.cursor(dictionary=True)
    mycursor.execute("SELECT * FROM articles WHERE author = %s", [session['username']])
    result = mycursor.fetchall()
    if result:
        return render_template('dashboard.html', articles=result)
    else:
        msg = 'No Articles Found'
        return render_template('dashboard.html', msg=msg)
    mycursor.close()

# @app.route('/api/v1/adduser')
# def api_add_user():
#         _json = request.json
#         customer_id = _json['customer_id']
#         name = _json['name']
#         email = _json['email']
#         surname = _json['surname']
#         # validate the received values
#         if name and email and password and request.method == 'POST':
#             # save details
#             id = db.add({'customer_id': customer_id, 'name': name, 'email': email, 'surname': surname})
#             resp = jsonify('User added successfully!')
#             resp.status_code = 200
#             return resp
#         else:
#             return not_found()


# @app.route('/api/v1/listusers')
# def api_get_users():
#         try:
#                 rows = db.get_data()
#                 resp = dumps(rows, indent=4)
#                 # resp = json.dumps(rows, indent=4)
#                 return resp
#         except Exception as e:
#                 print(e)

# @app.route('/api/v1/listuser/<customer_id>')
# def api_get_user(customer_id):
#         try:
#                 user = db.get_customer(customer_id)
#                 resp = dumps(rows, indent=4)
#                 # resp = json.dumps(user, indent=4)
#                 return resp
#         except Exception as e:
#                 print(e)

# @app.route('/api/v1/update/<customer_id>', methods=['PUT'])
# def api_update_user(customer_id):
#     try:
#         _json = request.json
#         customer_id = _json['customer_id']
#         name = _json['name']
#         email = _json['email']
#         surname = _json['surname']
#         # validate the received values
#         if name and email and surname and customer_id and request.method == 'PUT':
#             # save edits
#             db.update({'customer_id': customer_id, 'name': name, 'email': email, 'surname': surname})
#             resp = jsonify('User updated successfully!')
#             resp.status_code = 200
#             return resp
#         else:
#             return not_found()
#     except Exception as e:
#         print(e)
#         print("in update")

# @app.route('/api/v1/delete/<customer_id>', methods=['DELETE'])
# def api_delete_user(customer_id):
# 	db.delete(customer_id)
# 	resp = jsonify('User deleted successfully!')
# 	resp.status_code = 200
# 	return resp


if __name__ == "__main__":
    app.secret_key = 'nagarajan'
    app.run(debug=True)
