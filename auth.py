from flask import Blueprint, render_template, request, redirect, session, url_for
from models import register_user, verify_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = verify_user(request.form['username'], request.form['password'])
        if user_id:
            session['user_id'] = user_id
            session['username'] = request.form['username']
            return redirect('/')
        return render_template('login.html', error="Invalid credentials.")
    return render_template('login.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        success = register_user(username, password, email)
        if success:
            return redirect('/login')
        else:
            return "User with that username or email already exists.", 400
    return render_template('register.html')


@auth.route('/logout')
def logout():
    session.clear()
    return redirect('/login')
