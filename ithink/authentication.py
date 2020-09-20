import re

from flask import (Blueprint, session, g, url_for, request, render_template,
                   flash)
from werkzeug.utils import redirect

from ithink.database import get_database
from ithink.security.cryptography import ascii_encrypt, ascii_decrypt

authentication = Blueprint('authentication', __name__,
                           url_prefix='/authentication')


@authentication.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('authentication/login.html')
    elif request.method == 'POST':
        error = None
        if request.form['email'] == '':
            error = 'You must enter your email!'
        elif request.form['password'] == '':
            error = 'You must enter your password!'
        if error is None:
            email = ascii_encrypt(request.form['email'])
            password = ascii_encrypt(request.form['password'])
            database = get_database()
            test_user = database.execute('SELECT * FROM Users '
                                         'WHERE Email=? and Password=?',
                                         (email, password,)).fetchone()
            if test_user is None:
                error = 'Incorrect email or password!'
            else:
                session.clear()
                session['user_id'] = test_user['Id']
                return redirect(url_for('blog.index'))
        flash(error)
        return render_template('authentication/login.html')


@authentication.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'GET':
        return render_template('authentication/registration.html')
    elif request.method == 'POST':
        error = None
        regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        if request.form['username'] == '':
            error = 'You must enter your username!'
        elif request.form['email'] == '':
            error = 'You must enter your email!'
        elif request.form['password'] == '':
            error = 'You must enter your password!'
        elif len(request.form['username']) < 2:
            error = 'Your username is too short, it must be at least 2 ' \
                    'symbols long!'
        elif len(request.form['password']) < 8:
            error = 'Your password is too short, it must be at least 8 ' \
                    'symbols long!'
        elif len(request.form['username']) > 256:
            error = 'Your username is to long, it must be shorter then 256 ' \
                    'symbols!'
        elif len(request.form['password']) > 256:
            error = 'Your password is to long, it must be shorter then 256 ' \
                    'symbols!'
        elif re.search(regex, request.form['email']) is None:
            error = 'Email is invalid, please check it out again!'
        if error is None:
            username = ascii_encrypt(request.form['username'])
            email = ascii_encrypt(request.form['email'])
            password = ascii_encrypt(request.form['password'])
            database = get_database()
            test_user = database.execute('SELECT * FROM Users '
                                         'WHERE Email=?', (email,)).fetchone()
            if test_user is None:
                database.execute('INSERT INTO Users '
                                 '(Username, Email, Password) '
                                 'VALUES (?, ?, ?)', (username, email,
                                                      password))
                database.commit()
                return redirect(url_for('authentication.login'))
            else:
                error = 'Sorry, but this user already exists!'
        flash(error)
        return render_template('authentication/registration.html')


@authentication.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('blog.index'))


@authentication.route('/edit', methods=['GET', 'POST'])
def edit():
    if request.method == 'GET':
        database = get_database()
        user_id = session.get('user_id')
        if user_id is not None:
            test_user = database.execute('SELECT * FROM Users '
                                         'WHERE Id=?', (user_id,)).fetchone()
            if test_user is not None:
                g.username = ascii_decrypt(test_user['Username'])
                g.email = ascii_decrypt(test_user['Email'])
                g.posts = database.execute('SELECT * FROM Posts '
                                           'WHERE Id=?', (user_id,)).fetchall()
                return render_template('authentication/edit.html')
        return redirect('blog.index')
    elif request.method == 'POST':
        error = None
        regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        if request.form['username'] == '':
            error = 'You must enter your username!'
        elif request.form['email'] == '':
            error = 'You must enter your email!'
        elif request.form['password'] == '':
            error = 'You must enter your password!'
        elif len(request.form['username']) < 2:
            error = 'Your username is too short, it must be at least 2 ' \
                    'symbols long!'
        elif len(request.form['password']) < 8:
            error = 'Your password is too short, it must be at least 8 ' \
                    'symbols long!'
        elif len(request.form['username']) > 256:
            error = 'Your username is to long, it must be shorter then 256 ' \
                    'symbols!'
        elif len(request.form['password']) > 256:
            error = 'Your password is to long, it must be shorter then 256 ' \
                    'symbols!'
        elif re.search(regex, request.form['email']) is None:
            error = 'Email is invalid, please check it out again!'
        if error is None:
            username = ascii_encrypt(request.form['username'])
            email = ascii_encrypt(request.form['email'])
            password = ascii_encrypt(request.form['password'])
            database = get_database()
            test_user = database.execute('SELECT * FROM Users '
                                         'WHERE Email=?', (email,)).fetchone()
            if test_user is not None:
                database.execute('UPDATE Users SET '
                                 'Username=?, Email=?, Password=? '
                                 'WHERE Id=?', (username, email,
                                                password, test_user['Id'],))
                database.commit()
                return redirect(url_for('blog.index'))
            else:
                error = 'Sorry, but this user already exists!'
        flash(error)
        return render_template('authentication/edit.html')


@authentication.route('/delete', methods=['GET', 'POST'])
def delete():
    if request.method == 'GET':
        return render_template('authentication/delete.html')
    elif request.method == 'POST':
        error = None
        user_id = session.get('user_id')
        if user_id is not None:
            password = ascii_encrypt(request.form['password'])
            database = get_database()
            test_user = database.execute('SELECT * FROM Users '
                                         'WHERE Id=? and Password=?',
                                         (user_id, password)).fetchone()
            if test_user is not None:
                database.execute('DELETE FROM Users '
                                 'WHERE Id=?', (user_id,))
                database.execute('DELETE FROM Posts '
                                 'Where Author=?', (user_id,))
                database.execute('DELETE FROM Comments '
                                 'WHERE Post=(SELECT Id FROM Posts '
                                 'WHERE Author=?)', (user_id,))
                database.execute('DELETE FROM Comments '
                                 'WHERE Author=?', (user_id,))
                database.commit()
                session.clear()
            else:
                error = 'Could not find such user!'
        else:
            error = 'Some cache error!'
        if error is None:
            return redirect(url_for('blog.index'))
        else:
            flash(error)
            return render_template('authentication/delete.html')
