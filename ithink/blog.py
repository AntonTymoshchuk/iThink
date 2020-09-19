from flask import Blueprint, session, g, render_template, request, url_for, \
    flash
from werkzeug.utils import redirect

from ithink.database import get_database
from ithink.security.cryptography import ascii_encrypt, ascii_decrypt

blog = Blueprint('blog', __name__)


@blog.route('/')
def index():
    database = get_database()
    user_id = session.get('user_id')
    if user_id is not None:
        test_user = database.execute('SELECT * FROM Users '
                                     'WHERE Id=?', (user_id,)).fetchone()
        if test_user is not None:
            g.username = ascii_decrypt(test_user['Username'])
            g.posts = database.execute('SELECT * FROM Posts '
                                       'WHERE Id=?', (user_id,)).fetchall()
    enc_posts = database.execute('SELECT * FROM Posts '
                                 'ORDER BY Created DESC').fetchall()
    g.posts = []
    for enc_post in enc_posts:
        author = database.execute('SELECT * FROM Users WHERE Id=?',
                                  (enc_post['Author'],)).fetchone()
        author = ascii_decrypt(author['Username'])
        post = {'Id': enc_post['Id'],
                'Theme': ascii_decrypt(enc_post['Theme']),
                'Content': ascii_decrypt(enc_post['Content']),
                'Created': enc_post['Created'],
                'Author': author}
        g.posts.append(post)
    return render_template('blog/blog.html')


@blog.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'GET':
        return render_template('blog/create.html')
    elif request.method == 'POST':
        error = None
        if request.form['theme'] is None:
            error = 'You must enter a theme of your post!'
        elif request.form['content'] is None:
            error = 'You must enter some text of your post!'
        elif len(request.form['theme']) < 2:
            error = 'Your theme is too short, it must be at least 2 ' \
                    'symbols long!'
        elif len(request.form['theme']) > 256:
            error = 'Your theme is to long, it must be shorter then 256 ' \
                    'symbols!'
        if error is None:
            user_id = session.get('user_id')
            if user_id is not None:
                database = get_database()
                test_user = database.execute('SELECT * FROM Users '
                                             'WHERE Id=?',
                                             (user_id,)).fetchone()
                if test_user is not None:
                    theme = ascii_encrypt(request.form['theme'])
                    content = ascii_encrypt(request.form['content'])
                    database = get_database()
                    database.execute('INSERT INTO Posts'
                                     '(Author, Theme, Content) '
                                     'VALUES (?, ?, ?)',
                                     (session.get('user_id'),
                                      theme, content,))
                    database.commit()
                    return redirect(url_for('blog.index'))
                else:
                    error = 'Could not find such user!'
            else:
                error = 'Some cache error!'
        flash(error)
        return render_template('blog/create.html')


@blog.route('/edit/<int:post_id>', methods=['GET', 'POST'])
def edit(post_id):
    if request.method == 'GET':
        database = get_database()
        test_post = database.execute('SELECT * FROM Posts WHERE Id=?',
                                     (post_id,)).fetchone()
        if test_post is not None:
            g.post = {'Theme': ascii_decrypt(test_post['Theme']),
                      'Content': ascii_decrypt(test_post['Content'])}
            return render_template('blog/edit.html')
        return redirect('blog.index')
    elif request.method == 'POST':
        error = None
        if request.form['theme'] is None:
            error = 'You must enter a theme of your post!'
        elif request.form['content'] is None:
            error = 'You must enter some text of your post!'
        elif len(request.form['theme']) < 2:
            error = 'Your theme is too short, it must be at least 2 ' \
                    'symbols long!'
        elif len(request.form['theme']) > 256:
            error = 'Your theme is to long, it must be shorter then 256 ' \
                    'symbols!'
        if error is None:
            theme = ascii_encrypt(request.form['theme'])
            content = ascii_encrypt(request.form['content'])
            database = get_database()
            database.execute('UPDATE Posts SET Theme=?, Content=? '
                             'WHERE Id=?', (theme, content, post_id,))
            database.commit()
            return redirect(url_for('blog.index'))
        flash(error)
        return render_template('blog/edit.html')


@blog.route('/delete/<int:post_id>', methods=['GET', 'POST'])
def delete(post_id):
    if request.method == 'GET':
        return render_template('blog/delete.html')
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
                database.execute('DELETE FROM Posts '
                                 'WHERE Id=?', (post_id,))
                database.commit()
            else:
                error = 'Could not find such user!'
        else:
            error = 'Some cache error!'
        if error is None:
            return redirect(url_for('blog.index'))
        else:
            flash(error)
            return render_template('blog/delete.html')
