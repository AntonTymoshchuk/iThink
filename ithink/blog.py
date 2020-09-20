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
                'Author': author,
                'Likes': enc_post['Likes'],
                'Dislikes': enc_post['Dislikes'],
                'Tag': ''}
        if enc_post['Tag'] != '':
            post['Tag'] = ascii_decrypt(enc_post['Tag'])
        g.posts.append(post)
    enc_comments = database.execute('SELECT * FROM Comments '
                                    'ORDER BY Created DESC').fetchall()
    g.comments = []
    for enc_comment in enc_comments:
        author = database.execute('SELECT * FROM Users WHERE Id=?',
                                  (enc_comment['Author'],)).fetchone()
        author = ascii_decrypt(author['Username'])
        user_comment = {'Post': enc_comment['Post'],
                        'Author': author,
                        'Content': ascii_decrypt(enc_comment['Content']),
                        'Created': enc_comment['Created']}
        g.comments.append(user_comment)
    return render_template('blog/blog.html')


@blog.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'GET':
        return render_template('blog/create.html')
    elif request.method == 'POST':
        error = None
        if request.form['theme'] == '':
            error = 'You must enter a theme of your post!'
        elif request.form['content'] == '':
            error = 'You must enter some text of your post!'
        elif len(request.form['theme']) < 2:
            error = 'Your theme is too short, it must be at least 2 ' \
                    'symbols long!'
        elif len(request.form['theme']) > 256:
            error = 'Your theme is to long, it must be shorter then 256 ' \
                    'symbols!'
        if request.form['tag'] != '':
            if len(request.form['tag']) < 2:
                error = 'Your tag is too short, it must be at least 2 ' \
                        'symbols long!'
            elif len(request.form['tag']) > 256:
                error = 'Your tag is to long, it must be shorter then ' \
                        '256 symbols!'
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
                    tag = ''
                    if request.form['tag'] != '':
                        tag = ascii_encrypt(request.form['tag'])
                    database = get_database()
                    database.execute('INSERT INTO Posts'
                                     '(Author, Theme, Content, Tag) '
                                     'VALUES (?, ?, ?, ?)',
                                     (session.get('user_id'),
                                      theme, content, tag))
                    database.commit()
                    return redirect(url_for('blog.index'))
                else:
                    error = 'User not found!'
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
                      'Content': ascii_decrypt(test_post['Content']),
                      'Tag': ''}
            if test_post['Tag'] != '':
                g.post['Tag'] = ascii_decrypt(test_post['Tag'])
            return render_template('blog/edit.html')
        return redirect('blog.index')
    elif request.method == 'POST':
        error = None
        if request.form['theme'] == '':
            error = 'You must enter a theme of your post!'
        elif request.form['content'] == '':
            error = 'You must enter some text of your post!'
        elif len(request.form['theme']) < 2:
            error = 'Your theme is too short, it must be at least 2 ' \
                    'symbols long!'
        elif len(request.form['theme']) > 256:
            error = 'Your theme is to long, it must be shorter then 256 ' \
                    'symbols!'
        if request.form['tag'] != '':
            if len(request.form['tag']) < 2:
                error = 'Your tag is too short, it must be at least 2 ' \
                        'symbols long!'
            elif len(request.form['tag']) > 256:
                error = 'Your tag is to long, it must be shorter then ' \
                        '256 symbols!'
        if error is None:
            theme = ascii_encrypt(request.form['theme'])
            content = ascii_encrypt(request.form['content'])
            tag = ''
            if request.form['tag'] != '':
                tag = ascii_encrypt(request.form['tag'])
            database = get_database()
            database.execute('UPDATE Posts SET Theme=?, Content=?, Tag=? '
                             'WHERE Id=?', (theme, content, tag, post_id,))
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
                error = 'User not found!'
        else:
            error = 'Some cache error!'
        if error is None:
            return redirect(url_for('blog.index'))
        else:
            flash(error)
            return render_template('blog/delete.html')


@blog.route('/like/<int:post_id>')
def like(post_id):
    if request.method == 'GET':
        database = get_database()
        test_post = database.execute('SELECT * FROM Posts '
                                     'WHERE Id=?', (post_id,)).fetchone()
        if test_post is not None:
            likes = test_post['Likes'] + 1
            database.execute('UPDATE Posts SET Likes=? '
                             'WHERE Id=?', (likes, post_id,))
            database.commit()
        return redirect(url_for('blog.index'))


@blog.route('/dislike/<int:post_id>')
def dislike(post_id):
    if request.method == 'GET':
        database = get_database()
        test_post = database.execute('SELECT * FROM Posts '
                                     'WHERE Id=?', (post_id,)).fetchone()
        if test_post is not None:
            dislikes = test_post['Dislikes'] + 1
            database.execute('UPDATE Posts SET Dislikes=? '
                             'WHERE Id=?', (dislikes, post_id,))
            database.commit()
        return redirect(url_for('blog.index'))


@blog.route('/comment/<int:post_id>', methods=['GET', 'POST'])
def comment(post_id):
    if request.method == 'GET':
        database = get_database()
        test_post = database.execute('SELECT * FROM Posts '
                                     'WHERE Id=?', (post_id,)).fetchone()
        if test_post is not None:
            g.post_content = ascii_decrypt(test_post['Content'])
            return render_template('blog/comment.html')
        return redirect(url_for('blog.index'))
    elif request.method == 'POST':
        error = None
        database = get_database()
        user_id = session.get('user_id')
        if user_id is not None:
            test_user = database.execute('SELECT * FROM Users '
                                         'WHERE Id=?', (user_id,)).fetchone()
            if test_user is not None:
                test_post = database.execute('SELECT * FROM Posts '
                                             'WHERE Id=?',
                                             (post_id,)).fetchone()
                if test_post is not None:
                    database.execute('INSERT INTO Comments '
                                     '(Post, Author, Content) '
                                     'VALUES (?, ?, ?)',
                                     (test_post['Id'], test_user['Id'],
                                      ascii_encrypt(
                                          request.form['comment']),))
                    database.commit()
                else:
                    error = 'Post not found!'
            else:
                error = 'User not found!'
        else:
            error = 'Some cache error!'
        if error is None:
            return redirect(url_for('blog.index'))
        else:
            return render_template('blog/comment.html')


@blog.route('/tag/<string:tag_name>')
def tag(tag_name):
    database = get_database()
    user_id = session.get('user_id')
    if user_id is not None:
        test_user = database.execute('SELECT * FROM Users '
                                     'WHERE Id=?', (user_id,)).fetchone()
        if test_user is not None:
            g.username = ascii_decrypt(test_user['Username'])
    enc_posts = database.execute('SELECT * FROM Posts '
                                 'WHERE Tag=? ORDER BY Created DESC',
                                 (ascii_encrypt(tag_name),)).fetchall()
    g.posts = []
    for enc_post in enc_posts:
        author = database.execute('SELECT * FROM Users WHERE Id=?',
                                  (enc_post['Author'],)).fetchone()
        author = ascii_decrypt(author['Username'])
        post = {'Id': enc_post['Id'],
                'Theme': ascii_decrypt(enc_post['Theme']),
                'Content': ascii_decrypt(enc_post['Content']),
                'Created': enc_post['Created'],
                'Author': author,
                'Likes': enc_post['Likes'],
                'Dislikes': enc_post['Dislikes'],
                'Tag': ascii_decrypt(enc_post['Tag'])}
        g.posts.append(post)
    g.comments = []
    for post in g.posts:
        enc_comments = database.execute('SELECT * FROM Comments '
                                        'WHERE Post=? '
                                        'ORDER BY Created DESC',
                                        (post['Id'],)).fetchall()
        for enc_comment in enc_comments:
            author = database.execute('SELECT * FROM Users WHERE Id=?',
                                      (enc_comment['Author'],)).fetchone()
            author = ascii_decrypt(author['Username'])
            user_comment = {'Post': enc_comment['Post'],
                            'Author': author,
                            'Content': ascii_decrypt(enc_comment['Content']),
                            'Created': enc_comment['Created']}
            g.comments.append(user_comment)
    return render_template('blog/tag.html')
