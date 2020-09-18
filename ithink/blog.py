from flask import Blueprint, session, g, render_template

from ithink.database import get_database
from ithink.security.cryptography import ascii_decrypt

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
    g.posts = database.execute('SELECT * FROM Posts '
                               'ORDER BY Created DESC').fetchall()
    return render_template('blog/blog.html')
