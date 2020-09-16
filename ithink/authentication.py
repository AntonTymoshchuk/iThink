from flask import Blueprint, session, g, url_for
from werkzeug.utils import redirect

from ithink.database import get_database

authentication = Blueprint('authentication', __name__,
                           url_prefix='/authentication')


@authentication.route('/')
def index():
    user_id = session.get('user_id')
    g.user = None
    if user_id is not None:
        database = get_database()
        user = database.execute('SELECT * FROM Users '
                                'WHERE Id=?', (user_id,)).fetchone()
        if user is not None:
            g.user = user
            return redirect(url_for('blog'))
        else:
            return redirect(url_for('authentication.registration'))
    else:
        return redirect(url_for('authentication.login'))


@authentication.route('/login', methods=['GET', 'POST'])
def login():
    pass


@authentication.route('/registration', methods=['GET', 'POST'])
def registration():
    pass
