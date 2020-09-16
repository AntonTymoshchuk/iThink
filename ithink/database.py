import sqlite3

import click
from flask import g, current_app
from flask.cli import with_appcontext


@click.command('initialize-database')
@with_appcontext
def initialize_database():
    database = get_database()
    with current_app.open_resource('schema.sql') as resource:
        database.executescript(resource.read().decode('UTF-8'))
    click.echo('Database created')


def get_database():
    if 'database' not in g:
        g.database = sqlite3.connect(current_app.config['DATABASE'],
                                     detect_types=sqlite3.PARSE_DECLTYPES)
        g.database.row_factory = sqlite3.Row
    return g.database


def close_database(e=None):
    database = g.pop('database', None)
    if database is not None:
        database.close()
