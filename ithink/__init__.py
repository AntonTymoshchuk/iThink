import os

from flask import Flask

from ithink import authentication, database


def create_app(config_file=None):
    app = Flask(__name__, instance_relative_config=True)
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    if config_file is not None:
        app.config.from_pyfile(os.path.join(app.instance_path,
                                            config_file))
    else:
        app.config.from_mapping(
            SECRET_KEY=b'PGN@m\x90\xb3\xf3\x0f\x90\xb5S\x80)\xdaw',
            DATABASE=os.path.join(app.instance_path, 'ithink.sqlite'))

    app.register_blueprint(authentication.authentication)

    app.teardown_appcontext(database.close_database)
    app.cli.add_command(database.initialize_database)

    return app
