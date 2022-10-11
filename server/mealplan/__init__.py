from flask import Flask
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from config import DevConfig

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
bcrypt = Bcrypt()
cor = CORS()

def create_app():
    app = Flask("mealplan")
    app.config.from_object(DevConfig)
    db.init_app(app)
    migrate.init_app(app=app, db=db)
    jwt.init_app(app)
    bcrypt.init_app(app)
    cor.init_app(app=app)

    with app.app_context():
        from mealplan import routes
        db.create_all()

    return app