from os import environ as env
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

class DevConfig(object):
    SECRET_KEY = env.get('SECRET_KEY')
    JWT_SECRET_KEY = env.get('JWT_SECRET_KEY')
    JWT_COOKIE_SECURE = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=10)
    SQLALCHEMY_DATABASE_URI = env.get('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = env.get('SQLALCHEMY_TRACK_MODIFICATIONS')
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_COOKIE_CSRF_PROTECT = False