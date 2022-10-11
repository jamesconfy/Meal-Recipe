from mealplan import db, jwt
from sqlalchemy import Column, Integer, String, ForeignKey, Text, DateTime
from datetime import datetime
from marshmallow import Schema, fields

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


class User(db.Model):
    id = Column(Integer, primary_key=True)
    firstName = Column(String(120), unique=False, nullable=False)
    lastName = Column(String(120), unique=False, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password = Column(String(120), unique=False, nullable=False)
    dateCreated = Column(DateTime(), default=datetime.utcnow)
    chef = db.relationship('MealPlan', backref='chef', lazy=True)

class UserSchema(Schema):
    id = fields.Str(data_key='ID')
    firstName = fields.Str(data_key='First Name')
    lastName = fields.Str(data_key='Last Name')
    email = fields.Str(data_key='Email')
    dateCreated = fields.Str(data_key='Date Created')


class MealPlan(db.Model):
    __tablename__ = 'mealplan'
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    introduction = Column(Text, nullable=False)
    dateCreated = Column(DateTime(), default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('user.id'))
    mealplan = db.relationship('Meal', backref='plan', lazy=True)

class MealPlanSchema(Schema):
    id = fields.Str(data_key='ID')
    name = fields.Str(data_key='Name')
    introduction = fields.Str(data_key='Introduction')
    dateCreated = fields.Str(data_key='Date Created')
    user = fields.Nested(UserSchema)


class Meal(db.Model):
    __tablename__ = 'meal'
    id = Column(Integer, primary_key=True)
    week = Column(String(120), nullable=False)
    day = Column(String(120), nullable=False)
    dayInt = Column(Integer, nullable=False)
    weekInt = Column(Integer, nullable=False)

    breakfast = Column(Text, nullable=True)
    lunch = Column(Text, nullable=True)
    snack = Column(Text, nullable=True)
    dinner = Column(Text, nullable=True)
    dateCreated = Column(DateTime, default=datetime.utcnow)
    mealplan_id = Column(Integer, ForeignKey('mealplan.id'))

class MealSchema(Schema):
    id = fields.Str(data_key='ID')
    week = fields.Str(data_key='Week')
    day = fields.Str(data_key='Day')
    breakfast = fields.Str(data_key='Breakfast')
    lunch = fields.Str(data_key='Lunch')
    snack = fields.Str(data_key='Snack')
    dinner = fields.Str(data_key='Dinner')
    dateCreated = fields.Str(data_key='Date Created')