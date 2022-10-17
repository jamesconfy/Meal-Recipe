from datetime import datetime

from marshmallow import Schema, fields
from mealplan import db, jwt
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


class User(db.Model):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    firstName = Column(String(120), unique=False, nullable=False)
    lastName = Column(String(120), unique=False, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password = Column(String(120), unique=False, nullable=False)
    dateCreated = Column(DateTime(), default=datetime.utcnow)
    mealplan = db.relationship('MealPlan', back_populates='user', lazy=True)

class MealPlan(db.Model):
    __tablename__ = 'mealplan'
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    introduction = Column(Text, nullable=False)
    dateCreated = Column(DateTime(), default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = db.relationship('User', back_populates='mealplan')
    mealplan = db.relationship('Meal', back_populates='plan', lazy=True)

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
    plan = db.relationship('MealPlan', back_populates='mealplan')

class UserSchema(Schema):
    class Meta:
        model = User
        load_instance = True
        sqla_session = db.session

    id = fields.Integer()
    firstName = fields.String()
    lastName = fields.String()
    email = fields.String()
    dateCreated = fields.DateTime()

class MealPlanSchema(Schema):
    class Meta:
        model = MealPlan
        load_instance = True
        sqla_session = db.session

    id = fields.Integer()
    name = fields.String()
    introduction = fields.String()
    dateCreated = fields.DateTime()
    user = fields.Nested(UserSchema(exclude=["id"]))

class MealSchema(Schema):
    class Meta:
        model = Meal
        load_instance = True
        sqla_session = db.session

    id = fields.Int()
    week = fields.String()
    day = fields.String()
    breakfast = fields.String()
    lunch = fields.String()
    snack = fields.String()
    dinner = fields.String()
    dateCreated = fields.DateTime()
    plan = fields.Nested(MealPlanSchema)