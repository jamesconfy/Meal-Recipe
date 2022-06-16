from mealplan import db, jwt
from sqlalchemy import Column, Integer, String, ForeignKey, Text, DateTime
from datetime import datetime

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

    def __repr__(self):
        return f'{self.firstName} {self.lastName}'

class MealPlan(db.Model):
    __tablename__ = 'mealplan'
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    introduction = Column(Text, nullable=False)
    dateCreated = Column(DateTime(), default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('user.id'))
    mealplan = db.relationship('Meal', backref='plan', lazy=True)

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

    def __repr__(self):
        return f'{self.week} {self.day}'