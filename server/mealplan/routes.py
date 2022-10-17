import json
from datetime import timedelta

import pdfkit
from flask import abort
from flask import current_app as app
from flask import jsonify, make_response, render_template, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                current_user, jwt_required,
                                verify_jwt_in_request)
from flask_swagger_ui import get_swaggerui_blueprint
from mealplan import bcrypt, db
from mealplan.models import (Meal, MealPlan, MealPlanSchema, MealSchema, User,
                             UserSchema)
from mealplan.utils import listOfDays, listOfWeeks
from werkzeug.exceptions import HTTPException

user_schema = UserSchema()
users_schema = UserSchema(many=True)
mealplan_schema = MealPlanSchema()
mealplans_schema = MealPlanSchema(many=True)
meal_schema = MealSchema()
meals_schema = MealSchema(many=True)


@app.route('/')
@app.route('/home')
def home():
    return jsonify('Home alone again!')

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        if request.is_json:
            email = request.json.get('email')
            if User.query.filter_by(email=email).first():
                abort(409, description='This email is taken!')
            firstName = request.json.get('firstName')
            lastName = request.json.get('lastName')
            password = bcrypt.generate_password_hash(
                request.json.get('password')).decode('utf-8')

            user = User(firstName=firstName, lastName=lastName, email=email, password=password)
            db.session.add(user)
            db.session.commit()

            return jsonify("Registered successfully")
        else:
            return abort(400, description='Content-Type needs to be JSON')

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            user = User.query.filter_by(
                email=request.json.get('email')).one_or_none()

            if user and bcrypt.check_password_hash(user.password, request.json.get('password')):
                access_token = create_access_token(identity=user, expires_delta=timedelta(hours=1))
                refresh_token = create_refresh_token(identity=user, expires_delta=timedelta(days=2))

                response = jsonify({
                    "msg": "logged in successfully.",
                    "access token": access_token,
                    "refresh token": refresh_token
                })
                return response, 200
            else:
                abort(401, description='Email or Password is incorrect')

@app.route('/users', methods=['GET'])
def users():
    users = User.query.all()
    result = users_schema.dump(users)

    return jsonify(result), 200


@app.route('/users/<int:user_id>', methods=['GET', 'PATCH', 'DELETE'])
def user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'GET':
        return jsonify(user_schema.dump(user))

    verify_jwt_in_request(locations='headers')
    if request.method == 'PATCH':
        if current_user == user:
            if request.is_json:
                email = request.json.get('email')
                if User.query.filter_by(email=email).first():
                    abort(409, description='This email is taken!')
                if email:
                    user.email = email

                firstName = request.json.get('firstName')
                if firstName:
                    user.firstName = firstName

                lastName = request.json.get('lastName')
                if lastName:
                    user.lastName = lastName

                db.session.commit()
                return jsonify('Updated Successfully!'), 200

    if request.method == 'DELETE':
        if current_user == user:
            db.session.delete(user)
            db.session.commit()
            response = jsonify({"msg": "Successfully."})
            return response

    abort(403, description="You are not authorized to do that.")

@app.route('/users/<int:user_id>/meals', methods=['POST', 'GET'])
def meals(user_id):
    user = User.query.get_or_404(user_id, description='User not found!')
    if request.method == 'GET':
        plans = MealPlan.query.filter_by(user_id=user_id).all()
        if plans:
            result1 = mealplans_schema.dump(plans)
            return jsonify(result1), 200

        else:
            return jsonify(description='You do not have a valid meal plan'), 200

    verify_jwt_in_request(locations='headers')
    if request.method == 'POST':
        if current_user == user:
            if request.is_json:
                name = request.json.get('name')
                introduction = request.json.get('introduction')
                check = MealPlan.query.filter_by(user_id=current_user.id, name=name).one_or_none()
                if check:
                    abort(409, description='You already have a meal plan with that name.')

                mealplan = MealPlan(name=name, user_id=current_user.id, introduction=introduction)
                db.session.add(mealplan)
                db.session.commit()
                return jsonify('Added Successfully'), 200

    abort(401, description="You need to be logged in to do that!")

@app.route('/users/<int:user_id>/meals/<int:mealplan_id>',
           methods=['PATCH', 'GET', 'DELETE'])
def specMeal(user_id, mealplan_id):
    meal = MealPlan.query.filter_by(user_id=user_id,
                                    id=mealplan_id).first_or_404()
    if request.method == 'GET':
        return jsonify(mealplan_schema.dump(meal))

    verify_jwt_in_request(locations='headers')
    if current_user == meal.user:
        if request.method == 'PATCH' and request.is_json:
            name = request.json.get('name')
            meal.name = name

            db.session.commit()
            return jsonify('Modified Successfully'), 200

        if request.method == 'DELETE':
            db.session.delete(meal)
            db.session.commit()
            return jsonify('Deleted Successfully!'), 200

    abort(403, description="You are not authorized to do that!")


@app.route('/users/<int:user_id>/meals/<int:mealplan_id>/plans',
           methods=['POST', 'GET'])
def plans(user_id, mealplan_id):
    meal = MealPlan.query.filter_by(user_id=user_id,
                                    id=mealplan_id).first_or_404()
    if request.method == 'GET':
        plans = Meal.query.filter_by(mealplan_id=mealplan_id).order_by(
            Meal.weekInt.asc(), Meal.dayInt.asc()).all()
        if plans:
            result = meals_schema.dump(plans)
            return jsonify(result), 200
        else:
            return jsonify(description='No meal'), 200

    verify_jwt_in_request(locations='headers')
    if current_user == meal.user:
        if request.method == 'POST' and request.is_json:
            day = request.json.get('day')
            dayInt = listOfDays.get(day)
            week = request.json.get('week')
            weekInt = listOfWeeks.get(week)
            breakfast = request.json.get('breakfast', None)
            lunch = request.json.get('lunch', None)
            snack = request.json.get('snack', None)
            dinner = request.json.get('dinner', None)

            check = Meal.query.filter_by(mealplan_id=mealplan_id,
                                         day=day,
                                         week=week).one_or_none()
            if check:
                abort(
                    409,
                    description=
                    'You already have a meal plan for this day, you can edit it though, if that is what you want!'
                )

            meal = Meal(week=week,
                        day=day,
                        breakfast=breakfast,
                        lunch=lunch,
                        snack=snack,
                        dinner=dinner,
                        dayInt=dayInt,
                        weekInt=weekInt,
                        mealplan_id=mealplan_id)
            db.session.add(meal)
            db.session.commit()
            return jsonify('Added Successfully'), 200

    abort(401, description="You need to be logged in to do that!")


@app.route('/users/<int:user_id>/meals/<int:mealplan_id>/plans/<int:plan_id>',
           methods=['PATCH', 'GET', 'DELETE'])
def specPlan(user_id, mealplan_id, plan_id):
    _ = User.query.get_or_404(user_id)
    meal = MealPlan.query.filter_by(
        user_id=user_id,
        id=mealplan_id).first_or_404(description="Check your Meal ID.")
    plan = Meal.query.filter_by(
        mealplan_id=mealplan_id,
        id=plan_id).first_or_404(description='Check your Plan ID')
    if request.method == 'GET':
        result = meal_schema.dump(plan)
        return jsonify(result), 200

    verify_jwt_in_request(locations='headers')
    if current_user == meal.user:
        if request.method == 'PATCH':
            if request.is_json:
                breakfast = request.json.get('breakfast')
                if breakfast:
                    plan.breakfast = breakfast

                lunch = request.json.get('lunch')
                if lunch:
                    plan.lunch = lunch

                snack = request.json.get('snack')
                if snack:
                    plan.snack = snack

                dinner = request.json.get('dinner')
                if dinner:
                    plan.dinner = dinner

                db.session.commit()
                return jsonify('Your Plan have been updated Successfully'), 200

        if request.method == 'DELETE':
            db.session.delete(plan)
            db.session.commit()
            return jsonify('Deleted Successfully'), 200

    abort(403, description='You are not authorized to do that')


@app.route('/users/<int:user_id>/meals/<int:mealplan_id>/download')
@jwt_required(locations='headers')
def downloadMeals(user_id, mealplan_id):
    user = User.query.get_or_404(user_id,
                                 description='That user does not exist!')
    mealplan = MealPlan.query.filter_by(
        user_id=user_id, id=mealplan_id).first_or_404(
            description='That meal plan does not exist')
    if current_user == user:
        plans = Meal.query.filter_by(mealplan_id=mealplan_id).order_by(
            Meal.weekInt.asc(), Meal.dayInt.asc()).all()
        data = {}
        for plan in plans:
            if plan.week in data:
                day = {
                    "breakfast": plan.breakfast,
                    "lunch": plan.lunch,
                    "snack": plan.snack,
                    "dinner": plan.dinner
                }

                data[plan.week][plan.day] = day

            else:
                day = {
                    "breakfast": plan.breakfast,
                    "lunch": plan.lunch,
                    "snack": plan.snack,
                    "dinner": plan.dinner
                }

                data[plan.week] = {plan.day: day}

        options = {
            "orientation": "landscape",
            "page-size": "A4",
            "margin-top": "1.0cm",
            "margin-right": "1.0cm",
            "margin-bottom": "1.0cm",
            "margin-left": "1.0cm",
            "encoding": "UTF-8",
        }

        name = mealplan.name
        introduction = mealplan.introduction
        body = render_template('pdf.html',
                               data=data,
                               user=user,
                               name=name,
                               introduction=introduction)
        response = make_response(pdfkit.from_string(body, output_path=False, options=options))
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = "inline; filename=output.pdf"
        return response

    abort(403, description='You are not authorized to do that')


@app.route('/refresh/token')
@jwt_required(refresh=True, locations='headers')
def refreshToken():
    access_token = create_access_token(identity=current_user, expires_delta=timedelta(minutes=30))
    response = jsonify({
        "msg": "access token refreshed.",
        "access token": access_token,
        #               "refresh token": refresh_token,
        "email": current_user.email
    })
    # set_refresh_headers(response, refresh_token)
    return response

@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "message": e.description
    })
    response.content_type = "application/json"
    return response


SWAGGER_URL = '/swagger'
API_URL = '/static/output.yaml'

# Call factory function to create our blueprint
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  # Swagger UI static files will be mapped to '{SWAGGER_URL}/dist/'
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': "Meal Recipe",
        'app_version': 1.0
    },
)

app.register_blueprint(swaggerui_blueprint)