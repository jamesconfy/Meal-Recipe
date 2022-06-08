from datetime import timedelta
import json
import pdfkit
from flask import current_app as app, jsonify, request, abort, render_template
from werkzeug.exceptions import HTTPException
from mealplan import bcrypt, db
from mealplan.models import User, MealPlan, Meal
from mealplan.utils import listOfWeeks, listOfDays
from flask_jwt_extended import (create_access_token, current_user,
                                jwt_required, set_access_cookies,
                                unset_jwt_cookies, create_refresh_token,
                                set_refresh_cookies, verify_jwt_in_request)


@app.route('/')
@app.route('/home')
def home():
    #return render_template("layout.html")
    return jsonify('Home alone again!')


@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        if request.is_json:
            email = request.json.get('email')
            if User.query.filter_by(email=email).first():
                abort(409, description='This email is taken!')
            firstName = request.json.get('first name')
            lastName = request.json.get('last name')
            password = bcrypt.generate_password_hash(request.json.get('password')).decode('utf-8')

            user = User(firstName=firstName,
                        lastName=lastName,
                        email=email,
                        password=password)
            db.session.add(user)
            db.session.commit()

            return jsonify(user.__repr__())
        else:
            return abort(400, description='Content-Type needs to be JSON')

@app.route('/login', methods=['POST'])
def login():
    # if request.method == 'GET':
    #     if verify_jwt_in_request(optional=True):
    #         return jsonify('You are already logged in'), 200

    #     else:
    #         return jsonify('You need to sign in'), 200

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
                set_access_cookies(response, access_token)
                set_refresh_cookies(response, refresh_token)
                return response, 200
            else:
                abort(401, description='Email or Password is incorrect')

@app.route('/users', methods=['GET'])
def users():
    users = User.query.all()
    for user in users:
        print(user.__repr__())

    return jsonify('Successful')

@app.route('/users/<int:user_id>', methods=['GET', 'PATCH', 'DELETE'])
def user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'GET':
        print(user.__repr__())
        return jsonify('Checking')

    verify_jwt_in_request(locations='cookies')
    if request.method == 'PATCH':
        if current_user == user:
            if request.is_json:
                email = request.json.get('email')
                if User.query.filter_by(email=email).first():
                    abort(409, description='This email is taken!')
                if email:
                    user.email = email

                firstName = request.json.get('first name')
                if firstName:
                    user.firstName = firstName

                lastName = request.json.get('last name')
                if lastName:
                    user.lastName = lastName

                db.session.commit()
                print(current_user)
                return jsonify('Updated Successfully!'), 200

    if request.method == 'DELETE':
        if current_user == user:
            db.session.delete(user)
            db.session.commit()
            response = jsonify({"msg": "Successfully."})
            unset_jwt_cookies(response)
            return response
            
    abort(403, description="You are not authorized to do that.")


@app.route('/users/<int:user_id>/meals', methods=['POST', 'GET'])
def meals(user_id):
    user = User.query.get_or_404(user_id, description='User not found!')
    if request.method == 'GET':
        allplans = []
        plans = MealPlan.query.filter_by(user_id=user_id).all()
        if plans:
            for plan in plans:
                newObj = {
                   "Name": plan.name,
                   "Date Created": plan.dateCreated
                }

                allplans.append(newObj)
        return jsonify(allplans), 200

    verify_jwt_in_request(locations='cookies')
    if request.method == 'POST':
        if current_user == user:
            if request.is_json:
                name = request.json.get('name')
                check = MealPlan.query.filter_by(user_id=current_user.id, name=name).one_or_none()
                if check:
                    abort(409, description='You already have a meal plan with that name.')

                mealplan = MealPlan(name=name, user_id=current_user.id)
                db.session.add(mealplan)
                db.session.commit()
                return jsonify('Added Successfully'), 200

    abort(401, description="You need to be logged in to do that!")


@app.route('/users/<int:user_id>/meals/<int:mealplan_id>', methods=['PATCH', 'GET', 'DELETE'])
def specMeal(user_id, mealplan_id):
    meal = MealPlan.query.filter_by(user_id=user_id, id=mealplan_id).first_or_404()
    if request.method == 'GET':
        newObj = {
                "Name": meal.name
            }

        return jsonify(newObj), 200

    verify_jwt_in_request(locations='cookies')
    if current_user == meal.chef:    
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


@app.route('/users/<int:user_id>/meals/<int:mealplan_id>/plans', methods=['POST', 'GET'])
def plans(user_id, mealplan_id):
    meal = MealPlan.query.filter_by(user_id=user_id, id=mealplan_id).first_or_404()
    if request.method == 'GET':
        allPlans = []
        plans = Meal.query.filter_by(mealplan_id=mealplan_id).order_by(Meal.weekInt.asc(), Meal.dayInt.asc()).all()
        if plans:
            for plan in plans:
                newObj = {
                    "Day": plan.day,
                    "Week": plan.week,
                    "Breakfast": plan.breakfast,
                    "Lunch": plan.lunch,
                    "Snack": plan.snack,
                    "Dinner": plan.dinner,
 #                   "Date Created": plan.dateCreated
                }

                allPlans.append(newObj)
        return jsonify(allPlans), 200

    verify_jwt_in_request(locations='cookies')
    if current_user == meal.chef:    
        if request.method == 'POST' and request.is_json:
            day = request.json.get('day')
            dayInt = listOfDays.get(day)
            week = request.json.get('week')
            weekInt = listOfWeeks.get(week)
            breakfast = request.json.get('breakfast', None)
            lunch = request.json.get('lunch', None)
            snack = request.json.get('snack', None)
            dinner = request.json.get('dinner', None)

            check = Meal.query.filter_by(mealplan_id=mealplan_id, day=day, week=week).one_or_none()
            if check:
                abort(409, description='You already have a meal plan for this day, you can edit it though, if that is what you want!')

            meal = Meal(week=week, day=day, breakfast=breakfast, lunch=lunch, snack=snack, dinner=dinner, dayInt=dayInt, weekInt=weekInt, mealplan_id=mealplan_id)
            db.session.add(meal)
            db.session.commit()
            return jsonify('Added Successfully'), 200

    abort(401, description="You need to be logged in to do that!")

@app.route('/users/<int:user_id>/meals/<int:mealplan_id>/plans/<int:plan_id>', methods=['PATCH', 'GET', 'DELETE'])
def specPlan(user_id, mealplan_id, plan_id):
    _ = User.query.get_or_404(user_id)
    meal = MealPlan.query.filter_by(user_id=user_id, id=mealplan_id).first_or_404(description="Check your Meal ID.")
    plan = Meal.query.filter_by(mealplan_id=mealplan_id, id=plan_id).first_or_404(description='Check your Plan ID')
    if request.method == 'GET':
        newObj = {
            "Day": plan.day,
            "Week": plan.week,
            "Breakfast": plan.breakfast,
            "Lunch": plan.lunch,
            "Snack": plan.snack,
            "Dinner": plan.dinner
        }
        return jsonify(newObj), 200

    verify_jwt_in_request(locations='cookies')
    if current_user == meal.chef:
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
@jwt_required(locations='cookies')
def downloadMeals(user_id, mealplan_id):
    user = User.query.get_or_404(user_id, description='That user does not exist!')
    _ = MealPlan.query.filter_by(user_id=user_id, id=mealplan_id).first_or_404()
    if current_user == user:
        plans = Meal.query.filter_by(mealplan_id=mealplan_id).order_by(Meal.weekInt.asc(), Meal.dayInt.asc()).all()
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

        cover = render_template('cover.html')
        rendered = render_template('pdf.html', data=data)
        pdfkit.from_string(rendered, output_path="output.pdf")

        return jsonify("Successfully")

    abort(403, description='You are not authorized to do that')

@app.route('/refresh/token')
@jwt_required(refresh=True, locations='cookies')
def refreshToken():
    access_token = create_access_token(identity=current_user, expires_delta=timedelta(minutes=30))
    #refresh_token = create_refresh_token(identity=current_user, expires_delta=timedelta(days=2))

    response = jsonify({
                "msg": "access token refreshed.",
                "access token": access_token,
#               "refresh token": refresh_token,
                "email": current_user.email
            })
    set_access_cookies(response, access_token)
   # set_refresh_cookies(response, refresh_token)
    return response


@app.route("/protected", methods=["GET"])
@jwt_required(locations='cookies')
def protected():
    return jsonify({
        "id": current_user.id,
        "email": current_user.email,
        "name": f'{current_user.firstName} {current_user.lastName}',
    }), 200


@app.route("/logout", methods=['GET'])
@jwt_required(locations='cookies')
def logout():
    response = jsonify({"msg": "logout successfully."})
    unset_jwt_cookies(response)
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