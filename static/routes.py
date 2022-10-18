import json
from datetime import timedelta

import pdfkit
from flask import abort
from flask import current_app as app
from flask import jsonify, render_template, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                current_user, jwt_required, set_access_cookies,
                                set_refresh_cookies, unset_jwt_cookies,
                                verify_jwt_in_request)
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
    #return render_template("layout.html")
    return jsonify('Home alone again!')


@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        """
            @api [post] /register
            tags: [Users]
            summary: Register a user
            description: Route to register a user
            requestBody:
                description: Input your credentials to be registered
                content:
                    application/json:
                        schema:
                            "$ref": "#/components/schemas/BaseUser"
            responses:
                200:
                    description: OK
                    content:
                        application/json:
                            schema:
                                type: string
        """
        if request.is_json:
            email = request.json.get('email')
            if User.query.filter_by(email=email).first():
                abort(409, description='This email is taken!')
            firstName = request.json.get('first name')
            lastName = request.json.get('last name')
            password = bcrypt.generate_password_hash(
                request.json.get('password')).decode('utf-8')

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
        """
            @api [post] /login
            tags: [Users]
            summary: Login
            description: Route to login a user
            requestBody:
                description: Provide credentials to be logged in
                content:
                    application/json:
                        schema:
                            "$ref": "#/components/schemas/Login"
            responses:
                200:
                    description: OK
                    content:
                        application/json:
                            schema:
                                "$ref": "#/components/schemas/Token"

        """
        if request.is_json:
            user = User.query.filter_by(
                email=request.json.get('email')).one_or_none()

            if user and bcrypt.check_password_hash(
                    user.password, request.json.get('password')):
                access_token = create_access_token(
                    identity=user, expires_delta=timedelta(hours=1))
                refresh_token = create_refresh_token(
                    identity=user, expires_delta=timedelta(days=2))

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
    """
        @api [get] /users
        tags: [Users]
        description: Return list of users
        summary: Users route
        responses:
            200:
                description: OK
                content:
                    application/json:
                        schema:
                            type: array
                            items:
                                "$ref": "#/components/schemas/Users"
    """
    users = User.query.all()
    result = users_schema.dump(users)

    return jsonify(result), 200


@app.route('/users/<int:user_id>', methods=['GET', 'PATCH', 'DELETE'])
def user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'GET':
        """
            @api [get] /users/{user_id}
            tags: [Users]
            description: Return the values of a specific user
            summary: Get a specific user
            parameters:
                - "$ref": "#/components/parameters/user_id"
            responses:
                200:
                    description: OK
                    content:
                        application/json:
                            schema:
                                "$ref": "#/components/schemas/Users"
        """
        return jsonify(user_schema.dump(user))

    verify_jwt_in_request(locations='cookies')
    if current_user == user:
        if request.method == 'PATCH':
            """
                @api [patch] /users/{user_id}
                tags: [Users]
                description: Update the details of a specific user
                summary: Update user
                security: [{BearerAuth: []}]
                parameters:
                    - (path) user_id* {integer:int32} User ID
                requestBody:
                    description: Input your updated details
                    content:
                        application/json:
                            schema:
                                properties:
                                    firstName:
                                        type: string
                                    lastName:
                                        type: string 
                responses:
                    200:
                        description: OK
                        content:
                            application/json:
                                schema:
                                    properties:
                                        msg:
                                            type: string
            """
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
                return jsonify({"msg": 'Updated Successfully!'}), 200

        if request.method == 'DELETE':
            """
                @api [delete] /users/{user_id}
                tags: [Users]
                description: Delete a specific user
                summary: Delete user
                security: [{BearerAuth: []}]
                parameters:
                    - (path) user_id* {integer:int32} User ID
                responses:
                    200:
                        description: OK
                        content:
                            application/json:
                                schema:
                                    properties:
                                        msg:
                                            type: string
            """
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
        """
            @api [get] /users/{user_id}/meals
            tags: [Meals]
            description: Get all the meals recipe a user has
            summary: Total meals
            parameters:
                - "$ref": "#/components/parameters/user_id"
            responses:
                200:
                    description: OK
                    content:
                        application/json:
                            schema:
                                type: array
                                items:
                                    
                                    "$ref": "#/components/schemas/Meals"                      
        """
        plans = MealPlan.query.filter_by(user_id=user_id).all()
        if plans:
            result = {**plans, user: user}
            result1 = mealplans_schema.dump(result)
            return jsonify(result1), 200

        else:
            return jsonify(
                description='You do not have a valid meal plan'), 200

    verify_jwt_in_request(locations='cookies')
    if request.method == 'POST':
        """
            @api [post] /users/{user_id}/meals
            tags: [Meals]
            description: Add a meal recipe to a user's account
            summary: Add meal
            security: [{BearerAuth: []}]
            parameters:
                - "$ref": "#/components/parameters/user_id"
            requestBody:
                description: Enter the details of meal
                content:
                    application/json:
                        schema:
                            "$ref": "#/components/schemas/BaseMeal"
            responses:
                200:
                    description: OK
                    content:
                        application/json:
                            schema:
                                properties:
                                    msg:
                                        type: string
        """
        if current_user == user:
            if request.is_json:
                name = request.json.get('name')
                check = MealPlan.query.filter_by(user_id=current_user.id,
                                                 name=name).one_or_none()
                if check:
                    abort(409,
                          description=
                          'You already have a meal plan with that name.')

                mealplan = MealPlan(name=name, user_id=current_user.id)
                db.session.add(mealplan)
                db.session.commit()
                return jsonify({'msg': 'Added Successfully'}), 200

    abort(401, description="You need to be logged in to do that!")


@app.route('/users/<int:user_id>/meals/<int:mealplan_id>', methods=['PATCH', 'GET', 'DELETE'])
def specMeal(user_id, mealplan_id):
    meal = MealPlan.query.filter_by(user_id=user_id, id=mealplan_id).first_or_404()
    if request.method == 'GET':
        """
            @api [get] /users/{user_id}/meals/{mealplan_id}
            tags: [Meals]
            description: Get a the specific meal recipe
            summary: Get meal recipe
            parameters:
                - "$ref": "#/components/parameters/user_id"
                - "$ref": "#/components/parameters/mealplan_id"
            responses:
                200:
                    description: OK
                    content:
                        application/json:
                            schema:
                                "$ref": "#/components/schemas/Meals"
                                
        """
        return jsonify(mealplan_schema.dump(meal))

    verify_jwt_in_request(locations='cookies')
    if current_user == meal.chef:
        if request.method == 'PATCH' and request.is_json:
            """
                @api [patch] /users/{user_id}/meals/{mealplan_id}
                tags: [Meals]
                description: Update a specific meal recipe
                summary: Update meal recipe
                security: [{BearerAuth: []}]
                parameters:
                    - "$ref": "#/components/parameters/user_id"
                    - "$ref": "#/components/parameters/mealplan_id"
                requestBody:
                    description: Enter the new name of the meal recipe
                    content:
                        application/json:
                            schema:
                                "$ref": "#/components/schemas/BaseMeal"
                responses:
                    200:
                        description: OK
                        content:
                            application/json:
                                schema:
                                    type: string
            """
            name = request.json.get('name')
            if name:
                meal.name = name

            introduction = request.json.get('introduction')
            if introduction:
                meal.introduction = introduction

            db.session.commit()
            return jsonify('Modified Successfully'), 200

        if request.method == 'DELETE':
            """
                @api [delete] /users/{user_id}/meals/{mealplan_id}
                tags: [Meals]
                description: Delete a specific meal recipe
                summary: Delete meal recipe
                security: [{BearerAuth: []}]
                parameters:
                    - "$ref": "#/components/parameters/user_id"
                    - "$ref": "#/components/parameters/mealplan_id"
                responses:
                    200:
                        description: OK
                        content:
                            application/json:
                                schema:
                                    type: string
            """
            db.session.delete(meal)
            db.session.commit()
            return jsonify('Deleted Successfully!'), 200

    abort(403, description="You are not authorized to do that!")


@app.route('/users/<int:user_id>/meals/<int:mealplan_id>/plans', methods=['POST', 'GET'])
def plans(user_id, mealplan_id):
    meal = MealPlan.query.filter_by(user_id=user_id, id=mealplan_id).first_or_404()
    if request.method == 'GET':
        """
            @api [get] /users/{user_id}/meals/{mealplan_id}/plans
            tags: [Meal Plans]
            description: Get a the meal plan in a particular meal recipe
            summary: Get mealplans
            parameters:
                - "$ref": "#/components/parameters/user_id"
                - "$ref": "#/components/parameters/mealplan_id"
            responses:
                200:
                    description: OK
                    content:
                        application/json:
                            schema:
                                type: array
                                items:
                                    "$ref": "#/components/schemas/Plans"
        """
        plans = Meal.query.filter_by(mealplan_id=mealplan_id).order_by(Meal.weekInt.asc(), Meal.dayInt.asc()).all()
        if plans:
            result = meals_schema.dump(plans)
            return jsonify(result), 200
        else:
            return jsonify(description='No meal'), 200

    verify_jwt_in_request(locations='cookies')
    if current_user == meal.chef:
        if request.method == 'POST' and request.is_json:
            """
                @api [post] /users/{user_id}/meals/{mealplan_id}/plans
                tags: [Meal Plans]
                description: Add a meal plan to a specific meal recipe
                summary: Add mealplan
                security: [{BearerAuth: []}]
                parameters:
                    - "$ref": "#/components/parameters/user_id"
                    - "$ref": "#/components/parameters/mealplan_id"
                requestBody:
                    description: Enter the details of the meal plan to be added
                    content:
                        application/json:
                            schema:
                                "$ref": "#/components/schemas/BasePlan"
                responses:
                    200:
                        description: OK
                        content:
                            application/json:
                                schema:
                                    type: string
            """
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

            meal = Meal(week=week, day=day, breakfast=breakfast, lunch=lunch, snack=snack,
                        dinner=dinner, dayInt=dayInt, weekInt=weekInt, mealplan_id=mealplan_id)
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
        """
            @api [get] /users/{user_id}/meals/{mealplan_id}/plans/{plan_id}
            tags: [Meal Plans]
            description: Get a specific meal plan from a meal recipe
            summary: Get meal plan
            parameters:
                - "$ref": "#/components/parameters/user_id"
                - "$ref": "#/components/parameters/mealplan_id"
                - "$ref": "#/components/parameters/plan_id"
            responses:
                200:
                    description: OK
                    content:
                        application/json:
                            schema:
                                "$ref": "#/components/schemas/Plans"
        """
        result = meal_schema.dump(plan)
        return jsonify(result), 200

    verify_jwt_in_request(locations='cookies')
    if current_user == meal.chef:
        if request.method == 'PATCH':
            """
                @api [patch] /users/{user_id}/meals/{mealplan_id}/plans/{plan_id}
                tags: [Meal Plans]
                description: Update a meal plan from a meal recipe
                summary: Update meal plan
                security: [{BearerAuth: []}]
                parameters:
                    - "$ref": "#/components/parameters/user_id"
                    - "$ref": "#/components/parameters/mealplan_id"
                    - "$ref": "#/components/parameters/plan_id"
                requestBody:
                    description: Enter the updated values of your meal plan
                    content:
                        application/json:
                            schema:
                                "$ref": "#/components/schemas/SpecPlan"
                responses:
                    200:
                        description: OK
                        content:
                            application/json:
                                schema:
                                    type: string
            """
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
            """
                @api [delete] /users/{user_id}/meals/{mealplan_id}/plans/{plan_id}
                tags: [Meal Plans]
                description: Delete a meal plan from a meal recipe
                summary: Delete meal plan
                security: [{BearerAuth: []}]
                parameters:
                    - "$ref": "#/components/parameters/user_id"
                    - "$ref": "#/components/parameters/mealplan_id"
                    - "$ref": "#/components/parameters/plan_id"
                responses:
                    200:
                        description: OK
                        content:
                            application/json:
                                schema:
                                    type: string
            """
            db.session.delete(plan)
            db.session.commit()
            return jsonify('Deleted Successfully'), 200

    abort(403, description='You are not authorized to do that')


@app.route('/users/<int:user_id>/meals/<int:mealplan_id>/download')
@jwt_required(locations='cookies')
def downloadMeals(user_id, mealplan_id):
    """
        @api [get] /users/{user_id}/meals/{mealplan_id}/download
        tags: [Save]
        description: Download a meal recipe as pdf to your computer
        summary: Download meal recipe
        security: [{BearerAuth: []}]
        parameters:
            - "$ref": "#/components/parameters/user_id"
            - "$ref": "#/components/parameters/mealplan_id"
        responses:
            200:
                description: OK
                content:
                    application/pdf:
                        schema:
                            type: string
                            format: binary
    """
    user = User.query.get_or_404(user_id, description='That user does not exist!')
    mealplan = MealPlan.query.filter_by(user_id=user_id, id=mealplan_id).first_or_404(description='That meal plan does not exist')
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

        name = mealplan.name
        introduction = mealplan.introduction
        body = render_template('pdf.html',
                               data=data,
                               user=user,
                               name=name,
                               introduction=introduction)
        rendered = pdfkit.from_string(input=body, output_path="output.pdf")

        return jsonify("Successful")

    abort(403, description='You are not authorized to do that')


@app.route('/refresh/token')
@jwt_required(refresh=True, locations='cookies')
def refreshToken():
    """
        @api [get] /refresh/token
        tags: [Users]
        description: Refresh a user's access token
        summary: Refresh token
        security: [{BearerAuth: []}]
        responses:
            200:
                description: OK
                content:
                    application/json:
                        schema:
                            "$ref": "#/components/schemas/RefreshToken"
    """
    access_token = create_access_token(identity=current_user,
                                       expires_delta=timedelta(minutes=30))
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