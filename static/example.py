from flask_swagger_ui import get_swaggerui_blueprint
import logging, os
import json
from datetime import datetime, timezone
from werkzeug.exceptions import HTTPException
from flask import current_app as app, request, jsonify, abort
from bankingapp import db, bcrypt
from bankingapp.models import Transfer, User, Deposit, UserSchema, DepositSchema, Transfer, TransferSchema, TokenBlocklist
from flask_jwt_extended import unset_jwt_cookies, verify_jwt_in_request, current_user, get_jwt
from flask_jwt_extended import set_access_cookies, create_access_token, create_refresh_token, set_refresh_cookies, get_jwt_identity
# from flask_swagger import swagger

accountNumber = "1000000010"
userSchema = UserSchema()
allUserSchema = UserSchema(many=True)
depositSchema = DepositSchema()
allDepositSchema = DepositSchema(many=True)
transferSchema = TransferSchema()
allTransferSchema = TransferSchema(many=True)

@app.before_first_request
def before_first_request():
    log_level = logging.INFO

    for handler in app.logger.handlers:
        app.logger.removeHandler(handler)

    root = os.path.dirname(os.path.abspath(__file__))
    logdir = os.path.join(root, 'logs')
    if not os.path.exists(logdir):
        os.mkdir(logdir)
    log_file = os.path.join(logdir, 'app.log')
    handler = logging.FileHandler(log_file)
    handler.setLevel(log_level)
    app.logger.addHandler(handler)

    app.logger.setLevel(log_level)

    defaultFormatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    handler.setFormatter(defaultFormatter)


@app.before_request
def checkSafeToSpend():
    if 'access_token_cookie' in request.cookies:
        verify_jwt_in_request(locations='cookies', refresh=True)
        # # token = request.cookies['access_token_cookie']
        # # print(token)
        # identity = get_jwt_identity()
        if current_user.role == 'Customer':
            today = datetime.utcnow()
            if today.strftime("%d-%m-%Y") != current_user.dateSpend.strftime("%d-%m-%Y"):
                # print(datetime.utcnow(), current_user.dateSpend)
                current_user.safeToSpend = 500000
                current_user.dateSpend = datetime.utcnow()

                db.session.commit()
                app.logger.info(f'Update save to spend')
    return


@app.route('/api')
@app.route('/api/home', methods=['GET'])
def home():
    """
        @api [get] /api/home
        tags: [Default]
        summary: Home route
        description: Returns JSON if site is up and running
        responses:
            200:
                description: OK!
                content:
                    application/json:
                        schema:
                            properties:
                                value:
                                    type: string 
    """
    app.logger.info('Home Page')
    return jsonify('My Banking App!')

@app.route('/api/register', methods=['POST'])
def register():
    global accountNumber
    if request.method == 'POST' and request.is_json:
        """
        @api [post] /api/register
        tags: [User]
        summary: Register user
        description: A route to register user
        requestBody:
            description: Input your credentials to be registered.
            content:
                application/json:
                    schema:
                        required:
                            - email
                            - password
                            - first name
                            - last name
                            - accountType
                            - role
                        properties:
                            email:
                                type: string
                                format: email
                                example: testing@demo.com
                            password:
                                type: string
                                format: password
                                example: thatisme
                            first name:
                                type: string
                                example: Confidence
                            last name:
                                type: string
                                example: James
                            account type:
                                type: string
                                example: Savings
                            phone number:
                                type: string
                                example: +23481xxxxxxxx
                            role:
                                type: string
                                example: Customer
        responses:
            200:
                description: OK
                content:
                    application/json:
                        schema:  
                            type: string
            400:
                description: The email or phone number is already in our database, try again!
            404:
                description: Not Found.
            500:
                description: We are having server issues, don't mind us, lol x.
        """

        user = User.query.filter_by(email=request.json.get('email')).one_or_none()
        phone = User.query.filter_by(phoneNumber=request.json.get('phone number')).one_or_none()
        if user:
            app.logger.warning(f'Email already exists \n Email: {user.email}')
            abort(403, description='Email already exists')
        if phone:
            app.logger.warning(f'Phone Number already exists \n Phone Number: {user.phoneNumber}')
            abort(403, description='Phone Number already exists')

        email = request.json.get('email')
        password = bcrypt.generate_password_hash(request.json.get('password')).decode('utf-8')
        firstName = request.json.get('first name')
        lastName = request.json.get('last name')
        phoneNumber = request.json.get('phone number')
        accountType = request.json.get('account type')
        role = request.json.get('role')

        if role:
            user = User(email=email, password=password, firstName=firstName, lastName=lastName, phoneNumber=phoneNumber, accountType=accountType, accountNumber=accountNumber, role=role)
        else:
            user = User(email=email, password=password, firstName=firstName, lastName=lastName, phoneNumber=phoneNumber, accountType=accountType, accountNumber=accountNumber)

        db.session.add(user)
        db.session.commit()
        app.logger.info(f'Registration Successful \n Email: {user.email} \n Role: {user.role} \n Account Number: {user.accountNumber}')
        accountNumber = str(int(accountNumber) + 1)

        result = userSchema.dump(user)
        return result, 201

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        """
        @api [post] /api/login
        tags: [User]
        summary: Register user
        description: A route to register user
        requestBody:
            description: Input your credentials to be registered.
            content:
                application/json:
                    schema:
                        required:
                            - email
                            - password
                        properties:
                            email:
                                type: string
                                format: email
                                example: testing@demo.com
                            password:
                                type: string
                                format: password
                                example: thatisme
        responses:
            200:
                description: OK
                content:
                    application/json:
                        schema:  
                            properties:
                                access token:
                                    type: string
                                email:
                                    type: string
                                    format: email
                                    example: test@demo.com
                                msg:
                                    type: string
                                    default: successful
                                refresh token:
                                    type: string
            400:
                description: Email or password is incorrect, please try again!
            404:
                description: Not Found.
            500:
                description: We are having server issues, don't mind us, lol x.
        """
        if request.is_json:
            user = User.query.filter_by(email=request.json.get('email')).one_or_none()
            if user and bcrypt.check_password_hash(user.password, request.json.get('password')):
                access_token = create_access_token(identity=user, fresh=True)
                refresh_token = create_refresh_token(identity=user)
                response = jsonify({
                    'email': user.email,
                    'msg': 'logged in successfully',
                    'access token': access_token,
                    'refresh token': refresh_token
                })
                set_access_cookies(response, access_token)
                set_refresh_cookies(response, refresh_token)
                app.logger.info(f'Login Successful \n User: {user.email}')
                return response, 200
            else:
                app.logger.warning(f"Email or Password Incorrect \n Email: {request.json.get('email')} \n Password: {request.json.get('password')}")
                return jsonify('Email or Password is incorrect'), 400
        else:
            abort(400, description='Content-Type must be application/json')

@app.route('/api/users')
def users():
    """
        @api [get] /api/users
        tags: [User]
        summary: Get all users
        description: Returns JSON if site is up and running
        responses:
            200:
                description: OK!
                content:
                    application/json:
                        schema:
                            type: array
                            items:
                                type: object
                                properties:
                                    email:
                                        type: string
                                        example: test@demo.com
                                    First Name:
                                        type: string
                                        example: Example
                                    Last Name:
                                        type: string
                                        example: Example
                                    Phone Number:
                                        type: string
                                        example: 23481xxxxxxxx
                                    Account Number:
                                        type: string
                                        format: number
                                        example: 1000000000
                                    Account Balance:
                                        type: number
                                        format: float
                                        example: 1.0
                                    Account Type:
                                        type: string
                                        example: Savings
                                    Account Status:
                                        type: string
                                        example: Active
                                    Date Of Birth:
                                        type: string
                                        format: date
                                        example: 06-12-1970
                                    Date Created:
                                        type: string
                                        format: date
                                        example: 06-12-1970
                                    Safe To Spend:
                                        type: number
                                        format: float
                                        example: 5000.000
                                    Date Spend:
                                        type: string
                                        format: date
                                        example: 06-12-1970
                                    Role:
                                        type: string
                                        example: Customer
            400:
                description: Email or password is incorrect, please try again!
            404:
                description: Not Found.
            500:
                description: We are having server issues, don't mind us, lol x.
    """
    users = User.query.filter_by(role='Customer').order_by(User.dateCreated.desc()).all()
    result = allUserSchema.dump(users)
    return jsonify(result)

@app.route('/api/users/<int:user_id>', methods=['PATCH', 'GET', 'DELETE'])
def user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'GET':
        """
        @api [get] /api/users/{user_id}
        tags: [User]
        summary: Get a specific user
        description: Returns JSON if site is up and running
        parameters:
            - (path) user_id* {integer:int32} User ID
        responses:
            200:
                description: OK!
                content:
                    application/json:
                        schema:
                            properties:
                                email:
                                    type: string
                                    example: test@demo.com
                                First Name:
                                    type: string
                                    example: Example
                                Last Name:
                                    type: string
                                    example: Example
                                Phone Number:
                                    type: string
                                    example: 23481xxxxxxxx
                                Account Number:
                                    type: string
                                    format: number
                                    example: 1000000000
                                Account Balance:
                                    type: number
                                    format: float
                                    example: 1.0
                                Account Type:
                                    type: string
                                    example: Savings
                                Account Status:
                                    type: string
                                    example: Active
                                Date Of Birth:
                                    type: string
                                    format: date
                                    example: 06-12-1970
                                Date Created:
                                    type: string
                                    format: date
                                    example: 06-12-1970
                                Safe To Spend:
                                    type: number
                                    format: float
                                    example: 5000.000
                                Date Spend:
                                    type: string
                                    format: date
                                    example: 06-12-1970
                                Role:
                                    type: string
                                    example: Customer
            400:
                description: Email or password is incorrect, please try again!
            404:
                description: Not Found.
            500:
                description: We are having server issues, don't mind us, lol x.
    """
        return userSchema.dump(user)

    verify_jwt_in_request(locations='cookies')
    if request.method == 'PATCH':
        """
        @api [patch] /api/users/{user_id}
        tags: [User]
        parameters:
            - (path) user_id* {integer:int32} User ID
        summary: Update User
        description: A route to update a user
        requestBody:
            description: Input your credentials to be update your profile
            content:
                application/json:
                    schema:
                        properties:
                            email:
                                type: string
                                format: email
                                example: testing@demo.com
                            first name:
                                type: string
                                example: Confidence
                            last name:
                                type: string
                                example: James
                            phone number:
                                type: string
                                example: 23481xxxxxxxx
        responses:
            200:
                description: OK!
                content:
                    application/json:
                        schema:
                            properties:
                                email:
                                    type: string
                                    example: test@demo.com
                                First Name:
                                    type: string
                                    example: Example
                                Last Name:
                                    type: string
                                    example: Example
                                Phone Number:
                                    type: string
                                    example: 23481xxxxxxxx
                                Account Number:
                                    type: string
                                    format: number
                                    example: 1000000000
                                Account Balance:
                                    type: number
                                    format: float
                                    example: 1.0
                                Account Type:
                                    type: string
                                    example: Savings
                                Account Status:
                                    type: string
                                    example: Active
                                Date Of Birth:
                                    type: string
                                    format: date
                                    example: 06-12-1970
                                Date Created:
                                    type: string
                                    format: date
                                    example: 06-12-1970
                                Safe To Spend:
                                    type: number
                                    format: float
                                    example: 5000.000
                                Date Spend:
                                    type: string
                                    format: date
                                    example: 06-12-1970
                                Role:
                                    type: string
                                    example: Customer
            400:
                description: The email or phone number is already in our database, try again!
            404:
                description: Not Found.
            500:
                description: We are having server issues, don't mind us, lol x.
        """

        if request.is_json:
            if current_user == user:
                email = request.json.get('email')
                if User.query.filter_by(email=email).first():
                    abort(409, description='Email already exists')
                if email:
                    user.email = email

                firstName = request.json.get('first name')
                if firstName:
                    user.firstName = firstName
                lastName = request.json.get('last name')
                if lastName:
                    user.lastName = lastName
                phoneNumber = request.json.get('phone number')
                if User.query.filter_by(phoneNumber=phoneNumber).first():
                    abort(409, description='Phone Number already exists')
                if phoneNumber:
                    user.phoneNumber = phoneNumber

                db.session.commit()
                return userSchema.dump(user)

        else:
            abort(400, description='Content-Type must be application/json')

    if request.method == 'DELETE':
        """
        @api [delete] /api/users/{user_id}
        tags: [User]
        parameters:
            - (path) user_id* {integer:int32} User ID
        summary: Delete User
        description: A route to delete a user
        responses:
            200:
                description: OK!
                content:
                    application/json:
                        schema:
                            properties:
                                msg:
                                    type: string
                                    example: User successfully deleted.
            400:
                description: The email or phone number is already in our database, try again!
            404:
                description: Not Found.
            500:
                description: We are having server issues, don't mind us, lol x.
        """
        db.session.delete(user)
        db.session.commit()

        response = jsonify({
            "msg": "Delete Successful!"
        })
        access_token = request.cookies.get("access_token")
        refresh_token = request.cookies.get("refresh_token")
        unset_jwt_cookies(response, access_token)
        unset_jwt_cookies(response, refresh_token)
        return response, 200

@app.route('/api/deposits', methods=['POST', 'GET'])
def deposit():
    verify_jwt_in_request(locations='cookies')
    if request.method == 'GET':
        """
        @api [get] /api/deposits
        tags: [Deposit]
        summary: History of deposits.
        description: Get the history of deposits into a user's account.
        responses:
            200:
                description: OK!
                content:
                    application/json:
                        schema:
                            type: array
                            items:
                                type: object
                                properties:
                                    Date Created:
                                        type: string
                                        format: date
                                        example: 06-12-1970
                                    amount:
                                        type: number
                                        format: float
                                        example: 50000.00
                                    sender:
                                        type: string
                                        example: Confidence James
            400:
                description: You are not authorized to do that.
            404:
                description: Not Found.
            500:
                description: We are having server issues, don't mind us, lol x.
        """
        deposit = Deposit.query.filter_by(user_deposit=current_user)
        return jsonify(allDepositSchema.dump(deposit))
    
    if request.method == 'POST':
        """
        @api [post] /api/deposits
        tags: [Deposit]
        summary: Make a deposit
        description: Make a deposit
        requestBody:
            description: Input the sender, receiver and amount to be deposited
            content:
                application/json:
                    schema:
                        required:
                            - account number
                            - sender
                            - amount
                        properties:
                            account number:
                                type: string
                                example: 100000000
                            sender:
                                type: string
                                example: James Confidence
                            amount:
                                type: number
                                format: float
                                example: 50000.00
        responses:
            200:
                description: OK!
                content:
                    application/json:
                        schema:
                            properties:
                                msg:
                                    type: string
                                    example: 50000 deposited successfully to Confidence James with account number of 100000000
            400:
                description: You are not authorized to do this!
            404:
                description: Not Found.
            500:
                description: We are having server issues, don't mind us, lol x.
        """
        if request.is_json:
            if current_user.role == 'Admin':
                accountNumber = request.json.get('account number')
                sender = request.json.get('sender')
                if not accountNumber:
                    abort(400, description='You must provide an account number')
                
                customer = User.query.filter_by(accountNumber=accountNumber).first()
                if not customer:
                    abort(400, description='That account number is not in our database!')

                amount = request.json.get('amount')
                if not amount:
                    abort(400, description='You must provide the amount to deposit')

                customer.accountBalance += amount
                deposit = Deposit(amount=amount, sender=sender, user_deposit=customer)
                db.session.add(deposit)
                db.session.commit()

                response = jsonify({
                    "code": 200,
                    "msg": f"{amount} deposited successfully to {customer.firstName} {customer.lastName} with account number of {accountNumber}"
                })

                return response, 200

            else:
                abort(404, description='You are not authorized to do that!')
        else:
            abort(400, description='Content-Type must be application/json')

@app.route('/api/deposits/<int:deposit_id>', methods=['GET', 'DELETE'])
def depositHistoryOne(deposit_id):
    verify_jwt_in_request(locations='cookies')
    deposit = Deposit.query.get_or_404(deposit_id)
    if current_user == deposit.user_deposit:
        if request.method == 'GET':
            """
            @api [get] /api/deposits/{deposit_id}
            tags: [Deposit]
            parameters:
                - (path) deposit_id* {integer:int32} Deposit ID
            summary: History of deposits.
            description: Get a particular deposit into a user's account.
            responses:
                200:
                    description: OK!
                    content:
                        application/json:
                            schema:
                                properties:
                                    Date Created:
                                        type: string
                                        format: date
                                        example: 06-12-1970
                                    amount:
                                        type: number
                                        format: float
                                        example: 50000.00
                                    sender:
                                        type: string
                                        example: Confidence James
                400:
                    description: You are not authorized to do that.
                404:
                    description: Not Found.
                500:
                    description: We are having server issues, don't mind us, lol x.
            """
            return jsonify(depositSchema.dump(deposit))

        if request.method == 'DELETE':
            """
            @api [delete] /api/deposits/{deposit_id}
            tags: [Deposit]
            parameters:
                - (path) deposit_id* {integer:int32} Deposit ID
            summary: Delete a particular deposit.
            description: Get a particular deposit into a user's account and delete it.
            responses:
                200:
                    description: OK!
                    content:
                        application/json:
                            schema:
                                type: object
                                properties:
                                    msg:
                                        type: string
                                        example: Deleted successfully.
                400:
                    description: You are not authorized to do that.
                404:
                    description: Not Found.
                500:
                    description: We are having server issues, don't mind us, lol x.
            """
            response = {
                "code": 200,
                "msg": "Ticket deleted successfully."
            }
            db.session.delete(deposit)
            db.session.commit()

            return response, 200

    abort(400, description='You are not authorized to do that!')
    
@app.route('/transfers', methods=['POST', 'GET'])
def transfer():
    verify_jwt_in_request(locations='cookies')
    if request.method == 'GET':
        """
        @api [get] /api/transfers
        tags: [Transfer]
        summary: History of transfers.
        description: Get the history of transfers from a user's account.
        responses:
            200:
                description: OK!
                content:
                    application/json:
                        schema:
                            type: array
                            items:
                                type: object
                                properties:
                                    Date Created:
                                        type: string
                                        format: date
                                        example: 06-12-1970
                                    Amount:
                                        type: number
                                        format: float
                                        example: 50000.00
                                    Receiver's Name:
                                        type: string
                                        example: Confidence James
                                    Receiver's Account Number:
                                        type: string
                                        example: 100000000
            400:
                description: You are not authorized to do that.
            404:
                description: Not Found.
            500:
                description: We are having server issues, don't mind us, lol x.
        """
        transfer = Transfer.query.filter_by(user_transfer=current_user)
        # if current_user.role == 'Admin' or current_user == transfer.user_transfer:
        return jsonify(allTransferSchema.dump(transfer))
        
        # abort(400, description='You are not authorized to do that!') 
    
    if request.method == 'POST':
        if current_user.role == 'Customer':
            """
            @api [post] /api/transfers
            tags: [Customer, Transfer]
            summary: Make a transfer (customer)
            description: Make a transfer, the operator have to be a customer
            requestBody:
                description: Input the sender, receiver and amount to be transferred
                content:
                    application/json:
                        schema:
                            required:
                                - receiver
                                - amount
                            properties:
                                receiver:
                                    type: string
                                    example: 100000000
                                amount:
                                    type: number
                                    format: float
                                    example: 50000.00
            responses:
                200:
                    description: OK!
                    content:
                        application/json:
                            schema:
                                properties:
                                    code:
                                        type: number
                                        example: 200
                                    sender:
                                        type: string
                                        example: Confidence James
                                    amount sent: 
                                        type: number
                                        format: float
                                        example: 200000.00
                                    recipient: 
                                        type: string
                                        example: Prisca Ugbah
                                    message:
                                        type: string
                                        example: Successful
                                        
                400:
                    description: You are not authorized to do this!
                404:
                    description: Not Found.
                500:
                    description: We are having server issues, don't mind us, lol x.
            """
            if request.is_json: 
                recipient = User.query.filter_by(accountNumber=request.json.get('receiver')).first()
                if not recipient:
                    abort(404, description='Check the account number and try again')

                amount = request.json.get('amount')
                if amount:
                    if amount <= current_user.accountBalance:
                        if amount <= current_user.safeToSpend:
                            recipient.accountBalance += amount
                            current_user.accountBalance -= amount
                            current_user.safeToSpend -= amount
                        else:
                            abort(400, description=f'Amount greater than safe to spend, your safe to spend is {current_user.safeToSpend}')
                    else:
                        abort(400, description='Insufficient Balance!')
                else:
                    abort(400, description='Provide an amount!')

                transfer = Transfer(amount=amount, receiverAccountNumber=f'{recipient.accountNumber}', receiverName=f'{recipient.firstName} {recipient.lastName}', user_transfer=current_user)
                db.session.add(transfer)

                deposit = Deposit(amount=amount, sender=f'{current_user.firstName} {current_user.lastName}', user_deposit=recipient)
                db.session.add(deposit)

                db.session.commit()
                response = {
                    "code": 200,
                    "sender": f"{current_user.firstName} {current_user.lastName}",
                    "amount sent": amount,
                    "recipient": f"{recipient.firstName} {recipient.lastName}",
                    "message": "Successful"
                }

                return response, 200             

        else:
            abort(400, description='You are not authorized to do that.')

@app.route('/api/transfers/admin', methods=['POST'])
def adminTransfer():
    verify_jwt_in_request(locations='cookies')
    if current_user.role == 'Admin':
        if request.is_json: 
            """
            @api [post] /api/transfers/admin
            tags: [Admin, Transfer]
            summary: Make a transfer (admin)
            description: Make a transfer, operator have to be an admin
            requestBody:
                description: Input the sender, receiver and amount to be transferred
                content:
                    application/json:
                        schema:
                            required:
                                - receiver
                                - sender
                                - amount
                            properties:
                                account number:
                                    type: string
                                    example: 100000000
                                sender:
                                    type: string
                                    example: James Confidence
                                amount:
                                    type: number
                                    format: float
                                    example: 50000.00
            responses:
                200:
                    description: OK!
                    content:
                        application/json:
                            schema:
                                properties:
                                    code:
                                        type: number
                                        example: 200
                                    sender:
                                        type: string
                                        example: Confidence James
                                    amount sent:
                                        type: number
                                        format: float
                                        example: 500000.00
                                    receiver:
                                        type: string
                                        example: Prisca Ugbah
                                    message:
                                        type: string
                                        example: Successful
                400:
                    description: You are not authorized to do this!
                404:
                    description: Not Found.
                500:
                    description: We are having server issues, don't mind us, lol x.
            """
            sender = User.query.filter_by(accountNumber=request.json.get('sender')).first()
            if not sender:
                abort(404, description="Check the sender's account")

            recipient = User.query.filter_by(accountNumber=request.json.get('receiver')).first()
            if not recipient:
                abort(404, description="Check your destination's account")

            amount = request.json.get('amount')
            if amount and amount <= sender.accountBalance:
                sender.accountBalance -= amount
                sender.safeToSpend -= amount
                recipient.accountBalance += amount
            else:
                abort(400, description='Insufficient Balance!')

            transfer = Transfer(amount=amount, receiverAccountNumber=f'{recipient.accountNumber}', receiverName=f'{recipient.firstName} {recipient.lastName}', user_transfer=sender)
            db.session.add(transfer)

            deposit = Deposit(amount=amount, sender=f'{recipient.firstName} {recipient.lastName}', user_deposit=recipient)
            db.session.add(deposit)

            db.session.commit()
            response = {
                "code": 200,
                "sender": f"{sender.firstName} {sender.lastName}",
                "amount sent": amount,
                "receiver": f"{recipient.firstName} {recipient.lastName}",
                "message": "Successful"
            }

            return response, 200
    else:
        abort(400, description='You are not authorized to do that.')   

@app.route('/transfers/<int:transfer_id>', methods=['GET', 'DELETE'])
def transferHistoryOne(transfer_id):
    verify_jwt_in_request(locations='cookies')
    transfer = Transfer.query.get_or_404(transfer_id)
    if current_user == transfer.user_transfer:
        if request.method == 'GET':
            """
            @api [get] /api/transfers/{transfer_id}
            tags: [Transfer]
            parameters:
                - (path) transfer_id* {integer:int32} Transfer ID
            summary: History of a particular transfer.
            description: Get a particular transfer from a user's account.
            responses:
                200:
                    description: OK!
                    content:
                        application/json:
                            schema:
                                type: object
                                properties:
                                    Date Created:
                                        type: string
                                        format: date
                                        example: 06-12-1970
                                    Amount:
                                        type: number
                                        format: float
                                        example: 50000.00
                                    Receiver's Name:
                                        type: string
                                        example: Confidence James
                                    Receiver's Account Number:
                                        type: string
                                        example: 100000000
                400:
                    description: You are not authorized to do that.
                404:
                    description: Not Found.
                500:
                    description: We are having server issues, don't mind us, lol x.
            """
            return jsonify(transferSchema.dump(transfer))

        if request.method == 'DELETE':
            """
            @api [delete] /api/transfers/{transfer_id}
            tags: [Transfer]
            parameters:
                - (path) transfer_id* {integer:int32} Transfer ID
            summary: Delete a particular transfer.
            description: Get a particular transfer from a user's account and delete it.
            responses:
                200:
                    description: OK!
                    content:
                        application/json:
                            schema:
                                type: object
                                properties:
                                    code:
                                        type: integer
                                        format: int32
                                        example: 200
                                    msg:
                                        type: string
                                        example: Successful

                400:
                    description: You are not authorized to do that.
                404:
                    description: Not Found.
                500:
                    description: We are having server issues, don't mind us, lol x.
            """
            response = {
                "code": 200,
                "msg": "Ticket deleted successfully."
            }
            db.session.delete(transfer)
            db.session.commit()

            return response, 200

    abort(400, description='You are not authorized to do that!')

@app.route('/api/safe')
def safe():
    verify_jwt_in_request(locations='cookies')
    """
    @api [get] /api/safe
    tags: [Safe]
    summary: Safe to spend
    description: Get the safe amount left for a user to spend for that particular day.
    responses:
        200:
            description: OK!
            content:
                application/json:
                    schema:
                        type: object
                        properties:
                            code:
                                type: integer
                                format: int32
                                example: 200
                            Safe To Spend:
                                type: number
                                format: float
                                example: 50000.00
        400:
            description: You are not authorized to do that.
        404:
            description: Not Found.
        500:
            description: We are having server issues, don't mind us, lol x.
    """
    response = {
        "code": 200,
        "Safe To Spend": current_user.safeToSpend
    }

    return response, 200

@app.route('/api/users/logout')
def logout():
    """
    @api [get] /api/users/logout
    tags: [User]
    summary: Logout a user
    description: Logout a user and also blacklist the access token.
    responses:
        200:
            description: OK!
            content:
                application/json:
                    schema:
                        type: array
                        items:
                            type: object
                            properties:
                                msg:
                                    type: string
                                    example: Logout Successful
        400:
            description: You are not authorized to do that.
        404:
            description: Not Found.
        500:
            description: We are having server issues, don't mind us, lol x.
    """
    verify_jwt_in_request(locations='cookies')
    jti = get_jwt()["jti"]
    tokenBlock = TokenBlocklist(jti=jti, dateCreated=datetime.now(timezone.utc))
    db.session.add(tokenBlock)
    db.session.commit()
    response = jsonify({"msg": "logout successfully."})
    unset_jwt_cookies(response)
    return response, 200

@app.route('/api/users/refresh', methods=['POST'])
# @jwt_required(locations='cookies', refresh=True)
def refresh():
    verify_jwt_in_request(locations='cookies', refresh=True)
    """
    @api [get] /api/users/refresh
    tags: [User]
    summary: Refresh Token
    description: Refresh a users existing token and return a new access token
    responses:
        200:
            description: OK!
            content:
                application/json:
                    schema:
                        type: array
                        items:
                            type: object
                            properties:
                                access_token:
                                    type: string
                                    example: random string
        400:
            description: You are not authorized to do that.
        404:
            description: Not Found.
        500:
            description: We are having server issues, don't mind us, lol x.
    """
    access_token = create_access_token(identity=current_user, fresh=False)
    return jsonify(access_token=access_token)

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

# @app.route('/spec')
# def spec():
#     swag = swagger(app=app)
#     swag["info"]["version"] = 1.0
#     swag["info"]["title"] = "Banking App"
#     return swag


SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.yaml'

# Call factory function to create our blueprint
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  # Swagger UI static files will be mapped to '{SWAGGER_URL}/dist/'
    API_URL,
    config={  # Swagger UI config overrides
        
        'app_name': "Banking App",
        'app_version': 1.0
    },
    # oauth_config={  # OAuth config. See https://github.com/swagger-api/swagger-ui#oauth2-configuration .
    #    'clientId': "your-client-id",
    #    'clientSecret': "your-client-secret-if-required",
    #    'realm': "your-realms",
    #    'appName': "your-app-name",
    #    'scopeSeparator': " ",
    #    'additionalQueryStringParams': {'test': "hello"}
    # }
)

app.register_blueprint(swaggerui_blueprint)