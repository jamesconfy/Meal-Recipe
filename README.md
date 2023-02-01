# Meal-Recipe

## Introduction

This is a meal recipe api, where you can create new user, register and create meal plans. You can still download such said meal plans as a pdf file.

## Directions

To get the app up and running. [(repo link)](https://github.com/jamesconfy/Meal-Recipe.git/). You can do this by opening up a terminal on your system and typing `git clone https://github.com/jamesconfy/Meal-Recipe.git/`.

**N.B:** [(Note this should be done in the server folder)](/server/). To navigate to the server directory, run a `cd server/` on your terminal before you continue.

After it is done cloning and you can confirm that you are now in the [server directory](./server/), you create a virtual environment and activate it with this command `python3 -m venv .venv && source .venv/bin/activate`. This is assuming you have the latest version of Python (3.11 as of the writing of this documentation), if not you can download it using this link: [python](https://www.python.org/downloads/).

The next step is to upgrade pip, this can be done with the command `pip install --upgrade pip`.
After pip is done upgrading, you install the requirements.txt file using `pip install -r requirements.txt`

After going through all those set-ups, you are ready to start the app, but do not forget to create a `.env` file using the sample.env provided for you, copy the variables and provide what is required (in this case it is just your jwt secret key and a secret key).

You can finally run `flask run` to start the app in development mode, or `gunicorn --bind :5000 --workers 1 --threads 8 --timeout 0 run:app` for production mode.

You could just use the already created Makefile to start the application `make run`, this run in production mode.

## Navigate

- **Using flask run**
  After starting the app (using `flask run`), you should see the below message.

  ```terminal
  * Serving Flask app 'run.py' (lazy loading)
  * Environment: production
  WARNING: This is a development server. Do not use it in a production deployment.
  Use a production WSGI server instead.
  * Debug mode: off
  * Running on http://127.0.0.1:5000 (Press CTRL+C to quit)

  ```

- **Using gunicorn**
  After starting the app (using the gunicorn command), you should see the below message.

  ```terminal
  [2023-01-24 19:59:03 +0100] [75909] [INFO] Starting gunicorn 20.1.0
  [2023-01-24 19:59:03 +0100] [75909] [INFO] Listening at: http://0.0.0.0:5000 (75909)
  [2023-01-24 19:59:03 +0100] [75909] [INFO] Using worker: gthread
  [2023-01-24 19:59:03 +0100] [75910] [INFO] Booting worker with pid: 75910
  ```

After seeing this, you can then access the application on [localhost](http://localhost:5000/api/home)
