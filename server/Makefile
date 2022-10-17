activate:
	. venv/bin/activate

install:
	pip install --upgrade pip
	pip install -r requirements.txt

run:
	gunicorn --bind 0.0.0.0:80 run:app