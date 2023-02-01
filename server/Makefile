activate:
	. venv/bin/activate

install:
	pip install --upgrade pip
	pip install -r requirements.txt

run:
	gunicorn --bind :5000 --workers 1 --threads 8 --timeout 0 run:app

migration:
	# Uncomment out this line if you do not have migration folder already
	# flask db init
	flask db stamp head
	flask db migrate -m "Update"
	flask db upgrade