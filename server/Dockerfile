FROM python:3.10.2-alpine

WORKDIR /app

COPY . /app

RUN pip install --upgrade pip && pip install -r requirements.txt

EXPOSE 80

CMD [ "gunicorn", "--bind", "0.0.0.0:80", "run:app" ]