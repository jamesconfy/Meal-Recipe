docker:
	docker build -t everybody8/meal-recipe:v1.0 server/.

tag:
	docker tag everybody8/meal-recipe:v1.0 gcr.io/meal-recipe/meal-recipe:v1.0

push:
	docker push gcr.io/meal-recipe/meal-recipe:v1.0

deploy:
	gcloud run deploy --image gcr.io/meal-recipe/meal-recipe:v1.0