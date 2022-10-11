generate_docs:
	oas generate output.yaml | json2yaml | tee ../server/mealplan/static/output.yaml
watch_oas:
	watchman-make -p './**/*.py' -t generate_docs