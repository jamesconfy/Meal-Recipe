from mealplan import create_app

app = create_app()

if __name__ == '__main__':
    app.run(host='localhost', port=8080, load_dotenv=True)