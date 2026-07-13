from app import create_app
app = create_app()

# Handle the branch where __name__ == '__main__' evaluates to true.
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=app.config["APP_PORT"])
