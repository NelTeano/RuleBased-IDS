# app.py
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os
from extensions import limiter


## Importing Blueprints
from routes.IDSRoutes import IDS_bp

load_dotenv()
app = Flask(__name__)
limiter.init_app(app)
SERVER_PORT = os.getenv('SERVER_PORT')
IDS_PORT = os.getenv('IDS_PORT')
PORT = int(os.environ.get("PORT", SERVER_PORT))


app.config['SERVER_PORT'] = SERVER_PORT
app.config['IDS_PORT'] = IDS_PORT

## Check if the environment variable is set
if SERVER_PORT != '' and IDS_PORT != '':
    print(f"SERVER_PORT: {SERVER_PORT}")
    print(f"IDS_PORT: {IDS_PORT}")
else:
    print("Environment variables SERVER_PORT or IDS_PORT are not set.")


@app.route('/')
def home():
    return 'Flask Server is Running!'

## REGISTER ROUTE BLUEPRINTS
app.register_blueprint(IDS_bp, url_prefix='/api/ids')

if __name__ == '__main__':
    app.run(debug=True, port=PORT)
