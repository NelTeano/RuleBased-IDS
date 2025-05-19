# app.py
from flask import Flask, jsonify, request
import requests
import os

port = int(os.environ.get("PORT", 5000))
app = Flask(__name__)

dashboardPORT = 5114  # Port for the Node.js dashboard server

@app.route('/')
def home():
    return 'Flask Server is Running!'



@app.route('/trigger-intrusion', methods=['POST'])
def trigger_intrusion():
    try:
        # Forward the incoming JSON to the Node.js server
        response = requests.post(
            f'http://localhost:{dashboardPORT}/api/ids',  # Adjust to your Node.js endpoint
            json=request.json
        )
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
