from flask import Flask, jsonify, request
import requests
import os

IDS_PORT = os.getenv('IDS_PORT')


def trigger_intrusion():
    try:
        # Forward the incoming JSON to the Node.js server
        response = requests.post(
            f'http://localhost:{IDS_PORT}/api/ids',  # Adjust to your Node.js endpoint
            json=request.json
        )
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
    
def test_get():
    return jsonify({'message': 'GET request successful!'}), 200