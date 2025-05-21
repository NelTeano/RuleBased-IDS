from flask import Flask, jsonify, request
import requests
import os

IDS_PORT = os.getenv('IDS_PORT')

def trigger_intrusion():

    # Extract JSON data from the incoming request
    data = request.get_json()

    # Optional: Extract individual fields if needed
    src_ip = request.remote_addr  # The IP address of the client sending the request
    dst_ip = data.get('dst_ip')
    intrusion_type = data.get('intrusion_type')
    timestamp = data.get('timestamp')

    print(f"[Flask] Forwarding intrusion log: {src_ip=} {dst_ip=} {intrusion_type=} {timestamp=}")


    try:
        response = requests.post(
            f'http://localhost:{IDS_PORT}/api/ids/intrusion-trigger',
            json=data,
            timeout=5
        )

        return jsonify(response.json()), response.status_code
    
    except requests.exceptions.RequestException as e:
        print(f"[Flask] Failed to forward request: {e}")
        return jsonify({'error': str(e)}), 500
    


    
def test_get():
    return jsonify({'message': 'GET request successful!'}), 200