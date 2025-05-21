from flask import Blueprint, request
from extensions import limiter  # ⬅️ import the same limiter
from controllers.IDSController import trigger_intrusion, test_get

## CONTROLLER IMPORTS
from controllers.IDSController import trigger_intrusion, test_get


IDS_bp = Blueprint('IDS_bp', __name__)


@IDS_bp.route('/trigger-intrusion', methods=['POST'])
def trigger_intrusion_route():
    return trigger_intrusion()


@IDS_bp.route('/test-get', methods=['GET'])
@limiter.limit("1 per 30 seconds")
def test_get_route():
    return test_get()