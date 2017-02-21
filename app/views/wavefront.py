'''
Send alert events to Wavefront.
'''

from flask import Blueprint, jsonify, request
import logging
import app.models.wavefront as wavefront_model
import app.models.threatstack as threatstack_model

_logger = logging.getLogger(__name__)

wavefront = Blueprint('wavefront', __name__)

#decerator refers to the blueprint object.
@wavefront.route('/status', methods=['GET'])
def is_available():
    '''
    Test that Threat Stack and wavefront bucket are reachable.
    '''
    wf = wavefront_model.WaveFrontModel()
    wavefront_status = wf.is_available()
    wavefront_info = {'success': wavefront_status}

    ts = threatstack_model.ThreatStackModel()
    ts_status = ts.is_available()
    ts_info = {'success': ts_status}

    status_code = 200
    if wavefront_status and ts_status:
        success = True
    else:
        success = False

    return jsonify(success=success, wavefront=wavefront_info, threatstack=ts_info), status_code

@wavefront.route('/event', methods=['POST'])
def put_alert():
    '''
    Archive Threat Stack alerts to wavefront.
    '''
    wavefront_response_list = []
    webhook_data = request.get_json()
    for alert in webhook_data.get('alerts'):
        ts = threatstack_model.ThreatStackModel()
        alert_full = ts.get_alert_by_id(alert.get('id'))
        if alert_full.get('agent_id'):
            agent = ts.get_agent_by_id(alert_full.get('agent_id'))
            hostname = agent.get('hostname')
        else:
            hostname = None

        wf = wavefront_model.WaveFrontModel()
        wavefront_response = wf.put_alert_event(alert_full, hostname)
        wavefront_response_list.append(wavefront_response)

    status_code = 200
    success = True
    response = {'success': success, 'wavefront': wavefront_response_list}

    return jsonify(response), status_code

