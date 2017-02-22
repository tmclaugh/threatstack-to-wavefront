'''
Wavefront Model
'''
import config
import logging
import wavefront_api_client

_logger = logging.getLogger(__name__)

WAVEFRONT_API_TOKEN = config.WAVEFRONT_API_TOKEN
WAVEFRONT_BASE_URL = config.WAVEFRONT_BASE_URL
WAVEFRONT_ALERT_TYPE = 'Threat Stack'
WAVEFRONT_TAG_NAME= 'ThreatStack'

THREATSTACK_TO_WAVEFRONT_ALERTS = {
    1: 'severe',
    2: 'warning',
    3: 'info'
}

class WaveFrontModel:
    def __init__(self, base_url=WAVEFRONT_BASE_URL,
                 api_key=WAVEFRONT_API_TOKEN):
        self.wavefront_client = wavefront_api_client.ApiClient(
            host=WAVEFRONT_BASE_URL,
            header_name='Authorization',
            header_value=WAVEFRONT_API_TOKEN
        )

    def is_available(self):
        '''
        Check Wavefront availability
        '''

        source_api = wavefront_api_client.SourceApi(self.wavefront_client)
        response = source_api.get_all_source(limit=1)

        if response.status.result == 'OK':
            success = True
        else:
            success = False

        return success

    def put_alert_event(self, alert, hostname):
        '''
        Put alert data into Wavefront
        '''
        event = {}
        event['name'] = 'Threat Stack alert: {}'.format(alert.get('rule').get('original_rule').get('name'))
        event['startTime'] = alert.get('created_at')
        event['endTime'] = alert.get('expires_at')
        event['hosts'] = [hostname]
        event['tags'] = [WAVEFRONT_TAG_NAME]
        event['annotations'] = {}
        event['annotations']['severity'] = THREATSTACK_TO_WAVEFRONT_ALERTS[alert.get('severity')]
        event['annotations']['type'] = WAVEFRONT_ALERT_TYPE
        event['annotations']['details'] = alert.get('title')

        # Create the event
        event_api = wavefront_api_client.EventApi(self.wavefront_client)
        resp = event_api.create_event(body=event)

        return resp.to_dict()

