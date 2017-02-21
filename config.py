import os
THREATSTACK_API_KEY = os.environ.get('THREATSTACK_API_KEY')
THREATSTACK_BASE_URL = os.environ.get('THREATSTACK_BASE_URL', 'https://app.threatstack.com/api/v1')

WAVEFRONT_API_TOKEN = os.environ.get('WAVEFRONT_API_TOKEN')
WAVEFRONT_BASE_URL = os.environ.get('WAVEFRONT_BASE_URL', 'https://try.wavefront.com')

