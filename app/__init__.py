'''
Assemble our service.
'''
from flask_lambda import FlaskLambda
import logging

_logger = logging.getLogger(__name__)

def _initialize_blueprints(application):
    '''
    Register Flask blueprints
    '''
    from app.views.wavefront import wavefront
    application.register_blueprint(wavefront, url_prefix='/threatstack-to-wavefront/api/v1/wavefront')

def _initialize_errorhandlers(application):
    '''
    Initialize error handlers
    '''
    from app.errors import errors
    application.register_blueprint(errors)

def create_app():
    '''
    Create an app by initializing components.
    '''
    _logger.info('Initializing application')
    application = FlaskLambda(__name__)

    _initialize_errorhandlers(application)
    _initialize_blueprints(application)

    # Do it!
    return application

