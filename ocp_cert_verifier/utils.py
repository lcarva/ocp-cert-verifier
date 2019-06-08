import logging
from io import StringIO


def once(func):
    no_result = object()
    context = {'result': no_result}

    def wrapped(*args, **kwargs):
        if context['result'] == no_result:
            context['result'] = func(*args, **kwargs)
        return context['result']

    return wrapped


@once
def setup_app_logger():
    logger = logging.getLogger('ocp_cert_verifier')

    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


@once
def setup_string_logger():
    logger = logging.getLogger('ocp_cert_verifier')
    formatter = logging.Formatter('%(levelname)-8s %(message)s')
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return stream


def setup_string_logger_and_reset():
    stream = setup_string_logger()
    stream.seek(0)
    stream.truncate(0)
    return stream


def validate_smtp_info(smtp_info):
    if not smtp_info:
        return
    assert bool(smtp_info['server']) == bool(smtp_info['to']) == bool(smtp_info['from'])
