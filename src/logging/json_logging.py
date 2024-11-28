import logging
from logging.handlers import TimedRotatingFileHandler
from pythonjsonlogger import jsonlogger
from uuid import uuid4
import pendulum


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        log_record['timestamp'] = pendulum.now().to_iso8601_string() 
        log_record['uuid'] = str(uuid4())
        log_record['process_id'] = record.process
        log_record['thread_id'] = record.thread
        log_record['thread_name'] = record.threadName
        log_record['module'] = record.module
        log_record['line_number'] = record.lineno

        
def setup_logger(name: str = 'ApplicationLogger', log_file: str = 'app.log', level: int = logging.INFO) -> logging.Logger:
    """Setup logger with JSON formatter for file and plain text formatter for stream."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    json_log_format = CustomJsonFormatter('%(uuid)s %(timestamp)s %(name)s %(levelname)s %(message)s %(process_id)s %(thread_id)s %(thread_name)s %(module)s %(line_number)s')
    file_handler = TimedRotatingFileHandler(log_file, when="D", interval=1, backupCount=30)
    file_handler.setFormatter(json_log_format)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_log_format = logging.Formatter('%(asctime)s | %(name)s | %(levelname)s | %(message)s | %(process)d | %(thread)d | %(threadName)s | %(module)s | %(lineno)d')
    stream_handler.setFormatter(stream_log_format)
    logger.addHandler(stream_handler)

    return logger

# test_logger = setup_logger('test_logger')
