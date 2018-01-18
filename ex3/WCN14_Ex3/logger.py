from threading import current_thread

LOG_DEBUG = 1
LOG_INFO = 2
LOG_WARNING = 3
LOG_ERROR = 4
LOG_CRITICAL = 5


class Logger:
    def __init__(self, severity=LOG_DEBUG):
        self.level = severity
        self.sev_str = ['', 'DBG', 'INF', 'WRN', 'ERR', 'CRT']

    def set_level(self, severity):
        self.level = severity

    def log(self, msg, severity):
        if severity >= self.level:
            print '%s\t%s\t%s' % (self.sev_str[severity], current_thread().name, msg)

    def debug(self, msg):
        self.log(msg, LOG_DEBUG)

    def info(self, msg):
        self.log(msg, LOG_INFO)

    def warning(self, msg):
        self.log(msg, LOG_WARNING)

    def error(self, msg):
        self.log(msg, LOG_ERROR)

    def critical(self, msg):
        self.log(msg, LOG_CRITICAL)


