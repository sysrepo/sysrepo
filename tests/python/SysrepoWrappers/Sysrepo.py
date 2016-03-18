import sysrepoPy as sr


class Sysrepo:

    def __init__(self, app_name, options):
        self.connection = sr.sr_connect(app_name, options)

    def __del__(self):
        try:
            sr.sr_disconnect(self.connection)
        except AttributeError:
            pass

    @classmethod
    def log_stderr(self, level):
        sr.sr_log_stderr(level)

    @classmethod
    def log_syslog(self, level):
        sr.sr_log_syslog(level)
