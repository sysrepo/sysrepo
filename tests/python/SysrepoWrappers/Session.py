import sysrepoPy as sr


class Session:

    def __init__(self, sysrepo, datastore, user_name=None):
        if user_name is None:
            self.session = sr.sr_session_start(sysrepo.connection, datastore)
        else:
            self.session = sr.sr_session_start_user(sysrepo.connection, user_name, datastore)

    def __del__(self):
        sr.sr_session_stop(self.session)

    def refresh(self):
        sr.sr_session_refresh(self.session)

    def get_last_error(self):
        return sr.sr_get_last_error(self.session)

    def get_last_errors(self):
        return sr.sr_get_last_errors(self.session)

    def list_schemas(self):
        return sr.sr_list_schemas(self.session)

    def get_schema(self, module_name, revision, submodule_name, schema_format):
        return sr.sr_get_schema(self.session, module_name, submodule_name, schema_format)

    def get_item(self, path):
        return sr.sr_get_item(self.session, path)

    def get_items(self, path):
        return sr.sr_get_items(self.session, path)

    def set_item(self, path, value, options):
        sr.sr_set_item(self.session, path, value, options)