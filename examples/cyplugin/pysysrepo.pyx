import sys
sys.path.insert(0, '/home/equinox/c++/sysrepo/examples/cyplugin')

from libc.stdlib cimport malloc, free
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, int8_t, int16_t, int32_t, int64_t
from cpython cimport PyObject, Py_INCREF, Py_DECREF

cdef extern from "sysrepo.h":
    ####
    struct sr_session_ctx_s:
        pass
    ctypedef sr_session_ctx_s sr_session_ctx_t

    ####
    enum sr_notif_event_e:
        pass
    ctypedef sr_notif_event_e sr_notif_event_t

    enum sr_subscr_flag_e:
        SR_SUBSCR_DEFAULT,
        SR_SUBSCR_CTX_REUSE,
        SR_SUBSCR_PASSIVE,
        R_SUBSCR_VERIFIER,

    ####
    ctypedef uint32_t sr_subscr_options_t

    ####
    ctypedef int (*sr_module_change_cb)(sr_session_ctx_t *session, const char *module_name,
        sr_notif_event_t event, void *private_ctx)

    ####
    struct sr_subscription_ctx_s:
        pass
    ctypedef sr_subscription_ctx_s sr_subscription_ctx_t

    ####
    int sr_module_change_subscribe(
            sr_session_ctx_t *session,
            const char *module_name,
            sr_module_change_cb callback,
            void *private_ctx,
            uint32_t priority,
            sr_subscr_options_t opts,
            sr_subscription_ctx_t **subscription)

    ####
    enum sr_type_e:
        SR_UNKNOWN_T,

        SR_LIST_T,
        SR_CONTAINER_T,
        SR_CONTAINER_PRESENCE_T,
        SR_LEAF_EMPTY_T,
        SR_UNION_T,

        SR_BINARY_T,
        SR_BITS_T,
        SR_BOOL_T,
        SR_DECIMAL64_T,
        SR_ENUM_T,
        SR_IDENTITYREF_T,
        SR_INSTANCEID_T,
        SR_INT8_T,
        SR_INT16_T,
        SR_INT32_T,
        SR_INT64_T,
        SR_STRING_T,
        SR_UINT8_T,
        SR_UINT16_T,
        SR_UINT32_T,
        SR_UINT64_T
    ctypedef sr_type_e sr_type_t

    struct sr_val_data:
        char *enum_val
        int8_t int8_val
        int16_t int16_val
        int32_t int32_val
        int64_t int64_val
        char *string_val
        uint8_t uint8_val
        uint16_t uint16_val
        uint32_t uint32_val
        uint64_t uint64_val

    struct sr_val_s:
        char *xpath
        sr_type_t type
        sr_val_data data
    ctypedef sr_val_s sr_val_t

    int sr_get_items(
            sr_session_ctx_t *session,
            const char *xpath,
            sr_val_t **values,
            size_t *value_cnt)
    void sr_free_values(
            sr_val_t *values,
            size_t count)

cdef struct _cbargs:
    void * cb
    void * args
    void * sesswrap
ctypedef _cbargs cbargs

cdef int subsc_callback(
            sr_session_ctx_t *session,
            const char *module_name,
            sr_notif_event_t event,
            void *private_ctx):

    cdef cbargs *ctxargs = <cbargs *>private_ctx
    cb = <object>ctxargs.cb
    args = <object>ctxargs.args
    sesswrap = <object>ctxargs.sesswrap

    cb(sesswrap, module_name, event, args)

#cpdef pack_unpack():
#    cdef node my_node = node(<void *>"some object")
#
#    # This is what should be returned
#    cdef node *m = &my_node
#    return <object>m.data

cdef class Value:
    cdef sr_val_t *value

    def __cinit__(self, val):
        self.value = <sr_val_t *><long>val
    def __repr__(self):
        return '<Sysrepo Value @ "%s", type %d>' % (self.value.xpath, self.value.type)

cdef class ValueContainer(Value):
    def __repr__(self):
        return '<Sysrepo Container @ "%s">' % (self.value.xpath)

cdef class ValueInt(Value):
    def get(self):
        if self.value.type == SR_INT8_T:
            return self.value.data.int8_val
        if self.value.type == SR_INT16_T:
            return self.value.data.int16_val
        if self.value.type == SR_INT32_T:
            return self.value.data.int32_val
        if self.value.type == SR_INT64_T:
            return self.value.data.int64_val
        if self.value.type == SR_UINT8_T:
            return self.value.data.uint8_val
        if self.value.type == SR_UINT16_T:
            return self.value.data.uint16_val
        if self.value.type == SR_UINT32_T:
            return self.value.data.uint32_val
        if self.value.type == SR_UINT64_T:
            return self.value.data.uint64_val

    def __repr__(self):
        return '<Sysrepo Int @ "%s" = %d>' % (self.value.xpath, self.get())

cdef class ValueStr(Value):
    def get(self):
        if self.value.type == SR_ENUM_T:
            return self.value.data.enum_val
        if self.value.type == SR_STRING_T:
            return self.value.data.string_val

    def __repr__(self):
        return '<Sysrepo Str @ "%s" = %s>' % (self.value.xpath, self.get())


cdef class Values:
    cdef sr_val_t *values
    cdef size_t count

    def __cinit__(self, vals, count):
        self.values = <sr_val_t *><long>vals
        self.count = count
    def __init__(self, food):
        raise ValueError('instances of this class cannot be created')

    def __len__(self):
        return self.count
    def __getitem__(self, idx):
        cdef size_t cidx = idx
        if cidx >= self.count:
            raise IndexError('index %r not in Values list' % idx)
        cdef sr_val_t *value = self.values + cidx
        if value.type == SR_CONTAINER_T:
            return ValueContainer.__new__(ValueContainer, <long>value)
        elif value.type in [SR_INT8_T, SR_INT16_T, SR_INT32_T, SR_INT64_T,
                SR_UINT8_T, SR_UINT16_T, SR_UINT32_T, SR_UINT64_T]:
            return ValueInt.__new__(ValueInt, <long>value)
        elif value.type in [SR_STRING_T, SR_ENUM_T]:
            return ValueStr.__new__(ValueStr, <long>value)
        else:
            return Value.__new__(Value, <long>value)

    def __dealloc__(self):
        sr_free_values(self.values, self.count)

cdef class Session:
    cdef sr_session_ctx_t *ctx

    def __cinit__(self, ctx):
        self.ctx = <sr_session_ctx_t *><long>ctx
    def __init__(self, food):
        raise ValueError('instances of this class cannot be created')

    def subscribe(self, char *module_name, callback, args):
        cdef sr_subscription_ctx_t *retval = NULL
        cdef cbargs *ctxargs = <cbargs *>malloc(sizeof(cbargs))
        Py_INCREF(callback)
        Py_INCREF(args)
        Py_INCREF(self)
        ctxargs.cb = <void *>callback
        ctxargs.args = <void *>args
        ctxargs.sesswrap = <void *>self

        sr_module_change_subscribe(self.ctx, module_name,
                <sr_module_change_cb>subsc_callback, ctxargs, 0,
                SR_SUBSCR_DEFAULT, &retval)

    def get_items(self, xpath):
        cdef sr_val_t *values = NULL
        cdef size_t count = 0
        cdef int ret

        ret = sr_get_items(self.ctx, xpath, &values, &count)
        if ret != 0:
            raise ValueError('sr_get_items returned %d' % ret)

        wrap = Values.__new__(Values, <long>values, count)
        return wrap
        # sr_free_values(values, count)

cdef extern from "pysysrepo.h":
    cdef void pysysrepo_init(sr_session_ctx_t *session)

print 'python import ok'

# try:
#    import ocbgp
# except:
#     sys.excepthook(*sys.exc_info())

cdef void pysysrepo_init(sr_session_ctx_t *session):
    try:
        wrap = Session.__new__(Session, <long>session)

        import usermod
        usermod.init(wrap)
    except:
        sys.excepthook(*sys.exc_info())

# pyocbgp_process(xmlNode *node):
#    cdef cetree._Document cdoc
#    cdef cetree._Element celem
#    try:
#        root = cetree.makeElement('{urn:ietf:params:xml:ns:netconf:base:1.0}data', None, None, text = '', tail = '',
#                attrib = None, nsmap = {None: "urn:ietf:params:xml:ns:netconf:base:1.0"})
#        cdoc  = cetree.documentOrRaise(root._doc)
#        celem = cetree.deepcopyNodeToDocument(cdoc, node)
#        root.append(celem)
#
#        ocbgp.apply(root)
#    except:
#        sys.excepthook(*sys.exc_info())

