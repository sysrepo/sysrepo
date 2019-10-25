%module sysrepo

%include <stdint.i>

/* Filter out 'Setting a const char * variable may leak memory' warnings */
%warnfilter(451);

/* Filter out 'Identifier '~Subscribe' redefined by %extend (ignored)'*/
%warnfilter(302);

%{
    extern "C" {
        #include "../inc/sysrepo.h"
    }

%}

%include <std_except.i>
%catches(std::runtime_error, std::exception, std::string);

%inline %{
#include <unistd.h>
#include "../inc/sysrepo.h"
#include <signal.h>
#include <vector>
#include <memory>

#include "Sysrepo.hpp"
#include "Struct.hpp"
#include "Session.hpp"


/* custom infinite loop */
volatile int exit_application = 0;

static void
sigint_handler(int signum)
{
    exit_application = 1;
}


static void global_loop() {
    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    while (!exit_application) {
        sleep(1000);  /* or do some more useful work... */
    }
}

class Wrap_cb {
public:
    Wrap_cb(PyObject *callback): _callback(nullptr) {

        if (!PyCallable_Check(callback)) {
            throw std::runtime_error("Python Object is not callable.\n");
        }
        else {
            _callback = callback;
            Py_XINCREF(_callback);
        }
    }
    ~Wrap_cb() {
        if(_callback)
            Py_XDECREF(_callback);
    }

    int module_change_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, \
            uint32_t request_id, PyObject *private_data) {
        PyObject *arglist;
#if defined(SWIG_PYTHON_THREADS)
        SWIG_Python_Thread_Block safety;
#endif

        sysrepo::Session *sess = (sysrepo::Session *)new sysrepo::Session(session);
        std::shared_ptr<sysrepo::Session> *shared_sess = sess ? new std::shared_ptr<sysrepo::Session>(sess) : 0;
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_DISOWN);

        arglist = Py_BuildValue("(OsiO)", s, module_name, event, request_id, private_data);
        PyObject *result = PyEval_CallObject(_callback, arglist);
        Py_DECREF(arglist);
        if (result == nullptr) {
            sess->~Session();
            throw std::runtime_error("Python callback module_change_subscribe failed.\n");
        } else {
            sess->~Session();
            int ret = SR_ERR_OK;
            if (result && PyInt_Check(result)) {
                ret = PyInt_AsLong(result);
            }
            Py_DECREF(result);
            return ret;
        }
    }

        int rpc_cb(
        sr_session_ctx_t *session, const char *op_path, const sr_val_t *input, const size_t input_cnt, \
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, PyObject *private_data) {
        PyObject *arglist;
#if defined(SWIG_PYTHON_THREADS)
        SWIG_Python_Thread_Block safety;
#endif

        sysrepo::Session *sess = (sysrepo::Session *)new sysrepo::Session(session);
        std::shared_ptr<sysrepo::Session> *shared_sess = sess ? new std::shared_ptr<sysrepo::Session>(sess) : 0;
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_DISOWN);

        sysrepo::Vals *in_vals =(sysrepo::Vals *)new sysrepo::Vals(input, input_cnt, nullptr);
        sysrepo::Vals_Holder *out_vals =(sysrepo::Vals_Holder *)new sysrepo::Vals_Holder(output, output_cnt);

        std::shared_ptr<sysrepo::Vals> *shared_in_vals = in_vals ? new std::shared_ptr<sysrepo::Vals>(in_vals) : 0;
        PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_in_vals), SWIGTYPE_p_std__shared_ptrT_sysrepo__Vals_t, SWIG_POINTER_DISOWN);

        std::shared_ptr<sysrepo::Vals_Holder> *shared_out_vals = out_vals ? new std::shared_ptr<sysrepo::Vals_Holder>(out_vals) : 0;
        PyObject *out = SWIG_NewPointerObj(SWIG_as_voidptr(shared_out_vals), SWIGTYPE_p_std__shared_ptrT_sysrepo__Vals_Holder_t, SWIG_POINTER_DISOWN);

        arglist = Py_BuildValue("(sOOO)",s, op_path, in,event,request_id, out, private_data);
        PyObject *result = PyEval_CallObject(_callback, arglist);
        Py_DECREF(arglist);
        if (result == nullptr) {
            in_vals->~Vals();
            out_vals->~Vals_Holder();
            throw std::runtime_error("Python callback rpc_cb failed.\n");
        } else {
            in_vals->~Vals();
            out_vals->~Vals_Holder();
            int ret = SR_ERR_OK;
            if (result && PyInt_Check(result)) {
                ret = PyInt_AsLong(result);
            }
            Py_DECREF(result);
            return ret;
        }
     }

    int rpc_tree_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event, \
        uint32_t request_id, struct lyd_node *output, PyObject *private_data) {
        PyObject *arglist;
#if defined(SWIG_PYTHON_THREADS)
        SWIG_Python_Thread_Block safety;
#endif

        sysrepo::Session *sess = (sysrepo::Session *)new sysrepo::Session(session);
        std::shared_ptr<sysrepo::Session> *shared_sess = sess ? new std::shared_ptr<sysrepo::Session>(sess) : 0;
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_DISOWN);

        libyang::Data_Node *in_tree =(libyang::Data_Node *)new libyang::Data_Node(const_cast<struct lyd_node *>(input));
        libyang::Data_Node *out_tree =(libyang::Data_Node *)new libyang::Data_Node(const_cast<struct lyd_node *>(output));

        std::shared_ptr<libyang::Data_Node> *shared_in_tree = in_tree ? new std::shared_ptr<libyang::Data_Node>(in_tree) : 0;
        PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_in_tree), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_t, SWIG_POINTER_DISOWN);

        std::shared_ptr<libyang::Data_Node> *shared_out_tree = out_tree ? new std::shared_ptr<libyang::Data_Node>(out_tree) : 0;
        PyObject *out = SWIG_NewPointerObj(SWIG_as_voidptr(shared_out_tree), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_t, SWIG_POINTER_DISOWN);
        arglist = Py_BuildValue("(sOOO)",s,op_path, in, event, request_id, out, private_data);
        PyObject *result = PyEval_CallObject(_callback, arglist);
        Py_DECREF(arglist);
        if (result == nullptr) {
            in_tree->~Data_Node();
            out_tree->~Data_Node();
            throw std::runtime_error("Python callback rpc_tree_cb failed.\n");
        } else {
            in_tree->~Data_Node();
            out_tree->~Data_Node();
            int ret = SR_ERR_OK;
            if (result && PyInt_Check(result)) {
                ret = PyInt_AsLong(result);
            }
            Py_DECREF(result);
            return ret;
        }
    }

    void event_notif(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const char *path, \
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, PyObject *private_data) {
        PyObject *arglist;
#if defined(SWIG_PYTHON_THREADS)
        SWIG_Python_Thread_Block safety;
#endif

        sysrepo::Session *sess = (sysrepo::Session *)new sysrepo::Session(session);
        std::shared_ptr<sysrepo::Session> *shared_sess = sess ? new std::shared_ptr<sysrepo::Session>(sess) : 0;
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_DISOWN);

        sysrepo::Vals *in_vals =(sysrepo::Vals *)new sysrepo::Vals(values, values_cnt, nullptr);
        std::shared_ptr<sysrepo::Vals> *shared_in_vals = in_vals ? new std::shared_ptr<sysrepo::Vals>(in_vals) : 0;
        PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_in_vals), SWIGTYPE_p_std__shared_ptrT_sysrepo__Vals_t, SWIG_POINTER_DISOWN);

        arglist = Py_BuildValue("(sOlO)", s, notif_type, path, in, (long)timestamp, private_data);
        PyObject *result = PyEval_CallObject(_callback, arglist);
        Py_DECREF(arglist);
        if (result == nullptr) {
            in_vals->~Vals();
            throw std::runtime_error("Python callback event_notif failed.\n");
        } else {
            in_vals->~Vals();
            Py_DECREF(result);
        }
    }

    void event_notif_tree(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, \
        const struct lyd_node *notif, time_t timestamp, PyObject *private_data) {
        PyObject *arglist;
#if defined(SWIG_PYTHON_THREADS)
        SWIG_Python_Thread_Block safety;
#endif
        sysrepo::Session *sess = (sysrepo::Session *)new sysrepo::Session(session);
        std::shared_ptr<sysrepo::Session> *shared_sess = sess ? new std::shared_ptr<sysrepo::Session>(sess) : 0;
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_DISOWN);

        libyang::Data_Node *node =(libyang::Data_Node *)new libyang::Data_Node(const_cast<struct lyd_node *>(notif));
        std::shared_ptr<libyang::Data_Node> *shared_node = node ? new std::shared_ptr<libyang::Data_Node>(node) : 0;
        PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_node), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_t, SWIG_POINTER_DISOWN);

        arglist = Py_BuildValue("(sOlO)", s, notif_type, in, (long)timestamp, private_data);
        PyObject *result = PyEval_CallObject(_callback, arglist);
        Py_DECREF(arglist);
        if (result == nullptr) {
            node->~Data_Node();
            throw std::runtime_error("Python callback event_notif_tree failed.\n");
        } else {
            node->~Data_Node();
            Py_DECREF(result);
        }
    }

    int oper_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *path, \
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
    {
        PyObject *arglist;
#if defined(SWIG_PYTHON_THREADS)
        SWIG_Python_Thread_Block safety;
#endif

        
        sysrepo::Session *sess = (sysrepo::Session *)new sysrepo::Session(session);
        std::shared_ptr<sysrepo::Session> *shared_sess = sess ? new std::shared_ptr<sysrepo::Session>(sess) : 0;
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_DISOWN);
        if (*parent) {
            libyang::Data_Node *tree =(libyang::Data_Node *)new libyang::Data_Node(const_cast<struct lyd_node *>(*parent));
            
            std::shared_ptr<libyang::Data_Node> *shared_tree = tree ? new std::shared_ptr<libyang::Data_Node>(tree) : 0;
            PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_tree), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_t, SWIG_POINTER_DISOWN);

            arglist = Py_BuildValue("(sOlO)", s, module_name, path, request_xpath, request_id, in, private_data);
            PyObject *result = PyEval_CallObject(_callback, arglist);
            Py_DECREF(arglist);
            if (result == nullptr) {
                tree->~Data_Node();
                throw std::runtime_error("Python callback oper_get_items_cb failed.\n");
            } else {
                tree->~Data_Node();
                Py_DECREF(result);
            }
        } else {
            libyang::Data_Node *tree =(libyang::Data_Node *)new libyang::Data_Node(nullptr);
            
            std::shared_ptr<libyang::Data_Node> *shared_tree = tree ? new std::shared_ptr<libyang::Data_Node>(tree) : 0;
            PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_tree), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_t, SWIG_POINTER_DISOWN);

            arglist = Py_BuildValue("(sOlO)", s, module_name, path, request_xpath, request_id, in, private_data);
            PyObject *result = PyEval_CallObject(_callback, arglist);
            Py_DECREF(arglist);
            if (result == nullptr) {
                tree->~Data_Node();
                throw std::runtime_error("Python callback oper_get_items_cb failed.\n");
            } else {
                tree->~Data_Node();
                Py_DECREF(result);
            }
        }
        return 0;
    }

    PyObject *private_ctx;

private:
    PyObject *_callback;
};

static int g_module_change_subscribe_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, \
                                        sr_event_t event, uint32_t request_id, void *private_data)
{
    Wrap_cb *ctx = (Wrap_cb *) private_data;
    return ctx->module_change_subscribe(session, module_name, xpath, event, request_id, ctx->private_data);
}

static int g_rpc_cb(sr_session_ctx_t *session, const char *op_path, const sr_val_t *input, const size_t input_cnt, \
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    Wrap_cb *ctx = (Wrap_cb *) private_data;
    return ctx->rpc_cb(session, op_path, input, input_cnt, event, request_id, output, output_cnt, ctx->private_data);
}

static int g_rpc_tree_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, \
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    Wrap_cb *ctx = (Wrap_cb *) private_data;
    return ctx->rpc_tree_cb(session, op_path, input, event, request_id, output, ctx->private_data);
}

static void g_event_notif_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const char *path, \
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_data)
{
    Wrap_cb *ctx = (Wrap_cb *) private_data;
    ctx->event_notif(session, notif_type, path, values, values_cnt, timestamp, ctx->private_data);
}

static void g_event_notif_tree_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, \
        const struct lyd_node *notif, time_t timestamp, void *private_data)
{
    Wrap_cb *ctx = (Wrap_cb *) private_data;
    ctx->event_notif_tree(session, notif_type, notif, timestamp, ctx->private_data);
}

static int g_oper_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *path, \
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    Wrap_cb *ctx = (Wrap_cb *) private_data;
    return ctx->oper_get_items_cb(session, module_name, path, request_xpath, request_id, parent, ctx->private_data);
}


%}

%extend sysrepo::Subscribe {

    void module_change_subscribe(const char *module_name, PyObject *callback, const char *xpath, \
                                 PyObject *private_data = nullptr, \
                                 uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        /* create class */
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_data) {
            class_ctx->private_data = private_data;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_data = Py_None;
        }

        int ret = sr_module_change_subscribe(self->swig_sess(), module_name, xpath,\
                                             g_module_change_subscribe_cb, class_ctx, priority, \
                                             opts, self->swig_sub());
        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    };

    void subtree_change_subscribe(const char *xpath, PyObject *callback, PyObject *private_ctx = nullptr,\
                                 uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        /* create class */
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_ctx) {
            class_ctx->private_ctx = private_ctx;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_ctx = Py_None;
        }

        int ret = sr_subtree_change_subscribe(self->swig_sess(), xpath, g_subtree_change_cb, class_ctx,\
                                              priority, opts, self->swig_sub());
        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void module_install_subscribe(PyObject *callback, PyObject *private_ctx = nullptr,\
                                  sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        /* create class */
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_ctx) {
            class_ctx->private_ctx = private_ctx;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_ctx = Py_None;
        }

        int ret =  sr_module_install_subscribe(self->swig_sess(), g_module_install_cb, class_ctx,
                                               opts, self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void feature_enable_subscribe(PyObject *callback, PyObject *private_ctx = nullptr,\
                                  sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        /* create class */
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_ctx) {
            class_ctx->private_ctx = private_ctx;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_ctx = Py_None;
        }

        int ret = sr_feature_enable_subscribe(self->swig_sess(), g_feature_enable_cb, class_ctx,
                                              opts, self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void rpc_subscribe(const char *xpath, PyObject *callback, PyObject *private_ctx = nullptr,\
                       sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_ctx) {
            class_ctx->private_ctx = private_ctx;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_ctx = Py_None;
        }

        int ret = sr_rpc_subscribe(self->swig_sess(), xpath, g_rpc_cb, class_ctx, opts,\
                                   self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void action_subscribe(const char *xpath, PyObject *callback, PyObject *private_ctx = nullptr,\
                       sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_ctx) {
            class_ctx->private_ctx = private_ctx;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_ctx = Py_None;
        }

        int ret = sr_action_subscribe(self->swig_sess(), xpath, g_action_cb, class_ctx, opts,\
                                   self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void rpc_subscribe_tree(const char *xpath, PyObject *callback, PyObject *private_ctx = nullptr,\
                       sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_ctx) {
            class_ctx->private_ctx = private_ctx;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_ctx = Py_None;
        }

        int ret = sr_rpc_subscribe_tree(self->swig_sess(), xpath, g_rpc_tree_cb, class_ctx, opts,\
                                   self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void action_subscribe_tree(const char *xpath, PyObject *callback, PyObject *private_ctx = nullptr,\
                       sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_ctx) {
            class_ctx->private_ctx = private_ctx;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_ctx = Py_None;
        }

        int ret = sr_action_subscribe_tree(self->swig_sess(), xpath, g_action_tree_cb, class_ctx, opts,\
                                   self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void event_notif_subscribe(const char *xpath, PyObject *callback, PyObject *private_ctx = nullptr,\
                               sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_ctx) {
            class_ctx->private_ctx = private_ctx;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_ctx = Py_None;
        }

        int ret = sr_event_notif_subscribe(self->swig_sess(), xpath, g_event_notif_cb, class_ctx, opts,\
                                   self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void event_notif_subscribe_tree(const char *xpath, PyObject *callback, PyObject *private_ctx = nullptr,\
                               sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_ctx) {
            class_ctx->private_ctx = private_ctx;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_ctx = Py_None;
        }

        int ret = sr_event_notif_subscribe_tree(self->swig_sess(), xpath, g_event_notif_tree_cb,\
                                                class_ctx, opts, self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void dp_get_items_subscribe(const char *xpath, PyObject *callback, PyObject *private_ctx = nullptr, \
                               sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_ctx) {
            class_ctx->private_ctx = private_ctx;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_ctx = Py_None;
        }

        int ret = sr_dp_get_items_subscribe(self->swig_sess(), xpath, g_dp_get_items_cb, class_ctx,\
                                            opts, self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void additional_cleanup(void *private_ctx) {
        delete static_cast<Wrap_cb*>(private_ctx);
    }
};

%include "../swig_base/python_base.i"
