%module sysrepo

%include <stdint.i>

/* Filter out 'Setting a const char * variable may leak memory' warnings */
%warnfilter(451);

/* Filter out 'Identifier '~Subscribe' redefined by %extend (ignored)'*/
%warnfilter(302);

%{
    extern "C" {
        #include "sysrepo.h"
    }

%}

%include <std_except.i>
%catches(std::runtime_error, std::exception, std::string);

%inline %{
#include <unistd.h>
#include "sysrepo.h"
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
    signal(SIGUSR1, sigint_handler);
    signal(SIGUSR2, sigint_handler);
    signal(SIGALRM, sigint_handler);
    signal(SIGTERM, sigint_handler);
    while (!exit_application) {
        sleep(1000);  /* or do some more useful work... */
    }
    exit_application = 0;
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
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_OWN);

        arglist = Py_BuildValue("(OssiiO)", s, module_name, xpath, event, request_id, private_data);
        PyObject *result = PyEval_CallObject(_callback, arglist);
        Py_DECREF(arglist);
        Py_DECREF(s);
        if (result == nullptr) {
            throw std::runtime_error("Python callback module_change_subscribe failed.\n");
        } else {
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
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_OWN);

        sysrepo::Vals *in_vals =(sysrepo::Vals *)new sysrepo::Vals(input, input_cnt, nullptr);
        sysrepo::Vals_Holder *out_vals =(sysrepo::Vals_Holder *)new sysrepo::Vals_Holder(output, output_cnt);

        std::shared_ptr<sysrepo::Vals> *shared_in_vals = in_vals ? new std::shared_ptr<sysrepo::Vals>(in_vals) : 0;
        PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_in_vals), SWIGTYPE_p_std__shared_ptrT_sysrepo__Vals_t, SWIG_POINTER_OWN);

        std::shared_ptr<sysrepo::Vals_Holder> *shared_out_vals = out_vals ? new std::shared_ptr<sysrepo::Vals_Holder>(out_vals) : 0;
        PyObject *out = SWIG_NewPointerObj(SWIG_as_voidptr(shared_out_vals), SWIGTYPE_p_std__shared_ptrT_sysrepo__Vals_Holder_t, SWIG_POINTER_OWN);

        arglist = Py_BuildValue("(OsOiiOO)",s, op_path, in,event,request_id, out, private_data);
        PyObject *result = PyEval_CallObject(_callback, arglist);
        Py_DECREF(arglist);
        Py_DECREF(out);
        Py_DECREF(in);
        Py_DECREF(s);
        if (result == nullptr) {
            throw std::runtime_error("Python callback rpc_cb failed.\n");
        } else {
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
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_OWN);

        libyang::Data_Node *in_tree =(libyang::Data_Node *)new libyang::Data_Node(const_cast<struct lyd_node *>(input));
        libyang::Data_Node *out_tree =(libyang::Data_Node *)new libyang::Data_Node(const_cast<struct lyd_node *>(output));

        std::shared_ptr<libyang::Data_Node> *shared_in_tree = in_tree ? new std::shared_ptr<libyang::Data_Node>(in_tree) : 0;
        PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_in_tree), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_t, SWIG_POINTER_OWN);

        std::shared_ptr<libyang::Data_Node> *shared_out_tree = out_tree ? new std::shared_ptr<libyang::Data_Node>(out_tree) : 0;
        PyObject *out = SWIG_NewPointerObj(SWIG_as_voidptr(shared_out_tree), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_t, SWIG_POINTER_OWN);
        arglist = Py_BuildValue("(OsOiiOO)",s,op_path, in, event, request_id, out, private_data);
        PyObject *result = PyEval_CallObject(_callback, arglist);
        Py_DECREF(arglist);
        Py_DECREF(out);
        Py_DECREF(in);
        Py_DECREF(s);
        if (result == nullptr) {
            throw std::runtime_error("Python callback rpc_tree_cb failed.\n");
        } else {
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
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_OWN);

        sysrepo::Vals *in_vals =(sysrepo::Vals *)new sysrepo::Vals(values, values_cnt, nullptr);
        std::shared_ptr<sysrepo::Vals> *shared_in_vals = in_vals ? new std::shared_ptr<sysrepo::Vals>(in_vals) : 0;
        PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_in_vals), SWIGTYPE_p_std__shared_ptrT_sysrepo__Vals_t, SWIG_POINTER_OWN);

        arglist = Py_BuildValue("(OisOlO)", s, notif_type, path, in, (long)timestamp, private_data);
        PyObject *result = PyEval_CallObject(_callback, arglist);
        Py_DECREF(arglist);
        Py_DECREF(in);
        Py_DECREF(s);
        if (result == nullptr) {
            throw std::runtime_error("Python callback event_notif failed.\n");
        } else {
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
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_OWN);

        libyang::Data_Node *node =(libyang::Data_Node *)new libyang::Data_Node(const_cast<struct lyd_node *>(notif));
        std::shared_ptr<libyang::Data_Node> *shared_node = node ? new std::shared_ptr<libyang::Data_Node>(node) : 0;
        PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_node), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_t, SWIG_POINTER_OWN);

        arglist = Py_BuildValue("(OiOlO)", s, notif_type, in, (long)timestamp, private_data);
        PyObject *result = PyEval_CallObject(_callback, arglist);
        Py_DECREF(arglist);
        Py_DECREF(in);
        Py_DECREF(s);
        if (result == nullptr) {
            throw std::runtime_error("Python callback event_notif_tree failed.\n");
        } else {
            Py_DECREF(result);
        }
    }

    int oper_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *path, \
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, PyObject *private_data)
    {
        PyObject *arglist;
#if defined(SWIG_PYTHON_THREADS)
        SWIG_Python_Thread_Block safety;
#endif


        sysrepo::Session *sess = (sysrepo::Session *)new sysrepo::Session(session);
        std::shared_ptr<sysrepo::Session> *shared_sess = sess ? new std::shared_ptr<sysrepo::Session>(sess) : 0;
        PyObject *s = SWIG_NewPointerObj(SWIG_as_voidptr(shared_sess), SWIGTYPE_p_std__shared_ptrT_sysrepo__Session_t, SWIG_POINTER_OWN);
        if (*parent) {
            libyang::Data_Node *tree =(libyang::Data_Node *)new libyang::Data_Node(const_cast<struct lyd_node *>(*parent));

            std::shared_ptr<libyang::Data_Node> *shared_tree = new std::shared_ptr<libyang::Data_Node>(tree);

            PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_tree), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_t, SWIG_POINTER_OWN);

            arglist = Py_BuildValue("(OsssiOO)", s, module_name, path, request_xpath, request_id, in, private_data);
            PyObject *result = PyEval_CallObject(_callback, arglist);
            Py_DECREF(arglist);
            Py_DECREF(in);
            Py_DECREF(s);
            if (result == nullptr) {
                throw std::runtime_error("Python callback oper_get_items_cb failed.\n");
            } else {
                int ret = SR_ERR_OK;
                if (result && PyInt_Check(result)) {
                ret = PyInt_AsLong(result);
                }
                Py_DECREF(result);
                return ret;
            }
        } else {
            libyang::Data_Node *tree =(libyang::Data_Node *)new libyang::Data_Node(nullptr);
            std::shared_ptr<libyang::Data_Node> *shared_tree = new std::shared_ptr<libyang::Data_Node>(tree);

            PyObject *in = SWIG_NewPointerObj(SWIG_as_voidptr(shared_tree), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_t, SWIG_POINTER_OWN);

            arglist = Py_BuildValue("(OsssiOO)", s, module_name, path, request_xpath, request_id, in, private_data);
            PyObject *result = PyEval_CallObject(_callback, arglist);
            Py_DECREF(arglist);
            if (result == nullptr) {
                throw std::runtime_error("Python callback oper_get_items_cb failed.\n");
            Py_DECREF(in);
            Py_DECREF(s);
            } else {
                if (tree) {
                    *parent = lyd_dup(tree->swig_node(), LYD_DUP_OPT_RECURSIVE);
                }
                int ret = SR_ERR_OK;
                Py_DECREF(in);
                Py_DECREF(s);

                if (result && PyInt_Check(result)) {
                ret = PyInt_AsLong(result);
                }
                Py_DECREF(result);
                return ret;
            }
        }
        return 0;
    }

    std::pair<char *, LYS_INFORMAT> ly_module_imp_clb(const char *mod_name, const char *mod_rev, const char *submod_name, const char *sub_rev, PyObject *user_data) {
        PyObject *arglist = Py_BuildValue("(ssssO)", mod_name, mod_rev, submod_name, sub_rev, user_data);
        PyObject *my_result = PyEval_CallObject(_callback, arglist);
        Py_DECREF(arglist);
        if (my_result == nullptr) {
            throw std::runtime_error("Python callback ly_module_imp_clb failed.\n");
        } else {
            LYS_INFORMAT format;
            char *data;

            if (!PyArg_ParseTuple(my_result, "is", &format, &data)) {
                Py_DECREF(my_result);
                std::runtime_error("failed to parse ly_module_imp_clb");
            }

            Py_DECREF(my_result);
            return std::make_pair(data,format);
        }
    }

    PyObject *private_data;

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

static const char *g_ly_module_imp_clb(const char *mod_name, const char *mod_rev, const char *submod_name, const char *sub_rev,
                                   void *user_data, LYS_INFORMAT *format, void (**free_module_data)(void *model_data, void *user_data)) {
#if defined(SWIG_PYTHON_THREADS)
    SWIG_Python_Thread_Block safety;
#endif
    Wrap_cb *ctx = (Wrap_cb *) user_data;
    (void)free_module_data;
    auto pair = ctx->ly_module_imp_clb(mod_name, mod_rev, submod_name, sub_rev, ctx->private_data);
    *format = pair.second;
    return pair.first;
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

    void rpc_subscribe(const char *xpath, PyObject *callback, PyObject *private_data = nullptr,\
                       uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_data) {
            class_ctx->private_data = private_data;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_data = Py_None;
        }

        int ret = sr_rpc_subscribe(self->swig_sess(), xpath, g_rpc_cb, class_ctx, priority,opts,\
                                   self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void rpc_subscribe_tree(const char *xpath, PyObject *callback, PyObject *private_data = nullptr,\
                            uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_data) {
            class_ctx->private_data = private_data;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_data = Py_None;
        }

        int ret = sr_rpc_subscribe_tree(self->swig_sess(), xpath, g_rpc_tree_cb, class_ctx, priority, opts,\
                                        self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void event_notif_subscribe(const char *module_name, PyObject *callback, const char *xpath, \
                               time_t start_time = 0, time_t stop_time = 0, PyObject *private_data = nullptr, \
                               sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_data) {
            class_ctx->private_data = private_data;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_data = Py_None;
        }

        int ret = sr_event_notif_subscribe(self->swig_sess(), module_name, xpath, start_time, \
                                           stop_time, g_event_notif_cb, class_ctx, opts, self->swig_sub());

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void event_notif_subscribe_tree(const char *module_name, PyObject *callback, const char *xpath, \
                                    time_t start_time, time_t stop_time, PyObject *private_data = nullptr, \
                                    sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_data) {
            class_ctx->private_data = private_data;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_data = Py_None;
        }

        int ret = sr_event_notif_subscribe_tree(self->swig_sess(), module_name, xpath, start_time, \
                                                stop_time, g_event_notif_tree_cb, class_ctx, opts, \
                                                self->swig_sub());

       if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }
    void oper_get_items_subscribe(const char *module_name, const char *path, PyObject *callback, \
                                  PyObject *private_data = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(callback);

        self->wrap_cb_l.push_back(class_ctx);
        if (private_data) {
            class_ctx->private_data = private_data;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_data = Py_None;
        }
        int ret = sr_oper_get_items_subscribe(self->swig_sess(), module_name, path, g_oper_get_items_cb, \
                                              class_ctx, opts, self->swig_sub());
        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }

    }
};

%extend libyang::Context {

    void set_module_imp_clb(PyObject *clb, PyObject *user_data = nullptr) {
        /* create class */
        Wrap_cb *class_ctx = nullptr;
        class_ctx = new Wrap_cb(clb);

        self->wrap_cb_l.push_back(class_ctx);
        if (user_data) {
            class_ctx->private_data = user_data;
        } else {
            Py_INCREF(Py_None);
            class_ctx->private_data = Py_None;
        }

        ly_ctx_set_module_imp_clb(self->swig_ctx(), g_ly_module_imp_clb, class_ctx);
    };
}

%extend libyang::Data_Node {
    PyObject *subtype() {
        PyObject *casted = 0;

        auto type = self->swig_node()->schema->nodetype;
        if (LYS_LEAF == type || LYS_LEAFLIST == type) {
            auto node_leaf_list = new std::shared_ptr<libyang::Data_Node_Leaf_List>(new libyang::Data_Node_Leaf_List(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node_leaf_list), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_Leaf_List_t, SWIG_POINTER_OWN);
        } else if (LYS_ANYDATA == type || LYS_ANYXML == type) {
            auto node_anydata = new std::shared_ptr<libyang::Data_Node_Anydata>(new libyang::Data_Node_Anydata(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node_anydata), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_Anydata_t, SWIG_POINTER_OWN);
        } else {
            auto node = new std::shared_ptr<libyang::Data_Node>(new libyang::Data_Node(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Data_Node_t, SWIG_POINTER_OWN);
        }

        return casted;
    }

    void reset(libyang::Data_Node reset_val){
         *self=reset_val;
     }
};

%extend libyang::Schema_Node {
    PyObject *subtype() {
        PyObject *casted = 0;

        auto type = self->swig_node()->nodetype;
        if (LYS_CONTAINER == type) {
            auto node = new std::shared_ptr<libyang::Schema_Node_Container>(new libyang::Schema_Node_Container(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_Container_t, SWIG_POINTER_OWN);
        } else if (LYS_CHOICE == type) {
            auto node = new std::shared_ptr<libyang::Schema_Node_Choice>(new libyang::Schema_Node_Choice(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_Choice_t, SWIG_POINTER_OWN);
        } else if (LYS_LEAF == type) {
            auto node = new std::shared_ptr<libyang::Schema_Node_Leaf>(new libyang::Schema_Node_Leaf(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_Leaf_t, SWIG_POINTER_OWN);
        } else if (LYS_LEAFLIST == type) {
            auto node = new std::shared_ptr<libyang::Schema_Node_Leaflist>(new libyang::Schema_Node_Leaflist(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_Leaflist_t, SWIG_POINTER_OWN);
        } else if (LYS_LIST == type) {
            auto node = new std::shared_ptr<libyang::Schema_Node_List>(new libyang::Schema_Node_List(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_List_t, SWIG_POINTER_OWN);
        } else if (LYS_ANYDATA == type || LYS_ANYXML == type) {
            auto node = new std::shared_ptr<libyang::Schema_Node_Anydata>(new libyang::Schema_Node_Anydata(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_Anydata_t, SWIG_POINTER_OWN);
        } else if (LYS_USES == type) {
            auto node = new std::shared_ptr<libyang::Schema_Node_Uses>(new libyang::Schema_Node_Uses(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_Uses_t, SWIG_POINTER_OWN);
        } else if (LYS_GROUPING == type || LYS_RPC == type || LYS_ACTION == type) {
            auto node = new std::shared_ptr<libyang::Schema_Node_Grp>(new libyang::Schema_Node_Grp(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_Grp_t, SWIG_POINTER_OWN);
        } else if (LYS_CASE == type) {
            auto node = new std::shared_ptr<libyang::Schema_Node_Case>(new libyang::Schema_Node_Case(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_Case_t, SWIG_POINTER_OWN);
        } else if (LYS_INPUT == type || LYS_OUTPUT == type) {
            auto node = new std::shared_ptr<libyang::Schema_Node_Inout>(new libyang::Schema_Node_Inout(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_Inout_t, SWIG_POINTER_OWN);
        } else if (LYS_NOTIF == type) {
            auto node = new std::shared_ptr<libyang::Schema_Node_Notif>(new libyang::Schema_Node_Notif(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_Notif_t, SWIG_POINTER_OWN);
        } else {
            auto node = new std::shared_ptr<libyang::Schema_Node>(new libyang::Schema_Node(self->swig_node(), self->swig_deleter()));
            casted = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p_std__shared_ptrT_libyang__Schema_Node_t, SWIG_POINTER_OWN);
        }

        return casted;
    }
};

%include "../swig_base/python_base.i"
