%module libsysrepoLua51

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

%include "lua_fnptr.i"

%inline %{
#include <unistd.h>
#include "../inc/sysrepo.h"
#include <signal.h>
#include <vector>
#include <memory>

#include "Sysrepo.h"
#include "Struct.h"
#include "Session.h"

class Callback_lua {
public:
    Callback_lua(SWIGLUA_REF fn) : fn(fn) {};
    SWIGLUA_REF fn;
};


class Wrap_cb {
public:
    Wrap_cb(SWIGLUA_REF fn) : fn(fn) {};
    void module_change_subscribe(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, \
                                 void *private_ctx) {
        Session *sess = (Session *)new Session(session);
        if (sess == NULL)
            throw std::runtime_error("No memory for class Session in callback module_change_subscribe.\n");
        swiglua_ref_get(&fn);
        SWIG_NewPointerObj(fn.L, sess, SWIGTYPE_p_Session, 0);
        lua_pushstring(fn.L, module_name);
        lua_pushnumber(fn.L, (lua_Number)(int)(event));
        SWIG_NewPointerObj(fn.L, private_ctx, SWIGTYPE_p_void, 0);
        lua_call(fn.L, 4, 0);
    }

    void subtree_change(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event,\
                       void *private_ctx) {
        Session *sess = (Session *)new Session(session);
        if (sess == NULL)
            throw std::runtime_error("No memory for class Session in callback subtree_change.\n");

        swiglua_ref_get(&fn);
        SWIG_NewPointerObj(fn.L, sess, SWIGTYPE_p_Session, 0);
        lua_pushstring(fn.L, xpath);
        lua_pushnumber(fn.L, (lua_Number)(int)(event));
        SWIG_NewPointerObj(fn.L, private_ctx, SWIGTYPE_p_void, 0);
        lua_call(fn.L, 4, 0);
    }

    void module_install(const char *module_name, const char *revision, bool installed, void *private_ctx) {
        swiglua_ref_get(&fn);
        lua_pushstring(fn.L, module_name);
        lua_pushstring(fn.L, revision);
        lua_pushboolean(fn.L, installed);
        SWIG_NewPointerObj(fn.L, private_ctx, SWIGTYPE_p_void, 0);
        lua_call(fn.L, 4, 0);
    }

    void feature_enable(const char *module_name, const char *feature_name, bool enabled, void *private_ctx) {
        swiglua_ref_get(&fn);
        lua_pushstring(fn.L, module_name);
        lua_pushstring(fn.L, feature_name);
        lua_pushboolean(fn.L, enabled);
        SWIG_NewPointerObj(fn.L, private_ctx, SWIGTYPE_p_void, 0);
        lua_call(fn.L, 4, 0);
    }

    void rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output,\
               size_t *output_cnt, void *private_ctx) {

        Vals *in_vals =(Vals *)new Vals(input, input_cnt, NULL);
        Vals *out_vals =(Vals *)new Vals(output, output_cnt, NULL);
        if (in_vals == NULL && out_vals == NULL)
            throw std::runtime_error("No memory for class Vals in callback rpc_cb.\n");

        swiglua_ref_get(&fn);
        lua_pushstring(fn.L, xpath);
        SWIG_NewPointerObj(fn.L, in_vals, SWIGTYPE_p_Vals, 0);
        SWIG_NewPointerObj(fn.L, out_vals, SWIGTYPE_p_Vals, 0);
        SWIG_NewPointerObj(fn.L, private_ctx, SWIGTYPE_p_void, 0);
        lua_call(fn.L, 4, 0);
    }

    void rpc_tree_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt,\
                         sr_node_t **output, size_t *output_cnt, void *private_ctx) {

        Trees *in_vals =(Trees *)new Trees(input, input_cnt, NULL);
        Trees *out_vals =(Trees *)new Trees(output, output_cnt, NULL);
        if (in_vals == NULL && out_vals == NULL)
            throw std::runtime_error("No memory for class Trees in callback rpc_tree_cb.\n");

        swiglua_ref_get(&fn);
        lua_pushstring(fn.L, xpath);
        SWIG_NewPointerObj(fn.L, in_vals, SWIGTYPE_p_Trees, 0);
        SWIG_NewPointerObj(fn.L, out_vals, SWIGTYPE_p_Trees, 0);
        SWIG_NewPointerObj(fn.L, private_ctx, SWIGTYPE_p_void, 0);
        lua_call(fn.L, 4, 0);
    }

    void dp_get_items(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {

        Vals *in_vals =(Vals *)new Vals(values, values_cnt, NULL);
        if (in_vals == NULL)
            throw std::runtime_error("No memory for class Vals in callback dp_get_items.\n");

        swiglua_ref_get(&fn);
        lua_pushstring(fn.L, xpath);
        SWIG_NewPointerObj(fn.L, in_vals, SWIGTYPE_p_Vals, 0);
        SWIG_NewPointerObj(fn.L, private_ctx, SWIGTYPE_p_void, 0);
        lua_call(fn.L, 3, 0);
    }

    void event_notif(const char *xpath, const sr_val_t *values, const size_t values_cnt, void *private_ctx) {

        Vals *in_vals =(Vals *)new Vals(values, values_cnt, NULL);
        if (in_vals == NULL)
            throw std::runtime_error("No memory for class Vals in callback event_notif.\n");

        swiglua_ref_get(&fn);
        lua_pushstring(fn.L, xpath);
        SWIG_NewPointerObj(fn.L, in_vals, SWIGTYPE_p_Vals, 0);
        SWIG_NewPointerObj(fn.L, private_ctx, SWIGTYPE_p_void, 0);
        lua_call(fn.L, 3, 0);
    }

    void event_notif_tree(const char *xpath, const sr_node_t *trees, const size_t tree_cnt, void *private_ctx) {

        Trees *in_vals =(Trees *)new Trees(trees, tree_cnt, NULL);
        if (in_vals == NULL)
            throw std::runtime_error("No memory for class Trees in callback rpc_cb.\n");

        swiglua_ref_get(&fn);
        lua_pushstring(fn.L, xpath);
        SWIG_NewPointerObj(fn.L, in_vals, SWIGTYPE_p_Trees, 0);
        SWIG_NewPointerObj(fn.L, private_ctx, SWIGTYPE_p_void, 0);
        lua_call(fn.L, 3, 0);
    }


    void *private_ctx;

private:
    SWIGLUA_REF fn;
};

static int g_module_change_subscribe_cb(sr_session_ctx_t *session, const char *module_name,\
                                        sr_notif_event_t event, void *private_ctx)
{
    Wrap_cb *ctx = (Wrap_cb *) private_ctx;
    ctx->module_change_subscribe(session, module_name, event, ctx->private_ctx);

    return SR_ERR_OK;
}

static int g_subtree_change_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event,\
                               void *private_ctx)
{
    Wrap_cb *ctx = (Wrap_cb *) private_ctx;
    ctx->subtree_change(session, xpath, event, ctx->private_ctx);

    return SR_ERR_OK;
}

static void g_module_install_cb(const char *module_name, const char *revision, bool installed, void *private_ctx)
{
    Wrap_cb *ctx = (Wrap_cb *) private_ctx;
    ctx->module_install(module_name, revision, installed, ctx->private_ctx);
}

static void g_feature_enable_cb(const char *module_name, const char *feature_name, bool enabled, void *private_ctx)
{
    Wrap_cb *ctx = (Wrap_cb *) private_ctx;
    ctx->feature_enable(module_name, feature_name, enabled, ctx->private_ctx);
}

static int g_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output,\
                     size_t *output_cnt, void *private_ctx)
{
    Wrap_cb *ctx = (Wrap_cb *) private_ctx;
    ctx->rpc_cb(xpath, input, input_cnt, output, output_cnt, ctx->private_ctx);

    return SR_ERR_OK;
}

static int g_rpc_tree_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt,\
                         sr_node_t **output, size_t *output_cnt, void *private_ctx)
{
    Wrap_cb *ctx = (Wrap_cb *) private_ctx;
    ctx->rpc_tree_cb(xpath, input, input_cnt, output, output_cnt, ctx->private_ctx);

    return SR_ERR_OK;
}

static int g_dp_get_items_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    Wrap_cb *ctx = (Wrap_cb *) private_ctx;
    ctx->dp_get_items(xpath, values, values_cnt, ctx->private_ctx);

    return SR_ERR_OK;
}

static void g_event_notif_cb(const char *xpath, const sr_val_t *values, const size_t values_cnt, void *private_ctx)
{
    Wrap_cb *ctx = (Wrap_cb *) private_ctx;
    ctx->event_notif(xpath, values, values_cnt, ctx->private_ctx);
}

static void g_event_notif_tree_cb(const char *xpath, const sr_node_t *trees, const size_t tree_cnt, void *private_ctx)
{
    Wrap_cb *ctx = (Wrap_cb *) private_ctx;
    ctx->event_notif_tree(xpath, trees, tree_cnt, ctx->private_ctx);
}



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

%}

%extend Subscribe {

    void module_change_subscribe(const char *module_name, Callback_lua *cb, void *private_ctx = NULL, \
                                 uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        /* create class */
        SWIGLUA_REF callback = cb->fn;
        Wrap_cb *class_ctx = NULL;
        class_ctx = new Wrap_cb(callback);

        if (class_ctx == NULL)
            throw std::runtime_error("Ne enough space for helper class!\n");

        self->wrap_cb_l.push_back(class_ctx);
        class_ctx->private_ctx = private_ctx;

        int ret = sr_module_change_subscribe(self->swig_sess->get(), module_name, g_module_change_subscribe_cb, \
                                             class_ctx, priority, opts, &self->swig_sub);
        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    };

    void subtree_change_subscribe(const char *xpath, Callback_lua *cb, void *private_ctx = NULL,\
                                 uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        /* create class */
        SWIGLUA_REF callback = cb->fn;
        Wrap_cb *class_ctx = NULL;
        class_ctx = new Wrap_cb(callback);

        if (class_ctx == NULL)
            throw std::runtime_error("Ne enough space for helper class!\n");

        self->wrap_cb_l.push_back(class_ctx);
        class_ctx->private_ctx = private_ctx;

        int ret = sr_subtree_change_subscribe(self->swig_sess->get(), xpath, g_subtree_change_cb, class_ctx,\
                                              priority, opts, &self->swig_sub);
        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void module_install_subscribe(Callback_lua *cb, void *private_ctx = NULL,\
                                  sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        /* create class */
        SWIGLUA_REF callback = cb->fn;
        Wrap_cb *class_ctx = NULL;
        class_ctx = new Wrap_cb(callback);

        if (class_ctx == NULL)
            throw std::runtime_error("Ne enough space for helper class!\n");

        self->wrap_cb_l.push_back(class_ctx);
        class_ctx->private_ctx = private_ctx;

        int ret =  sr_module_install_subscribe(self->swig_sess->get(), g_module_install_cb, class_ctx,
                                               opts, &self->swig_sub);

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void feature_enable_subscribe(Callback_lua *cb, void *private_ctx = NULL,\
                                  sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        /* create class */
        SWIGLUA_REF callback = cb->fn;
        Wrap_cb *class_ctx = NULL;
        class_ctx = new Wrap_cb(callback);

        if (class_ctx == NULL)
            throw std::runtime_error("Ne enough space for helper class!\n");

        self->wrap_cb_l.push_back(class_ctx);
        class_ctx->private_ctx = private_ctx;

        int ret = sr_feature_enable_subscribe(self->swig_sess->get(), g_feature_enable_cb, class_ctx,
                                              opts, &self->swig_sub);

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void rpc_subscribe(const char *xpath, Callback_lua *cb, void *private_ctx = NULL,\
                       sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        SWIGLUA_REF callback = cb->fn;
        Wrap_cb *class_ctx = NULL;
        class_ctx = new Wrap_cb(callback);

        if (class_ctx == NULL)
            throw std::runtime_error("Ne enough space for helper class!\n");

        self->wrap_cb_l.push_back(class_ctx);
        class_ctx->private_ctx = private_ctx;

        int ret = sr_rpc_subscribe(self->swig_sess->get(), xpath, g_rpc_cb, class_ctx, opts,\
                                   &self->swig_sub);

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void rpc_subscribe_tree(const char *xpath, Callback_lua *cb, void *private_ctx = NULL,\
                       sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        SWIGLUA_REF callback = cb->fn;
        Wrap_cb *class_ctx = NULL;
        class_ctx = new Wrap_cb(callback);

        if (class_ctx == NULL)
            throw std::runtime_error("Ne enough space for helper class!\n");

        self->wrap_cb_l.push_back(class_ctx);
        class_ctx->private_ctx = private_ctx;

        int ret = sr_rpc_subscribe_tree(self->swig_sess->get(), xpath, g_rpc_tree_cb, class_ctx, opts,\
                                   &self->swig_sub);

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void event_notif_subscribe(const char *xpath, Callback_lua *cb, void *private_ctx,\
                               sr_subscr_options_t opts) {
        SWIGLUA_REF callback = cb->fn;
        Wrap_cb *class_ctx = NULL;
        class_ctx = new Wrap_cb(callback);

        if (class_ctx == NULL)
            throw std::runtime_error("Ne enough space for helper class!\n");

        self->wrap_cb_l.push_back(class_ctx);
        class_ctx->private_ctx = private_ctx;

        int ret = sr_event_notif_subscribe(self->swig_sess->get(), xpath, g_event_notif_cb, class_ctx, opts,\
                                   &self->swig_sub);

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void event_notif_subscribe_tree(const char *xpath, Callback_lua *cb, void *private_ctx,\
                               sr_subscr_options_t opts) {
        SWIGLUA_REF callback = cb->fn;
        Wrap_cb *class_ctx = NULL;
        class_ctx = new Wrap_cb(callback);

        if (class_ctx == NULL)
            throw std::runtime_error("Ne enough space for helper class!\n");

        self->wrap_cb_l.push_back(class_ctx);
        class_ctx->private_ctx = private_ctx;

        int ret = sr_event_notif_subscribe_tree(self->swig_sess->get(), xpath, g_event_notif_tree_cb,\
                                                class_ctx, opts, &self->swig_sub);

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void dp_get_items_subscribe(const char *xpath, Callback_lua *cb, void *private_ctx, \
                               sr_subscr_options_t opts = SUBSCR_DEFAULT) {
        SWIGLUA_REF callback = cb->fn;
        Wrap_cb *class_ctx = NULL;
        class_ctx = new Wrap_cb(callback);

        if (class_ctx == NULL)
            throw std::runtime_error("Ne enough space for helper class!\n");

        self->wrap_cb_l.push_back(class_ctx);
        class_ctx->private_ctx = private_ctx;

        int ret = sr_dp_get_items_subscribe(self->swig_sess->get(), xpath, g_dp_get_items_cb, class_ctx,\
                                            opts, &self->swig_sub);

        if (SR_ERR_OK != ret) {
            throw std::runtime_error(sr_strerror(ret));
        }
    }

    void additional_cleanup(void *private_ctx) {
        delete static_cast<Wrap_cb*>(private_ctx);
    }

};

%include "../swig_base/lua_base.i"
