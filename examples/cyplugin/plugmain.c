


#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <Python.h>
#include "sysrepo.h"
#include "pysysrepo.h"

#define PYMOD_ENVNAME "PYSYSREPO_MOD"

struct cyplug_ctx {
	sr_session_ctx_t *session;
	PyThreadState *pythread;
};

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
	struct cyplug_ctx *ctx = malloc(sizeof(*ctx));
	ctx->session = session;

	PyEval_InitThreads();
	Py_InitializeEx(0);
	initpysysrepo();
	pysysrepo_init(session);

	// ctx->pythread = PyEval_SaveThread();

	return SR_ERR_OK;
}

#if 0
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    rc = sr_module_change_subscribe(session, "turing-machine", module_change_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_rpc_subscribe(session, "/turing-machine:initialize", rpc_initialize_cb, NULL,
            SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_rpc_subscribe(session, "/turing-machine:run", rpc_run_cb, NULL,
            SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    log_msg("turing-machine plugin initialized successfully");

    retrieve_current_config(session);

    /* set subscription as our private context */
    *private_ctx = subscription;

    return SR_ERR_OK;

error:
    log_fmt("turing-machine plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    return rc;
}

#endif

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
	struct cyplug_ctx *ctx = private_ctx;

	free(ctx);
}
