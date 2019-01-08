
#ifndef _EDIT_DIFF_H
#define _EDIT_DIFF_H

#include <libyang/libyang.h>

#include "common.h"

sr_error_info_t *sr_ly_edit_mod_apply(const struct lyd_node *edit, struct sr_mod_info_mod_s *mod, struct lyd_node **mod_data,
        struct lyd_node **mod_diff);

sr_error_info_t *sr_ly_diff_mod_apply(struct lyd_node *diff, struct sr_mod_info_mod_s *mod, struct lyd_node **mod_data);

sr_error_info_t *sr_ly_diff_merge(struct lyd_node **diff, struct ly_ctx *ly_ctx, struct lyd_difflist *ly_diff,
        int *dflt_change);

sr_error_info_t *sr_edit_item(sr_session_ctx_t *session, const char *xpath, const char *value, const char *operation,
        const char *def_operation, const sr_move_position_t *position, const char *keys, const char *val);

#endif
