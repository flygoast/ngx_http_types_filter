/*
 * Copyright (c) 2013-2014, FengGu <flygoast@126.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_array_t  *codes;
    ngx_array_t  *lengths;
    ngx_array_t  *values;
    ngx_str_t     type;
} ngx_http_types_filter_condition_t;


typedef struct {
    ngx_flag_t    use_default;
    ngx_array_t  *conditions;   /* ngx_http_types_filter_condition_t */
} ngx_http_types_filter_loc_conf_t;


typedef struct {
    unsigned    required:1;
} ngx_http_types_filter_main_conf_t;


static volatile ngx_cycle_t  *ngx_http_types_filter_prev_cycle;


static char *ngx_http_types_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_types_filter_condition_value(ngx_conf_t *cf,
    ngx_http_types_filter_condition_t *condition, ngx_str_t *value);
static char *ngx_http_types_filter_condition(ngx_conf_t *cf,
    ngx_http_types_filter_condition_t *condition, ngx_uint_t offset);
static ngx_int_t ngx_http_types_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_set_content_type_exten(ngx_http_request_t *r,
    ngx_str_t *exten);
static ngx_int_t ngx_http_parse_exten(ngx_str_t *val, ngx_str_t *exten);
static ngx_int_t ngx_http_types_header_filter(ngx_http_request_t *r);
static void *ngx_http_types_filter_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_types_filter_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_types_filter_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t  ngx_http_types_filter_commands[] = {

    { ngx_string("types_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("types_filter_use_default"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_types_filter_loc_conf_t, use_default),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_types_filter_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_types_filter_init,             /* postconfiguration */

    ngx_http_types_filter_create_main_conf, /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_types_filter_create_loc_conf,  /* create location configuration */
    ngx_http_types_filter_merge_loc_conf,   /* merge location configuration */
};


ngx_module_t  ngx_http_types_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_types_filter_module_ctx,      /* module context */
    ngx_http_types_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_types_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                          *value;
    ngx_uint_t                          n;
    ngx_http_script_compile_t           sc;
    ngx_http_types_filter_condition_t  *condition;
    ngx_http_types_filter_main_conf_t  *tmcf;
    ngx_http_types_filter_loc_conf_t   *tlcf = conf;

    if (tlcf->conditions == NULL) {
        tlcf->conditions = ngx_array_create(cf->pool, 4,
                                     sizeof(ngx_http_types_filter_condition_t));
        if (tlcf->conditions == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    condition = ngx_array_push(tlcf->conditions);
    if (condition == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(condition, sizeof(ngx_http_types_filter_condition_t));

    value = cf->args->elts;
    condition->type = value[1];

    n = ngx_http_script_variables_count(&condition->type);

    if (n) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &condition->type;
        sc.lengths = &condition->lengths;
        sc.values = &condition->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (cf->args->nelts == 2) {
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[2].data, "if") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "incorrect token \"%V\" in directive \"types_filter\"",
                         &value[2]);
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid syntax in directive \"types_filter\"");
        return NGX_CONF_ERROR;
    }

    if (ngx_http_types_filter_condition(cf, condition, 2) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    tmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_types_filter_module);
    tmcf->required = 1;

    return NGX_CONF_OK;
}


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_types_header_filter(ngx_http_request_t *r)
{
    ngx_uint_t                          i;
    ngx_str_t                           type, exten;
    ngx_http_script_engine_t            e;
    ngx_http_script_code_pt             code;
    ngx_http_variable_value_t           stack[10];
    ngx_http_types_filter_loc_conf_t   *tlcf;
    ngx_http_types_filter_condition_t  *conditions;

    if (r != r->main
        || (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_CREATED
            && r->headers_out.status != NGX_HTTP_NO_CONTENT
            && r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT
            && r->headers_out.status != NGX_HTTP_MOVED_PERMANENTLY
            && r->headers_out.status != NGX_HTTP_MOVED_TEMPORARILY
            && r->headers_out.status != NGX_HTTP_SEE_OTHER
            && r->headers_out.status != NGX_HTTP_NOT_MODIFIED
            && r->headers_out.status != NGX_HTTP_TEMPORARY_REDIRECT))
    {
        return ngx_http_next_header_filter(r);
    }

    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_types_filter_module);
    conditions = tlcf->conditions->elts;
    for (i = 0; i < tlcf->conditions->nelts; i++) {
        if (conditions[i].codes == NULL) {
            break;
        }
    
        ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
        ngx_memzero(&stack, sizeof(stack));

        e.sp = stack;
        e.ip = conditions[i].codes->elts;
        e.request = r;
        e.quote = 1;
        e.log = 1;
        e.status = NGX_DECLINED;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code(&e);
        }

        e.sp--;

        if (e.sp->len && (e.sp->len != 1 || e.sp->data[0] != '0')) {
            break;
        }
    }

    if (i == tlcf->conditions->nelts) {
        return ngx_http_next_header_filter(r);
    }

    if (conditions[i].lengths) {
        if (ngx_http_script_run(r, &type, conditions[i].lengths->elts, 0, 
                                conditions[i].values->elts)
            == NULL)
        {
            return NGX_ERROR;
        }

    } else {
        type = conditions[i].type;
    }

    if (type.len == 0 && !tlcf->use_default) {
        return ngx_http_next_header_filter(r);
    }

    if (ngx_http_parse_exten(&type, &exten) != NGX_OK && !tlcf->use_default) {
        return ngx_http_next_header_filter(r);
    }

    if (ngx_http_set_content_type_exten(r, &exten) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_set_content_type_exten(ngx_http_request_t *r, ngx_str_t *exten)
{
    ngx_http_types_filter_loc_conf_t  *tlcf;
    ngx_http_core_loc_conf_t          *clcf;
    ngx_str_t                         *type;
    ngx_uint_t                         hash;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (exten->len == 0) {
        r->headers_out.content_type_len = clcf->default_type.len;
        r->headers_out.content_type = clcf->default_type;
       
        return NGX_OK;
    }

    hash = ngx_hash_key_lc(exten->data, exten->len);

    type = ngx_hash_find(&clcf->types_hash, hash, exten->data, exten->len);

    if (type) {
        r->headers_out.content_type_len = type->len;
        r->headers_out.content_type = *type;

        return NGX_OK;
    }

    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_types_filter_module);

    if (r->headers_out.content_type.len && !tlcf->use_default) {
        return NGX_OK;
    }

    r->headers_out.content_type_len = clcf->default_type.len;
    r->headers_out.content_type = clcf->default_type;

    return NGX_OK;
}


static ngx_int_t
ngx_http_parse_exten(ngx_str_t *val, ngx_str_t *exten)
{
    ngx_int_t  i;

    if (val->len == 0) {
        exten->len = 0;
        exten->data = NULL;

        return NGX_DECLINED;
    }

    for (i = val->len - 1; i > 0; i--) {
        if (val->data[i] == '.' && val->data[i - 1] != '/') {
            exten->len = val->len - i - 1;
            exten->data = &val->data[i + 1];

            return NGX_OK;

        } else if (val->data[i] == '/') {
            exten->len = 0;
            exten->data = NULL;

            return NGX_DECLINED;
        }
    }

    if (val->data[0] == '.') {
        exten->len = val->len - 1;
        exten->data = &val->data[1];

        return NGX_OK;
    }

    exten->len = 0;
    exten->data = NULL;

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_types_filter_init(ngx_conf_t *cf)
{
    int                                 multi_http_blocks;
    ngx_http_types_filter_main_conf_t  *tmcf;

    tmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_types_filter_module);

    if (ngx_http_types_filter_prev_cycle != ngx_cycle) {
        ngx_http_types_filter_prev_cycle = ngx_cycle;
        multi_http_blocks = 0;

    } else {
        multi_http_blocks = 1;
    }

    if (multi_http_blocks || tmcf->required) {
        ngx_http_next_header_filter = ngx_http_top_header_filter;
        ngx_http_top_header_filter = ngx_http_types_header_filter;
    }

    return NGX_OK;
}


static char *
ngx_http_types_filter_condition(ngx_conf_t *cf,
    ngx_http_types_filter_condition_t *condition, ngx_uint_t offset)
{
    u_char                        *p;
    size_t                         len;
    ngx_str_t                     *value;
    ngx_uint_t                     cur, last;
    ngx_regex_compile_t            rc;
    ngx_http_script_code_pt       *code;
    ngx_http_script_file_code_t   *fop;
    ngx_http_script_regex_code_t  *regex;
    u_char                         errstr[NGX_MAX_CONF_ERRSTR];

    value = cf->args->elts;
    last = cf->args->nelts - 1;

    value += offset;
    last -= offset;

    if (value[1].len < 1 || value[1].data[0] != '(') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (value[1].len == 1) {
        cur = 2;

    } else {
        cur = 1;
        value[1].len--;
        value[1].data++;
    }

    if (value[last].len < 1 || value[last].data[value[last].len - 1] != ')') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[last]);
        return NGX_CONF_ERROR;
    }

    if (value[last].len == 1) {
        last--;

    } else {
        value[last].len--;
        value[last].data[value[last].len] = '\0';
    }

    len = value[cur].len;
    p = value[cur].data;

    if (len > 1 && p[0] == '$') {

        if (cur != last && cur + 2 != last) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return NGX_CONF_ERROR;
        }

        if (ngx_http_types_filter_condition_value(cf, condition, &value[cur])
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (cur == last) {
            goto end;
        }

        cur++;

        len = value[cur].len;
        p = value[cur].data;

        if (len == 1 && p[0] == '=') {
            if (ngx_http_types_filter_condition_value(cf, condition,
                                                      &value[last])
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            code = ngx_http_script_start_code(cf->pool, &condition->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return NGX_CONF_ERROR;
            }

            *code = ngx_http_script_equal_code;

            goto end;
        }

        if (len == 2 && p[0] == '!' && p[1] == '=') {

            if (ngx_http_types_filter_condition_value(cf, condition,
                                                      &value[last])
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            code = ngx_http_script_start_code(cf->pool, &condition->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return NGX_CONF_ERROR;
            }

            *code = ngx_http_script_not_equal_code;
            goto end;
        }

        if ((len == 1 && p[0] == '~')
            || (len == 2 && p[0] == '~' && p[1] == '*')
            || (len == 2 && p[0] == '!' && p[1] == '~')
            || (len == 3 && p[0] == '!' && p[1] == '~' && p[2] == '*'))
        {
            regex = ngx_http_script_start_code(cf->pool, &condition->codes,
                                          sizeof(ngx_http_script_regex_code_t));
            if (regex == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(regex, sizeof(ngx_http_script_regex_code_t));
            
            ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

            rc.pattern = value[last];
            rc.options = (p[len - 1] == '*') ? NGX_REGEX_CASELESS : 0;
            rc.err.len = NGX_MAX_CONF_ERRSTR;
            rc.err.data = errstr;

            regex->regex = ngx_http_regex_compile(cf, &rc);
            if (regex->regex == NULL) {
                return NGX_CONF_ERROR;
            }

            regex->code = ngx_http_script_regex_start_code;
            regex->next = sizeof(ngx_http_script_regex_code_t);
            regex->test = 1;
            if (p[0] == '!') {
                regex->negative_test = 1;
            }
            regex->name = value[last];

            goto end;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unexpected \"%V\" in condition", &value[cur]);
        return NGX_CONF_ERROR;

    } else if ((len == 2 && p[0] == '-')
               || (len == 3 && p[0] == '!' && p[1] == '-'))
    {
        if (cur + 1 != last) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return NGX_CONF_ERROR;
        }

        value[last].data[value[last].len] = '\0';
        value[last].len++;

        if (ngx_http_types_filter_condition_value(cf, condition, &value[last])
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        fop = ngx_http_script_start_code(cf->pool, &condition->codes,
                                         sizeof(ngx_http_script_file_code_t));
        if (fop == NULL) {
            return NGX_CONF_ERROR;
        }

        fop->code = ngx_http_script_file_code;

        if (p[1] == 'f') {
            fop->op = ngx_http_script_file_plain;
            goto end;
        }

        if (p[1] == 'd') {
            fop->op = ngx_http_script_file_dir;
            goto end;
        }

        if (p[1] == 'e') {
            fop->op = ngx_http_script_file_exists;
            goto end;
        }

        if (p[1] == 'x') {
            fop->op = ngx_http_script_file_exec;
            goto end;
        }

        if (p[0] == '!') {
            if (p[2] == 'f') {
                fop->op = ngx_http_script_file_not_plain;
                goto end;
            }

            if (p[2] == 'd') {
                fop->op = ngx_http_script_file_not_dir;
                goto end;
            }

            if (p[2] == 'e') {
                fop->op = ngx_http_script_file_not_exists;
                goto end;
            }

            if (p[2] == 'x') {
                fop->op = ngx_http_script_file_not_exec;
                goto end;
            }
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[cur]);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid condition \"%V\"", &value[cur]);

    return NGX_CONF_ERROR;

end:

    code = ngx_array_push_n(condition->codes, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_CONF_ERROR;
    }

    *code = (uintptr_t) NULL;

    return NGX_CONF_OK;
}


static char *
ngx_http_types_filter_condition_value(ngx_conf_t *cf,
    ngx_http_types_filter_condition_t *condition, ngx_str_t *value)
{
    ngx_int_t                              n;
    ngx_http_script_compile_t              sc;
    ngx_http_script_value_code_t          *val;
    ngx_http_script_complex_value_code_t  *complex;

    n = ngx_http_script_variables_count(value);

    if (n == 0) {
        val = ngx_http_script_start_code(cf->pool, &condition->codes,
                                         sizeof(ngx_http_script_value_code_t));
        if (val == NULL) {
            return NGX_CONF_ERROR;
        }

        n = ngx_atoi(value->data, value->len);

        if (n == NGX_ERROR) {
            n = 0;
        }

        val->code = ngx_http_script_value_code;
        val->value = (uintptr_t) n;
        val->text_len = (uintptr_t) value->len;
        val->text_data = (uintptr_t) value->data;

        return NGX_CONF_OK;
    }

    complex = ngx_http_script_start_code(cf->pool, &condition->codes,
                                  sizeof(ngx_http_script_complex_value_code_t));
    if (complex == NULL) {
        return NGX_CONF_ERROR;
    }

    complex->code = ngx_http_script_complex_value_code;
    complex->lengths = NULL;

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = value;
    sc.lengths = &complex->lengths;
    sc.values = &condition->codes;
    sc.variables = n;
    sc.complete_lengths = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_types_filter_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_types_filter_main_conf_t  *tmcf;

    tmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_types_filter_main_conf_t));
    if (tmcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *     tmcf->required = 0;
     */

    return tmcf;
}


static void *
ngx_http_types_filter_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_types_filter_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_types_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->use_default = NGX_CONF_UNSET;
    
    return conf;
}


static char *
ngx_http_types_filter_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_types_filter_loc_conf_t  *prev = parent;
    ngx_http_types_filter_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->use_default, prev->use_default, 1);

    if (conf->conditions == NULL && prev->conditions) {
        conf->conditions = prev->conditions;
    }

    return NGX_CONF_OK;
}
