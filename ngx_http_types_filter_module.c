/*
 * Copyright (c) 2013, FengGu <flygoast@126.com>
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
    ngx_int_t     index;
    ngx_flag_t    use_default;
    ngx_array_t  *values;
    ngx_array_t  *lengths;
} ngx_http_types_filter_loc_conf_t;


static ngx_int_t ngx_http_types_filter_init(ngx_conf_t *cf);
static char *ngx_http_types_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_types_filter_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_types_filter_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_set_content_type_exten(ngx_http_request_t *r,
    ngx_str_t *exten);
static ngx_int_t ngx_http_parse_exten(ngx_str_t *val, ngx_str_t *exten);
static ngx_int_t ngx_http_types_header_filter(ngx_http_request_t *r);


static ngx_command_t  ngx_http_types_filter_commands[] = {

    { ngx_string("types_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE12,
      ngx_http_types_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("types_filter_use_default"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_types_filter_loc_conf_t, use_default),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_types_filter_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_types_filter_init,             /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_types_filter_create_loc_conf,  /* create location configuration */
    ngx_http_types_filter_merge_loc_conf,   /* merge location configuration */
};


ngx_module_t  ngx_http_types_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_types_filter_module_ctx,     /* module context */
    ngx_http_types_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_types_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_types_filter_loc_conf_t  *tlcf = conf;
    ngx_str_t                         *value, cond;
    ngx_array_t                       *lengths, *values;
    ngx_http_script_compile_t          sc;

    if (tlcf->lengths != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    lengths = NULL;
    values = NULL;

    value = cf->args->elts;

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &lengths;
    sc.values = &values;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    tlcf->lengths = lengths->elts;
    tlcf->values = values->elts;

    if (cf->args->nelts == 3) {
        cond = value[2];

        if (cond.data[0] != '$') {
            return "invalid condition variable";
        }

        cond.len--;
        cond.data++;

        tlcf->index = ngx_http_get_variable_index(cf, &cond);
        if (tlcf->index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_types_header_filter(ngx_http_request_t *r)
{
    ngx_http_types_filter_loc_conf_t  *tlcf;
    ngx_http_variable_value_t         *vv;
    ngx_str_t                          val, exten;

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

    if (tlcf->lengths == NULL) {
        return ngx_http_next_header_filter(r);
    }

    if (tlcf->index != -1) {
        vv = ngx_http_get_flushed_variable(r, tlcf->index);
        if (vv == NULL || vv->not_found) {
            return ngx_http_next_header_filter(r);
        }

        if (vv->len != 1 || vv->data[0] != '1') {
            return ngx_http_next_header_filter(r);
        }
    }

    if (ngx_http_script_run(r, &val, tlcf->lengths, 0, tlcf->values) == NULL) {
        return NGX_ERROR;
    }

    if (val.len == 0 && !tlcf->use_default) {
        return ngx_http_next_header_filter(r);
    }

    if (ngx_http_parse_exten(&val, &exten) != NGX_OK && !tlcf->use_default) {
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

    for (i = val->len - 1; i > 1; i--) {
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
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_types_header_filter;

    return NGX_OK;
}


static void *
ngx_http_types_filter_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_types_filter_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_types_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->index = NGX_CONF_UNSET;
    conf->use_default = NGX_CONF_UNSET;
    conf->values = NGX_CONF_UNSET_PTR;
    conf->lengths = NGX_CONF_UNSET_PTR;
    
    return conf;
}


static char *
ngx_http_types_filter_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_types_filter_loc_conf_t  *prev = parent;
    ngx_http_types_filter_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->index, prev->index, -1);
    ngx_conf_merge_value(conf->use_default, prev->use_default, 1);
    ngx_conf_merge_ptr_value(conf->values, prev->values, NULL);
    ngx_conf_merge_ptr_value(conf->lengths, prev->lengths, NULL);

    return NGX_CONF_OK;
}
