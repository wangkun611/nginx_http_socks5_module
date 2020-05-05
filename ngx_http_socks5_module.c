#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>
#include <ngx_http.h>
#include <ngx_string.h>

#include "ngx_http_socks5_module.h"

ngx_http_socks5_ctx_t *ngx_http_socks5_create_ctx(ngx_http_request_t *r);
ngx_int_t
ngx_http_socks5_connect(ngx_http_request_t *r, ngx_str_t *addr, ngx_int_t port, ngx_str_t *data);

static void *
ngx_http_socks5_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_socks5_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_socks5_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_str_null(&conf->method);
    ngx_str_null(&conf->addr);
    ngx_str_null(&conf->port);
    ngx_str_null(&conf->data);

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.cache_zone = NULL;
     *     conf->upstream.cache_use_stale = 0;
     *     conf->upstream.cache_methods = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *     conf->upstream.ssl_name = NULL;
     *
     *     conf->method = NULL;
     *     conf->location = NULL;
     *     conf->url = { 0, NULL };
     *     conf->headers_source = NULL;
     *     conf->headers.lengths = NULL;
     *     conf->headers.values = NULL;
     *     conf->headers.hash = { NULL, 0 };
     *     conf->headers_cache.lengths = NULL;
     *     conf->headers_cache.values = NULL;
     *     conf->headers_cache.hash = { NULL, 0 };
     *     conf->body_lengths = NULL;
     *     conf->body_values = NULL;
     *     conf->body_source = { 0, NULL };
     *     conf->redirects = NULL;
     *     conf->ssl = 0;
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *     conf->ssl_certificate = { 0, NULL };
     *     conf->ssl_certificate_key = { 0, NULL };
     */

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;
    conf->upstream.force_ranges = 1;
    conf->upstream.preserve_output = 1;

    ngx_str_set(&conf->upstream.module, "socks5");

    return conf;
}

static char *
ngx_http_socks5_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_socks5_loc_conf_t *prev = parent;
    ngx_http_socks5_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->method, prev->method, "method");
    ngx_conf_merge_str_value(conf->addr, prev->addr, "addr");
    ngx_conf_merge_str_value(conf->port, prev->port, "port");
    ngx_conf_merge_str_value(conf->data, prev->data, "data");

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    return NGX_CONF_OK;
}

ngx_http_socks5_ctx_t *
ngx_http_socks5_create_ctx(ngx_http_request_t *r)
{
    ngx_http_socks5_ctx_t *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_socks5_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    return ctx;
}

static ngx_int_t
ngx_http_socks5_handler(ngx_http_request_t *r)
{
    ngx_http_socks5_loc_conf_t  *hlcf;
    ngx_str_t    method, addr, port, data;
    ngx_int_t    socks_cmd;
    ngx_int_t    socks_port;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_socks5_module);

    /* retrieve parameters */
    if (r->method & NGX_HTTP_GET) {
        if (ngx_http_arg(r, hlcf->method.data, hlcf->method.len, &method) != NGX_OK) {
            return NGX_HTTP_BAD_REQUEST;
        }
        socks_cmd = ngx_atoi(method.data, method.len);
        if (socks_cmd == 0x01) { /* CONNECT */
            if (ngx_http_arg(r, hlcf->addr.data, hlcf->addr.len, &addr) != NGX_OK
                || ngx_http_arg(r, hlcf->port.data, hlcf->port.len, &port) != NGX_OK
                || ngx_http_arg(r, hlcf->data.data, hlcf->data.len, &data) != NGX_OK)
            {
                return NGX_HTTP_BAD_REQUEST;
            }
            socks_port = ngx_atoi(port.data, port.len);
            if(socks_port <= 0 || socks_port > 65535) {
                return NGX_HTTP_BAD_REQUEST;
            }
            
            return ngx_http_socks5_connect(r, &addr, socks_port, &data);
        } else if (socks_cmd == 0x02) { /* BIND */
            return NGX_HTTP_NOT_IMPLEMENTED;
        } else if (socks_cmd == 0x03) { /* UDP ASSOCIATE */
            return NGX_HTTP_NOT_IMPLEMENTED;
        }
    } else if (r->method & NGX_HTTP_POST) {
            return NGX_HTTP_NOT_IMPLEMENTED;
    } else {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* r->count ++; */
    return NGX_HTTP_NOT_IMPLEMENTED;
}

static char *
ngx_http_socks5(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_socks5_loc_conf_t *hlcf;
    ngx_http_core_loc_conf_t    *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_socks5_handler;

    hlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_socks5_module);
    if (cf->args->nelts > 1) {
    }

    return NGX_CONF_OK;
}

static ngx_http_module_t  ngx_http_socks5_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    ngx_http_socks5_create_loc_conf,  /* create location configuration */
    ngx_http_socks5_merge_loc_conf    /* merge location configuration */
};

static ngx_command_t  ngx_http_socks5_commands[] = {
    
    { ngx_string("http_socks5"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_NOARGS,
      ngx_http_socks5,
      0,
      0,
      NULL },

    { ngx_string("http_socks5_method"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_socks5_loc_conf_t, method),
      NULL},

    ngx_null_command
};

ngx_module_t ngx_http_socks5_module = {
    NGX_MODULE_V1,
    &ngx_http_socks5_ctx,       /* module context */
    ngx_http_socks5_commands,   /* module directives */
    NGX_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    NULL,                        /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    NULL,                        /* exit process */
    NULL,                        /* exit master */
    NGX_MODULE_V1_PADDING
};
