#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>
#include <ngx_http.h>
#include <ngx_string.h>

#include "ngx_http_socks5_module.h"

ngx_http_socks5_ctx_t * ngx_http_socks5_create_ctx(ngx_http_request_t *r);

static ngx_int_t ngx_http_socks5_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_socks5_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_socks5_process_header(ngx_http_request_t *r);
static void ngx_http_socks5_abort_request(ngx_http_request_t *r);
static void ngx_http_socks5_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

ngx_int_t
ngx_http_socks5_connect(ngx_http_request_t *r, ngx_str_t *addr, ngx_int_t port, ngx_str_t *data)
{
    ngx_http_socks5_loc_conf_t     *hlcf;
    ngx_http_socks5_ctx_t          *ctx;
    ngx_http_upstream_t            *u;
    ngx_http_upstream_srv_conf_t   *uscf;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_http_socks5_create_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_socks5_module);

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_socks5_module);

    u = r->upstream;

    u->output.tag = (ngx_buf_tag_t) &ngx_http_socks5_module;

    u->conf = &hlcf->upstream;

    u->create_request = ngx_http_socks5_create_request;
    u->reinit_request = ngx_http_socks5_reinit_request;
    u->process_header = ngx_http_socks5_process_header;
    u->abort_request = ngx_http_socks5_abort_request;
    u->finalize_request = ngx_http_socks5_finalize_request;

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    u->resolved->host = *addr;
    u->resolved->port = port;
    u->resolved->no_port = 0;

    r->state = 0;

    ctx->method = 0x01;     /* connect */
    ctx->addr = *addr;
    ctx->port = port;
    ctx->data = *data;

    r->request_body_no_buffering = 1;
    ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    return NGX_DONE;
}

ngx_int_t ngx_http_socks5_create_request(ngx_http_request_t *r)
{
    ngx_http_socks5_loc_conf_t  *hlcf;
    ngx_http_socks5_ctx_t       *ctx;
    ngx_buf_t                   *b;
    ngx_chain_t                 *cl;
    size_t                       len;
    ngx_str_t                    data;
    ngx_int_t                    rc;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_socks5_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_socks5_module);

    if(ctx->data.len <= 0) {
        return NGX_OK;
    }
    
    len = ngx_base64_decoded_length(ctx->data.len);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    data.data = b->last;
    data.len = len;
    rc = ngx_decode_base64url(&data, &ctx->data);
    if(rc != NGX_OK) {
        return rc;
    }
    b->last += data.len;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    return NGX_OK;
}

ngx_int_t ngx_http_socks5_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}

ngx_int_t ngx_http_socks5_process_header(ngx_http_request_t *r)
{
    ngx_http_upstream_t            *u;

    u = r->upstream;

    u->state->status = NGX_HTTP_OK;
    u->headers_in.status_n = NGX_HTTP_OK;
    u->headers_in.content_length_n = -1;
    return NGX_OK;
}

void ngx_http_socks5_abort_request(ngx_http_request_t *r)
{
}

void ngx_http_socks5_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc)
{
}
