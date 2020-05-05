#ifndef _NGX_HTTP_SOCKS5_
#define _NGX_HTTP_SOCKS5_

#include <ngx_config.h>

extern ngx_module_t  ngx_http_socks5_module;

/* location config struct */
typedef struct {
    ngx_http_upstream_conf_t   upstream;

    ngx_str_t method;
    ngx_str_t addr;
    ngx_str_t port;
    ngx_str_t data;
} ngx_http_socks5_loc_conf_t;

typedef struct {
    ngx_int_t method;

    /* connect */
    ngx_str_t addr;
    ngx_int_t port;
    ngx_str_t data;
} ngx_http_socks5_ctx_t;

#endif /* _NGX_HTTP_SOCKS5_ */