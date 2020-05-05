# nginx_http_socks5_module

socks5 over http

http parameter:
GET
http://example.com/socks.html?method=1&addr=192.168.1.1&port=443&data=urlsafe_base64()

POST
application/x-www-form-urlencoded
method=1&addr=192.168.1.1&port=443&data=urlsafe_base64()

application/octet-stream
raw socks data

WebSocket
raw socks data

client receive data:
raw socks data
