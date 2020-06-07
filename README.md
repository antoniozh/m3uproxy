### m3u Proxy

This proxy server proxies an .m3u playlist for IPTV. It supports multiple credentials and will add them as GET query params. It also supports "restreaming", the proxied stream will be written to all the output streams requesting for the same URI. It should only be used on the same host though, since it's not programmed asynchronously. 