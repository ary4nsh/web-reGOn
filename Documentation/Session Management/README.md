## Cache Control
Use the `--cache-control` flag to recieve and analyse Cache-Control, Strict-Transport-Security and Expires headers and their values.

The value of the Cache-Control header must not be only `Public` or `Private`, because the `Public` value allows webpages to be cached in any proxy or caching server between the client and server, while the `Private` value allows the Session ID to be cached in the computer's file system, making it vulnerable to compromise by a hacker with access to the system. Setting only `Public` or `Private` values may lead to a Session Hijacking attack.

The session must expire with the `Expires` header. If it does not, the session value might be cracked if it is not secure, leading to the creation of a fake session using it. The expiration time must be set suitably: it should not be too short, allowing little time for clients to use a particular service, and not too long, giving enough time for hackers to crack it.

The presence of the `Secure` value in `Set-Cookie` ensures that the cookie is transmitted only via a secure channel (HTTPS).

The best way to prevent storing the session cookie is to set the `Cache-Control` value to `no-cache`, `no-store`, `must-revalidate`, or a combination of these:

```
Pragma: no-cache
Cache-Control: max-age=0
Expires: 0
```

Cache-Control directives:
- `no-cache` does not prevent a browser from storing cache data; it only forces validation of the stored data.
- `no-store` forces the browser not to store anything locally.
- `max-age` specifies how long a response can be stored in cache memory. Setting it to 0 prevents storage/caching.
- `must-revalidate` ensures that, since browsers have different default behaviors for storing HTTPS content, pages containing sensitive information have a `cache-control` header to ensure that the contents are not cached. The "Back" button can be prevented from displaying sensitive data by setting the "must-revalidate" option for this header.

Expires directives:
- This header is similar to `max-age` in `Cache-Control`; if `max-age` is used, the `Expires` header is ignored. This header is used for backward compatibility in some organizations. Setting it to 0 or -1 prevents storage/caching.

Pragma directives:
- This is not supported for HTTP/1.0 or HTTP/1.1 clients and only includes the `no-cache` directive.

 You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --cache-control [domain name] --port [port number]
```