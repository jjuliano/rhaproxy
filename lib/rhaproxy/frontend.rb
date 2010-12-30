  # = rhaproxy - A HAproxy gem for Ruby
  #
  # Homepage::  http://github.com/jjuliano/rhaproxy
  # Author::    Joel Bryan Juliano
  # Copyright:: (cc) 2011 Joel Bryan Juliano
  # License::   MIT

  #
  # class RhaproxyFrontend.new( array, str, array)
  #

  #
  # A "frontend" section describes a set of listening sockets accepting client
  # connections.
  #
  class RhaproxyFrontend

    #
    # acl <aclname> <criterion> [flags] [operator] <value> ...
    #   Declare or complete an access list.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Example:
    #         acl invalid_src  src          0.0.0.0/7 224.0.0.0/3
    #         acl invalid_src  src_port     0:1023
    #         acl local_dst    hdr(host) -i localhost
    #
    #   See section 7 about ACL usage.
    #
    attr_accessor :acl

    #
    # bind [<address>]:<port_range> [, ...]
    # bind [<address>]:<port_range> [, ...] interface <interface>
    # bind [<address>]:<port_range> [, ...] mss <maxseg>
    # bind [<address>]:<port_range> [, ...] transparent
    # bind [<address>]:<port_range> [, ...] id <id>
    # bind [<address>]:<port_range> [, ...] name <name>
    # bind [<address>]:<port_range> [, ...] defer-accept
    # bind [<address>]:<port_range> [, ...] accept-proxy
    # bind /<path> [, ...]
    # bind /<path> [, ...] mode <mode>
    # bind /<path> [, ...] [ user <user> | uid <uid> ]
    # bind /<path> [, ...] [ group <user> | gid <gid> ]
    #   Define one or several listening addresses and/or ports in a frontend.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                   no   |    yes   |   yes  |   no
    #   Arguments :
    #     <address>     is optional and can be a host name, an IPv4 address, an IPv6
    #                   address, or '*'. It designates the address the frontend will
    #                   listen on. If unset, all IPv4 addresses of the system will be
    #                   listened on. The same will apply for '*' or the system's
    #                   special address "0.0.0.0".
    #
    #     <port_range>  is either a unique TCP port, or a port range for which the
    #                   proxy will accept connections for the IP address specified
    #                   above. The port is mandatory for TCP listeners. Note that in
    #                   the case of an IPv6 address, the port is always the number
    #                   after the last colon (':'). A range can either be :
    #                    - a numerical port (ex: '80')
    #                    - a dash-delimited ports range explicitly stating the lower
    #                      and upper bounds (ex: '2000-2100') which are included in
    #                      the range.
    #
    #                   Particular care must be taken against port ranges, because
    #                   every <address:port> couple consumes one socket (= a file
    #                   descriptor), so it's easy to consume lots of descriptors
    #                   with a simple range, and to run out of sockets. Also, each
    #                   <address:port> couple must be used only once among all
    #                   instances running on a same system. Please note that binding
    #                   to ports lower than 1024 generally require particular
    #                   privileges to start the program, which are independant of
    #                   the 'uid' parameter.
    #
    #     <path>        is a UNIX socket path beginning with a slash ('/'). This is
    #                   alternative to the TCP listening port. Haproxy will then
    #                   receive UNIX connections on the socket located at this place.
    #                   The path must begin with a slash and by default is absolute.
    #                   It can be relative to the prefix defined by "unix-bind" in
    #                   the global section. Note that the total length of the prefix
    #                   followed by the socket path cannot exceed some system limits
    #                   for UNIX sockets, which commonly are set to 107 characters.
    #
    #     <interface>   is an optional physical interface name. This is currently
    #                   only supported on Linux. The interface must be a physical
    #                   interface, not an aliased interface. When specified, all
    #                   addresses on the same line will only be accepted if the
    #                   incoming packet physically come through the designated
    #                   interface. It is also possible to bind multiple frontends to
    #                   the same address if they are bound to different interfaces.
    #                   Note that binding to a physical interface requires root
    #                   privileges. This parameter is only compatible with TCP
    #                   sockets.
    #
    #     <maxseg>      is an optional TCP Maximum Segment Size (MSS) value to be
    #                   advertised on incoming connections. This can be used to force
    #                   a lower MSS for certain specific ports, for instance for
    #                   connections passing through a VPN. Note that this relies on a
    #                   kernel feature which is theorically supported under Linux but
    #                   was buggy in all versions prior to 2.6.28. It may or may not
    #                   work on other operating systems. The commonly advertised
    #                   value on Ethernet networks is 1460 = 1500(MTU) - 40(IP+TCP).
    #                   This parameter is only compatible with TCP sockets.
    #
    #     <id>          is a persistent value for socket ID. Must be positive and
    #                   unique in the proxy. An unused value will automatically be
    #                   assigned if unset. Can only be used when defining only a
    #                   single socket.
    #
    #     <name>        is an optional name provided for stats
    #
    #     <mode>        is the octal mode used to define access permissions on the
    #                   UNIX socket. It can also be set by default in the global
    #                   section's "unix-bind" statement. Note that some platforms
    #                   simply ignore this.
    #
    #     <user>        is the name of user that will be marked owner of the UNIX
    #                   socket.  It can also be set by default in the global
    #                   section's "unix-bind" statement. Note that some platforms
    #                   simply ignore this.
    #
    #     <group>       is the name of a group that will be used to create the UNIX
    #                   socket. It can also be set by default in the global section's
    #                   "unix-bind" statement. Note that some platforms simply ignore
    #                   this.
    #
    #     <uid>         is the uid of user that will be marked owner of the UNIX
    #                   socket. It can also be set by default in the global section's
    #                   "unix-bind" statement. Note that some platforms simply ignore
    #                   this.
    #
    #     <gid>         is the gid of a group that will be used to create the UNIX
    #                   socket. It can also be set by default in the global section's
    #                   "unix-bind" statement. Note that some platforms simply ignore
    #                   this.
    #
    #     transparent   is an optional keyword which is supported only on certain
    #                   Linux kernels. It indicates that the addresses will be bound
    #                   even if they do not belong to the local machine. Any packet
    #                   targeting any of these addresses will be caught just as if
    #                   the address was locally configured. This normally requires
    #                   that IP forwarding is enabled. Caution! do not use this with
    #                   the default address '*', as it would redirect any traffic for
    #                   the specified port. This keyword is available only when
    #                   HAProxy is built with USE_LINUX_TPROXY=1. This parameter is
    #                   only compatible with TCP sockets.
    #
    #     defer-accept  is an optional keyword which is supported only on certain
    #                   Linux kernels. It states that a connection will only be
    #                   accepted once some data arrive on it, or at worst after the
    #                   first retransmit. This should be used only on protocols for
    #                   which the client talks first (eg: HTTP). It can slightly
    #                   improve performance by ensuring that most of the request is
    #                   already available when the connection is accepted. On the
    #                   other hand, it will not be able to detect connections which
    #                   don't talk. It is important to note that this option is
    #                   broken in all kernels up to 2.6.31, as the connection is
    #                   never accepted until the client talks. This can cause issues
    #                   with front firewalls which would see an established
    #                   connection while the proxy will only see it in SYN_RECV.
    #
    #     accept-proxy  is an optional keyword which enforces use of the PROXY
    #                   protocol over any connection accepted by this listener. The
    #                   PROXY protocol dictates the layer 3/4 addresses of the
    #                   incoming connection to be used everywhere an address is used,
    #                   with the only exception of "tcp-request connection" rules
    #                   which will only see the real connection address. Logs will
    #                   reflect the addresses indicated in the protocol, unless it is
    #                   violated, in which case the real address will still be used.
    #                   This keyword combined with support from external components
    #                   can be used as an efficient and reliable alternative to the
    #                   X-Forwarded-For mechanism which is not always reliable and
    #                   not even always usable.
    #
    #   It is possible to specify a list of address:port combinations delimited by
    #   commas. The frontend will then listen on all of these addresses. There is no
    #   fixed limit to the number of addresses and ports which can be listened on in
    #   a frontend, as well as there is no limit to the number of "bind" statements
    #   in a frontend.
    #
    #   Example :
    #         listen http_proxy
    #             bind :80,:443
    #             bind 10.0.0.1:10080,10.0.0.1:10443
    #             bind /var/run/ssl-frontend.sock user root mode 600 accept-proxy
    #
    #   See also : "source", "option forwardfor", "unix-bind" and the PROXY protocol
    #              documentation.
    #
    attr_accessor :bind

    #
    # block { if | unless } <condition>
    #   Block a layer 7 request if/unless a condition is matched
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #
    #   The HTTP request will be blocked very early in the layer 7 processing
    #   if/unless <condition> is matched. A 403 error will be returned if the request
    #   is blocked. The condition has to reference ACLs (see section 7). This is
    #   typically used to deny access to certain sensible resources if some
    #   conditions are met or not met. There is no fixed limit to the number of
    #   "block" statements per instance.
    #
    #   Example:
    #         acl invalid_src  src          0.0.0.0/7 224.0.0.0/3
    #         acl invalid_src  src_port     0:1023
    #         acl local_dst    hdr(host) -i localhost
    #         block if invalid_src || local_dst
    #
    #   See section 7 about ACL usage.
    #
    attr_accessor :block

    #
    # capture cookie <name> len <length>
    #   Capture and log a cookie in the request and in the response.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                   no   |    yes   |   yes  |   no
    #   Arguments :
    #     <name>    is the beginning of the name of the cookie to capture. In order
    #               to match the exact name, simply suffix the name with an equal
    #               sign ('='). The full name will appear in the logs, which is
    #               useful with application servers which adjust both the cookie name
    #               and value (eg: ASPSESSIONXXXXX).
    #
    #     <length>  is the maximum number of characters to report in the logs, which
    #               include the cookie name, the equal sign and the value, all in the
    #               standard "name=value" form. The string will be truncated on the
    #               right if it exceeds <length>.
    #
    #   Only the first cookie is captured. Both the "cookie" request headers and the
    #   "set-cookie" response headers are monitored. This is particularly useful to
    #   check for application bugs causing session crossing or stealing between
    #   users, because generally the user's cookies can only change on a login page.
    #
    #   When the cookie was not presented by the client, the associated log column
    #   will report "-". When a request does not cause a cookie to be assigned by the
    #   server, a "-" is reported in the response column.
    #
    #   The capture is performed in the frontend only because it is necessary that
    #   the log format does not change for a given frontend depending on the
    #   backends. This may change in the future. Note that there can be only one
    #   "capture cookie" statement in a frontend. The maximum capture length is
    #   configured in the sources by default to 64 characters. It is not possible to
    #   specify a capture in a "defaults" section.
    #
    #   Example:
    #         capture cookie ASPSESSION len 32
    #
    #   See also : "capture request header", "capture response header" as well as
    #             section 8 about logging.
    #
    attr_accessor :capture_cookie

    #
    # capture request header <name> len <length>
    #   Capture and log the first occurrence of the specified request header.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                   no   |    yes   |   yes  |   no
    #   Arguments :
    #     <name>    is the name of the header to capture. The header names are not
    #               case-sensitive, but it is a common practice to write them as they
    #               appear in the requests, with the first letter of each word in
    #               upper case. The header name will not appear in the logs, only the
    #               value is reported, but the position in the logs is respected.
    #
    #     <length>  is the maximum number of characters to extract from the value and
    #               report in the logs. The string will be truncated on the right if
    #               it exceeds <length>.
    #
    #   Only the first value of the last occurrence of the header is captured. The
    #   value will be added to the logs between braces ('{}'). If multiple headers
    #   are captured, they will be delimited by a vertical bar ('|') and will appear
    #   in the same order they were declared in the configuration. Non-existent
    #   headers will be logged just as an empty string. Common uses for request
    #   header captures include the "Host" field in virtual hosting environments, the
    #   "Content-length" when uploads are supported, "User-agent" to quickly
    #   differentiate between real users and robots, and "X-Forwarded-For" in proxied
    #   environments to find where the request came from.
    #
    #   Note that when capturing headers such as "User-agent", some spaces may be
    #   logged, making the log analysis more difficult. Thus be careful about what
    #   you log if you know your log parser is not smart enough to rely on the
    #   braces.
    #
    #   There is no limit to the number of captured request headers, but each capture
    #   is limited to 64 characters. In order to keep log format consistent for a
    #   same frontend, header captures can only be declared in a frontend. It is not
    #   possible to specify a capture in a "defaults" section.
    #
    #   Example:
    #         capture request header Host len 15
    #         capture request header X-Forwarded-For len 15
    #         capture request header Referrer len 15
    #
    #   See also : "capture cookie", "capture response header" as well as section 8
    #              about logging.
    #
    attr_accessor :capture_request_header

    #
    # capture response header <name> len <length>
    #   Capture and log the first occurrence of the specified response header.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                   no   |    yes   |   yes  |   no
    #   Arguments :
    #     <name>    is the name of the header to capture. The header names are not
    #               case-sensitive, but it is a common practice to write them as they
    #               appear in the response, with the first letter of each word in
    #               upper case. The header name will not appear in the logs, only the
    #               value is reported, but the position in the logs is respected.
    #
    #     <length>  is the maximum number of characters to extract from the value and
    #               report in the logs. The string will be truncated on the right if
    #               it exceeds <length>.
    #
    #   Only the first value of the last occurrence of the header is captured. The
    #   result will be added to the logs between braces ('{}') after the captured
    #   request headers. If multiple headers are captured, they will be delimited by
    #   a vertical bar ('|') and will appear in the same order they were declared in
    #   the configuration. Non-existent headers will be logged just as an empty
    #   string. Common uses for response header captures include the "Content-length"
    #   header which indicates how many bytes are expected to be returned, the
    #   "Location" header to track redirections.
    #
    #   There is no limit to the number of captured response headers, but each
    #   capture is limited to 64 characters. In order to keep log format consistent
    #   for a same frontend, header captures can only be declared in a frontend. It
    #   is not possible to specify a capture in a "defaults" section.
    #
    #   Example:
    #         capture response header Content-length len 9
    #         capture response header Location len 15
    #
    #   See also : "capture cookie", "capture request header" as well as section 8
    #              about logging.
    #
    attr_accessor :capture_response_header

    #
    # force-persist { if | unless } <condition>
    #   Declare a condition to force persistence on down servers
    #   May be used in sections:    defaults | frontend | listen | backend
    #                                   no   |    yes   |   yes  |   yes
    #
    #   By default, requests are not dispatched to down servers. It is possible to
    #   force this using "option persist", but it is unconditional and redispatches
    #   to a valid server if "option redispatch" is set. That leaves with very little
    #   possibilities to force some requests to reach a server which is artificially
    #   marked down for maintenance operations.
    #
    #   The "force-persist" statement allows one to declare various ACL-based
    #   conditions which, when met, will cause a request to ignore the down status of
    #   a server and still try to connect to it. That makes it possible to start a
    #   server, still replying an error to the health checks, and run a specially
    #   configured browser to test the service. Among the handy methods, one could
    #   use a specific source IP address, or a specific cookie. The cookie also has
    #   the advantage that it can easily be added/removed on the browser from a test
    #   page. Once the service is validated, it is then possible to open the service
    #   to the world by returning a valid response to health checks.
    #
    #   The forced persistence is enabled when an "if" condition is met, or unless an
    #   "unless" condition is met. The final redispatch is always disabled when this
    #   is used.
    #
    #   See also : "option redispatch", "ignore-persist", "persist",
    #              and section 7 about ACL usage.
    #
    attr_accessor :force_persist

    #
    # http-request { allow | deny | auth [realm <realm>] }
    #              [ { if | unless } <condition> ]
    #   Access control for Layer 7 requests
    #
    #   May be used in sections:   defaults | frontend | listen | backend
    #                                 no    |    yes   |   yes  |   yes
    #
    #   These set of options allow to fine control access to a
    #   frontend/listen/backend. Each option may be followed by if/unless and acl.
    #   First option with matched condition (or option without condition) is final.
    #   For "deny" a 403 error will be returned, for "allow" normal processing is
    #   performed, for "auth" a 401/407 error code is returned so the client
    #   should be asked to enter a username and password.
    #
    #   There is no fixed limit to the number of http-request statements per
    #   instance.
    #
    #   Example:
    #         acl nagios src 192.168.129.3
    #         acl local_net src 192.168.0.0/16
    #         acl auth_ok http_auth(L1)
    #
    #         http-request allow if nagios
    #         http-request allow if local_net auth_ok
    #         http-request auth realm Gimme if local_net auth_ok
    #         http-request deny
    #
    #   Example:
    #         acl auth_ok http_auth_group(L1) G1
    #
    #         http-request auth unless auth_ok
    #
    #   See also : "stats http-request", section 3.4 about userlists and section 7
    #              about ACL usage.
    #
    attr_accessor :http_request

    # id <value>
    #   Set a persistent ID to a proxy.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                   no   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   Set a persistent ID for the proxy. This ID must be unique and positive.
    #   An unused ID will automatically be assigned if unset. The first assigned
    #   value will be 1. This ID is currently only returned in statistics.
    #
    attr_accessor :persistent_id

    #
    # ignore-persist { if | unless } <condition>
    #   Declare a condition to ignore persistence
    #   May be used in sections:    defaults | frontend | listen | backend
    #                                   no   |    yes   |   yes  |   yes
    #
    #   By default, when cookie persistence is enabled, every requests containing
    #   the cookie are unconditionally persistent (assuming the target server is up
    #   and running).
    #
    #   The "ignore-persist" statement allows one to declare various ACL-based
    #   conditions which, when met, will cause a request to ignore persistence.
    #   This is sometimes useful to load balance requests for static files, which
    #   oftenly don't require persistence. This can also be used to fully disable
    #   persistence for a specific User-Agent (for example, some web crawler bots).
    #
    #   Combined with "appsession", it can also help reduce HAProxy memory usage, as
    #   the appsession table won't grow if persistence is ignored.
    #
    #   The persistence is ignored when an "if" condition is met, or unless an
    #   "unless" condition is met.
    #
    #   See also : "force-persist", "cookie", and section 7 about ACL usage.
    #
    attr_accessor :ignore_persist

    #
    # monitor fail { if | unless } <condition>
    #   Add a condition to report a failure to a monitor HTTP request.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   no
    #   Arguments :
    #     if <cond>     the monitor request will fail if the condition is satisfied,
    #                   and will succeed otherwise. The condition should describe a
    #                   combined test which must induce a failure if all conditions
    #                   are met, for instance a low number of servers both in a
    #                   backend and its backup.
    #
    #     unless <cond> the monitor request will succeed only if the condition is
    #                   satisfied, and will fail otherwise. Such a condition may be
    #                   based on a test on the presence of a minimum number of active
    #                   servers in a list of backends.
    #
    #   This statement adds a condition which can force the response to a monitor
    #   request to report a failure. By default, when an external component queries
    #   the URI dedicated to monitoring, a 200 response is returned. When one of the
    #   conditions above is met, haproxy will return 503 instead of 200. This is
    #   very useful to report a site failure to an external component which may base
    #   routing advertisements between multiple sites on the availability reported by
    #   haproxy. In this case, one would rely on an ACL involving the "nbsrv"
    #   criterion. Note that "monitor fail" only works in HTTP mode.
    #
    #   Example:
    #      frontend www
    #         mode http
    #         acl site_dead nbsrv(dynamic) lt 2
    #         acl site_dead nbsrv(static)  lt 2
    #         monitor-uri   /site_alive
    #         monitor fail  if site_dead
    #
    #   See also : "monitor-net", "monitor-uri"
    #
    attr_accessor :monitor_fail

    #
    # option ignore-persist { if | unless } <condition>
    #   Declare a condition to ignore persistence
    #   May be used in sections:    defaults | frontend | listen | backend
    #                                   no   |    yes   |   yes  |   yes
    #
    #   By default, when cookie persistence is enabled, every requests containing
    #   the cookie are unconditionally persistent (assuming the target server is up
    #   and running).
    #
    #   The "ignore-persist" statement allows one to declare various ACL-based
    #   conditions which, when met, will cause a request to ignore persistence.
    #   This is sometimes useful to load balance requests for static files, which
    #   oftenly don't require persistence. This can also be used to fully disable
    #   persistence for a specific User-Agent (for example, some web crawler bots).
    #
    #   Combined with "appsession", it can also help reduce HAProxy memory usage, as
    #   the appsession table won't grow if persistence is ignored.
    #
    #   The persistence is ignored when an "if" condition is met, or unless an
    #   "unless" condition is met.
    #
    #   See also : "option force-persist", "cookie", and section 7 about ACL usage.
    #
    attr_accessor :option_ignore_presist

    #
    # redirect location <to> [code <code>] <option> [(if | unless) <condition>]
    # redirect prefix   <to> [code <code>] <option> [(if | unless) <condition>]
    #   Return an HTTP redirection if/unless a condition is matched
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #
    #   If/unless the condition is matched, the HTTP request will lead to a redirect
    #   response. If no condition is specified, the redirect applies unconditionally.
    #
    #   Arguments :
    #     <to>      With "redirect location", the exact value in <to> is placed into
    #               the HTTP "Location" header. In case of "redirect prefix", the
    #               "Location" header is built from the concatenation of <to> and the
    #               complete URI, including the query string, unless the "drop-query"
    #               option is specified (see below). As a special case, if <to>
    #               equals exactly "/" in prefix mode, then nothing is inserted
    #               before the original URI. It allows one to redirect to the same
    #               URL.
    #
    #     <code>    The code is optional. It indicates which type of HTTP redirection
    #               is desired. Only codes 301, 302 and 303 are supported, and 302 is
    #               used if no code is specified. 301 means "Moved permanently", and
    #               a browser may cache the Location. 302 means "Moved permanently"
    #               and means that the browser should not cache the redirection. 303
    #               is equivalent to 302 except that the browser will fetch the
    #               location with a GET method.
    #
    #     <option>  There are several options which can be specified to adjust the
    #               expected behaviour of a redirection :
    #
    #       - "drop-query"
    #         When this keyword is used in a prefix-based redirection, then the
    #         location will be set without any possible query-string, which is useful
    #         for directing users to a non-secure page for instance. It has no effect
    #         with a location-type redirect.
    #
    #       - "append-slash"
    #         This keyword may be used in conjunction with "drop-query" to redirect
    #         users who use a URL not ending with a '/' to the same one with the '/'.
    #         It can be useful to ensure that search engines will only see one URL.
    #         For this, a return code 301 is preferred.
    #
    #       - "set-cookie NAME[=value]"
    #         A "Set-Cookie" header will be added with NAME (and optionally "=value")
    #         to the response. This is sometimes used to indicate that a user has
    #         been seen, for instance to protect against some types of DoS. No other
    #         cookie option is added, so the cookie will be a session cookie. Note
    #         that for a browser, a sole cookie name without an equal sign is
    #         different from a cookie with an equal sign.
    #
    #       - "clear-cookie NAME[=]"
    #         A "Set-Cookie" header will be added with NAME (and optionally "="), but
    #         with the "Max-Age" attribute set to zero. This will tell the browser to
    #         delete this cookie. It is useful for instance on logout pages. It is
    #         important to note that clearing the cookie "NAME" will not remove a
    #         cookie set with "NAME=value". You have to clear the cookie "NAME=" for
    #         that, because the browser makes the difference.
    #
    #   Example: move the login URL only to HTTPS.
    #         acl clear      dst_port  80
    #         acl secure     dst_port  8080
    #         acl login_page url_beg   /login
    #         acl logout     url_beg   /logout
    #         acl uid_given  url_reg   /login?userid=[^&]+
    #         acl cookie_set hdr_sub(cookie) SEEN=1
    #
    #         redirect prefix   https://mysite.com set-cookie SEEN=1 if !cookie_set
    #         redirect prefix   https://mysite.com           if login_page !secure
    #         redirect prefix   http://mysite.com drop-query if login_page !uid_given
    #         redirect location http://mysite.com/           if !login_page secure
    #         redirect location / clear-cookie USERID=       if logout
    #
    #   Example: send redirects for request for articles without a '/'.
    #         acl missing_slash path_reg ^/article/[^/]*$
    #         redirect code 301 prefix / drop-query append-slash if missing_slash
    #
    #   See section 7 about ACL usage.
    #
    attr_accessor :redirect

    #
    # reqadd  <string> [(if | unless) <cond>]
    #   Add a header at the end of the HTTP request
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <string>  is the complete line to be added. Any space or known delimiter
    #               must be escaped using a backslash ('\'). Please refer to section
    #               6 about HTTP header manipulation for more information.
    #
    #     <cond>    is an optional matching condition built from ACLs. It makes it
    #               possible to ignore this rule when other conditions are not met.
    #
    #   A new line consisting in <string> followed by a line feed will be added after
    #   the last header of an HTTP request.
    #
    #   Header transformations only apply to traffic which passes through HAProxy,
    #   and not to traffic generated by HAProxy, such as health-checks or error
    #   responses.
    #
    #   Example : add "X-Proto: SSL" to requests coming via port 81
    #      acl is-ssl  dst_port       81
    #      reqadd      X-Proto:\ SSL  if is-ssl
    #
    #   See also: "rspadd", section 6 about HTTP header manipulation, and section 7
    #             about ACLs.
    #
    attr_accessor :reqadd

    #
    # reqallow  <search> [(if | unless) <cond>]
    # reqiallow <search> [(if | unless) <cond>] (ignore case)
    #   Definitely allow an HTTP request if a line matches a regular expression
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <search>  is the regular expression applied to HTTP headers and to the
    #               request line. This is an extended regular expression. Parenthesis
    #               grouping is supported and no preliminary backslash is required.
    #               Any space or known delimiter must be escaped using a backslash
    #               ('\'). The pattern applies to a full line at a time. The
    #               "reqallow" keyword strictly matches case while "reqiallow"
    #               ignores case.
    #
    #     <cond>    is an optional matching condition built from ACLs. It makes it
    #               possible to ignore this rule when other conditions are not met.
    #
    #   A request containing any line which matches extended regular expression
    #   <search> will mark the request as allowed, even if any later test would
    #   result in a deny. The test applies both to the request line and to request
    #   headers. Keep in mind that URLs in request line are case-sensitive while
    #   header names are not.
    #
    #   It is easier, faster and more powerful to use ACLs to write access policies.
    #   Reqdeny, reqallow and reqpass should be avoided in new designs.
    #
    #   Example :
    #      # allow www.* but refuse *.local
    #      reqiallow ^Host:\ www\.
    #      reqideny  ^Host:\ .*\.local
    #
    #   See also: "reqdeny", "block", section 6 about HTTP header manipulation, and
    #             section 7 about ACLs.
    #
    attr_accessor :reqallow
    attr_accessor :reqiallow

    #
    # reqdel  <search> [(if | unless) <cond>]
    # reqidel <search> [(if | unless) <cond>]  (ignore case)
    #   Delete all headers matching a regular expression in an HTTP request
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <search>  is the regular expression applied to HTTP headers and to the
    #               request line. This is an extended regular expression. Parenthesis
    #               grouping is supported and no preliminary backslash is required.
    #               Any space or known delimiter must be escaped using a backslash
    #               ('\'). The pattern applies to a full line at a time. The "reqdel"
    #               keyword strictly matches case while "reqidel" ignores case.
    #
    #     <cond>    is an optional matching condition built from ACLs. It makes it
    #               possible to ignore this rule when other conditions are not met.
    #
    #   Any header line matching extended regular expression <search> in the request
    #   will be completely deleted. Most common use of this is to remove unwanted
    #   and/or dangerous headers or cookies from a request before passing it to the
    #   next servers.
    #
    #   Header transformations only apply to traffic which passes through HAProxy,
    #   and not to traffic generated by HAProxy, such as health-checks or error
    #   responses. Keep in mind that header names are not case-sensitive.
    #
    #   Example :
    #      # remove X-Forwarded-For header and SERVER cookie
    #      reqidel ^X-Forwarded-For:.*
    #      reqidel ^Cookie:.*SERVER=
    #
    #   See also: "reqadd", "reqrep", "rspdel", section 6 about HTTP header
    #             manipulation, and section 7 about ACLs.
    #
    attr_accessor :reqdel
    attr_accessor :reqidel

    #
    # reqdeny  <search> [(if | unless) <cond>]
    # reqideny <search> [(if | unless) <cond>]  (ignore case)
    #   Deny an HTTP request if a line matches a regular expression
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <search>  is the regular expression applied to HTTP headers and to the
    #               request line. This is an extended regular expression. Parenthesis
    #               grouping is supported and no preliminary backslash is required.
    #               Any space or known delimiter must be escaped using a backslash
    #               ('\'). The pattern applies to a full line at a time. The
    #               "reqdeny" keyword strictly matches case while "reqideny" ignores
    #               case.
    #
    #     <cond>    is an optional matching condition built from ACLs. It makes it
    #               possible to ignore this rule when other conditions are not met.
    #
    #   A request containing any line which matches extended regular expression
    #   <search> will mark the request as denied, even if any later test would
    #   result in an allow. The test applies both to the request line and to request
    #   headers. Keep in mind that URLs in request line are case-sensitive while
    #   header names are not.
    #
    #   A denied request will generate an "HTTP 403 forbidden" response once the
    #   complete request has been parsed. This is consistent with what is practiced
    #   using ACLs.
    #
    #   It is easier, faster and more powerful to use ACLs to write access policies.
    #   Reqdeny, reqallow and reqpass should be avoided in new designs.
    #
    #   Example :
    #      # refuse *.local, then allow www.*
    #      reqideny  ^Host:\ .*\.local
    #      reqiallow ^Host:\ www\.
    #
    #   See also: "reqallow", "rspdeny", "block", section 6 about HTTP header
    #             manipulation, and section 7 about ACLs.
    #
    attr_accessor :reqdeny
    attr_accessor :reqideny

    #
    # reqpass  <search> [(if | unless) <cond>]
    # reqipass <search> [(if | unless) <cond>]  (ignore case)
    #   Ignore any HTTP request line matching a regular expression in next rules
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <search>  is the regular expression applied to HTTP headers and to the
    #               request line. This is an extended regular expression. Parenthesis
    #               grouping is supported and no preliminary backslash is required.
    #               Any space or known delimiter must be escaped using a backslash
    #               ('\'). The pattern applies to a full line at a time. The
    #               "reqpass" keyword strictly matches case while "reqipass" ignores
    #               case.
    #
    #     <cond>    is an optional matching condition built from ACLs. It makes it
    #               possible to ignore this rule when other conditions are not met.
    #
    #   A request containing any line which matches extended regular expression
    #   <search> will skip next rules, without assigning any deny or allow verdict.
    #   The test applies both to the request line and to request headers. Keep in
    #   mind that URLs in request line are case-sensitive while header names are not.
    #
    #   It is easier, faster and more powerful to use ACLs to write access policies.
    #   Reqdeny, reqallow and reqpass should be avoided in new designs.
    #
    #   Example :
    #      # refuse *.local, then allow www.*, but ignore "www.private.local"
    #      reqipass  ^Host:\ www.private\.local
    #      reqideny  ^Host:\ .*\.local
    #      reqiallow ^Host:\ www\.
    #
    #   See also: "reqallow", "reqdeny", "block", section 6 about HTTP header
    #             manipulation, and section 7 about ACLs.
    #
    attr_accessor :reqpass
    attr_accessor :reqipass

    #
    # reqrep  <search> <string> [(if | unless) <cond>]
    # reqirep <search> <string> [(if | unless) <cond>]   (ignore case)
    #   Replace a regular expression with a string in an HTTP request line
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <search>  is the regular expression applied to HTTP headers and to the
    #               request line. This is an extended regular expression. Parenthesis
    #               grouping is supported and no preliminary backslash is required.
    #               Any space or known delimiter must be escaped using a backslash
    #               ('\'). The pattern applies to a full line at a time. The "reqrep"
    #               keyword strictly matches case while "reqirep" ignores case.
    #
    #     <string>  is the complete line to be added. Any space or known delimiter
    #               must be escaped using a backslash ('\'). References to matched
    #               pattern groups are possible using the common \N form, with N
    #               being a single digit between 0 and 9. Please refer to section
    #               6 about HTTP header manipulation for more information.
    #
    #     <cond>    is an optional matching condition built from ACLs. It makes it
    #               possible to ignore this rule when other conditions are not met.
    #
    #   Any line matching extended regular expression <search> in the request (both
    #   the request line and header lines) will be completely replaced with <string>.
    #   Most common use of this is to rewrite URLs or domain names in "Host" headers.
    #
    #   Header transformations only apply to traffic which passes through HAProxy,
    #   and not to traffic generated by HAProxy, such as health-checks or error
    #   responses. Note that for increased readability, it is suggested to add enough
    #   spaces between the request and the response. Keep in mind that URLs in
    #   request line are case-sensitive while header names are not.
    #
    #   Example :
    #      # replace "/static/" with "/" at the beginning of any request path.
    #      reqrep ^([^\ ]*)\ /static/(.*)     \1\ /\2
    #      # replace "www.mydomain.com" with "www" in the host name.
    #      reqirep ^Host:\ www.mydomain.com   Host:\ www
    #
    #   See also: "reqadd", "reqdel", "rsprep", section 6 about HTTP header
    #             manipulation, and section 7 about ACLs.
    #
    attr_accessor :reqrep
    attr_accessor :reqirep

    #
    # reqtarpit  <search> [(if | unless) <cond>]
    # reqitarpit <search> [(if | unless) <cond>]  (ignore case)
    #   Tarpit an HTTP request containing a line matching a regular expression
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <search>  is the regular expression applied to HTTP headers and to the
    #               request line. This is an extended regular expression. Parenthesis
    #               grouping is supported and no preliminary backslash is required.
    #               Any space or known delimiter must be escaped using a backslash
    #               ('\'). The pattern applies to a full line at a time. The
    #               "reqtarpit" keyword strictly matches case while "reqitarpit"
    #               ignores case.
    #
    #     <cond>    is an optional matching condition built from ACLs. It makes it
    #               possible to ignore this rule when other conditions are not met.
    #
    #   A request containing any line which matches extended regular expression
    #   <search> will be tarpitted, which means that it will connect to nowhere, will
    #   be kept open for a pre-defined time, then will return an HTTP error 500 so
    #   that the attacker does not suspect it has been tarpitted. The status 500 will
    #   be reported in the logs, but the completion flags will indicate "PT". The
    #   delay is defined by "timeout tarpit", or "timeout connect" if the former is
    #   not set.
    #
    #   The goal of the tarpit is to slow down robots attacking servers with
    #   identifiable requests. Many robots limit their outgoing number of connections
    #   and stay connected waiting for a reply which can take several minutes to
    #   come. Depending on the environment and attack, it may be particularly
    #   efficient at reducing the load on the network and firewalls.
    #
    #   Examples :
    #      # ignore user-agents reporting any flavour of "Mozilla" or "MSIE", but
    #      # block all others.
    #      reqipass   ^User-Agent:\.*(Mozilla|MSIE)
    #      reqitarpit ^User-Agent:
    #
    #      # block bad guys
    #      acl badguys src 10.1.0.3 172.16.13.20/28
    #      reqitarpit . if badguys
    #
    #   See also: "reqallow", "reqdeny", "reqpass", section 6 about HTTP header
    #             manipulation, and section 7 about ACLs.
    #
    attr_accessor :reqtarpit
    attr_accessor :reqitarpit

    #
    # rspadd <string> [(if | unless) <cond>]
    #   Add a header at the end of the HTTP response
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <string>  is the complete line to be added. Any space or known delimiter
    #               must be escaped using a backslash ('\'). Please refer to section
    #               6 about HTTP header manipulation for more information.
    #
    #     <cond>    is an optional matching condition built from ACLs. It makes it
    #               possible to ignore this rule when other conditions are not met.
    #
    #   A new line consisting in <string> followed by a line feed will be added after
    #   the last header of an HTTP response.
    #
    #   Header transformations only apply to traffic which passes through HAProxy,
    #   and not to traffic generated by HAProxy, such as health-checks or error
    #   responses.
    #
    #   See also: "reqadd", section 6 about HTTP header manipulation, and section 7
    #             about ACLs.
    #
    attr_accessor :rspadd

    #
    # rspdel  <search> [(if | unless) <cond>]
    # rspidel <search> [(if | unless) <cond>]  (ignore case)
    #   Delete all headers matching a regular expression in an HTTP response
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <search>  is the regular expression applied to HTTP headers and to the
    #               response line. This is an extended regular expression, so
    #               parenthesis grouping is supported and no preliminary backslash
    #               is required. Any space or known delimiter must be escaped using
    #               a backslash ('\'). The pattern applies to a full line at a time.
    #               The "rspdel" keyword strictly matches case while "rspidel"
    #               ignores case.
    #
    #     <cond>    is an optional matching condition built from ACLs. It makes it
    #               possible to ignore this rule when other conditions are not met.
    #
    #   Any header line matching extended regular expression <search> in the response
    #   will be completely deleted. Most common use of this is to remove unwanted
    #   and/or sensible headers or cookies from a response before passing it to the
    #   client.
    #
    #   Header transformations only apply to traffic which passes through HAProxy,
    #   and not to traffic generated by HAProxy, such as health-checks or error
    #   responses. Keep in mind that header names are not case-sensitive.
    #
    #   Example :
    #      # remove the Server header from responses
    #      reqidel ^Server:.*
    #
    #   See also: "rspadd", "rsprep", "reqdel", section 6 about HTTP header
    #             manipulation, and section 7 about ACLs.
    #
    attr_accessor :rspdel
    attr_accessor :rspidel

    #
    # rspdeny  <search> [(if | unless) <cond>]
    # rspideny <search> [(if | unless) <cond>]  (ignore case)
    #   Block an HTTP response if a line matches a regular expression
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <search>  is the regular expression applied to HTTP headers and to the
    #               response line. This is an extended regular expression, so
    #               parenthesis grouping is supported and no preliminary backslash
    #               is required. Any space or known delimiter must be escaped using
    #               a backslash ('\'). The pattern applies to a full line at a time.
    #               The "rspdeny" keyword strictly matches case while "rspideny"
    #               ignores case.
    #
    #     <cond>    is an optional matching condition built from ACLs. It makes it
    #               possible to ignore this rule when other conditions are not met.
    #
    #   A response containing any line which matches extended regular expression
    #   <search> will mark the request as denied. The test applies both to the
    #   response line and to response headers. Keep in mind that header names are not
    #   case-sensitive.
    #
    #   Main use of this keyword is to prevent sensitive information leak and to
    #   block the response before it reaches the client. If a response is denied, it
    #   will be replaced with an HTTP 502 error so that the client never retrieves
    #   any sensitive data.
    #
    #   It is easier, faster and more powerful to use ACLs to write access policies.
    #   Rspdeny should be avoided in new designs.
    #
    #   Example :
    #      # Ensure that no content type matching ms-word will leak
    #      rspideny  ^Content-type:\.*/ms-word
    #
    #   See also: "reqdeny", "acl", "block", section 6 about HTTP header manipulation
    #             and section 7 about ACLs.
    #
    attr_accessor :rspdeny
    attr_accessor :rspideny

    #
    # rsprep  <search> <string> [(if | unless) <cond>]
    # rspirep <search> <string> [(if | unless) <cond>]  (ignore case)
    #   Replace a regular expression with a string in an HTTP response line
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <search>  is the regular expression applied to HTTP headers and to the
    #               response line. This is an extended regular expression, so
    #               parenthesis grouping is supported and no preliminary backslash
    #               is required. Any space or known delimiter must be escaped using
    #               a backslash ('\'). The pattern applies to a full line at a time.
    #               The "rsprep" keyword strictly matches case while "rspirep"
    #               ignores case.
    #
    #     <string>  is the complete line to be added. Any space or known delimiter
    #               must be escaped using a backslash ('\'). References to matched
    #               pattern groups are possible using the common \N form, with N
    #               being a single digit between 0 and 9. Please refer to section
    #               6 about HTTP header manipulation for more information.
    #
    #     <cond>    is an optional matching condition built from ACLs. It makes it
    #               possible to ignore this rule when other conditions are not met.
    #
    #   Any line matching extended regular expression <search> in the response (both
    #   the response line and header lines) will be completely replaced with
    #   <string>. Most common use of this is to rewrite Location headers.
    #
    #   Header transformations only apply to traffic which passes through HAProxy,
    #   and not to traffic generated by HAProxy, such as health-checks or error
    #   responses. Note that for increased readability, it is suggested to add enough
    #   spaces between the request and the response. Keep in mind that header names
    #   are not case-sensitive.
    #
    #   Example :
    #      # replace "Location: 127.0.0.1:8080" with "Location: www.mydomain.com"
    #      rspirep ^Location:\ 127.0.0.1:8080    Location:\ www.mydomain.com
    #
    #   See also: "rspadd", "rspdel", "reqrep", section 6 about HTTP header
    #             manipulation, and section 7 about ACLs.
    #
    attr_accessor :rsprep
    attr_accessor :rspirep

    #
    # tcp-request connection <action> [(if | unless) <condition>]
    #   Perform an action on an incoming connection depending on a layer 4 condition
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   no
    #   Arguments :
    #     <action>    defines the action to perform if the condition applies. Valid
    #                 actions include : "accept", "reject", "track-sc1", "track-sc2".
    #                 See below for more details.
    #
    #     <condition> is a standard layer4-only ACL-based condition (see section 7).
    #
    #   Immediately after acceptance of a new incoming connection, it is possible to
    #   evaluate some conditions to decide whether this connection must be accepted
    #   or dropped or have its counters tracked. Those conditions cannot make use of
    #   any data contents because the connection has not been read from yet, and the
    #   buffers are not yet allocated. This is used to selectively and very quickly
    #   accept or drop connections from various sources with a very low overhead. If
    #   some contents need to be inspected in order to take the decision, the
    #   "tcp-request content" statements must be used instead.
    #
    #   The "tcp-request connection" rules are evaluated in their exact declaration
    #   order. If no rule matches or if there is no rule, the default action is to
    #   accept the incoming connection. There is no specific limit to the number of
    #   rules which may be inserted.
    #
    #   Three types of actions are supported :
    #     - accept :
    #         accepts the connection if the condition is true (when used with "if")
    #         or false (when used with "unless"). The first such rule executed ends
    #         the rules evaluation.
    #
    #     - reject :
    #         rejects the connection if the condition is true (when used with "if")
    #         or false (when used with "unless"). The first such rule executed ends
    #         the rules evaluation. Rejected connections do not even become a
    #         session, which is why they are accounted separately for in the stats,
    #         as "denied connections". They are not considered for the session
    #         rate-limit and are not logged either. The reason is that these rules
    #         should only be used to filter extremely high connection rates such as
    #         the ones encountered during a massive DDoS attack. Under these extreme
    #         conditions, the simple action of logging each event would make the
    #         system collapse and would considerably lower the filtering capacity. If
    #         logging is absolutely desired, then "tcp-request content" rules should
    #         be used instead.
    #
    #     - { track-sc1 | track-sc2 } <key> [table <table>] :
    #         enables tracking of sticky counters from current connection. These
    #         rules do not stop evaluation and do not change default action. Two sets
    #         of counters may be simultaneously tracked by the same connection. The
    #         first "track-sc1" rule executed enables tracking of the counters of the
    #         specified table as the first set. The first "track-sc2" rule executed
    #         enables tracking of the counters of the specified table as the second
    #         set. It is a recommended practice to use the first set of counters for
    #         the per-frontend counters and the second set for the per-backend ones.
    #
    #         These actions take one or two arguments :
    #           <key>   is mandatory, and defines the criterion the tracking key will
    #                   be derived from. At the moment, only "src" is supported. With
    #                   it, the key will be the connection's source IPv4 address.
    #
    #          <table>  is an optional table to be used instead of the default one,
    #                   which is the stick-table declared in the current proxy. All
    #                   the counters for the matches and updates for the key will
    #                   then be performed in that table until the session ends.
    #
    #         Once a "track-sc*" rule is executed, the key is looked up in the table
    #         and if it is not found, an entry is allocated for it. Then a pointer to
    #         that entry is kept during all the session's life, and this entry's
    #         counters are updated as often as possible, every time the session's
    #         counters are updated, and also systematically when the session ends.
    #         If the entry tracks concurrent connection counters, one connection is
    #         counted for as long as the entry is tracked, and the entry will not
    #         expire during that time. Tracking counters also provides a performance
    #         advantage over just checking the keys, because only one table lookup is
    #         performed for all ACL checks that make use of it.
    #
    #   Note that the "if/unless" condition is optional. If no condition is set on
    #   the action, it is simply performed unconditionally. That can be useful for
    #   "track-sc*" actions as well as for changing the default action to a reject.
    #
    #   Example: accept all connections from white-listed hosts, reject too fast
    #            connection without counting them, and track accepted connections.
    #            This results in connection rate being capped from abusive sources.
    #
    #         tcp-request connection accept if { src -f /etc/haproxy/whitelist.lst }
    #         tcp-request connection reject if { src_conn_rate gt 10 }
    #         tcp-request connection track-sc1 src
    #
    #   Example: accept all connections from white-listed hosts, count all other
    #            connections and reject too fast ones. This results in abusive ones
    #            being blocked as long as they don't slow down.
    #
    #         tcp-request connection accept if { src -f /etc/haproxy/whitelist.lst }
    #         tcp-request connection track-sc1 src
    #         tcp-request connection reject if { sc1_conn_rate gt 10 }
    #
    #   See section 7 about ACL usage.
    #
    #   See also : "tcp-request content", "stick-table"
    #
    attr_accessor :tcp_request_connection

    #
    # tcp-request content <action> [(if | unless) <condition>]
    #   Perform an action on a new session depending on a layer 4-7 condition
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <action>    defines the action to perform if the condition applies. Valid
    #                 actions include : "accept", "reject", "track-sc1", "track-sc2".
    #                 See "tcp-request connection" above for their signification.
    #
    #     <condition> is a standard layer 4-7 ACL-based condition (see section 7).
    #
    #   A request's contents can be analysed at an early stage of request processing
    #   called "TCP content inspection". During this stage, ACL-based rules are
    #   evaluated every time the request contents are updated, until either an
    #   "accept" or a "reject" rule matches, or the TCP request inspection delay
    #   expires with no matching rule.
    #
    #   The first difference between these rules and "tcp-request connection" rules
    #   is that "tcp-request content" rules can make use of contents to take a
    #   decision. Most often, these decisions will consider a protocol recognition or
    #   validity. The second difference is that content-based rules can be used in
    #   both frontends and backends. In frontends, they will be evaluated upon new
    #   connections. In backends, they will be evaluated once a session is assigned
    #   a backend. This means that a single frontend connection may be evaluated
    #   several times by one or multiple backends when a session gets reassigned
    #   (for instance after a client-side HTTP keep-alive request).
    #
    #   Content-based rules are evaluated in their exact declaration order. If no
    #   rule matches or if there is no rule, the default action is to accept the
    #   contents. There is no specific limit to the number of rules which may be
    #   inserted.
    #
    #   Three types of actions are supported :
    #     - accept :
    #     - reject :
    #     - { track-sc1 | track-sc2 } <key> [table <table>]
    #
    #   They have the same meaning as their counter-parts in "tcp-request connection"
    #   so please refer to that section for a complete description.
    #
    #   Also, it is worth noting that if sticky counters are tracked from a rule
    #   defined in a backend, this tracking will automatically end when the session
    #   releases the backend. That allows per-backend counter tracking even in case
    #   of HTTP keep-alive requests when the backend changes. While there is nothing
    #   mandatory about it, it is recommended to use the track-sc1 pointer to track
    #   per-frontend counters and track-sc2 to track per-backend counters.
    #
    #   Note that the "if/unless" condition is optional. If no condition is set on
    #   the action, it is simply performed unconditionally. That can be useful for
    #   "track-sc*" actions as well as for changing the default action to a reject.
    #
    #   It is perfectly possible to match layer 7 contents with "tcp-request content"
    #   rules, but then it is important to ensure that a full request has been
    #   buffered, otherwise no contents will match. In order to achieve this, the
    #   best solution involves detecting the HTTP protocol during the inspection
    #   period.
    #
    #   Example:
    #         # Accept HTTP requests containing a Host header saying "example.com"
    #         # and reject everything else.
    #         acl is_host_com hdr(Host) -i example.com
    #         tcp-request inspect-delay 30s
    #         tcp-request content accept if HTTP is_host_com
    #         tcp-request content reject
    #
    #   Example:
    #         # reject SMTP connection if client speaks first
    #         tcp-request inspect-delay 30s
    #         acl content_present req_len gt 0
    #         tcp-request content reject if content_present
    #
    #         # Forward HTTPS connection only if client speaks
    #         tcp-request inspect-delay 30s
    #         acl content_present req_len gt 0
    #         tcp-request content accept if content_present
    #         tcp-request content reject
    #
    #   Example: track per-frontend and per-backend counters, block abusers at the
    #            frontend when the backend detects abuse.
    #
    #         frontend http
    #             # Use General Purpose Couter 0 in SC1 as a global abuse counter
    #             # protecting all our sites
    #             stick-table type ip size 1m expire 5m store gpc0
    #             tcp-request connection track-sc1 src
    #             tcp-request connection reject if { sc1_get_gpc0 gt 0 }
    #             ...
    #             use_backend http_dynamic if { path_end .php }
    #
    #         backend http_dynamic
    #             # if a source makes too fast requests to this dynamic site (tracked
    #             # by SC2), block it globally in the frontend.
    #             stick-table type ip size 1m expire 5m store http_req_rate(10s)
    #             acl click_too_fast sc2_http_req_rate gt 10
    #             acl mark_as_abuser sc1_inc_gpc0
    #             tcp-request content track-sc2 src
    #             tcp-request content reject if click_too_fast mark_as_abuser
    #
    #   See section 7 about ACL usage.
    #
    #   See also : "tcp-request connection", "tcp-request inspect-delay"
    #
    attr_accessor :tcp_request_content

    #
    # tcp-request inspect-delay <timeout>
    #   Set the maximum allowed time to wait for data during content inspection
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  no    |    yes   |   yes  |   yes
    #   Arguments :
    #     <timeout> is the timeout value specified in milliseconds by default, but
    #               can be in any other unit if the number is suffixed by the unit,
    #               as explained at the top of this document.
    #
    #   People using haproxy primarily as a TCP relay are often worried about the
    #   risk of passing any type of protocol to a server without any analysis. In
    #   order to be able to analyze the request contents, we must first withhold
    #   the data then analyze them. This statement simply enables withholding of
    #   data for at most the specified amount of time.
    #
    #   TCP content inspection applies very early when a connection reaches a
    #   frontend, then very early when the connection is forwarded to a backend. This
    #   means that a connection may experience a first delay in the frontend and a
    #   second delay in the backend if both have tcp-request rules.
    #
    #   Note that when performing content inspection, haproxy will evaluate the whole
    #   rules for every new chunk which gets in, taking into account the fact that
    #   those data are partial. If no rule matches before the aforementioned delay,
    #   a last check is performed upon expiration, this time considering that the
    #   contents are definitive. If no delay is set, haproxy will not wait at all
    #   and will immediately apply a verdict based on the available information.
    #   Obviously this is unlikely to be very useful and might even be racy, so such
    #   setups are not recommended.
    #
    #   As soon as a rule matches, the request is released and continues as usual. If
    #   the timeout is reached and no rule matches, the default policy will be to let
    #   it pass through unaffected.
    #
    #   For most protocols, it is enough to set it to a few seconds, as most clients
    #   send the full request immediately upon connection. Add 3 or more seconds to
    #   cover TCP retransmits but that's all. For some protocols, it may make sense
    #   to use large values, for instance to ensure that the client never talks
    #   before the server (eg: SMTP), or to wait for a client to talk before passing
    #   data to the server (eg: SSL). Note that the client timeout must cover at
    #   least the inspection delay, otherwise it will expire first. If the client
    #   closes the connection or if the buffer is full, the delay immediately expires
    #   since the contents will not be able to change anymore.
    #
    #   See also : "tcp-request content accept", "tcp-request content reject",
    #              "timeout client".
    #
    attr_accessor :tcp_request_inspect_delay

    #
    # use_backend <backend> if <condition>
    # use_backend <backend> unless <condition>
    #   Switch to a specific backend if/unless an ACL-based condition is matched.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                   no   |    yes   |   yes  |   no
    #   Arguments :
    #     <backend>   is the name of a valid backend or "listen" section.
    #
    #     <condition> is a condition composed of ACLs, as described in section 7.
    #
    #   When doing content-switching, connections arrive on a frontend and are then
    #   dispatched to various backends depending on a number of conditions. The
    #   relation between the conditions and the backends is described with the
    #   "use_backend" keyword. While it is normally used with HTTP processing, it can
    #   also be used in pure TCP, either without content using stateless ACLs (eg:
    #   source address validation) or combined with a "tcp-request" rule to wait for
    #   some payload.
    #
    #   There may be as many "use_backend" rules as desired. All of these rules are
    #   evaluated in their declaration order, and the first one which matches will
    #   assign the backend.
    #
    #   In the first form, the backend will be used if the condition is met. In the
    #   second form, the backend will be used if the condition is not met. If no
    #   condition is valid, the backend defined with "default_backend" will be used.
    #   If no default backend is defined, either the servers in the same section are
    #   used (in case of a "listen" section) or, in case of a frontend, no server is
    #   used and a 503 service unavailable response is returned.
    #
    #   Note that it is possible to switch from a TCP frontend to an HTTP backend. In
    #   this case, either the frontend has already checked that the protocol is HTTP,
    #   and backend processing will immediately follow, or the backend will wait for
    #   a complete HTTP request to get in. This feature is useful when a frontend
    #   must decode several protocols on a unique port, one of them being HTTP.
    #
    #   See also: "default_backend", "tcp-request", and section 7 about ACLs.
    #
    attr_accessor :use_backend

    #
    # description <text>
    #   Add a text that describes the instance.
    #
    #   Please note that it is required to escape certain characters (# for example)
    #   and this text is inserted into a html page so you should avoid using
    #   "<" and ">" characters.
    #
    attr_accessor :description

    #
    # backlog <conns>
    #   Give hints to the system about the approximate listen backlog desired size
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments :
    #     <conns>   is the number of pending connections. Depending on the operating
    #               system, it may represent the number of already acknowledged
    # 	      connections, of non-acknowledged ones, or both.
    #
    #   In order to protect against SYN flood attacks, one solution is to increase
    #   the system's SYN backlog size. Depending on the system, sometimes it is just
    #   tunable via a system parameter, sometimes it is not adjustable at all, and
    #   sometimes the system relies on hints given by the application at the time of
    #   the listen() syscall. By default, HAProxy passes the frontend's maxconn value
    #   to the listen() syscall. On systems which can make use of this value, it can
    #   sometimes be useful to be able to specify a different value, hence this
    #   backlog parameter.
    #
    #   On Linux 2.4, the parameter is ignored by the system. On Linux 2.6, it is
    #   used as a hint and the system accepts up to the smallest greater power of
    #   two, and never more than some limits (usually 32768).
    #
    #   See also : "maxconn" and the target operating system's tuning guide.
    #
    attr_accessor :backlog

    #
    # bind-process [ all | odd | even | <number 1-32> ] ...
    #   Limit visibility of an instance to a certain set of processes numbers.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     all           All process will see this instance. This is the default. It
    #                   may be used to override a default value.
    #
    #     odd           This instance will be enabled on processes 1,3,5,...31. This
    #                   option may be combined with other numbers.
    #
    #     even          This instance will be enabled on processes 2,4,6,...32. This
    #                   option may be combined with other numbers. Do not use it
    #                   with less than 2 processes otherwise some instances might be
    #                   missing from all processes.
    #
    #     number        The instance will be enabled on this process number, between
    #                   1 and 32. You must be careful not to reference a process
    #                   number greater than the configured global.nbproc, otherwise
    #                   some instances might be missing from all processes.
    #
    #   This keyword limits binding of certain instances to certain processes. This
    #   is useful in order not to have too many processes listening to the same
    #   ports. For instance, on a dual-core machine, it might make sense to set
    #   'nbproc 2' in the global section, then distributes the listeners among 'odd'
    #   and 'even' instances.
    #
    #   At the moment, it is not possible to reference more than 32 processes using
    #   this keyword, but this should be more than enough for most setups. Please
    #   note that 'all' really means all processes and is not limited to the first
    #   32.
    #
    #   If some backends are referenced by frontends bound to other processes, the
    #   backend automatically inherits the frontend's processes.
    #
    #   Example :
    #         listen app_ip1
    #             bind 10.0.0.1:80
    #             bind-process odd
    #
    #         listen app_ip2
    #             bind 10.0.0.2:80
    #             bind-process even
    #
    #         listen management
    #             bind 10.0.0.3:80
    #             bind-process 1 2 3 4
    #
    #   See also : "nbproc" in global section.
    #
    attr_accessor :bind_process

    #
    # default_backend <backend>
    #   Specify the backend to use when no "use_backend" rule has been matched.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments :
    #     <backend> is the name of the backend to use.
    #
    #   When doing content-switching between frontend and backends using the
    #   "use_backend" keyword, it is often useful to indicate which backend will be
    #   used when no rule has matched. It generally is the dynamic backend which
    #   will catch all undetermined requests.
    #
    #   Example :
    #
    #         use_backend     dynamic  if  url_dyn
    #         use_backend     static   if  url_css url_img extension_img
    #         default_backend dynamic
    #
    #   See also : "use_backend", "reqsetbe", "reqisetbe"
    #
    attr_accessor :default_backend

    #
    # disabled
    #   Disable a proxy, frontend or backend.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   The "disabled" keyword is used to disable an instance, mainly in order to
    #   liberate a listening port or to temporarily disable a service. The instance
    #   will still be created and its configuration will be checked, but it will be
    #   created in the "stopped" state and will appear as such in the statistics. It
    #   will not receive any traffic nor will it send any health-checks or logs. It
    #   is possible to disable many instances at once by adding the "disabled"
    #   keyword in a "defaults" section.
    #
    #   See also : "enabled"
    #
    attr_accessor :disabled

    #
    # enabled
    #   Enable a proxy, frontend or backend.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   The "enabled" keyword is used to explicitly enable an instance, when the
    #   defaults has been set to "disabled". This is very rarely used.
    #
    #   See also : "disabled"
    #
    attr_accessor :enabled

    #
    # errorfile <code> <file>
    #   Return a file contents instead of errors generated by HAProxy
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     <code>    is the HTTP status code. Currently, HAProxy is capable of
    #               generating codes 400, 403, 408, 500, 502, 503, and 504.
    #
    #     <file>    designates a file containing the full HTTP response. It is
    #               recommended to follow the common practice of appending ".http" to
    #               the filename so that people do not confuse the response with HTML
    #               error pages, and to use absolute paths, since files are read
    #               before any chroot is performed.
    #
    #   It is important to understand that this keyword is not meant to rewrite
    #   errors returned by the server, but errors detected and returned by HAProxy.
    #   This is why the list of supported errors is limited to a small set.
    #
    #   The files are returned verbatim on the TCP socket. This allows any trick such
    #   as redirections to another URL or site, as well as tricks to clean cookies,
    #   force enable or disable caching, etc... The package provides default error
    #   files returning the same contents as default errors.
    #
    #   The files should not exceed the configured buffer size (BUFSIZE), which
    #   generally is 8 or 16 kB, otherwise they will be truncated. It is also wise
    #   not to put any reference to local contents (eg: images) in order to avoid
    #   loops between the client and HAProxy when all servers are down, causing an
    #   error to be returned instead of an image. For better HTTP compliance, it is
    #   recommended that all header lines end with CR-LF and not LF alone.
    #
    #   The files are read at the same time as the configuration and kept in memory.
    #   For this reason, the errors continue to be returned even when the process is
    #   chrooted, and no file change is considered while the process is running. A
    #   simple method for developing those files consists in associating them to the
    #   403 status code and interrogating a blocked URL.
    #
    #   See also : "errorloc", "errorloc302", "errorloc303"
    #
    #   Example :
    #         errorfile 400 /etc/haproxy/errorfiles/400badreq.http
    #         errorfile 403 /etc/haproxy/errorfiles/403forbid.http
    #         errorfile 503 /etc/haproxy/errorfiles/503sorry.http
    #
    attr_accessor :errorfile

    #
    # errorloc <code> <url>
    #   Return an HTTP redirection to a URL instead of errors generated by HAProxy
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     <code>    is the HTTP status code. Currently, HAProxy is capable of
    #               generating codes 400, 403, 408, 500, 502, 503, and 504.
    #
    #     <url>     it is the exact contents of the "Location" header. It may contain
    #               either a relative URI to an error page hosted on the same site,
    #               or an absolute URI designating an error page on another site.
    #               Special care should be given to relative URIs to avoid redirect
    #               loops if the URI itself may generate the same error (eg: 500).
    #
    #   It is important to understand that this keyword is not meant to rewrite
    #   errors returned by the server, but errors detected and returned by HAProxy.
    #   This is why the list of supported errors is limited to a small set.
    #
    #   Note that both keyword return the HTTP 302 status code, which tells the
    #   client to fetch the designated URL using the same HTTP method. This can be
    #   quite problematic in case of non-GET methods such as POST, because the URL
    #   sent to the client might not be allowed for something other than GET. To
    #   workaround this problem, please use "errorloc303" which send the HTTP 303
    #   status code, indicating to the client that the URL must be fetched with a GET
    #   request.
    #
    #   See also : "errorfile", "errorloc303"
    #
    attr_accessor :errorloc

    #
    # errorloc302 <code> <url>
    #   Return an HTTP redirection to a URL instead of errors generated by HAProxy
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     <code>    is the HTTP status code. Currently, HAProxy is capable of
    #               generating codes 400, 403, 408, 500, 502, 503, and 504.
    #
    #     <url>     it is the exact contents of the "Location" header. It may contain
    #               either a relative URI to an error page hosted on the same site,
    #               or an absolute URI designating an error page on another site.
    #               Special care should be given to relative URIs to avoid redirect
    #               loops if the URI itself may generate the same error (eg: 500).
    #
    #   It is important to understand that this keyword is not meant to rewrite
    #   errors returned by the server, but errors detected and returned by HAProxy.
    #   This is why the list of supported errors is limited to a small set.
    #
    #   Note that both keyword return the HTTP 302 status code, which tells the
    #   client to fetch the designated URL using the same HTTP method. This can be
    #   quite problematic in case of non-GET methods such as POST, because the URL
    #   sent to the client might not be allowed for something other than GET. To
    #   workaround this problem, please use "errorloc303" which send the HTTP 303
    #   status code, indicating to the client that the URL must be fetched with a GET
    #   request.
    #
    #   See also : "errorfile", "errorloc303"
    #
    attr_accessor :errorloc302

    #
    # errorloc303 <code> <url>
    #   Return an HTTP redirection to a URL instead of errors generated by HAProxy
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     <code>    is the HTTP status code. Currently, HAProxy is capable of
    #               generating codes 400, 403, 408, 500, 502, 503, and 504.
    #
    #     <url>     it is the exact contents of the "Location" header. It may contain
    #               either a relative URI to an error page hosted on the same site,
    #               or an absolute URI designating an error page on another site.
    #               Special care should be given to relative URIs to avoid redirect
    #               loops if the URI itself may generate the same error (eg: 500).
    #
    #   It is important to understand that this keyword is not meant to rewrite
    #   errors returned by the server, but errors detected and returned by HAProxy.
    #   This is why the list of supported errors is limited to a small set.
    #
    #   Note that both keyword return the HTTP 303 status code, which tells the
    #   client to fetch the designated URL using the same HTTP GET method. This
    #   solves the usual problems associated with "errorloc" and the 302 code. It is
    #   possible that some very old browsers designed before HTTP/1.1 do not support
    #   it, but no such problem has been reported till now.
    #
    #   See also : "errorfile", "errorloc", "errorloc302"
    #
    attr_accessor :errorloc303

    #
    # grace <time>
    #   Maintain a proxy operational for some time after a soft stop
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     <time>    is the time (by default in milliseconds) for which the instance
    #               will remain operational with the frontend sockets still listening
    #               when a soft-stop is received via the SIGUSR1 signal.
    #
    #   This may be used to ensure that the services disappear in a certain order.
    #   This was designed so that frontends which are dedicated to monitoring by an
    #   external equipment fail immediately while other ones remain up for the time
    #   needed by the equipment to detect the failure.
    #
    #   Note that currently, there is very little benefit in using this parameter,
    #   and it may in fact complicate the soft-reconfiguration process more than
    #   simplify it.
    #
    attr_accessor :grace

    # log global
    # log <address> <facility> [<level> [<minlevel>]]
    #   Enable per-instance logging of events and traffic.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     global     should be used when the instance's logging parameters are the
    #                same as the global ones. This is the most common usage. "global"
    #                replaces <address>, <facility> and <level> with those of the log
    #                entries found in the "global" section. Only one "log global"
    #                statement may be used per instance, and this form takes no other
    #                parameter.
    #
    #     <address>  indicates where to send the logs. It takes the same format as
    #                for the "global" section's logs, and can be one of :
    #
    #                - An IPv4 address optionally followed by a colon (':') and a UDP
    #                  port. If no port is specified, 514 is used by default (the
    #                  standard syslog port).
    #
    #                - A filesystem path to a UNIX domain socket, keeping in mind
    #                  considerations for chroot (be sure the path is accessible
    #                  inside the chroot) and uid/gid (be sure the path is
    #                  appropriately writeable).
    #
    #     <facility> must be one of the 24 standard syslog facilities :
    #
    #                  kern   user   mail   daemon auth   syslog lpr    news
    #                  uucp   cron   auth2  ftp    ntp    audit  alert  cron2
    #                  local0 local1 local2 local3 local4 local5 local6 local7
    #
    #     <level>    is optional and can be specified to filter outgoing messages. By
    #                default, all messages are sent. If a level is specified, only
    #                messages with a severity at least as important as this level
    #                will be sent. An optional minimum level can be specified. If it
    #                is set, logs emitted with a more severe level than this one will
    #                be capped to this level. This is used to avoid sending "emerg"
    #                messages on all terminals on some default syslog configurations.
    #                Eight levels are known :
    #
    #                  emerg  alert  crit   err    warning notice info  debug
    #
    #   Note that up to two "log" entries may be specified per instance. However, if
    #   "log global" is used and if the "global" section already contains 2 log
    #   entries, then additional log entries will be ignored.
    #
    #   Also, it is important to keep in mind that it is the frontend which decides
    #   what to log from a connection, and that in case of content switching, the log
    #   entries from the backend will be ignored. Connections are logged at level
    #   "info".
    #
    #   However, backend log declaration define how and where servers status changes
    #   will be logged. Level "notice" will be used to indicate a server going up,
    #   "warning" will be used for termination signals and definitive service
    #   termination, and "alert" will be used for when a server goes down.
    #
    #   Note : According to RFC3164, messages are truncated to 1024 bytes before
    #          being emitted.
    #
    #   Example :
    #     log global
    #     log 127.0.0.1:514 local0 notice         # only send important events
    #     log 127.0.0.1:514 local0 notice notice  # same but limit output level
    #
    attr_accessor :log

    #
    # maxconn <conns>
    #   Fix the maximum number of concurrent connections on a frontend
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments :
    #     <conns>   is the maximum number of concurrent connections the frontend will
    #               accept to serve. Excess connections will be queued by the system
    #               in the socket's listen queue and will be served once a connection
    #               closes.
    #
    #   If the system supports it, it can be useful on big sites to raise this limit
    #   very high so that haproxy manages connection queues, instead of leaving the
    #   clients with unanswered connection attempts. This value should not exceed the
    #   global maxconn. Also, keep in mind that a connection contains two buffers
    #   of 8kB each, as well as some other data resulting in about 17 kB of RAM being
    #   consumed per established connection. That means that a medium system equipped
    #   with 1GB of RAM can withstand around 40000-50000 concurrent connections if
    #   properly tuned.
    #
    #   Also, when <conns> is set to large values, it is possible that the servers
    #   are not sized to accept such loads, and for this reason it is generally wise
    #   to assign them some reasonable connection limits.
    #
    #   See also : "server", global section's "maxconn", "fullconn"
    #
    attr_accessor :maxconn

    #
    # mode { tcp|http|health }
    #   Set the running mode or protocol of the instance
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     tcp       The instance will work in pure TCP mode. A full-duplex connection
    #               will be established between clients and servers, and no layer 7
    #               examination will be performed. This is the default mode. It
    #               should be used for SSL, SSH, SMTP, ...
    #
    #     http      The instance will work in HTTP mode. The client request will be
    #               analyzed in depth before connecting to any server. Any request
    #               which is not RFC-compliant will be rejected. Layer 7 filtering,
    #               processing and switching will be possible. This is the mode which
    #               brings HAProxy most of its value.
    #
    #     health    The instance will work in "health" mode. It will just reply "OK"
    #               to incoming connections and close the connection. Nothing will be
    #               logged. This mode is used to reply to external components health
    #               checks. This mode is deprecated and should not be used anymore as
    #               it is possible to do the same and even better by combining TCP or
    #               HTTP modes with the "monitor" keyword.
    #
    #    When doing content switching, it is mandatory that the frontend and the
    #    backend are in the same mode (generally HTTP), otherwise the configuration
    #    will be refused.
    #
    #    Example :
    #      defaults http_instances
    #          mode http
    #
    #    See also : "monitor", "monitor-net"
    #
    attr_accessor :mode

    #
    # monitor-net <source>
    #   Declare a source network which is limited to monitor requests
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments :
    #     <source>  is the source IPv4 address or network which will only be able to
    #               get monitor responses to any request. It can be either an IPv4
    #               address, a host name, or an address followed by a slash ('/')
    #               followed by a mask.
    #
    #   In TCP mode, any connection coming from a source matching <source> will cause
    #   the connection to be immediately closed without any log. This allows another
    #   equipment to probe the port and verify that it is still listening, without
    #   forwarding the connection to a remote server.
    #
    #   In HTTP mode, a connection coming from a source matching <source> will be
    #   accepted, the following response will be sent without waiting for a request,
    #   then the connection will be closed : "HTTP/1.0 200 OK". This is normally
    #   enough for any front-end HTTP probe to detect that the service is UP and
    #   running without forwarding the request to a backend server.
    #
    #   Monitor requests are processed very early. It is not possible to block nor
    #   divert them using ACLs. They cannot be logged either, and it is the intended
    #   purpose. They are only used to report HAProxy's health to an upper component,
    #   nothing more. Right now, it is not possible to set failure conditions on
    #   requests caught by "monitor-net".
    #
    #   Last, please note that only one "monitor-net" statement can be specified in
    #   a frontend. If more than one is found, only the last one will be considered.
    #
    #   Example :
    #     # addresses .252 and .253 are just probing us.
    #     frontend www
    #         monitor-net 192.168.0.252/31
    #
    #   See also : "monitor fail", "monitor-uri"
    #
    attr_accessor :monitor_net

    #
    # monitor-uri <uri>
    #   Intercept a URI used by external components' monitor requests
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments :
    #     <uri>     is the exact URI which we want to intercept to return HAProxy's
    #               health status instead of forwarding the request.
    #
    #   When an HTTP request referencing <uri> will be received on a frontend,
    #   HAProxy will not forward it nor log it, but instead will return either
    #   "HTTP/1.0 200 OK" or "HTTP/1.0 503 Service unavailable", depending on failure
    #   conditions defined with "monitor fail". This is normally enough for any
    #   front-end HTTP probe to detect that the service is UP and running without
    #   forwarding the request to a backend server. Note that the HTTP method, the
    #   version and all headers are ignored, but the request must at least be valid
    #   at the HTTP level. This keyword may only be used with an HTTP-mode frontend.
    #
    #   Monitor requests are processed very early. It is not possible to block nor
    #   divert them using ACLs. They cannot be logged either, and it is the intended
    #   purpose. They are only used to report HAProxy's health to an upper component,
    #   nothing more. However, it is possible to add any number of conditions using
    #   "monitor fail" and ACLs so that the result can be adjusted to whatever check
    #   can be imagined (most often the number of available servers in a backend).
    #
    #   Example :
    #     # Use /haproxy_test to report haproxy's status
    #     frontend www
    #         mode http
    #         monitor-uri /haproxy_test
    #
    #   See also : "monitor fail", "monitor-net"
    #
    attr_accessor :monitor_uri

    #
    # option accept-invalid-http-request
    # no option accept-invalid-http-request
    #   Enable or disable relaxing of HTTP request parsing
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments : none
    #
    #   By default, HAProxy complies with RFC2616 in terms of message parsing. This
    #   means that invalid characters in header names are not permitted and cause an
    #   error to be returned to the client. This is the desired behaviour as such
    #   forbidden characters are essentially used to build attacks exploiting server
    #   weaknesses, and bypass security filtering. Sometimes, a buggy browser or
    #   server will emit invalid header names for whatever reason (configuration,
    #   implementation) and the issue will not be immediately fixed. In such a case,
    #   it is possible to relax HAProxy's header name parser to accept any character
    #   even if that does not make sense, by specifying this option.
    #
    #   This option should never be enabled by default as it hides application bugs
    #   and open security breaches. It should only be deployed after a problem has
    #   been confirmed.
    #
    #   When this option is enabled, erroneous header names will still be accepted in
    #   requests, but the complete request will be captured in order to permit later
    #   analysis using the "show errors" request on the UNIX stats socket. Doing this
    #   also helps confirming that the issue has been solved.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option accept-invalid-http-response" and "show errors" on the
    #              stats socket.
    #
    attr_accessor :option_accept_invalid_http_request

    #
    # option clitcpka
    # no option clitcpka
    #   Enable or disable the sending of TCP keepalive packets on the client side
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments : none
    #
    #   When there is a firewall or any session-aware component between a client and
    #   a server, and when the protocol involves very long sessions with long idle
    #   periods (eg: remote desktops), there is a risk that one of the intermediate
    #   components decides to expire a session which has remained idle for too long.
    #
    #   Enabling socket-level TCP keep-alives makes the system regularly send packets
    #   to the other end of the connection, leaving it active. The delay between
    #   keep-alive probes is controlled by the system only and depends both on the
    #   operating system and its tuning parameters.
    #
    #   It is important to understand that keep-alive packets are neither emitted nor
    #   received at the application level. It is only the network stacks which sees
    #   them. For this reason, even if one side of the proxy already uses keep-alives
    #   to maintain its connection alive, those keep-alive packets will not be
    #   forwarded to the other side of the proxy.
    #
    #   Please note that this has nothing to do with HTTP keep-alive.
    #
    #   Using option "clitcpka" enables the emission of TCP keep-alive probes on the
    #   client side of a connection, which should help when session expirations are
    #   noticed between HAProxy and a client.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option srvtcpka", "option tcpka"
    #
    attr_accessor :option_clitcpka

    #
    # option contstats
    #   Enable continuous traffic statistics updates
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments : none
    #
    #   By default, counters used for statistics calculation are incremented
    #   only when a session finishes. It works quite well when serving small
    #   objects, but with big ones (for example large images or archives) or
    #   with A/V streaming, a graph generated from haproxy counters looks like
    #   a hedgehog. With this option enabled counters get incremented continuously,
    #   during a whole session. Recounting touches a hotpath directly so
    #   it is not enabled by default, as it has small performance impact (~0.5%).
    #
    attr_accessor :option_contstats

    #
    # option dontlog-normal
    # no option dontlog-normal
    #   Enable or disable logging of normal, successful connections
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments : none
    #
    #   There are large sites dealing with several thousand connections per second
    #   and for which logging is a major pain. Some of them are even forced to turn
    #   logs off and cannot debug production issues. Setting this option ensures that
    #   normal connections, those which experience no error, no timeout, no retry nor
    #   redispatch, will not be logged. This leaves disk space for anomalies. In HTTP
    #   mode, the response status code is checked and return codes 5xx will still be
    #   logged.
    #
    #   It is strongly discouraged to use this option as most of the time, the key to
    #   complex issues is in the normal logs which will not be logged here. If you
    #   need to separate logs, see the "log-separate-errors" option instead.
    #
    #   See also : "log", "dontlognull", "log-separate-errors" and section 8 about
    #              logging.
    #
    attr_accessor :option_dontlog_normal

    #
    # option dontlognull
    # no option dontlognull
    #   Enable or disable logging of null connections
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments : none
    #
    #   In certain environments, there are components which will regularly connect to
    #   various systems to ensure that they are still alive. It can be the case from
    #   another load balancer as well as from monitoring systems. By default, even a
    #   simple port probe or scan will produce a log. If those connections pollute
    #   the logs too much, it is possible to enable option "dontlognull" to indicate
    #   that a connection on which no data has been transferred will not be logged,
    #   which typically corresponds to those probes.
    #
    #   It is generally recommended not to use this option in uncontrolled
    #   environments (eg: internet), otherwise scans and other malicious activities
    #   would not be logged.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "log", "monitor-net", "monitor-uri" and section 8 about logging.
    #
    attr_accessor :option_dontlognull

    #
    # option forceclose
    # no option forceclose
    #   Enable or disable active connection closing after response is transferred.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   Some HTTP servers do not necessarily close the connections when they receive
    #   the "Connection: close" set by "option httpclose", and if the client does not
    #   close either, then the connection remains open till the timeout expires. This
    #   causes high number of simultaneous connections on the servers and shows high
    #   global session times in the logs.
    #
    #   When this happens, it is possible to use "option forceclose". It will
    #   actively close the outgoing server channel as soon as the server has finished
    #   to respond. This option implicitly enables the "httpclose" option. Note that
    #   this option also enables the parsing of the full request and response, which
    #   means we can close the connection to the server very quickly, releasing some
    #   resources earlier than with httpclose.
    #
    #   This option may also be combined with "option http-pretend-keepalive", which
    #   will disable sending of the "Connection: close" header, but will still cause
    #   the connection to be closed once the whole response is received.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option httpclose" and "option http-pretend-keepalive"
    #
    attr_accessor :option_forceclose

    #
    # option forwardfor [ except <network> ] [ header <name> ]
    #   Enable insertion of the X-Forwarded-For header to requests sent to servers
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     <network> is an optional argument used to disable this option for sources
    #               matching <network>
    #     <name>    an optional argument to specify a different "X-Forwarded-For"
    #               header name.
    #
    #   Since HAProxy works in reverse-proxy mode, the servers see its IP address as
    #   their client address. This is sometimes annoying when the client's IP address
    #   is expected in server logs. To solve this problem, the well-known HTTP header
    #   "X-Forwarded-For" may be added by HAProxy to all requests sent to the server.
    #   This header contains a value representing the client's IP address. Since this
    #   header is always appended at the end of the existing header list, the server
    #   must be configured to always use the last occurrence of this header only. See
    #   the server's manual to find how to enable use of this standard header. Note
    #   that only the last occurrence of the header must be used, since it is really
    #   possible that the client has already brought one.
    #
    #   The keyword "header" may be used to supply a different header name to replace
    #   the default "X-Forwarded-For". This can be useful where you might already
    #   have a "X-Forwarded-For" header from a different application (eg: stunnel),
    #   and you need preserve it. Also if your backend server doesn't use the
    #   "X-Forwarded-For" header and requires different one (eg: Zeus Web Servers
    #   require "X-Cluster-Client-IP").
    #
    #   Sometimes, a same HAProxy instance may be shared between a direct client
    #   access and a reverse-proxy access (for instance when an SSL reverse-proxy is
    #   used to decrypt HTTPS traffic). It is possible to disable the addition of the
    #   header for a known source address or network by adding the "except" keyword
    #   followed by the network address. In this case, any source IP matching the
    #   network will not cause an addition of this header. Most common uses are with
    #   private networks or 127.0.0.1.
    #
    #   This option may be specified either in the frontend or in the backend. If at
    #   least one of them uses it, the header will be added. Note that the backend's
    #   setting of the header subargument takes precedence over the frontend's if
    #   both are defined.
    #
    #   It is important to note that as long as HAProxy does not support keep-alive
    #   connections, only the first request of a connection will receive the header.
    #   For this reason, it is important to ensure that "option httpclose" is set
    #   when using this option.
    #
    #   Examples :
    #     # Public HTTP address also used by stunnel on the same machine
    #     frontend www
    #         mode http
    #         option forwardfor except 127.0.0.1  # stunnel already adds the header
    #
    #     # Those servers want the IP Address in X-Client
    #     backend www
    #         mode http
    #         option forwardfor header X-Client
    #
    #   See also : "option httpclose"
    #
    attr_accessor :option_forwardfor

    #
    # option http-pretend-keepalive
    # no option http-pretend-keepalive
    #   Define whether haproxy will announce keepalive to the server or not
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   When running with "option http-server-close" or "option forceclose", haproxy
    #   adds a "Connection: close" header to the request forwarded to the server.
    #   Unfortunately, when some servers see this header, they automatically refrain
    #   from using the chunked encoding for responses of unknown length, while this
    #   is totally unrelated. The immediate effect is that this prevents haproxy from
    #   maintaining the client connection alive. A second effect is that a client or
    #   a cache could receive an incomplete response without being aware of it, and
    #   consider the response complete.
    #
    #   By setting "option http-pretend-keepalive", haproxy will make the server
    #   believe it will keep the connection alive. The server will then not fall back
    #   to the abnormal undesired above. When haproxy gets the whole response, it
    #   will close the connection with the server just as it would do with the
    #   "forceclose" option. That way the client gets a normal response and the
    #   connection is correctly closed on the server side.
    #
    #   It is recommended not to enable this option by default, because most servers
    #   will more efficiently close the connection themselves after the last packet,
    #   and release its buffers slightly earlier. Also, the added packet on the
    #   network could slightly reduce the overall peak performance. However it is
    #   worth noting that when this option is enabled, haproxy will have slightly
    #   less work to do. So if haproxy is the bottleneck on the whole architecture,
    #   enabling this option might save a few CPU cycles.
    #
    #   This option may be set both in a frontend and in a backend. It is enabled if
    #   at least one of the frontend or backend holding a connection has it enabled.
    #   This option may be compbined with "option httpclose", which will cause
    #   keepalive to be announced to the server and close to be announced to the
    #   client. This practice is discouraged though.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option forceclose" and "option http-server-close"
    #
    attr_accessor :option_http_pretend_keepalive

    #
    # option http-server-close
    # no option http-server-close
    #   Enable or disable HTTP connection closing on the server side
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   By default, when a client communicates with a server, HAProxy will only
    #   analyze, log, and process the first request of each connection. Setting
    #   "option http-server-close" enables HTTP connection-close mode on the server
    #   side while keeping the ability to support HTTP keep-alive and pipelining on
    #   the client side.  This provides the lowest latency on the client side (slow
    #   network) and the fastest session reuse on the server side to save server
    #   resources, similarly to "option forceclose". It also permits non-keepalive
    #   capable servers to be served in keep-alive mode to the clients if they
    #   conform to the requirements of RFC2616. Please note that some servers do not
    #   always conform to those requirements when they see "Connection: close" in the
    #   request. The effect will be that keep-alive will never be used. A workaround
    #   consists in enabling "option http-pretend-keepalive".
    #
    #   At the moment, logs will not indicate whether requests came from the same
    #   session or not. The accept date reported in the logs corresponds to the end
    #   of the previous request, and the request time corresponds to the time spent
    #   waiting for a new request. The keep-alive request time is still bound to the
    #   timeout defined by "timeout http-keep-alive" or "timeout http-request" if
    #   not set.
    #
    #   This option may be set both in a frontend and in a backend. It is enabled if
    #   at least one of the frontend or backend holding a connection has it enabled.
    #   It is worth noting that "option forceclose" has precedence over "option
    #   http-server-close" and that combining "http-server-close" with "httpclose"
    #   basically achieve the same result as "forceclose".
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option forceclose", "option http-pretend-keepalive",
    #              "option httpclose" and "1.1. The HTTP transaction model".
    #
    attr_accessor :option_http_server_close

    #
    # option http-use-proxy-header
    # no option http-use-proxy-header
    #   Make use of non-standard Proxy-Connection header instead of Connection
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments : none
    #
    #   While RFC2616 explicitly states that HTTP/1.1 agents must use the
    #   Connection header to indicate their wish of persistent or non-persistent
    #   connections, both browsers and proxies ignore this header for proxied
    #   connections and make use of the undocumented, non-standard Proxy-Connection
    #   header instead. The issue begins when trying to put a load balancer between
    #   browsers and such proxies, because there will be a difference between what
    #   haproxy understands and what the client and the proxy agree on.
    #
    #   By setting this option in a frontend, haproxy can automatically switch to use
    #   that non-standard header if it sees proxied requests. A proxied request is
    #   defined here as one where the URI begins with neither a '/' nor a '*'. The
    #   choice of header only affects requests passing through proxies making use of
    #   one of the "httpclose", "forceclose" and "http-server-close" options. Note
    #   that this option can only be specified in a frontend and will affect the
    #   request along its whole life.
    #
    #   Also, when this option is set, a request which requires authentication will
    #   automatically switch to use proxy authentication headers if it is itself a
    #   proxied request. That makes it possible to check or enforce authentication in
    #   front of an existing proxy.
    #
    #   This option should normally never be used, except in front of a proxy.
    #
    #   See also : "option httpclose", "option forceclose" and "option
    #              http-server-close".
    #
    attr_accessor :option_http_use_proxy_header

    #
    # option httpclose
    # no option httpclose
    #   Enable or disable passive HTTP connection closing
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   By default, when a client communicates with a server, HAProxy will only
    #   analyze, log, and process the first request of each connection. If "option
    #   httpclose" is set, it will check if a "Connection: close" header is already
    #   set in each direction, and will add one if missing. Each end should react to
    #   this by actively closing the TCP connection after each transfer, thus
    #   resulting in a switch to the HTTP close mode. Any "Connection" header
    #   different from "close" will also be removed.
    #
    #   It seldom happens that some servers incorrectly ignore this header and do not
    #   close the connection eventhough they reply "Connection: close". For this
    #   reason, they are not compatible with older HTTP 1.0 browsers. If this happens
    #   it is possible to use the "option forceclose" which actively closes the
    #   request connection once the server responds. Option "forceclose" also
    #   releases the server connection earlier because it does not have to wait for
    #   the client to acknowledge it.
    #
    #   This option may be set both in a frontend and in a backend. It is enabled if
    #   at least one of the frontend or backend holding a connection has it enabled.
    #   If "option forceclose" is specified too, it has precedence over "httpclose".
    #   If "option http-server-close" is enabled at the same time as "httpclose", it
    #   basically achieves the same result as "option forceclose".
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option forceclose", "option http-server-close" and
    #              "1.1. The HTTP transaction model".
    #
    attr_accessor :option_httpclose

    #
    # option httplog [ clf ]
    #   Enable logging of HTTP request, session state and timers
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     clf       if the "clf" argument is added, then the output format will be
    #               the CLF format instead of HAProxy's default HTTP format. You can
    #               use this when you need to feed HAProxy's logs through a specific
    #               log analyser which only support the CLF format and which is not
    #               extensible.
    #
    #   By default, the log output format is very poor, as it only contains the
    #   source and destination addresses, and the instance name. By specifying
    #   "option httplog", each log line turns into a much richer format including,
    #   but not limited to, the HTTP request, the connection timers, the session
    #   status, the connections numbers, the captured headers and cookies, the
    #   frontend, backend and server name, and of course the source address and
    #   ports.
    #
    #   This option may be set either in the frontend or the backend.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it. Specifying
    #   only "option httplog" will automatically clear the 'clf' mode if it was set
    #   by default.
    #
    #   See also :  section 8 about logging.
    #
    attr_accessor :option_httplog

    #
    # option http_proxy
    # no option http_proxy
    #   Enable or disable plain HTTP proxy mode
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   It sometimes happens that people need a pure HTTP proxy which understands
    #   basic proxy requests without caching nor any fancy feature. In this case,
    #   it may be worth setting up an HAProxy instance with the "option http_proxy"
    #   set. In this mode, no server is declared, and the connection is forwarded to
    #   the IP address and port found in the URL after the "http://" scheme.
    #
    #   No host address resolution is performed, so this only works when pure IP
    #   addresses are passed. Since this option's usage perimeter is rather limited,
    #   it will probably be used only by experts who know they need exactly it. Last,
    #   if the clients are susceptible of sending keep-alive requests, it will be
    #   needed to add "option http_close" to ensure that all requests will correctly
    #   be analyzed.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   Example :
    #     # this backend understands HTTP proxy requests and forwards them directly.
    #     backend direct_forward
    #         option httpclose
    #         option http_proxy
    #
    #   See also : "option httpclose"
    #
    attr_accessor :option_http_proxy

    #
    # option independant-streams
    # no option independant-streams
    #   Enable or disable independant timeout processing for both directions
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |  yes
    #   Arguments : none
    #
    #   By default, when data is sent over a socket, both the write timeout and the
    #   read timeout for that socket are refreshed, because we consider that there is
    #   activity on that socket, and we have no other means of guessing if we should
    #   receive data or not.
    #
    #   While this default behaviour is desirable for almost all applications, there
    #   exists a situation where it is desirable to disable it, and only refresh the
    #   read timeout if there are incoming data. This happens on sessions with large
    #   timeouts and low amounts of exchanged data such as telnet session. If the
    #   server suddenly disappears, the output data accumulates in the system's
    #   socket buffers, both timeouts are correctly refreshed, and there is no way
    #   to know the server does not receive them, so we don't timeout. However, when
    #   the underlying protocol always echoes sent data, it would be enough by itself
    #   to detect the issue using the read timeout. Note that this problem does not
    #   happen with more verbose protocols because data won't accumulate long in the
    #   socket buffers.
    #
    #   When this option is set on the frontend, it will disable read timeout updates
    #   on data sent to the client. There probably is little use of this case. When
    #   the option is set on the backend, it will disable read timeout updates on
    #   data sent to the server. Doing so will typically break large HTTP posts from
    #   slow lines, so use it with caution.
    #
    #   See also : "timeout client" and "timeout server"
    #
    attr_accessor :option_independant_streams

    #
    # option log-separate-errors
    # no option log-separate-errors
    #   Change log level for non-completely successful connections
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments : none
    #
    #   Sometimes looking for errors in logs is not easy. This option makes haproxy
    #   raise the level of logs containing potentially interesting information such
    #   as errors, timeouts, retries, redispatches, or HTTP status codes 5xx. The
    #   level changes from "info" to "err". This makes it possible to log them
    #   separately to a different file with most syslog daemons. Be careful not to
    #   remove them from the original file, otherwise you would lose ordering which
    #   provides very important information.
    #
    #   Using this option, large sites dealing with several thousand connections per
    #   second may log normal traffic to a rotating buffer and only archive smaller
    #   error logs.
    #
    #   See also : "log", "dontlognull", "dontlog-normal" and section 8 about
    #              logging.
    #
    attr_accessor :option_log_separate_errors

    #
    # option logasap
    # no option logasap
    #   Enable or disable early logging of HTTP requests
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments : none
    #
    #   By default, HTTP requests are logged upon termination so that the total
    #   transfer time and the number of bytes appear in the logs. When large objects
    #   are being transferred, it may take a while before the request appears in the
    #   logs. Using "option logasap", the request gets logged as soon as the server
    #   sends the complete headers. The only missing information in the logs will be
    #   the total number of bytes which will indicate everything except the amount
    #   of data transferred, and the total time which will not take the transfer
    #   time into account. In such a situation, it's a good practice to capture the
    #   "Content-Length" response header so that the logs at least indicate how many
    #   bytes are expected to be transferred.
    #
    #   Examples :
    #       listen http_proxy 0.0.0.0:80
    #           mode http
    #           option httplog
    #           option logasap
    #           log 192.168.2.200 local3
    #
    #     >>> Feb  6 12:14:14 localhost \
    #           haproxy[14389]: 10.0.1.2:33317 [06/Feb/2009:12:14:14.655] http-in \
    #           static/srv1 9/10/7/14/+30 200 +243 - - ---- 3/1/1/1/0 1/0 \
    #           "GET /image.iso HTTP/1.0"
    #
    #   See also : "option httplog", "capture response header", and section 8 about
    #              logging.
    #
    attr_accessor :option_logasap

    #
    # option nolinger
    # no option nolinger
    #   Enable or disable immediate session resource cleaning after close
    #   May be used in sections:    defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   When clients or servers abort connections in a dirty way (eg: they are
    #   physically disconnected), the session timeouts triggers and the session is
    #   closed. But it will remain in FIN_WAIT1 state for some time in the system,
    #   using some resources and possibly limiting the ability to establish newer
    #   connections.
    #
    #   When this happens, it is possible to activate "option nolinger" which forces
    #   the system to immediately remove any socket's pending data on close. Thus,
    #   the session is instantly purged from the system's tables. This usually has
    #   side effects such as increased number of TCP resets due to old retransmits
    #   getting immediately rejected. Some firewalls may sometimes complain about
    #   this too.
    #
    #   For this reason, it is not recommended to use this option when not absolutely
    #   needed. You know that you need it when you have thousands of FIN_WAIT1
    #   sessions on your system (TIME_WAIT ones do not count).
    #
    #   This option may be used both on frontends and backends, depending on the side
    #   where it is required. Use it on the frontend for clients, and on the backend
    #   for servers.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    attr_accessor :option_nolinger

    #
    # option originalto [ except <network> ] [ header <name> ]
    #   Enable insertion of the X-Original-To header to requests sent to servers
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     <network> is an optional argument used to disable this option for sources
    #               matching <network>
    #     <name>    an optional argument to specify a different "X-Original-To"
    #               header name.
    #
    #   Since HAProxy can work in transparent mode, every request from a client can
    #   be redirected to the proxy and HAProxy itself can proxy every request to a
    #   complex SQUID environment and the destination host from SO_ORIGINAL_DST will
    #   be lost. This is annoying when you want access rules based on destination ip
    #   addresses. To solve this problem, a new HTTP header "X-Original-To" may be
    #   added by HAProxy to all requests sent to the server. This header contains a
    #   value representing the original destination IP address. Since this must be
    #   configured to always use the last occurrence of this header only. Note that
    #   only the last occurrence of the header must be used, since it is really
    #   possible that the client has already brought one.
    #
    #   The keyword "header" may be used to supply a different header name to replace
    #   the default "X-Original-To". This can be useful where you might already
    #   have a "X-Original-To" header from a different application, and you need
    #   preserve it. Also if your backend server doesn't use the "X-Original-To"
    #   header and requires different one.
    #
    #   Sometimes, a same HAProxy instance may be shared between a direct client
    #   access and a reverse-proxy access (for instance when an SSL reverse-proxy is
    #   used to decrypt HTTPS traffic). It is possible to disable the addition of the
    #   header for a known source address or network by adding the "except" keyword
    #   followed by the network address. In this case, any source IP matching the
    #   network will not cause an addition of this header. Most common uses are with
    #   private networks or 127.0.0.1.
    #
    #   This option may be specified either in the frontend or in the backend. If at
    #   least one of them uses it, the header will be added. Note that the backend's
    #   setting of the header subargument takes precedence over the frontend's if
    #   both are defined.
    #
    #   It is important to note that as long as HAProxy does not support keep-alive
    #   connections, only the first request of a connection will receive the header.
    #   For this reason, it is important to ensure that "option httpclose" is set
    #   when using this option.
    #
    #   Examples :
    #     # Original Destination address
    #     frontend www
    #         mode http
    #         option originalto except 127.0.0.1
    #
    #     # Those servers want the IP Address in X-Client-Dst
    #     backend www
    #         mode http
    #         option originalto header X-Client-Dst
    #
    #   See also : "option httpclose"
    #
    attr_accessor :option_originalto

    #
    # option socket-stats
    # no option socket-stats
    #
    #   Enable or disable collecting & providing separate statistics for each socket.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #
    #   Arguments : none
    #
    attr_accessor :option_socket_stats

    #
    # option splice-auto
    # no option splice-auto
    #   Enable or disable automatic kernel acceleration on sockets in both directions
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   When this option is enabled either on a frontend or on a backend, haproxy
    #   will automatically evaluate the opportunity to use kernel tcp splicing to
    #   forward data between the client and the server, in either direction. Haproxy
    #   uses heuristics to estimate if kernel splicing might improve performance or
    #   not. Both directions are handled independently. Note that the heuristics used
    #   are not much aggressive in order to limit excessive use of splicing. This
    #   option requires splicing to be enabled at compile time, and may be globally
    #   disabled with the global option "nosplice". Since splice uses pipes, using it
    #   requires that there are enough spare pipes.
    #
    #   Important note: kernel-based TCP splicing is a Linux-specific feature which
    #   first appeared in kernel 2.6.25. It offers kernel-based acceleration to
    #   transfer data between sockets without copying these data to user-space, thus
    #   providing noticeable performance gains and CPU cycles savings. Since many
    #   early implementations are buggy, corrupt data and/or are inefficient, this
    #   feature is not enabled by default, and it should be used with extreme care.
    #   While it is not possible to detect the correctness of an implementation,
    #   2.6.29 is the first version offering a properly working implementation. In
    #   case of doubt, splicing may be globally disabled using the global "nosplice"
    #   keyword.
    #
    #   Example :
    #         option splice-auto
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option splice-request", "option splice-response", and global
    #              options "nosplice" and "maxpipes"
    #
    attr_accessor :option_splice_auto

    #
    # option splice-request
    # no option splice-request
    #   Enable or disable automatic kernel acceleration on sockets for requests
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   When this option is enabled either on a frontend or on a backend, haproxy
    #   will user kernel tcp splicing whenever possible to forward data going from
    #   the client to the server. It might still use the recv/send scheme if there
    #   are no spare pipes left. This option requires splicing to be enabled at
    #   compile time, and may be globally disabled with the global option "nosplice".
    #   Since splice uses pipes, using it requires that there are enough spare pipes.
    #
    #   Important note: see "option splice-auto" for usage limitations.
    #
    #   Example :
    #         option splice-request
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option splice-auto", "option splice-response", and global options
    #              "nosplice" and "maxpipes"
    #
    attr_accessor :option_splice_request

    #
    # option splice-response
    # no option splice-response
    #   Enable or disable automatic kernel acceleration on sockets for responses
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   When this option is enabled either on a frontend or on a backend, haproxy
    #   will user kernel tcp splicing whenever possible to forward data going from
    #   the server to the client. It might still use the recv/send scheme if there
    #   are no spare pipes left. This option requires splicing to be enabled at
    #   compile time, and may be globally disabled with the global option "nosplice".
    #   Since splice uses pipes, using it requires that there are enough spare pipes.
    #
    #   Important note: see "option splice-auto" for usage limitations.
    #
    #   Example :
    #         option splice-response
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option splice-auto", "option splice-request", and global options
    #              "nosplice" and "maxpipes"
    #
    attr_accessor :option_splice_response

    #
    # option tcp-smart-accept
    # no option tcp-smart-accept
    #   Enable or disable the saving of one ACK packet during the accept sequence
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |    no
    #   Arguments : none
    #
    #   When an HTTP connection request comes in, the system acknowledges it on
    #   behalf of HAProxy, then the client immediately sends its request, and the
    #   system acknowledges it too while it is notifying HAProxy about the new
    #   connection. HAProxy then reads the request and responds. This means that we
    #   have one TCP ACK sent by the system for nothing, because the request could
    #   very well be acknowledged by HAProxy when it sends its response.
    #
    #   For this reason, in HTTP mode, HAProxy automatically asks the system to avoid
    #   sending this useless ACK on platforms which support it (currently at least
    #   Linux). It must not cause any problem, because the system will send it anyway
    #   after 40 ms if the response takes more time than expected to come.
    #
    #   During complex network debugging sessions, it may be desirable to disable
    #   this optimization because delayed ACKs can make troubleshooting more complex
    #   when trying to identify where packets are delayed. It is then possible to
    #   fall back to normal behaviour by specifying "no option tcp-smart-accept".
    #
    #   It is also possible to force it for non-HTTP proxies by simply specifying
    #   "option tcp-smart-accept". For instance, it can make sense with some services
    #   such as SMTP where the server speaks first.
    #
    #   It is recommended to avoid forcing this option in a defaults section. In case
    #   of doubt, consider setting it back to automatic values by prepending the
    #   "default" keyword before it, or disabling it using the "no" keyword.
    #
    #   See also : "option tcp-smart-connect"
    #
    attr_accessor :option_tcp_smart_accept

    #
    # option tcpka
    #   Enable or disable the sending of TCP keepalive packets on both sides
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   When there is a firewall or any session-aware component between a client and
    #   a server, and when the protocol involves very long sessions with long idle
    #   periods (eg: remote desktops), there is a risk that one of the intermediate
    #   components decides to expire a session which has remained idle for too long.
    #
    #   Enabling socket-level TCP keep-alives makes the system regularly send packets
    #   to the other end of the connection, leaving it active. The delay between
    #   keep-alive probes is controlled by the system only and depends both on the
    #   operating system and its tuning parameters.
    #
    #   It is important to understand that keep-alive packets are neither emitted nor
    #   received at the application level. It is only the network stacks which sees
    #   them. For this reason, even if one side of the proxy already uses keep-alives
    #   to maintain its connection alive, those keep-alive packets will not be
    #   forwarded to the other side of the proxy.
    #
    #   Please note that this has nothing to do with HTTP keep-alive.
    #
    #   Using option "tcpka" enables the emission of TCP keep-alive probes on both
    #   the client and server sides of a connection. Note that this is meaningful
    #   only in "defaults" or "listen" sections. If this option is used in a
    #   frontend, only the client side will get keep-alives, and if this option is
    #   used in a backend, only the server side will get keep-alives. For this
    #   reason, it is strongly recommended to explicitly use "option clitcpka" and
    #   "option srvtcpka" when the configuration is split between frontends and
    #   backends.
    #
    #   See also : "option clitcpka", "option srvtcpka"
    #
    attr_accessor :option_tcpka

    #
    # option tcplog
    #   Enable advanced logging of TCP connections with session state and timers
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments : none
    #
    #   By default, the log output format is very poor, as it only contains the
    #   source and destination addresses, and the instance name. By specifying
    #   "option tcplog", each log line turns into a much richer format including, but
    #   not limited to, the connection timers, the session status, the connections
    #   numbers, the frontend, backend and server name, and of course the source
    #   address and ports. This option is useful for pure TCP proxies in order to
    #   find which of the client or server disconnects or times out. For normal HTTP
    #   proxies, it's better to use "option httplog" which is even more complete.
    #
    #   This option may be set either in the frontend or the backend.
    #
    #   See also :  "option httplog", and section 8 about logging.
    #
    attr_accessor :option_tcplog

    #
    # rate-limit sessions <rate>
    #   Set a limit on the number of new sessions accepted per second on a frontend
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments :
    #     <rate>    The <rate> parameter is an integer designating the maximum number
    #               of new sessions per second to accept on the frontend.
    #
    #   When the frontend reaches the specified number of new sessions per second, it
    #   stops accepting new connections until the rate drops below the limit again.
    #   During this time, the pending sessions will be kept in the socket's backlog
    #   (in system buffers) and haproxy will not even be aware that sessions are
    #   pending. When applying very low limit on a highly loaded service, it may make
    #   sense to increase the socket's backlog using the "backlog" keyword.
    #
    #   This feature is particularly efficient at blocking connection-based attacks
    #   or service abuse on fragile servers. Since the session rate is measured every
    #   millisecond, it is extremely accurate. Also, the limit applies immediately,
    #   no delay is needed at all to detect the threshold.
    #
    #   Example : limit the connection rate on SMTP to 10 per second max
    #         listen smtp
    #             mode tcp
    #             bind :25
    #             rate-limit sessions 10
    #             server 127.0.0.1:1025
    #
    #   Note : when the maximum rate is reached, the frontend's status appears as
    #          "FULL" in the statistics, exactly as when it is saturated.
    #
    #   See also : the "backlog" keyword and the "fe_sess_rate" ACL criterion.
    #
    attr_accessor :rate_limit_sessions

    #
    # timeout client <timeout>
    # timeout clitimeout <timeout> (deprecated)
    #   Set the maximum inactivity time on the client side.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   no
    #   Arguments :
    #     <timeout> is the timeout value specified in milliseconds by default, but
    #               can be in any other unit if the number is suffixed by the unit,
    #               as explained at the top of this document.
    #
    #   The inactivity timeout applies when the client is expected to acknowledge or
    #   send data. In HTTP mode, this timeout is particularly important to consider
    #   during the first phase, when the client sends the request, and during the
    #   response while it is reading data sent by the server. The value is specified
    #   in milliseconds by default, but can be in any other unit if the number is
    #   suffixed by the unit, as specified at the top of this document. In TCP mode
    #   (and to a lesser extent, in HTTP mode), it is highly recommended that the
    #   client timeout remains equal to the server timeout in order to avoid complex
    #   situations to debug. It is a good practice to cover one or several TCP packet
    #   losses by specifying timeouts that are slightly above multiples of 3 seconds
    #   (eg: 4 or 5 seconds).
    #
    #   This parameter is specific to frontends, but can be specified once for all in
    #   "defaults" sections. This is in fact one of the easiest solutions not to
    #   forget about it. An unspecified timeout results in an infinite timeout, which
    #   is not recommended. Such a usage is accepted and works but reports a warning
    #   during startup because it may results in accumulation of expired sessions in
    #   the system if the system's timeouts are not configured either.
    #
    #   This parameter replaces the old, deprecated "clitimeout". It is recommended
    #   to use it to write new configurations. The form "timeout clitimeout" is
    #   provided only by backwards compatibility but its use is strongly discouraged.
    #
    #   See also : "clitimeout", "timeout server".
    #
    attr_accessor :timeout_client

    #
    # timeout http-keep-alive <timeout>
    #   Set the maximum allowed time to wait for a new HTTP request to appear
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     <timeout> is the timeout value specified in milliseconds by default, but
    #               can be in any other unit if the number is suffixed by the unit,
    #               as explained at the top of this document.
    #
    #   By default, the time to wait for a new request in case of keep-alive is set
    #   by "timeout http-request". However this is not always convenient because some
    #   people want very short keep-alive timeouts in order to release connections
    #   faster, and others prefer to have larger ones but still have short timeouts
    #   once the request has started to present itself.
    #
    #   The "http-keep-alive" timeout covers these needs. It will define how long to
    #   wait for a new HTTP request to start coming after a response was sent. Once
    #   the first byte of request has been seen, the "http-request" timeout is used
    #   to wait for the complete request to come. Note that empty lines prior to a
    #   new request do not refresh the timeout and are not counted as a new request.
    #
    #   There is also another difference between the two timeouts : when a connection
    #   expires during timeout http-keep-alive, no error is returned, the connection
    #   just closes. If the connection expires in "http-request" while waiting for a
    #   connection to complete, a HTTP 408 error is returned.
    #
    #   In general it is optimal to set this value to a few tens to hundreds of
    #   milliseconds, to allow users to fetch all objects of a page at once but
    #   without waiting for further clicks. Also, if set to a very small value (eg:
    #   1 millisecond) it will probably only accept pipelined requests but not the
    #   non-pipelined ones. It may be a nice trade-off for very large sites running
    #   with tens to hundreds of thousands of clients.
    #
    #   If this parameter is not set, the "http-request" timeout applies, and if both
    #   are not set, "timeout client" still applies at the lower level. It should be
    #   set in the frontend to take effect, unless the frontend is in TCP mode, in
    #   which case the HTTP backend's timeout will be used.
    #
    #   See also : "timeout http-request", "timeout client".
    #
    attr_accessor :timeout_http_keep_alive

    #
    # timeout http-request <timeout>
    #   Set the maximum allowed time to wait for a complete HTTP request
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     <timeout> is the timeout value specified in milliseconds by default, but
    #               can be in any other unit if the number is suffixed by the unit,
    #               as explained at the top of this document.
    #
    #   In order to offer DoS protection, it may be required to lower the maximum
    #   accepted time to receive a complete HTTP request without affecting the client
    #   timeout. This helps protecting against established connections on which
    #   nothing is sent. The client timeout cannot offer a good protection against
    #   this abuse because it is an inactivity timeout, which means that if the
    #   attacker sends one character every now and then, the timeout will not
    #   trigger. With the HTTP request timeout, no matter what speed the client
    #   types, the request will be aborted if it does not complete in time.
    #
    #   Note that this timeout only applies to the header part of the request, and
    #   not to any data. As soon as the empty line is received, this timeout is not
    #   used anymore. It is used again on keep-alive connections to wait for a second
    #   request if "timeout http-keep-alive" is not set.
    #
    #   Generally it is enough to set it to a few seconds, as most clients send the
    #   full request immediately upon connection. Add 3 or more seconds to cover TCP
    #   retransmits but that's all. Setting it to very low values (eg: 50 ms) will
    #   generally work on local networks as long as there are no packet losses. This
    #   will prevent people from sending bare HTTP requests using telnet.
    #
    #   If this parameter is not set, the client timeout still applies between each
    #   chunk of the incoming request. It should be set in the frontend to take
    #   effect, unless the frontend is in TCP mode, in which case the HTTP backend's
    #   timeout will be used.
    #
    #   See also : "timeout http-keep-alive", "timeout client".
    #
    attr_accessor :timeout_http_request

    #
    # timeout tarpit <timeout>
    #   Set the duration for which tarpitted connections will be maintained
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    yes   |   yes  |   yes
    #   Arguments :
    #     <timeout> is the tarpit duration specified in milliseconds by default, but
    #               can be in any other unit if the number is suffixed by the unit,
    #               as explained at the top of this document.
    #
    #   When a connection is tarpitted using "reqtarpit", it is maintained open with
    #   no activity for a certain amount of time, then closed. "timeout tarpit"
    #   defines how long it will be maintained open.
    #
    #   The value is specified in milliseconds by default, but can be in any other
    #   unit if the number is suffixed by the unit, as specified at the top of this
    #   document. If unspecified, the same value as the backend's connection timeout
    #   ("timeout connect") is used, for backwards compatibility with older versions
    #   with no "timeout tarpit" parameter.
    #
    #   See also : "timeout connect", "contimeout".
    #
    attr_accessor :timeout_tarpit

    attr_accessor :reqisetbe
    attr_accessor :reqsetbe

    #
    # name <name>
    #   The frontend name is required.
    #
    attr_accessor :name

    #
    # Returns a new RhaproxyFrontend Object
    #
    def initialize()
    end

    #
    # Compile the HAproxy frontend configuration
    #
    def config

      if @name

        conf = option_string()

        return conf

      else

        puts "frontend name not defined"

        return false

      end

    end

    private

    def option_string()

      ostring = "  " + "frontend " + @name + "\n"

      if @acl
        ostring += "    " + "acl " + @acl.to_s + "\n"
      end

      if @bind
        ostring += "    " + "bind " + @bind.to_s + "\n"
      end

      if @block
        ostring += "    " + "block " + @block.to_s + "\n"
      end

      if @capture_cookie
        ostring += "    " + "capture cookie " + @capture_cookie.to_s + "\n"
      end

      if @capture_request_header
        ostring += "    " + "capture request header " + @capture_request_header.to_s + "\n"
      end

      if @capture_response_header
        ostring += "    " + "capture response header " + @capture_response_header.to_s + "\n"
      end

      if @force_persist
        ostring += "    " + "force-persist " + @force_persist.to_s + "\n"
      end

      if @http_request
        ostring += "    " + "http-request " + @http_request.to_s + "\n"
      end

      if @persistent_id
        ostring += "    " + "id " + @persistent_id.to_s + "\n"
      end

      if @ignore_persist
        ostring += "    " + "ignore persist " + @ignore_persist.to_s + "\n"
      end

      if @monitor_fail
        ostring += "    " + "monitor fail " + @monitor_fail.to_s + "\n"
      end

      if @option_ignore_presist
        ostring += "    " + "option ignore-presist " + @option_ignore_presist.to_s + "\n"
      end

      if @redirect
        ostring += "    " + "redirect " + @redirect.to_s + "\n"
      end

      if @reqadd
        ostring += "    " + "reqadd " + @reqadd.to_s + "\n"
      end

      if @reqallow
        ostring += "    " + "reqallow " + @reqallow.to_s + "\n"
      end

      if @reqiallow
        ostring += "    " + "reqiallow " + @reqiallow.to_s + "\n"
      end

      if @reqdel
        ostring += "    " + "reqdel " + @reqdel.to_s + "\n"
      end

      if @reqidel
        ostring += "    " + "reqidel " + @reqidel.to_s + "\n"
      end

      if @reqdeny
        ostring += "    " + "reqdeny " + @reqdeny.to_s + "\n"
      end

      if @reqideny
        ostring += "    " + "reqideny " + @reqideny.to_s + "\n"
      end

      if @reqpass
        ostring += "    " + "reqpass " + @reqpass.to_s + "\n"
      end

      if @reqipass
        ostring += "    " + "reqipass " + @reqipass.to_s + "\n"
      end

      if @reqrep
        ostring += "    " + "reqrep " + @reqrep.to_s + "\n"
      end

      if @reqirep
        ostring += "    " + "reqirep " + @reqirep.to_s + "\n"
      end

      if @reqtarpit
        ostring += "    " + "reqtarpit " + @reqtarpit.to_s + "\n"
      end

      if @reqitarpit
        ostring += "    " + "reqitarpit " + @reqitarpit.to_s + "\n"
      end

      if @rspadd
        ostring += "    " + "rspadd " + @rspadd.to_s + "\n"
      end

      if @rspdel
        ostring += "    " + "rspdel " + @rspdel.to_s + "\n"
      end

      if @rspidel
        ostring += "    " + "rspidel " + @rspidel.to_s + "\n"
      end

      if @rspdeny
        ostring += "    " + "rspdeny " + @rspdeny.to_s + "\n"
      end

      if @rspideny
        ostring += "    " + "rspideny " + @rspideny.to_s + "\n"
      end

      if @rspirep
        ostring += "    " + "rspirep " + @rspirep.to_s + "\n"
      end

      if @rsprep
        ostring += "    " + "rsprep " + @rsprep.to_s + "\n"
      end

      if @tcp_request_connection
        ostring += "    " + "tcp-request connection " + @tcp_request_connection.to_s + "\n"
      end

      if @tcp_request_content
        ostring += "    " + "tcp-request content " + @tcp_request_content.to_s + "\n"
      end

      if @tcp_request_inspect_delay
        ostring += "    " + "tcp-request inspect-delay " + @tcp_request_inspect_delay.to_s + "\n"
      end

      if @use_backend
        ostring += "    " + "use_backend " + @use_backend.to_s + "\n"
      end

      if @description
        ostring += "    " + "description " + @description.to_s + "\n"
      end

      if @reqisetbe
        ostring += "    " + "reqisetbe " + @reqisetbe.to_s + "\n"
      end

      if @reqsetbe
        ostring += "    " + "reqsetbe " + @reqsetbe.to_s + "\n"
      end

      if @backlog
        ostring += "    " + "backlog " + @backlog.to_s + "\n"
      end

      if @bind_process
        ostring += "    " + "bind-process " + @bind_process.to_s + "\n"
      end

      if @default_backend
        ostring += "    " + "default_backend " + @default_backend.to_s + "\n"
      end

      if @disabled
        ostring += "    " + "disabled " + "\n"
      end

      if @enabled
        ostring += "    " + "enabled " + "\n"
      end

      if @errorfile
        ostring += "    " + "errorfile " + @errorfile.to_s + "\n"
      end

      if @errorloc
        ostring += "    " + "errorloc " + @errorloc.to_s + "\n"
      end

      if @errorloc302
        ostring += "    " + "errorloc302 " + @errorloc302.to_s + "\n"
      end

      if @errorloc303
        ostring += "    " + "errorloc303 " + @errorloc303.to_s + "\n"
      end

      if @grace
        ostring += "    " + "grace " + @grace.to_s + "\n"
      end

      if @log
        ostring += "    " + "log " + @log.to_s + "\n"
      end

      if @maxconn
        ostring += "    " + "maxconn " + @maxconn.to_s + "\n"
      end

      if @mode
        ostring += "    " + "mode " + @mode.to_s + "\n"
      end

      if @monitor_net
        ostring += "    " + "monitor-net " + @monitor_net.to_s + "\n"
      end

      if @monitor_uri
        ostring += "    " + "monitor-uri " + @monitor_uri.to_s + "\n"
      end

      if @option_accept_invalid_http_request
        ostring += "    " + "option accept-invalid-http-request " + "\n"
      end

      if @option_clitcpka
        ostring += "    " + "option clitcpka " + "\n"
      end

      if @option_contstats
        ostring += "    " + "option contstats " + "\n"
      end

      if @option_dontlog_normal
        ostring += "    " + "option dontlog-normal " + "\n"
      end

      if @option_dontlognull
        ostring += "    " + "option dontlognull " + "\n"
      end

      if @option_forceclose
        ostring += "    " + "option forceclose " + "\n"
      end

      if @option_forwardfor
        ostring += "    " + "option forwardfor " + @option_forwardfor.to_s + "\n"
      end

      if @option_http_pretend_keepalive
        ostring += "    " + "option http-pretend-keepalive " + "\n"
      end

      if @option_http_server_close
        ostring += "    " + "option http-server-close " + "\n"
      end

      if @option_http_use_proxy_header
        ostring += "    " + "option http-use-proxy-header " + "\n"
      end

      if @option_httpclose
        ostring += "    " + "option httpclose " + "\n"
      end

      if @option_httplog
        ostring += "    " + "option httplog " + "\n"
      end

      if @option_httplog_clf
        ostring += "    " + "option httplog " + @option_httplog_clf.to_s + "\n"
      end

      if @option_http_proxy
        ostring += "    " + "option http_proxy " + "\n"
      end

      if @option_independant_streams
        ostring += "    " + "option independant-streams " + "\n"
      end

      if @option_log_separate_errors
        ostring += "    " + "option log-separate-errors " + "\n"
      end

      if @option_logasap
        ostring += "    " + "option logasap " + "\n"
      end

      if @option_nolinger
        ostring += "    " + "option nolinger " + "\n"
      end

      if @option_originalto
        ostring += "    " + "option originalto " + @option_originalto.to_s + "\n"
      end

      if @option_socket_stats
        ostring += "    " + "option socket-stats " + "\n"
      end

      if @option_splice_auto
        ostring += "    " + "option splice-auto " + "\n"
      end

      if @option_splice_request
        ostring += "    " + "option splice-request " + "\n"
      end

      if @option_splice_response
        ostring += "    " + "option splice-response " + "\n"
      end

      if @option_tcp_smart_accept
        ostring += "    " + "option tcp-smart-accept " + "\n"
      end

      if @option_tcpka
        ostring += "    " + "option tcpka " + "\n"
      end

      if @option_tcplog
        ostring += "    " + "option tcplog " + "\n"
      end

      if @rate_limit_sessions
        ostring += "    " + "rate-limit sessions " + @rate_limit_sessions.to_s + "\n"
      end

      if @timeout_client
        ostring += "    " + "timeout client " + @timeout_client.to_s + "\n"
      end

      if @timeout_http_keep_alive
        ostring += "    " + "timeout http-keep-alive " + @timeout_http_keep_alive.to_s + "\n"
      end

      if @timeout_http_request
        ostring += "    " + "timeout http-request " + @timeout_http_request.to_s + "\n"
      end

      if @timeout_tarpit
        ostring += "    " + "timeout tarpit " + @timeout_tarpit.to_s + "\n"
      end

      ostring += "\n"

      return ostring

    end
  end

