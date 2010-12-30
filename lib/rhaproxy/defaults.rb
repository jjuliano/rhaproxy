  # = rhaproxy - A HAproxy gem for Ruby
  #
  # Homepage::  http://github.com/jjuliano/rhaproxy
  # Author::    Joel Bryan Juliano
  # Copyright:: (cc) 2011 Joel Bryan Juliano
  # License::   MIT

  #
  # class RhaproxyDefaults.new( array, str, array)
  #

  #
  # A "defaults" section sets default parameters for all other sections following
  # its declaration. Those default parameters are reset by the next "defaults"
  # section. See below for the list of parameters which can be set in a "defaults"
  # section. The name is optional but its use is encouraged for better readability.
  #
  class RhaproxyDefaults

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
    # balance <algorithm> [ <arguments> ]
    # balance url_param <param> [check_post [<max_wait>]]
    #   Define the load balancing algorithm to be used in a backend.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <algorithm> is the algorithm used to select a server when doing load
    #                 balancing. This only applies when no persistence information
    #                 is available, or when a connection is redispatched to another
    #                 server. <algorithm> may be one of the following :
    #
    #       roundrobin  Each server is used in turns, according to their weights.
    #                   This is the smoothest and fairest algorithm when the server's
    #                   processing time remains equally distributed. This algorithm
    #                   is dynamic, which means that server weights may be adjusted
    #                   on the fly for slow starts for instance. It is limited by
    #                   design to 4128 active servers per backend. Note that in some
    #                   large farms, when a server becomes up after having been down
    #                   for a very short time, it may sometimes take a few hundreds
    #                   requests for it to be re-integrated into the farm and start
    #                   receiving traffic. This is normal, though very rare. It is
    #                   indicated here in case you would have the chance to observe
    #                   it, so that you don't worry.
    #
    #       static-rr   Each server is used in turns, according to their weights.
    #                   This algorithm is as similar to roundrobin except that it is
    #                   static, which means that changing a server's weight on the
    #                   fly will have no effect. On the other hand, it has no design
    #                   limitation on the number of servers, and when a server goes
    #                   up, it is always immediately reintroduced into the farm, once
    #                   the full map is recomputed. It also uses slightly less CPU to
    #                   run (around -1%).
    #
    #       leastconn   The server with the lowest number of connections receives the
    #                   connection. Round-robin is performed within groups of servers
    #                   of the same load to ensure that all servers will be used. Use
    #                   of this algorithm is recommended where very long sessions are
    #                   expected, such as LDAP, SQL, TSE, etc... but is not very well
    #                   suited for protocols using short sessions such as HTTP. This
    #                   algorithm is dynamic, which means that server weights may be
    #                   adjusted on the fly for slow starts for instance.
    #
    #       source      The source IP address is hashed and divided by the total
    #                   weight of the running servers to designate which server will
    #                   receive the request. This ensures that the same client IP
    #                   address will always reach the same server as long as no
    #                   server goes down or up. If the hash result changes due to the
    #                   number of running servers changing, many clients will be
    #                   directed to a different server. This algorithm is generally
    #                   used in TCP mode where no cookie may be inserted. It may also
    #                   be used on the Internet to provide a best-effort stickiness
    #                   to clients which refuse session cookies. This algorithm is
    #                   static by default, which means that changing a server's
    #                   weight on the fly will have no effect, but this can be
    #                   changed using "hash-type".
    #
    #       uri         The left part of the URI (before the question mark) is hashed
    #                   and divided by the total weight of the running servers. The
    #                   result designates which server will receive the request. This
    #                   ensures that a same URI will always be directed to the same
    #                   server as long as no server goes up or down. This is used
    #                   with proxy caches and anti-virus proxies in order to maximize
    #                   the cache hit rate. Note that this algorithm may only be used
    #                   in an HTTP backend. This algorithm is static by default,
    #                   which means that changing a server's weight on the fly will
    #                   have no effect, but this can be changed using "hash-type".
    #
    #                   This algorithm support two optional parameters "len" and
    #                   "depth", both followed by a positive integer number. These
    #                   options may be helpful when it is needed to balance servers
    #                   based on the beginning of the URI only. The "len" parameter
    #                   indicates that the algorithm should only consider that many
    #                   characters at the beginning of the URI to compute the hash.
    #                   Note that having "len" set to 1 rarely makes sense since most
    #                   URIs start with a leading "/".
    #
    #                   The "depth" parameter indicates the maximum directory depth
    #                   to be used to compute the hash. One level is counted for each
    #                   slash in the request. If both parameters are specified, the
    #                   evaluation stops when either is reached.
    #
    #       url_param   The URL parameter specified in argument will be looked up in
    #                   the query string of each HTTP GET request.
    #
    #                   If the modifier "check_post" is used, then an HTTP POST
    # 		  request entity will be searched for the parameter argument,
    # 		  when the question mark indicating a query string ('?') is not
    # 		  present in the URL. Optionally, specify a number of octets to
    # 		  wait for before attempting to search the message body. If the
    # 		  entity can not be searched, then round robin is used for each
    # 		  request. For instance, if your clients always send the LB
    # 		  parameter in the first 128 bytes, then specify that. The
    # 		  default is 48. The entity data will not be scanned until the
    # 		  required number of octets have arrived at the gateway, this
    # 		  is the minimum of: (default/max_wait, Content-Length or first
    # 		  chunk length). If Content-Length is missing or zero, it does
    # 		  not need to wait for more data than the client promised to
    # 		  send. When Content-Length is present and larger than
    # 		  <max_wait>, then waiting is limited to <max_wait> and it is
    # 		  assumed that this will be enough data to search for the
    # 		  presence of the parameter. In the unlikely event that
    # 		  Transfer-Encoding: chunked is used, only the first chunk is
    # 		  scanned. Parameter values separated by a chunk boundary, may
    # 		  be randomly balanced if at all.
    #
    #                   If the parameter is found followed by an equal sign ('=') and
    #                   a value, then the value is hashed and divided by the total
    #                   weight of the running servers. The result designates which
    #                   server will receive the request.
    #
    #                   This is used to track user identifiers in requests and ensure
    #                   that a same user ID will always be sent to the same server as
    #                   long as no server goes up or down. If no value is found or if
    #                   the parameter is not found, then a round robin algorithm is
    #                   applied. Note that this algorithm may only be used in an HTTP
    #                   backend. This algorithm is static by default, which means
    #                   that changing a server's weight on the fly will have no
    #                   effect, but this can be changed using "hash-type".
    #
    #       hdr(name)   The HTTP header <name> will be looked up in each HTTP request.
    #                   Just as with the equivalent ACL 'hdr()' function, the header
    #                   name in parenthesis is not case sensitive. If the header is
    #                   absent or if it does not contain any value, the roundrobin
    #                   algorithm is applied instead.
    #
    #                   An optional 'use_domain_only' parameter is available, for
    #                   reducing the hash algorithm to the main domain part with some
    #                   specific headers such as 'Host'. For instance, in the Host
    #                   value "haproxy.1wt.eu", only "1wt" will be considered.
    #
    #                   This algorithm is static by default, which means that
    #                   changing a server's weight on the fly will have no effect,
    #                   but this can be changed using "hash-type".
    #
    #       rdp-cookie
    #       rdp-cookie(name)
    #                   The RDP cookie <name> (or "mstshash" if omitted) will be
    #                   looked up and hashed for each incoming TCP request. Just as
    #                   with the equivalent ACL 'req_rdp_cookie()' function, the name
    #                   is not case-sensitive. This mechanism is useful as a degraded
    #                   persistence mode, as it makes it possible to always send the
    #                   same user (or the same session ID) to the same server. If the
    #                   cookie is not found, the normal roundrobin algorithm is
    #                   used instead.
    #
    #                   Note that for this to work, the frontend must ensure that an
    #                   RDP cookie is already present in the request buffer. For this
    #                   you must use 'tcp-request content accept' rule combined with
    #                   a 'req_rdp_cookie_cnt' ACL.
    #
    #                   This algorithm is static by default, which means that
    #                   changing a server's weight on the fly will have no effect,
    #                   but this can be changed using "hash-type".
    #
    #     <arguments> is an optional list of arguments which may be needed by some
    #                 algorithms. Right now, only "url_param" and "uri" support an
    #                 optional argument.
    #
    #                 balance uri [len <len>] [depth <depth>]
    #                 balance url_param <param> [check_post [<max_wait>]]
    #
    #   The load balancing algorithm of a backend is set to roundrobin when no other
    #   algorithm, mode nor option have been set. The algorithm may only be set once
    #   for each backend.
    #
    #   Examples :
    #         balance roundrobin
    #         balance url_param userid
    #         balance url_param session_id check_post 64
    #         balance hdr(User-Agent)
    #         balance hdr(host)
    #         balance hdr(Host) use_domain_only
    #
    #   Note: the following caveats and limitations on using the "check_post"
    #   extension with "url_param" must be considered :
    #
    #     - all POST requests are eligible for consideration, because there is no way
    #       to determine if the parameters will be found in the body or entity which
    #       may contain binary data. Therefore another method may be required to
    #       restrict consideration of POST requests that have no URL parameters in
    #       the body. (see acl reqideny http_end)
    #
    #     - using a <max_wait> value larger than the request buffer size does not
    #       make sense and is useless. The buffer size is set at build time, and
    #       defaults to 16 kB.
    #
    #     - Content-Encoding is not supported, the parameter search will probably
    #       fail; and load balancing will fall back to Round Robin.
    #
    #     - Expect: 100-continue is not supported, load balancing will fall back to
    #       Round Robin.
    #
    #     - Transfer-Encoding (RFC2616 3.6.1) is only supported in the first chunk.
    #       If the entire parameter value is not present in the first chunk, the
    #       selection of server is undefined (actually, defined by how little
    #       actually appeared in the first chunk).
    #
    #     - This feature does not support generation of a 100, 411 or 501 response.
    #
    #     - In some cases, requesting "check_post" MAY attempt to scan the entire
    #       contents of a message body. Scanning normally terminates when linear
    #       white space or control characters are found, indicating the end of what
    #       might be a URL parameter list. This is probably not a concern with SGML
    #       type message bodies.
    #
    #   See also : "dispatch", "cookie", "appsession", "transparent", "hash-type" and
    #              "http_proxy".
    #
    attr_accessor :balance

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
    # cookie <name> [ rewrite | insert | prefix ] [ indirect ] [ nocache ]
    #               [ postonly ] [ preserve ] [ domain <domain> ]*
    #               [ maxidle <idle> ] [ maxlife <life> ]
    #   Enable cookie-based persistence in a backend.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <name>    is the name of the cookie which will be monitored, modified or
    #               inserted in order to bring persistence. This cookie is sent to
    #               the client via a "Set-Cookie" header in the response, and is
    #               brought back by the client in a "Cookie" header in all requests.
    #               Special care should be taken to choose a name which does not
    #               conflict with any likely application cookie. Also, if the same
    #               backends are subject to be used by the same clients (eg:
    #               HTTP/HTTPS), care should be taken to use different cookie names
    #               between all backends if persistence between them is not desired.
    #
    #     rewrite   This keyword indicates that the cookie will be provided by the
    #               server and that haproxy will have to modify its value to set the
    #               server's identifier in it. This mode is handy when the management
    #               of complex combinations of "Set-cookie" and "Cache-control"
    #               headers is left to the application. The application can then
    #               decide whether or not it is appropriate to emit a persistence
    #               cookie. Since all responses should be monitored, this mode only
    #               works in HTTP close mode. Unless the application behaviour is
    #               very complex and/or broken, it is advised not to start with this
    #               mode for new deployments. This keyword is incompatible with
    #               "insert" and "prefix".
    #
    #     insert    This keyword indicates that the persistence cookie will have to
    #               be inserted by haproxy in server responses if the client did not
    #
    #               already have a cookie that would have permitted it to access this
    #               server. When used without the "preserve" option, if the server
    #               emits a cookie with the same name, it will be remove before
    #               processing.  For this reason, this mode can be used to upgrade
    #               existing configurations running in the "rewrite" mode. The cookie
    #               will only be a session cookie and will not be stored on the
    #               client's disk. By default, unless the "indirect" option is added,
    #               the server will see the cookies emitted by the client. Due to
    #               caching effects, it is generally wise to add the "nocache" or
    #               "postonly" keywords (see below). The "insert" keyword is not
    #               compatible with "rewrite" and "prefix".
    #
    #     prefix    This keyword indicates that instead of relying on a dedicated
    #               cookie for the persistence, an existing one will be completed.
    #               This may be needed in some specific environments where the client
    #               does not support more than one single cookie and the application
    #               already needs it. In this case, whenever the server sets a cookie
    #               named <name>, it will be prefixed with the server's identifier
    #               and a delimiter. The prefix will be removed from all client
    #               requests so that the server still finds the cookie it emitted.
    #               Since all requests and responses are subject to being modified,
    #               this mode requires the HTTP close mode. The "prefix" keyword is
    #               not compatible with "rewrite" and "insert".
    #
    #     indirect  When this option is specified, no cookie will be emitted to a
    #               client which already has a valid one for the server which has
    #               processed the request. If the server sets such a cookie itself,
    #               it will be removed, unless the "preserve" option is also set. In
    #               "insert" mode, this will additionally remove cookies from the
    #               requests transmitted to the server, making the persistence
    #               mechanism totally transparent from an application point of view.
    #
    #     nocache   This option is recommended in conjunction with the insert mode
    #               when there is a cache between the client and HAProxy, as it
    #               ensures that a cacheable response will be tagged non-cacheable if
    #               a cookie needs to be inserted. This is important because if all
    #               persistence cookies are added on a cacheable home page for
    #               instance, then all customers will then fetch the page from an
    #               outer cache and will all share the same persistence cookie,
    #               leading to one server receiving much more traffic than others.
    #               See also the "insert" and "postonly" options.
    #
    #     postonly  This option ensures that cookie insertion will only be performed
    #               on responses to POST requests. It is an alternative to the
    #               "nocache" option, because POST responses are not cacheable, so
    #               this ensures that the persistence cookie will never get cached.
    #               Since most sites do not need any sort of persistence before the
    #               first POST which generally is a login request, this is a very
    #               efficient method to optimize caching without risking to find a
    #               persistence cookie in the cache.
    #               See also the "insert" and "nocache" options.
    #
    #     preserve  This option may only be used with "insert" and/or "indirect". It
    #               allows the server to emit the persistence cookie itself. In this
    #               case, if a cookie is found in the response, haproxy will leave it
    #               untouched. This is useful in order to end persistence after a
    #               logout request for instance. For this, the server just has to
    #               emit a cookie with an invalid value (eg: empty) or with a date in
    #               the past. By combining this mechanism with the "disable-on-404"
    #               check option, it is possible to perform a completely graceful
    #               shutdown because users will definitely leave the server after
    #               they logout.
    #
    #     domain    This option allows to specify the domain at which a cookie is
    #               inserted. It requires exactly one parameter: a valid domain
    #               name. If the domain begins with a dot, the browser is allowed to
    #               use it for any host ending with that name. It is also possible to
    #               specify several domain names by invoking this option multiple
    #               times. Some browsers might have small limits on the number of
    #               domains, so be careful when doing that. For the record, sending
    #               10 domains to MSIE 6 or Firefox 2 works as expected.
    #
    #     maxidle   This option allows inserted cookies to be ignored after some idle
    #               time. It only works with insert-mode cookies. When a cookie is
    #               sent to the client, the date this cookie was emitted is sent too.
    #               Upon further presentations of this cookie, if the date is older
    #               than the delay indicated by the parameter (in seconds), it will
    #               be ignored. Otherwise, it will be refreshed if needed when the
    #               response is sent to the client. This is particularly useful to
    #               prevent users who never close their browsers from remaining for
    #               too long on the same server (eg: after a farm size change). When
    #               this option is set and a cookie has no date, it is always
    #               accepted, but gets refreshed in the response. This maintains the
    #               ability for admins to access their sites. Cookies that have a
    #               date in the future further than 24 hours are ignored. Doing so
    #               lets admins fix timezone issues without risking kicking users off
    #               the site.
    #
    #     maxlife   This option allows inserted cookies to be ignored after some life
    #               time, whether they're in use or not. It only works with insert
    #               mode cookies. When a cookie is first sent to the client, the date
    #               this cookie was emitted is sent too. Upon further presentations
    #               of this cookie, if the date is older than the delay indicated by
    #               the parameter (in seconds), it will be ignored. If the cookie in
    #               the request has no date, it is accepted and a date will be set.
    #               Cookies that have a date in the future further than 24 hours are
    #               ignored. Doing so lets admins fix timezone issues without risking
    #               kicking users off the site. Contrary to maxidle, this value is
    #               not refreshed, only the first visit date counts. Both maxidle and
    #               maxlife may be used at the time. This is particularly useful to
    #               prevent users who never close their browsers from remaining for
    #               too long on the same server (eg: after a farm size change). This
    #               is stronger than the maxidle method in that it forces a
    #               redispatch after some absolute delay.
    #
    #   There can be only one persistence cookie per HTTP backend, and it can be
    #   declared in a defaults section. The value of the cookie will be the value
    #   indicated after the "cookie" keyword in a "server" statement. If no cookie
    #   is declared for a given server, the cookie is not set.
    #
    #   Examples :
    #         cookie JSESSIONID prefix
    #         cookie SRV insert indirect nocache
    #         cookie SRV insert postonly indirect
    #         cookie SRV insert indirect nocache maxidle 30m maxlife 8h
    #
    #   See also : "appsession", "balance source", "capture cookie", "server"
    #              and "ignore-persist".
    #
    attr_accessor :cookie

    #
    # default-server [param*]
    #   Change default options for a server in a backend
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments:
    #     <param*>  is a list of parameters for this server. The "default-server"
    #               keyword accepts an important number of options and has a complete
    #               section dedicated to it. Please refer to section 5 for more
    #               details.
    #
    #   Example :
    #         default-server inter 1000 weight 13
    #
    #   See also: "server" and section 5 about server options
    #
    attr_accessor :default_server

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
    # fullconn <conns>
    #   Specify at what backend load the servers will reach their maxconn
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <conns>   is the number of connections on the backend which will make the
    #               servers use the maximal number of connections.
    #
    #   When a server has a "maxconn" parameter specified, it means that its number
    #   of concurrent connections will never go higher. Additionally, if it has a
    #   "minconn" parameter, it indicates a dynamic limit following the backend's
    #   load. The server will then always accept at least <minconn> connections,
    #   never more than <maxconn>, and the limit will be on the ramp between both
    #   values when the backend has less than <conns> concurrent connections. This
    #   makes it possible to limit the load on the servers during normal loads, but
    #   push it further for important loads without overloading the servers during
    #   exceptional loads.
    #
    #   Example :
    #      # The servers will accept between 100 and 1000 concurrent connections each
    #      # and the maximum of 1000 will be reached when the backend reaches 10000
    #      # connections.
    #      backend dynamic
    #         fullconn   10000
    #         server     srv1   dyn1:80 minconn 100 maxconn 1000
    #         server     srv2   dyn2:80 minconn 100 maxconn 1000
    #
    #   See also : "maxconn", "server"
    #
    attr_accessor :fullconn

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

    #
    # hash-type <method>
    #   Specify a method to use for mapping hashes to servers
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     map-based   the hash table is a static array containing all alive servers.
    #                 The hashes will be very smooth, will consider weights, but will
    #                 be static in that weight changes while a server is up will be
    #                 ignored. This means that there will be no slow start. Also,
    #                 since a server is selected by its position in the array, most
    #                 mappings are changed when the server count changes. This means
    #                 that when a server goes up or down, or when a server is added
    #                 to a farm, most connections will be redistributed to different
    #                 servers. This can be inconvenient with caches for instance.
    #
    #     consistent  the hash table is a tree filled with many occurrences of each
    #                 server. The hash key is looked up in the tree and the closest
    #                 server is chosen. This hash is dynamic, it supports changing
    #                 weights while the servers are up, so it is compatible with the
    #                 slow start feature. It has the advantage that when a server
    #                 goes up or down, only its associations are moved. When a server
    #                 is added to the farm, only a few part of the mappings are
    #                 redistributed, making it an ideal algorithm for caches.
    #                 However, due to its principle, the algorithm will never be very
    #                 smooth and it may sometimes be necessary to adjust a server's
    #                 weight or its ID to get a more balanced distribution. In order
    #                 to get the same distribution on multiple load balancers, it is
    #                 important that all servers have the same IDs.
    #
    #   The default hash type is "map-based" and is recommended for most usages.
    #
    #   See also : "balance", "server"
    #
    attr_accessor :hash_type

    #
    # http-check disable-on-404
    #   Enable a maintenance mode upon HTTP/404 response to health-checks
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments : none
    #
    #   When this option is set, a server which returns an HTTP code 404 will be
    #   excluded from further load-balancing, but will still receive persistent
    #   connections. This provides a very convenient method for Web administrators
    #   to perform a graceful shutdown of their servers. It is also important to note
    #   that a server which is detected as failed while it was in this mode will not
    #   generate an alert, just a notice. If the server responds 2xx or 3xx again, it
    #   will immediately be reinserted into the farm. The status on the stats page
    #   reports "NOLB" for a server in this mode. It is important to note that this
    #   option only works in conjunction with the "httpchk" option. If this option
    #   is used with "http-check expect", then it has precedence over it so that 404
    #   responses will still be considered as soft-stop.
    #
    #   See also : "option httpchk", "http-check expect"
    #
    attr_accessor :http_check_disable_on_404

    #
    # http-check send-state
    #   Enable emission of a state header with HTTP health checks
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments : none
    #
    #   When this option is set, haproxy will systematically send a special header
    #   "X-Haproxy-Server-State" with a list of parameters indicating to each server
    #   how they are seen by haproxy. This can be used for instance when a server is
    #   manipulated without access to haproxy and the operator needs to know whether
    #   haproxy still sees it up or not, or if the server is the last one in a farm.
    #
    #   The header is composed of fields delimited by semi-colons, the first of which
    #   is a word ("UP", "DOWN", "NOLB"), possibly followed by a number of valid
    #   checks on the total number before transition, just as appears in the stats
    #   interface. Next headers are in the form "<variable>=<value>", indicating in
    #   no specific order some values available in the stats interface :
    #     - a variable "name", containing the name of the backend followed by a slash
    #       ("/") then the name of the server. This can be used when a server is
    #       checked in multiple backends.
    #
    #     - a variable "node" containing the name of the haproxy node, as set in the
    #       global "node" variable, otherwise the system's hostname if unspecified.
    #
    #     - a variable "weight" indicating the weight of the server, a slash ("/")
    #       and the total weight of the farm (just counting usable servers). This
    #       helps to know if other servers are available to handle the load when this
    #       one fails.
    #
    #     - a variable "scur" indicating the current number of concurrent connections
    #       on the server, followed by a slash ("/") then the total number of
    #       connections on all servers of the same backend.
    #
    #     - a variable "qcur" indicating the current number of requests in the
    #       server's queue.
    #
    #   Example of a header received by the application server :
    #     >>>  X-Haproxy-Server-State: UP 2/3; name=bck/srv2; node=lb1; weight=1/2; \
    #            scur=13/22; qcur=0
    #
    #   See also : "option httpchk", "http-check disable-on-404"
    #
    attr_accessor :http_check_send_state

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
    # option abortonclose
    # no option abortonclose
    #   Enable or disable early dropping of aborted requests pending in queues.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |     no   |   yes  |   yes
    #   Arguments : none
    #
    #   In presence of very high loads, the servers will take some time to respond.
    #   The per-instance connection queue will inflate, and the response time will
    #   increase respective to the size of the queue times the average per-session
    #   response time. When clients will wait for more than a few seconds, they will
    #   often hit the "STOP" button on their browser, leaving a useless request in
    #   the queue, and slowing down other users, and the servers as well, because the
    #   request will eventually be served, then aborted at the first error
    #   encountered while delivering the response.
    #
    #   As there is no way to distinguish between a full STOP and a simple output
    #   close on the client side, HTTP agents should be conservative and consider
    #   that the client might only have closed its output channel while waiting for
    #   the response. However, this introduces risks of congestion when lots of users
    #   do the same, and is completely useless nowadays because probably no client at
    #   all will close the session while waiting for the response. Some HTTP agents
    #   support this behaviour (Squid, Apache, HAProxy), and others do not (TUX, most
    #   hardware-based load balancers). So the probability for a closed input channel
    #   to represent a user hitting the "STOP" button is close to 100%, and the risk
    #   of being the single component to break rare but valid traffic is extremely
    #   low, which adds to the temptation to be able to abort a session early while
    #   still not served and not pollute the servers.
    #
    #   In HAProxy, the user can choose the desired behaviour using the option
    #   "abortonclose". By default (without the option) the behaviour is HTTP
    #   compliant and aborted requests will be served. But when the option is
    #   specified, a session with an incoming channel closed will be aborted while
    #   it is still possible, either pending in the queue for a connection slot, or
    #   during the connection establishment if the server has not yet acknowledged
    #   the connection request. This considerably reduces the queue size and the load
    #   on saturated servers when users are tempted to click on STOP, which in turn
    #   reduces the response time for other users.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "timeout queue" and server's "maxconn" and "maxqueue" parameters
    #
    attr_accessor :option_abortonclose

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
    # option accept-invalid-http-response
    # no option accept-invalid-http-response
    #   Enable or disable relaxing of HTTP response parsing
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |     no   |   yes  |   yes
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
    #   responses, but the complete response will be captured in order to permit
    #   later analysis using the "show errors" request on the UNIX stats socket.
    #   Doing this also helps confirming that the issue has been solved.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option accept-invalid-http-request" and "show errors" on the
    #              stats socket.
    #
    attr_accessor :option_accept_invalid_http_response

    #
    # option allbackups
    # no option allbackups
    #   Use either all backup servers at a time or only the first one
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |     no   |   yes  |   yes
    #   Arguments : none
    #
    #   By default, the first operational backup server gets all traffic when normal
    #   servers are all down. Sometimes, it may be preferred to use multiple backups
    #   at once, because one will not be enough. When "option allbackups" is enabled,
    #   the load balancing will be performed among all backup servers when all normal
    #   ones are unavailable. The same load balancing algorithm will be used and the
    #   servers' weights will be respected. Thus, there will not be any priority
    #   order between the backup servers anymore.
    #
    #   This option is mostly used with static server farms dedicated to return a
    #   "sorry" page when an application is completely offline.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    attr_accessor :option_allbackups

    #
    # option checkcache
    # no option checkcache
    #   Analyze all server responses and block requests with cacheable cookies
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |     no   |   yes  |   yes
    #   Arguments : none
    #
    #   Some high-level frameworks set application cookies everywhere and do not
    #   always let enough control to the developer to manage how the responses should
    #   be cached. When a session cookie is returned on a cacheable object, there is a
    #   high risk of session crossing or stealing between users traversing the same
    #   caches. In some situations, it is better to block the response than to let
    #   some sensible session information go in the wild.
    #
    #   The option "checkcache" enables deep inspection of all server responses for
    #   strict compliance with HTTP specification in terms of cacheability. It
    #   carefully checks "Cache-control", "Pragma" and "Set-cookie" headers in server
    #   response to check if there's a risk of caching a cookie on a client-side
    #   proxy. When this option is enabled, the only responses which can be delivered
    #   to the client are :
    #     - all those without "Set-Cookie" header ;
    #     - all those with a return code other than 200, 203, 206, 300, 301, 410,
    #       provided that the server has not set a "Cache-control: public" header ;
    #     - all those that come from a POST request, provided that the server has not
    #       set a 'Cache-Control: public' header ;
    #     - those with a 'Pragma: no-cache' header
    #     - those with a 'Cache-control: private' header
    #     - those with a 'Cache-control: no-store' header
    #     - those with a 'Cache-control: max-age=0' header
    #     - those with a 'Cache-control: s-maxage=0' header
    #     - those with a 'Cache-control: no-cache' header
    #     - those with a 'Cache-control: no-cache="set-cookie"' header
    #     - those with a 'Cache-control: no-cache="set-cookie,' header
    #       (allowing other fields after set-cookie)
    #
    #   If a response doesn't respect these requirements, then it will be blocked
    #   just as if it was from an "rspdeny" filter, with an "HTTP 502 bad gateway".
    #   The session state shows "PH--" meaning that the proxy blocked the response
    #   during headers processing. Additionally, an alert will be sent in the logs so
    #   that admins are informed that there's something to be fixed.
    #
    #   Due to the high impact on the application, the application should be tested
    #   in depth with the option enabled before going to production. It is also a
    #   good practice to always activate it during tests, even if it is not used in
    #   production, as it will report potentially dangerous application behaviours.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    attr_accessor :option_checkcache

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
    # option httpchk
    # option httpchk <uri>
    # option httpchk <method> <uri>
    # option httpchk <method> <uri> <version>
    #   Enable HTTP protocol to check on the servers health
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <method>  is the optional HTTP method used with the requests. When not set,
    #               the "OPTIONS" method is used, as it generally requires low server
    #               processing and is easy to filter out from the logs. Any method
    #               may be used, though it is not recommended to invent non-standard
    #               ones.
    #
    #     <uri>     is the URI referenced in the HTTP requests. It defaults to " / "
    #               which is accessible by default on almost any server, but may be
    #               changed to any other URI. Query strings are permitted.
    #
    #     <version> is the optional HTTP version string. It defaults to "HTTP/1.0"
    #               but some servers might behave incorrectly in HTTP 1.0, so turning
    #               it to HTTP/1.1 may sometimes help. Note that the Host field is
    #               mandatory in HTTP/1.1, and as a trick, it is possible to pass it
    #               after "\r\n" following the version string.
    #
    #   By default, server health checks only consist in trying to establish a TCP
    #   connection. When "option httpchk" is specified, a complete HTTP request is
    #   sent once the TCP connection is established, and responses 2xx and 3xx are
    #   considered valid, while all other ones indicate a server failure, including
    #   the lack of any response.
    #
    #   The port and interval are specified in the server configuration.
    #
    #   This option does not necessarily require an HTTP backend, it also works with
    #   plain TCP backends. This is particularly useful to check simple scripts bound
    #   to some dedicated ports using the inetd daemon.
    #
    #   Examples :
    #       # Relay HTTPS traffic to Apache instance and check service availability
    #       # using HTTP request "OPTIONS * HTTP/1.1" on port 80.
    #       backend https_relay
    #           mode tcp
    #           option httpchk OPTIONS * HTTP/1.1\r\nHost:\ www
    #           server apache1 192.168.1.1:443 check port 80
    #
    #   See also : "option ssl-hello-chk", "option smtpchk", "option mysql-check",
    #              "http-check" and the "check", "port" and "inter" server options.
    #
    attr_accessor :option_httpchk

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
    # option ldap-check
    #   Use LDAPv3 health checks for server testing
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments : none
    #
    #   It is possible to test that the server correctly talks LDAPv3 instead of just
    #   testing that it accepts the TCP connection. When this option is set, an
    #   LDAPv3 anonymous simple bind message is sent to the server, and the response
    #   is analyzed to find an LDAPv3 bind response message.
    #
    #   The server is considered valid only when the LDAP response contains success
    #   resultCode (http://tools.ietf.org/html/rfc4511#section-4.1.9).
    #
    #   Logging of bind requests is server dependent see your documentation how to
    #   configure it.
    #
    #   Example :
    #         option ldap-check
    #
    #   See also : "option httpchk"
    #
    attr_accessor :option_ldap_check

    #
    # option log-health-checks
    # no option log-health-checks
    #   Enable or disable logging of health checks
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |  yes
    #   Arguments : none
    #
    #   Enable health checks logging so it possible to check for example what
    #   was happening before a server crash. Failed health check are logged if
    #   server is UP and succeeded health checks if server is DOWN, so the amount
    #   of additional information is limited.
    #
    #   If health check logging is enabled no health check status is printed
    #   when servers is set up UP/DOWN/ENABLED/DISABLED.
    #
    #   See also: "log" and section 8 about logging.
    #
    attr_accessor :option_log_health_checks

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
    # option mysql-check [ user <username> ]
    #   Use MySQL health checks for server testing
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     user <username> This is the username which will be used when connecting
    #     to MySQL server.
    #
    #   If you specify a username, the check consists of sending two MySQL packet,
    #   one Client Authentication packet, and one QUIT packet, to correctly close
    #   MySQL session. We then parse the MySQL Handshake Initialisation packet and/or
    #   Error packet. It is a basic but useful test which does not produce error nor
    #   aborted connect on the server. However, it requires adding an authorization
    #   in the MySQL table, like this :
    #
    #       USE mysql;
    #       INSERT INTO user (Host,User) values ('<ip_of_haproxy>','<username>');
    #       FLUSH PRIVILEGES;
    #
    #   If you don't specify a username (it is deprecated and not recommended), the
    #   check only consists in parsing the Mysql Handshake Initialisation packet or
    #   Error packet, we don't send anything in this mode. It was reported that it
    #   can generate lockout if check is too frequent and/or if there is not enough
    #   traffic. In fact, you need in this case to check MySQL "max_connect_errors"
    #   value as if a connection is established successfully within fewer than MySQL
    #   "max_connect_errors" attempts after a previous connection was interrupted,
    #   the error count for the host is cleared to zero. If HAProxy's server get
    #   blocked, the "FLUSH HOSTS" statement is the only way to unblock it.
    #
    #   Remember that this does not check database presence nor database consistency.
    #   To do this, you can use an external check with xinetd for example.
    #
    #   The check requires MySQL >=4.0, for older version, please use TCP check.
    #
    #   Most often, an incoming MySQL server needs to see the client's IP address for
    #   various purposes, including IP privilege matching and connection logging.
    #   When possible, it is often wise to masquerade the client's IP address when
    #   connecting to the server using the "usesrc" argument of the "source" keyword,
    #   which requires the cttproxy feature to be compiled in, and the MySQL server
    #   to route the client via the machine hosting haproxy.
    #
    #   See also: "option httpchk"
    #
    attr_accessor :option_mysql_check

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
    # option persist
    # no option persist
    #   Enable or disable forced persistence on down servers
    #   May be used in sections:    defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments : none
    #
    #   When an HTTP request reaches a backend with a cookie which references a dead
    #   server, by default it is redispatched to another server. It is possible to
    #   force the request to be sent to the dead server first using "option persist"
    #   if absolutely needed. A common use case is when servers are under extreme
    #   load and spend their time flapping. In this case, the users would still be
    #   directed to the server they opened the session on, in the hope they would be
    #   correctly served. It is recommended to use "option redispatch" in conjunction
    #   with this option so that in the event it would not be possible to connect to
    #   the server at all (server definitely dead), the client would finally be
    #   redirected to another valid server.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option redispatch", "retries", "force-persist"
    #
    attr_accessor :option_persist

    #
    # option redispatch
    # no option redispatch
    #   Enable or disable session redistribution in case of connection failure
    #   May be used in sections:    defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments : none
    #
    #   In HTTP mode, if a server designated by a cookie is down, clients may
    #   definitely stick to it because they cannot flush the cookie, so they will not
    #   be able to access the service anymore.
    #
    #   Specifying "option redispatch" will allow the proxy to break their
    #   persistence and redistribute them to a working server.
    #
    #   It also allows to retry last connection to another server in case of multiple
    #   connection failures. Of course, it requires having "retries" set to a nonzero
    #   value.
    #
    #   This form is the preferred form, which replaces both the "redispatch" and
    #   "redisp" keywords.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "redispatch", "retries", "force-persist"
    #
    attr_accessor :option_redispatch

    #
    # option smtpchk
    # option smtpchk <hello> <domain>
    #   Use SMTP health checks for server testing
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <hello>   is an optional argument. It is the "hello" command to use. It can
    #               be either "HELO" (for SMTP) or "EHLO" (for ESTMP). All other
    #               values will be turned into the default command ("HELO").
    #
    #     <domain>  is the domain name to present to the server. It may only be
    #               specified (and is mandatory) if the hello command has been
    #               specified. By default, "localhost" is used.
    #
    #   When "option smtpchk" is set, the health checks will consist in TCP
    #   connections followed by an SMTP command. By default, this command is
    #   "HELO localhost". The server's return code is analyzed and only return codes
    #   starting with a "2" will be considered as valid. All other responses,
    #   including a lack of response will constitute an error and will indicate a
    #   dead server.
    #
    #   This test is meant to be used with SMTP servers or relays. Depending on the
    #   request, it is possible that some servers do not log each connection attempt,
    #   so you may want to experiment to improve the behaviour. Using telnet on port
    #   25 is often easier than adjusting the configuration.
    #
    #   Most often, an incoming SMTP server needs to see the client's IP address for
    #   various purposes, including spam filtering, anti-spoofing and logging. When
    #   possible, it is often wise to masquerade the client's IP address when
    #   connecting to the server using the "usesrc" argument of the "source" keyword,
    #   which requires the cttproxy feature to be compiled in.
    #
    #   Example :
    #         option smtpchk HELO mydomain.org
    #
    #   See also : "option httpchk", "source"
    #
    attr_accessor :option_smtpchk

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
    # option srvtcpka
    # no option srvtcpka
    #   Enable or disable the sending of TCP keepalive packets on the server side
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
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
    #   Using option "srvtcpka" enables the emission of TCP keep-alive probes on the
    #   server side of a connection, which should help when session expirations are
    #   noticed between HAProxy and a server.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option clitcpka", "option tcpka"
    #
    attr_accessor :option_srvtcpka

    #
    # option ssl-hello-chk
    #   Use SSLv3 client hello health checks for server testing
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments : none
    #
    #   When some SSL-based protocols are relayed in TCP mode through HAProxy, it is
    #   possible to test that the server correctly talks SSL instead of just testing
    #   that it accepts the TCP connection. When "option ssl-hello-chk" is set, pure
    #   SSLv3 client hello messages are sent once the connection is established to
    #   the server, and the response is analyzed to find an SSL server hello message.
    #   The server is considered valid only when the response contains this server
    #   hello message.
    #
    #   All servers tested till there correctly reply to SSLv3 client hello messages,
    #   and most servers tested do not even log the requests containing only hello
    #   messages, which is appreciable.
    #
    #   See also: "option httpchk"
    #
    attr_accessor :option_ssl_hello_chk

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
    # option tcp-smart-connect
    # no option tcp-smart-connect
    #   Enable or disable the saving of one ACK packet during the connect sequence
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments : none
    #
    #   On certain systems (at least Linux), HAProxy can ask the kernel not to
    #   immediately send an empty ACK upon a connection request, but to directly
    #   send the buffer request instead. This saves one packet on the network and
    #   thus boosts performance. It can also be useful for some servers, because they
    #   immediately get the request along with the incoming connection.
    #
    #   This feature is enabled when "option tcp-smart-connect" is set in a backend.
    #   It is not enabled by default because it makes network troubleshooting more
    #   complex.
    #
    #   It only makes sense to enable it with protocols where the client speaks first
    #   such as HTTP. In other situations, if there is no data to send in place of
    #   the ACK, a normal ACK is sent.
    #
    #   If this option has been enabled in a "defaults" section, it can be disabled
    #   in a specific instance by prepending the "no" keyword before it.
    #
    #   See also : "option tcp-smart-accept"
    #
    attr_accessor :option_tcp_smart_connect

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
    # option transparent
    # no option transparent
    #   Enable client-side transparent proxying
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments : none
    #
    #   This option was introduced in order to provide layer 7 persistence to layer 3
    #   load balancers. The idea is to use the OS's ability to redirect an incoming
    #   connection for a remote address to a local process (here HAProxy), and let
    #   this process know what address was initially requested. When this option is
    #   used, sessions without cookies will be forwarded to the original destination
    #   IP address of the incoming request (which should match that of another
    #   equipment), while requests with cookies will still be forwarded to the
    #   appropriate server.
    #
    #   Note that contrary to a common belief, this option does NOT make HAProxy
    #   present the client's IP to the server when establishing the connection.
    #
    #   See also: the "usersrc" argument of the "source" keyword, and the
    #             "transparent" option of the "bind" keyword.
    #
    attr_accessor :option_transparent

    #
    # persist rdp-cookie
    # persist rdp-cookie(name)
    #   Enable RDP cookie-based persistence
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <name>    is the optional name of the RDP cookie to check. If omitted, the
    #               default cookie name "msts" will be used. There currently is no
    #               valid reason to change this name.
    #
    #   This statement enables persistence based on an RDP cookie. The RDP cookie
    #   contains all information required to find the server in the list of known
    #   servers. So when this option is set in the backend, the request is analysed
    #   and if an RDP cookie is found, it is decoded. If it matches a known server
    #   which is still UP (or if "option persist" is set), then the connection is
    #   forwarded to this server.
    #
    #   Note that this only makes sense in a TCP backend, but for this to work, the
    #   frontend must have waited long enough to ensure that an RDP cookie is present
    #   in the request buffer. This is the same requirement as with the "rdp-cookie"
    #   load-balancing method. Thus it is highly recommended to put all statements in
    #   a single "listen" section.
    #
    #   Also, it is important to understand that the terminal server will emit this
    #   RDP cookie only if it is configured for "token redirection mode", which means
    #   that the "IP address redirection" option is disabled.
    #
    #   Example :
    #         listen tse-farm
    #             bind :3389
    #             # wait up to 5s for an RDP cookie in the request
    #             tcp-request inspect-delay 5s
    #             tcp-request content accept if RDP_COOKIE
    #             # apply RDP cookie persistence
    #             persist rdp-cookie
    #             # if server is unknown, let's balance on the same cookie.
    # 	    # alternatively, "balance leastconn" may be useful too.
    #             balance rdp-cookie
    #             server srv1 1.1.1.1:3389
    #             server srv2 1.1.1.2:3389
    #
    #   See also : "balance rdp-cookie", "tcp-request" and the "req_rdp_cookie" ACL.
    #
    attr_accessor :persist_rdp_cookie

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
    # retries <value>
    #   Set the number of retries to perform on a server after a connection failure
    #   May be used in sections:    defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <value>   is the number of times a connection attempt should be retried on
    #               a server when a connection either is refused or times out. The
    #               default value is 3.
    #
    #   It is important to understand that this value applies to the number of
    #   connection attempts, not full requests. When a connection has effectively
    #   been established to a server, there will be no more retry.
    #
    #   In order to avoid immediate reconnections to a server which is restarting,
    #   a turn-around timer of 1 second is applied before a retry occurs.
    #
    #   When "option redispatch" is set, the last retry may be performed on another
    #   server even if a cookie references a different server.
    #
    #   See also : "option redispatch"
    #
    attr_accessor :retries

    #
    # source <addr>[:<port>] [usesrc { <addr2>[:<port2>] | client | clientip } ]
    # source <addr>[:<port>] [usesrc { <addr2>[:<port2>] | hdr_ip(<hdr>[,<occ>]) } ]
    # source <addr>[:<port>] [interface <name>]
    #   Set the source address for outgoing connections
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <addr>    is the IPv4 address HAProxy will bind to before connecting to a
    #               server. This address is also used as a source for health checks.
    #               The default value of 0.0.0.0 means that the system will select
    #               the most appropriate address to reach its destination.
    #
    #     <port>    is an optional port. It is normally not needed but may be useful
    #               in some very specific contexts. The default value of zero means
    #               the system will select a free port. Note that port ranges are not
    #               supported in the backend. If you want to force port ranges, you
    #               have to specify them on each "server" line.
    #
    #     <addr2>   is the IP address to present to the server when connections are
    #               forwarded in full transparent proxy mode. This is currently only
    #               supported on some patched Linux kernels. When this address is
    #               specified, clients connecting to the server will be presented
    #               with this address, while health checks will still use the address
    #               <addr>.
    #
    #     <port2>   is the optional port to present to the server when connections
    #               are forwarded in full transparent proxy mode (see <addr2> above).
    #               The default value of zero means the system will select a free
    #               port.
    #
    #     <hdr>     is the name of a HTTP header in which to fetch the IP to bind to.
    #               This is the name of a comma-separated header list which can
    #               contain multiple IP addresses. By default, the last occurrence is
    #               used. This is designed to work with the X-Forwarded-For header
    #               and to automatically bind to the the client's IP address as seen
    #               by previous proxy, typically Stunnel. In order to use another
    #               occurrence from the last one, please see the <occ> parameter
    #               below. When the header (or occurrence) is not found, no binding
    #               is performed so that the proxy's default IP address is used. Also
    #               keep in mind that the header name is case insensitive, as for any
    #               HTTP header.
    #
    #     <occ>     is the occurrence number of a value to be used in a multi-value
    #               header. This is to be used in conjunction with "hdr_ip(<hdr>)",
    #               in order to specificy which occurrence to use for the source IP
    #               address. Positive values indicate a position from the first
    #               occurrence, 1 being the first one. Negative values indicate
    #               positions relative to the last one, -1 being the last one. This
    #               is helpful for situations where an X-Forwarded-For header is set
    #               at the entry point of an infrastructure and must be used several
    #               proxy layers away. When this value is not specified, -1 is
    #               assumed. Passing a zero here disables the feature.
    #
    #     <name>    is an optional interface name to which to bind to for outgoing
    #               traffic. On systems supporting this features (currently, only
    #               Linux), this allows one to bind all traffic to the server to
    #               this interface even if it is not the one the system would select
    #               based on routing tables. This should be used with extreme care.
    #               Note that using this option requires root privileges.
    #
    #   The "source" keyword is useful in complex environments where a specific
    #   address only is allowed to connect to the servers. It may be needed when a
    #   private address must be used through a public gateway for instance, and it is
    #   known that the system cannot determine the adequate source address by itself.
    #
    #   An extension which is available on certain patched Linux kernels may be used
    #   through the "usesrc" optional keyword. It makes it possible to connect to the
    #   servers with an IP address which does not belong to the system itself. This
    #   is called "full transparent proxy mode". For this to work, the destination
    #   servers have to route their traffic back to this address through the machine
    #   running HAProxy, and IP forwarding must generally be enabled on this machine.
    #
    #   In this "full transparent proxy" mode, it is possible to force a specific IP
    #   address to be presented to the servers. This is not much used in fact. A more
    #   common use is to tell HAProxy to present the client's IP address. For this,
    #   there are two methods :
    #
    #     - present the client's IP and port addresses. This is the most transparent
    #       mode, but it can cause problems when IP connection tracking is enabled on
    #       the machine, because a same connection may be seen twice with different
    #       states. However, this solution presents the huge advantage of not
    #       limiting the system to the 64k outgoing address+port couples, because all
    #       of the client ranges may be used.
    #
    #     - present only the client's IP address and select a spare port. This
    #       solution is still quite elegant but slightly less transparent (downstream
    #       firewalls logs will not match upstream's). It also presents the downside
    #       of limiting the number of concurrent connections to the usual 64k ports.
    #       However, since the upstream and downstream ports are different, local IP
    #       connection tracking on the machine will not be upset by the reuse of the
    #       same session.
    #
    #   Note that depending on the transparent proxy technology used, it may be
    #   required to force the source address. In fact, cttproxy version 2 requires an
    #   IP address in <addr> above, and does not support setting of "0.0.0.0" as the
    #   IP address because it creates NAT entries which much match the exact outgoing
    #   address. Tproxy version 4 and some other kernel patches which work in pure
    #   forwarding mode generally will not have this limitation.
    #
    #   This option sets the default source for all servers in the backend. It may
    #   also be specified in a "defaults" section. Finer source address specification
    #   is possible at the server level using the "source" server option. Refer to
    #   section 5 for more information.
    #
    #   Examples :
    #         backend private
    #             # Connect to the servers using our 192.168.1.200 source address
    #             source 192.168.1.200
    #
    #         backend transparent_ssl1
    #             # Connect to the SSL farm from the client's source address
    #             source 192.168.1.200 usesrc clientip
    #
    #         backend transparent_ssl2
    #             # Connect to the SSL farm from the client's source address and port
    #             # not recommended if IP conntrack is present on the local machine.
    #             source 192.168.1.200 usesrc client
    #
    #         backend transparent_ssl3
    #             # Connect to the SSL farm from the client's source address. It
    #             # is more conntrack-friendly.
    #             source 192.168.1.200 usesrc clientip
    #
    #         backend transparent_smtp
    #             # Connect to the SMTP farm from the client's source address/port
    #             # with Tproxy version 4.
    #             source 0.0.0.0 usesrc clientip
    #
    #         backend transparent_http
    #             # Connect to the servers using the client's IP as seen by previous
    #             # proxy.
    #             source 0.0.0.0 usesrc hdr_ip(x-forwarded-for,-1)
    #
    #   See also : the "source" server option in section 5, the Tproxy patches for
    #              the Linux kernel on www.balabit.com, the "bind" keyword.
    #
    attr_accessor :source

    #
    # stats auth <user>:<passwd>
    #   Enable statistics with authentication and grant access to an account
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <user>    is a user name to grant access to
    #
    #     <passwd>  is the cleartext password associated to this user
    #
    #   This statement enables statistics with default settings, and restricts access
    #   to declared users only. It may be repeated as many times as necessary to
    #   allow as many users as desired. When a user tries to access the statistics
    #   without a valid account, a "401 Forbidden" response will be returned so that
    #   the browser asks the user to provide a valid user and password. The real
    #   which will be returned to the browser is configurable using "stats realm".
    #
    #   Since the authentication method is HTTP Basic Authentication, the passwords
    #   circulate in cleartext on the network. Thus, it was decided that the
    #   configuration file would also use cleartext passwords to remind the users
    #   that those ones should not be sensible and not shared with any other account.
    #
    #   It is also possible to reduce the scope of the proxies which appear in the
    #   report using "stats scope".
    #
    #   Though this statement alone is enough to enable statistics reporting, it is
    #   recommended to set all other settings in order to avoid relying on default
    #   unobvious parameters.
    #
    #   Example :
    #     # public access (limited to this backend only)
    #     backend public_www
    #         server srv1 192.168.0.1:80
    #         stats enable
    #         stats hide-version
    #         stats scope   .
    #         stats uri     /admin?stats
    #         stats realm   Haproxy\ Statistics
    #         stats auth    admin1:AdMiN123
    #         stats auth    admin2:AdMiN321
    #
    #     # internal monitoring access (unlimited)
    #     backend private_monitoring
    #         stats enable
    #         stats uri     /admin?stats
    #         stats refresh 5s
    #
    #   See also : "stats enable", "stats realm", "stats scope", "stats uri"
    #
    attr_accessor :stats_auth

    #
    # stats enable
    #   Enable statistics reporting with default settings
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments : none
    #
    #   This statement enables statistics reporting with default settings defined
    #   at build time. Unless stated otherwise, these settings are used :
    #     - stats uri   : /haproxy?stats
    #     - stats realm : "HAProxy Statistics"
    #     - stats auth  : no authentication
    #     - stats scope : no restriction
    #
    #   Though this statement alone is enough to enable statistics reporting, it is
    #   recommended to set all other settings in order to avoid relying on default
    #   unobvious parameters.
    #
    #   Example :
    #     # public access (limited to this backend only)
    #     backend public_www
    #         server srv1 192.168.0.1:80
    #         stats enable
    #         stats hide-version
    #         stats scope   .
    #         stats uri     /admin?stats
    #         stats realm   Haproxy\ Statistics
    #         stats auth    admin1:AdMiN123
    #         stats auth    admin2:AdMiN321
    #
    #     # internal monitoring access (unlimited)
    #     backend private_monitoring
    #         stats enable
    #         stats uri     /admin?stats
    #         stats refresh 5s
    #
    #   See also : "stats auth", "stats realm", "stats uri"
    #
    attr_accessor :stats_enable

    #
    # stats hide-version
    #   Enable statistics and hide HAProxy version reporting
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments : none
    #
    #   By default, the stats page reports some useful status information along with
    #   the statistics. Among them is HAProxy's version. However, it is generally
    #   considered dangerous to report precise version to anyone, as it can help them
    #   target known weaknesses with specific attacks. The "stats hide-version"
    #   statement removes the version from the statistics report. This is recommended
    #   for public sites or any site with a weak login/password.
    #
    #   Though this statement alone is enough to enable statistics reporting, it is
    #   recommended to set all other settings in order to avoid relying on default
    #   unobvious parameters.
    #
    #   Example :
    #     # public access (limited to this backend only)
    #     backend public_www
    #         server srv1 192.168.0.1:80
    #         stats enable
    #         stats hide-version
    #         stats scope   .
    #         stats uri     /admin?stats
    #         stats realm   Haproxy\ Statistics
    #         stats auth    admin1:AdMiN123
    #         stats auth    admin2:AdMiN321
    #
    #     # internal monitoring access (unlimited)
    #     backend private_monitoring
    #         stats enable
    #         stats uri     /admin?stats
    #         stats refresh 5s
    #
    #   See also : "stats auth", "stats enable", "stats realm", "stats uri"
    #
    attr_accessor :stats_hide_version

    #
    # stats realm <realm>
    #   Enable statistics and set authentication realm
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <realm>   is the name of the HTTP Basic Authentication realm reported to
    #               the browser. The browser uses it to display it in the pop-up
    #               inviting the user to enter a valid username and password.
    #
    #   The realm is read as a single word, so any spaces in it should be escaped
    #   using a backslash ('\').
    #
    #   This statement is useful only in conjunction with "stats auth" since it is
    #   only related to authentication.
    #
    #   Though this statement alone is enough to enable statistics reporting, it is
    #   recommended to set all other settings in order to avoid relying on default
    #   unobvious parameters.
    #
    #   Example :
    #     # public access (limited to this backend only)
    #     backend public_www
    #         server srv1 192.168.0.1:80
    #         stats enable
    #         stats hide-version
    #         stats scope   .
    #         stats uri     /admin?stats
    #         stats realm   Haproxy\ Statistics
    #         stats auth    admin1:AdMiN123
    #         stats auth    admin2:AdMiN321
    #
    #     # internal monitoring access (unlimited)
    #     backend private_monitoring
    #         stats enable
    #         stats uri     /admin?stats
    #         stats refresh 5s
    #
    #   See also : "stats auth", "stats enable", "stats uri"
    #
    attr_accessor :stats_realm

    #
    # stats refresh <delay>
    #   Enable statistics with automatic refresh
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <delay>   is the suggested refresh delay, specified in seconds, which will
    #               be returned to the browser consulting the report page. While the
    #               browser is free to apply any delay, it will generally respect it
    #               and refresh the page this every seconds. The refresh interval may
    #               be specified in any other non-default time unit, by suffixing the
    #               unit after the value, as explained at the top of this document.
    #
    #   This statement is useful on monitoring displays with a permanent page
    #   reporting the load balancer's activity. When set, the HTML report page will
    #   include a link "refresh"/"stop refresh" so that the user can select whether
    #   he wants automatic refresh of the page or not.
    #
    #   Though this statement alone is enough to enable statistics reporting, it is
    #   recommended to set all other settings in order to avoid relying on default
    #   unobvious parameters.
    #
    #   Example :
    #     # public access (limited to this backend only)
    #     backend public_www
    #         server srv1 192.168.0.1:80
    #         stats enable
    #         stats hide-version
    #         stats scope   .
    #         stats uri     /admin?stats
    #         stats realm   Haproxy\ Statistics
    #         stats auth    admin1:AdMiN123
    #         stats auth    admin2:AdMiN321
    #
    #     # internal monitoring access (unlimited)
    #     backend private_monitoring
    #         stats enable
    #         stats uri     /admin?stats
    #         stats refresh 5s
    #
    #   See also : "stats auth", "stats enable", "stats realm", "stats uri"
    #
    attr_accessor :stats_refresh

    #
    # stats scope { <name> | "." }
    #   Enable statistics and limit access scope
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <name>    is the name of a listen, frontend or backend section to be
    #               reported. The special name "." (a single dot) designates the
    #               section in which the statement appears.
    #
    #   When this statement is specified, only the sections enumerated with this
    #   statement will appear in the report. All other ones will be hidden. This
    #   statement may appear as many times as needed if multiple sections need to be
    #   reported. Please note that the name checking is performed as simple string
    #   comparisons, and that it is never checked that a give section name really
    #   exists.
    #
    #   Though this statement alone is enough to enable statistics reporting, it is
    #   recommended to set all other settings in order to avoid relying on default
    #   unobvious parameters.
    #
    #   Example :
    #     # public access (limited to this backend only)
    #     backend public_www
    #         server srv1 192.168.0.1:80
    #         stats enable
    #         stats hide-version
    #         stats scope   .
    #         stats uri     /admin?stats
    #         stats realm   Haproxy\ Statistics
    #         stats auth    admin1:AdMiN123
    #         stats auth    admin2:AdMiN321
    #
    #     # internal monitoring access (unlimited)
    #     backend private_monitoring
    #         stats enable
    #         stats uri     /admin?stats
    #         stats refresh 5s
    #
    #   See also : "stats auth", "stats enable", "stats realm", "stats uri"
    #
    attr_accessor :stats_scope

    #
    # stats show-desc [ <desc> ]
    #   Enable reporting of a description on the statistics page.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #
    #     <desc>    is an optional description to be reported. If unspecified, the
    #               description from global section is automatically used instead.
    #
    #   This statement is useful for users that offer shared services to their
    #   customers, where node or description should be different for each customer.
    #
    #   Though this statement alone is enough to enable statistics reporting, it is
    #   recommended to set all other settings in order to avoid relying on default
    #   unobvious parameters.
    #
    #   Example :
    #     # internal monitoring access (unlimited)
    #     backend private_monitoring
    #         stats enable
    #         stats show-desc Master node for Europe, Asia, Africa
    #         stats uri       /admin?stats
    #         stats refresh   5s
    #
    #   See also: "show-node", "stats enable", "stats uri" and "description" in
    #             global section.
    #
    attr_accessor :stats_show_desc

    #
    # stats show-legends
    #   Enable reporting additional informations on the statistics page :
    #     - cap: capabilities (proxy)
    #     - mode: one of tcp, http or health (proxy)
    #     - id: SNMP ID (proxy, socket, server)
    #     - IP (socket, server)
    #     - cookie (backend, server)
    #
    #   Though this statement alone is enough to enable statistics reporting, it is
    #   recommended to set all other settings in order to avoid relying on default
    #   unobvious parameters.
    #
    #   See also: "stats enable", "stats uri".
    #
    attr_accessor :stats_show_legends

    #
    # stats show-node [ <name> ]
    #   Enable reporting of a host name on the statistics page.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments:
    #     <name>    is an optional name to be reported. If unspecified, the
    #               node name from global section is automatically used instead.
    #
    #   This statement is useful for users that offer shared services to their
    #   customers, where node or description might be different on a stats page
    #   provided for each customer.
    #
    #   Though this statement alone is enough to enable statistics reporting, it is
    #   recommended to set all other settings in order to avoid relying on default
    #   unobvious parameters.
    #
    #   Example:
    #     # internal monitoring access (unlimited)
    #     backend private_monitoring
    #         stats enable
    #         stats show-node Europe-1
    #         stats uri       /admin?stats
    #         stats refresh   5s
    #
    #   See also: "show-desc", "stats enable", "stats uri", and "node" in global
    #             section.
    #
    attr_accessor :stats_show_node

    #
    # stats uri <prefix>
    #   Enable statistics and define the URI prefix to access them
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <prefix>  is the prefix of any URI which will be redirected to stats. This
    #               prefix may contain a question mark ('?') to indicate part of a
    #               query string.
    #
    #   The statistics URI is intercepted on the relayed traffic, so it appears as a
    #   page within the normal application. It is strongly advised to ensure that the
    #   selected URI will never appear in the application, otherwise it will never be
    #   possible to reach it in the application.
    #
    #   The default URI compiled in haproxy is "/haproxy?stats", but this may be
    #   changed at build time, so it's better to always explicitly specify it here.
    #   It is generally a good idea to include a question mark in the URI so that
    #   intermediate proxies refrain from caching the results. Also, since any string
    #   beginning with the prefix will be accepted as a stats request, the question
    #   mark helps ensuring that no valid URI will begin with the same words.
    #
    #   It is sometimes very convenient to use "/" as the URI prefix, and put that
    #   statement in a "listen" instance of its own. That makes it easy to dedicate
    #   an address or a port to statistics only.
    #
    #   Though this statement alone is enough to enable statistics reporting, it is
    #   recommended to set all other settings in order to avoid relying on default
    #   unobvious parameters.
    #
    #   Example :
    #     # public access (limited to this backend only)
    #     backend public_www
    #         server srv1 192.168.0.1:80
    #         stats enable
    #         stats hide-version
    #         stats scope   .
    #         stats uri     /admin?stats
    #         stats realm   Haproxy\ Statistics
    #         stats auth    admin1:AdMiN123
    #         stats auth    admin2:AdMiN321
    #
    #     # internal monitoring access (unlimited)
    #     backend private_monitoring
    #         stats enable
    #         stats uri     /admin?stats
    #         stats refresh 5s
    #
    #   See also : "stats auth", "stats enable", "stats realm"
    #
    attr_accessor :stats_uri

    #
    # timeout check <timeout>
    #   Set additional check timeout, but only after a connection has been already
    #   established.
    #
    #   May be used in sections:    defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments:
    #     <timeout> is the timeout value specified in milliseconds by default, but
    #               can be in any other unit if the number is suffixed by the unit,
    #               as explained at the top of this document.
    #
    #   If set, haproxy uses min("timeout connect", "inter") as a connect timeout
    #   for check and "timeout check" as an additional read timeout. The "min" is
    #   used so that people running with *very* long "timeout connect" (eg. those
    #   who needed this due to the queue or tarpit) do not slow down their checks.
    #   (Please also note that there is no valid reason to have such long connect
    #   timeouts, because "timeout queue" and "timeout tarpit" can always be used to
    #   avoid that).
    #
    #   If "timeout check" is not set haproxy uses "inter" for complete check
    #   timeout (connect + read) exactly like all <1.3.15 version.
    #
    #   In most cases check request is much simpler and faster to handle than normal
    #   requests and people may want to kick out laggy servers so this timeout should
    #   be smaller than "timeout server".
    #
    #   This parameter is specific to backends, but can be specified once for all in
    #   "defaults" sections. This is in fact one of the easiest solutions not to
    #   forget about it.
    #
    #   See also: "timeout connect", "timeout queue", "timeout server",
    #             "timeout tarpit".
    #
    attr_accessor :timeout_check

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
    # timeout connect <timeout>
    # timeout contimeout <timeout> (deprecated)
    #   Set the maximum time to wait for a connection attempt to a server to succeed.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <timeout> is the timeout value specified in milliseconds by default, but
    #               can be in any other unit if the number is suffixed by the unit,
    #               as explained at the top of this document.
    #
    #   If the server is located on the same LAN as haproxy, the connection should be
    #   immediate (less than a few milliseconds). Anyway, it is a good practice to
    #   cover one or several TCP packet losses by specifying timeouts that are
    #   slightly above multiples of 3 seconds (eg: 4 or 5 seconds). By default, the
    #   connect timeout also presets both queue and tarpit timeouts to the same value
    #   if these have not been specified.
    #
    #   This parameter is specific to backends, but can be specified once for all in
    #   "defaults" sections. This is in fact one of the easiest solutions not to
    #   forget about it. An unspecified timeout results in an infinite timeout, which
    #   is not recommended. Such a usage is accepted and works but reports a warning
    #   during startup because it may results in accumulation of failed sessions in
    #   the system if the system's timeouts are not configured either.
    #
    #   This parameter replaces the old, deprecated "contimeout". It is recommended
    #   to use it to write new configurations. The form "timeout contimeout" is
    #   provided only by backwards compatibility but its use is strongly discouraged.
    #
    #   See also: "timeout check", "timeout queue", "timeout server", "contimeout",
    #             "timeout tarpit".
    #
    attr_accessor :timeout_connect

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
    # timeout queue <timeout>
    #   Set the maximum time to wait in the queue for a connection slot to be free
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <timeout> is the timeout value specified in milliseconds by default, but
    #               can be in any other unit if the number is suffixed by the unit,
    #               as explained at the top of this document.
    #
    #   When a server's maxconn is reached, connections are left pending in a queue
    #   which may be server-specific or global to the backend. In order not to wait
    #   indefinitely, a timeout is applied to requests pending in the queue. If the
    #   timeout is reached, it is considered that the request will almost never be
    #   served, so it is dropped and a 503 error is returned to the client.
    #
    #   The "timeout queue" statement allows to fix the maximum time for a request to
    #   be left pending in a queue. If unspecified, the same value as the backend's
    #   connection timeout ("timeout connect") is used, for backwards compatibility
    #   with older versions with no "timeout queue" parameter.
    #
    #   See also : "timeout connect", "contimeout".
    #
    attr_accessor :timeout_queue

    #
    # timeout server <timeout>
    # timeout srvtimeout <timeout> (deprecated)
    #   Set the maximum inactivity time on the server side.
    #   May be used in sections :   defaults | frontend | listen | backend
    #                                  yes   |    no    |   yes  |   yes
    #   Arguments :
    #     <timeout> is the timeout value specified in milliseconds by default, but
    #               can be in any other unit if the number is suffixed by the unit,
    #               as explained at the top of this document.
    #
    #   The inactivity timeout applies when the server is expected to acknowledge or
    #   send data. In HTTP mode, this timeout is particularly important to consider
    #   during the first phase of the server's response, when it has to send the
    #   headers, as it directly represents the server's processing time for the
    #   request. To find out what value to put there, it's often good to start with
    #   what would be considered as unacceptable response times, then check the logs
    #   to observe the response time distribution, and adjust the value accordingly.
    #
    #   The value is specified in milliseconds by default, but can be in any other
    #   unit if the number is suffixed by the unit, as specified at the top of this
    #   document. In TCP mode (and to a lesser extent, in HTTP mode), it is highly
    #   recommended that the client timeout remains equal to the server timeout in
    #   order to avoid complex situations to debug. Whatever the expected server
    #   response times, it is a good practice to cover at least one or several TCP
    #   packet losses by specifying timeouts that are slightly above multiples of 3
    #   seconds (eg: 4 or 5 seconds minimum).
    #
    #   This parameter is specific to backends, but can be specified once for all in
    #   "defaults" sections. This is in fact one of the easiest solutions not to
    #   forget about it. An unspecified timeout results in an infinite timeout, which
    #   is not recommended. Such a usage is accepted and works but reports a warning
    #   during startup because it may results in accumulation of expired sessions in
    #   the system if the system's timeouts are not configured either.
    #
    #   This parameter replaces the old, deprecated "srvtimeout". It is recommended
    #   to use it to write new configurations. The form "timeout srvtimeout" is
    #   provided only by backwards compatibility but its use is strongly discouraged.
    #
    #   See also : "srvtimeout", "timeout client".
    #
    attr_accessor :timeout_server

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

    #
    # name <name>
    #   The defaults name is encouraged for better readability.
    #
    attr_accessor :name

    #
    # Returns a new RhaproxyDefaults Object
    #
    def initialize()
    end

    #
    # Compile the HAproxy defaults configuration
    #
    def config

      conf = option_string()

      return conf

    end

    private

    def option_string()

      unless @name
        @name = ""
      end

      ostring = "  " + "defaults " + @name.to_s + "\n"

      if @backlog
        ostring += "    " + "backlog " + @backlog.to_s + "\n"
      end

      if @balance
        ostring += "    " + "balance " + @balance.to_s + "\n"
      end

      if @bind_process
        ostring += "    " + "bind-process " + @bind_process.to_s + "\n"
      end

      if @cookie
        ostring += "    " + "cookie " + @cookie.to_s + "\n"
      end

      if @default_server
        ostring += "    " + "default-server " + @default_server.to_s + "\n"
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

      if @fullconn
        ostring += "    " + "fullconn " + @fullconn.to_s + "\n"
      end

      if @grace
        ostring += "    " + "grace " + @grace.to_s + "\n"
      end

      if @hash_type
        ostring += "    " + "hash_type " + @hash_type.to_s + "\n"
      end

      if @http_check_disable_on_404
        ostring += "    " + "http-check disable-on-404 " + "\n"
      end

      if @http_check_send_state
        ostring += "    " + "http-check send-state " + "\n"
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

      if @option_abortonclose
        ostring += "    " + "option abortonclose " + "\n"
      end

      if @option_accept_invalid_http_request
        ostring += "    " + "option accept-invalid-http-request " + "\n"
      end

      if @option_accept_invalid_http_response
        ostring += "    " + "option accept-invalid-http-response " + "\n"
      end

      if @option_allbackups
        ostring += "    " + "option allbackups " + "\n"
      end

      if @option_checkcache
        ostring += "    " + "option checkcache " + "\n"
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

      if @option_httpchk
        ostring += "    " + "option httpchk " + @option_httpchk.to_s + "\n"
      end

      if @option_httpchk_complete
        ostring += "    " + "option httpchk " + "\n"
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

      if @option_ldap_check
        ostring += "    " + "option ldap-check " + "\n"
      end

      if @option_log_health_checks
        ostring += "    " + "option log-health-checks " + "\n"
      end

      if @option_log_separate_errors
        ostring += "    " + "option log-separate-errors " + "\n"
      end

      if @option_logasap
        ostring += "    " + "option logasap " + "\n"
      end

      if @option_mysql_check
        ostring += "    " + "option mysql-check " + @option_mysql_check.to_s + "\n"
      end

      if @option_nolinger
        ostring += "    " + "option nolinger " + "\n"
      end

      if @option_originalto
        ostring += "    " + "option originalto " + @option_originalto.to_s + "\n"
      end

      if @option_persist
        ostring += "    " + "option persist " + "\n"
      end

      if @option_redispatch
        ostring += "    " + "option redispatch " + "\n"
      end

      if @option_smtpchk
        ostring += "    " + "option smtpchk " + @option_smtpchk.to_s + "\n"
      end

      if @option_smtpchk_complete
        ostring += "    " + "option smtpchk " + "\n"
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

      if @option_srvtcpka
        ostring += "    " + "option srvtcpka " + "\n"
      end

      if @option_ssl_hello_chk
        ostring += "    " + "option ssl-hello-chk " + "\n"
      end

      if @option_tcp_smart_accept
        ostring += "    " + "option tcp-smart-accept " + "\n"
      end

      if @option_tcp_smart_connect
        ostring += "    " + "option tcp-smart-connect " + "\n"
      end

      if @option_tcpka
        ostring += "    " + "option tcpka " + "\n"
      end

      if @option_tcplog
        ostring += "    " + "option tcplog " + "\n"
      end

      if @option_transparent
        ostring += "    " + "option transparent " + "\n"
      end

      if @persist_rdp_cookie
        ostring += "    " + "persist rdp-cookie " + @persist_rdp_cookie.to_s + "\n"
      end

      if @persist_rdp_cookie_msts
        ostring += "    " + "persist rdp-cookie " + "\n"
      end

      if @rate_limit_sessions
        ostring += "    " + "rate-limit sessions " + @rate_limit_sessions.to_s + "\n"
      end

      if @retries
        ostring += "    " + "retries " + @retries.to_s + "\n"
      end

      if @source
        ostring += "    " + "source " + @source.to_s + "\n"
      end

      if @stats_auth
        ostring += "    " + "stats auth " + @stats_auth.to_s + "\n"
      end

      if @stats_enable
        ostring += "    " + "stats enable " + "\n"
      end

      if @stats_hide_version
        ostring += "    " + "stats hide-version " + "\n"
      end

      if @stats_realm
        ostring += "    " + "stats realm " + @stats_realm.to_s + "\n"
      end

      if @stats_refresh
        ostring += "    " + "stats refresh " + @stats_refresh.to_s + "\n"
      end

      if @stats_scope
        ostring += "    " + "stats scope " + @stats_scope.to_s + "\n"
      end

      if @stats_show_desc
        ostring += "    " + "stats show-desc " + @stats_show_desc.to_s + "\n"
      end

      if @stats_show_legends
        ostring += "    " + "stats show-legends " + "\n"
      end

      if @stats_show_node
        ostring += "    " + "stats show-node " + @stats_show_node.to_s + "\n"
      end

      if @stats_show_node_global
        ostring += "    " + "stats show-node " + "\n"
      end

      if @stats_uri
        ostring += "    " + "stats uri " + @stats_uri.to_s + "\n"
      end

      if @timeout_check
        ostring += "    " + "timeout check " + @timeout_check.to_s + "\n"
      end

      if @timeout_client
        ostring += "    " + "timeout client " + @timeout_client.to_s + "\n"
      end

      if @timeout_connect
        ostring += "    " + "timeout connect " + @timeout_connect.to_s + "\n"
      end

      if @timeout_http_keep_alive
        ostring += "    " + "timeout http-keep-alive " + @timeout_http_keep_alive.to_s + "\n"
      end

      if @timeout_http_request
        ostring += "    " + "timeout http-request " + @timeout_http_request.to_s + "\n"
      end

      if @timeout_queue
        ostring += "    " + "timeout queue " + @timeout_queue.to_s + "\n"
      end

      if @timeout_server
        ostring += "    " + "timeout server " + @timeout_server.to_s + "\n"
      end

      if @timeout_tarpit
        ostring += "    " + "timeout tarpit " + @timeout_tarpit.to_s + "\n"
      end

      ostring += "\n"

      return ostring

    end

  end

