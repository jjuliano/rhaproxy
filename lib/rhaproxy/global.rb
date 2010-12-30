  # = rhaproxy - A HAproxy gem for Ruby
  #
  # Homepage::  http://github.com/jjuliano/rhaproxy
  # Author::    Joel Bryan Juliano
  # Copyright:: (cc) 2011 Joel Bryan Juliano
  # License::   MIT

  #
  # class RhaproxyGlobal.new( array, str, array)
  #

  #
  # Parameters in the "global" section are process-wide and often OS-specific. They
  # are generally set once for all and do not need being changed once correct. Some
  # of them have command-line equivalents.
  #
  class RhaproxyGlobal

    #
    # chroot <jail dir>
    #   Changes current directory to <jail dir> and performs a chroot() there before
    #   dropping privileges. This increases the security level in case an unknown
    #   vulnerability would be exploited, since it would make it very hard for the
    #   attacker to exploit the system. This only works when the process is started
    #   with superuser privileges. It is important to ensure that <jail_dir> is both
    #   empty and unwritable to anyone.
    #
    attr_accessor :chroot

    #
    # daemon
    #   Makes the process fork into background. This is the recommended mode of
    #   operation. It is equivalent to the command line "-D" argument. It can be
    #   disabled by the command line "-db" argument.
    #
    attr_accessor :daemon

    #
    # gid <number>
    #   Changes the process' group ID to <number>. It is recommended that the group
    #   ID is dedicated to HAProxy or to a small set of similar daemons. HAProxy must
    #   be started with a user belonging to this group, or with superuser privileges.
    #   See also "group" and "uid".
    #
    attr_accessor :gid

    #
    # group <group name>
    #   Similar to "gid" but uses the GID of group name <group name> from /etc/group.
    #   See also "gid" and "user".
    #
    attr_accessor :group

    #
    # log <address> <facility> [max level [min level]]
    #   Adds a global syslog server. Up to two global servers can be defined. They
    #   will receive logs for startups and exits, as well as all logs from proxies
    #   configured with "log global".
    #
    #   <address> can be one of:
    #
    #         - An IPv4 address optionally followed by a colon and a UDP port. If
    #           no port is specified, 514 is used by default (the standard syslog
    #           port).
    #
    #         - A filesystem path to a UNIX domain socket, keeping in mind
    #           considerations for chroot (be sure the path is accessible inside
    #           the chroot) and uid/gid (be sure the path is appropriately
    #           writeable).
    #
    #   <facility> must be one of the 24 standard syslog facilities :
    #
    #           kern   user   mail   daemon auth   syslog lpr    news
    #           uucp   cron   auth2  ftp    ntp    audit  alert  cron2
    #           local0 local1 local2 local3 local4 local5 local6 local7
    #
    #   An optional level can be specified to filter outgoing messages. By default,
    #   all messages are sent. If a maximum level is specified, only messages with a
    #   severity at least as important as this level will be sent. An optional minimum
    #   level can be specified. If it is set, logs emitted with a more severe level
    #   than this one will be capped to this level. This is used to avoid sending
    #   "emerg" messages on all terminals on some default syslog configurations.
    #   Eight levels are known :
    #
    # 	  emerg  alert  crit   err    warning notice info  debug
    #
    attr_accessor :log

    #
    # nbproc <number>
    #   Creates <number> processes when going daemon. This requires the "daemon"
    #   mode. By default, only one process is created, which is the recommended mode
    #   of operation. For systems limited to small sets of file descriptors per
    #   process, it may be needed to fork multiple daemons. USING MULTIPLE PROCESSES
    #   IS HARDER TO DEBUG AND IS REALLY DISCOURAGED. See also "daemon".
    #
    attr_accessor :nbproc

    #
    # pidfile <pidfile>
    #   Writes pids of all daemons into file <pidfile>. This option is equivalent to
    #   the "-p" command line argument. The file must be accessible to the user
    #   starting the process. See also "daemon".
    #
    attr_accessor :pidfile

    #
    # uid <number>
    #   Changes the process' user ID to <number>. It is recommended that the user ID
    #   is dedicated to HAProxy or to a small set of similar daemons. HAProxy must
    #   be started with superuser privileges in order to be able to switch to another
    #   one. See also "gid" and "user".
    #
    attr_accessor :uid

    #
    # ulimit-n <number>
    #   Sets the maximum number of per-process file-descriptors to <number>. By
    #   default, it is automatically computed, so it is recommended not to use this
    #   option.
    #
    attr_accessor :ulimit_n

    #
    # user <user name>
    #   Similar to "uid" but uses the UID of user name <user name> from /etc/passwd.
    #   See also "uid" and "group".
    #
    attr_accessor :user

    #
    # stats socket <path> [(uid | user) <uid>] [(gid | group) <gid>] [mode <mode>]
    #   [level <level>]
    #
    #   Creates a UNIX socket in stream mode at location <path>. Any previously
    #   existing socket will be backed up then replaced. Connections to this socket
    #   will return various statistics outputs and even allow some commands to be
    #   issued. Please consult section 9.2 "Unix Socket commands" for more details.
    #
    #   An optional "level" parameter can be specified to restrict the nature of
    #   the commands that can be issued on the socket :
    #     - "user" is the least privileged level ; only non-sensitive stats can be
    #       read, and no change is allowed. It would make sense on systems where it
    #       is not easy to restrict access to the socket.
    #
    #     - "operator" is the default level and fits most common uses. All data can
    #       be read, and only non-sensible changes are permitted (eg: clear max
    #       counters).
    #
    #     - "admin" should be used with care, as everything is permitted (eg: clear
    #       all counters).
    #
    #   On platforms which support it, it is possible to restrict access to this
    #   socket by specifying numerical IDs after "uid" and "gid", or valid user and
    #   group names after the "user" and "group" keywords. It is also possible to
    #   restrict permissions on the socket by passing an octal value after the "mode"
    #   keyword (same syntax as chmod). Depending on the platform, the permissions on
    #   the socket will be inherited from the directory which hosts it, or from the
    #   user the process is started with.
    #
    attr_accessor :stats_socket

    #
    # stats timeout <timeout, in milliseconds>
    #   The default timeout on the stats socket is set to 10 seconds. It is possible
    #   to change this value with "stats timeout". The value must be passed in
    #   milliseconds, or be suffixed by a time unit among { us, ms, s, m, h, d }.
    #
    attr_accessor :stats_timeout

    #
    # stats maxconn <connections>
    #   By default, the stats socket is limited to 10 concurrent connections. It is
    #   possible to change this value with "stats maxconn".
    #
    attr_accessor :stats_maxconn

    #
    # node <name>
    #   Only letters, digits, hyphen and underscore are allowed, like in DNS names.
    #
    #   This statement is useful in HA configurations where two or more processes or
    #   servers share the same IP address. By setting a different node-name on all
    #   nodes, it becomes easy to immediately spot what server is handling the
    #   traffic.
    #
    attr_accessor :node

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
    # unix-bind [ prefix <prefix> ] [ mode <mode> ] [ user <user> ] [ uid <uid> ]
    #           [ group <group> ] [ gid <gid> ]
    #
    #   Fixes common settings to UNIX listening sockets declared in "bind" statements.
    #   This is mainly used to simplify declaration of those UNIX sockets and reduce
    #   the risk of errors, since those settings are most commonly required but are
    #   also process-specific. The <prefix> setting can be used to force all socket
    #   path to be relative to that directory. This might be needed to access another
    #   component's chroot. Note that those paths are resolved before haproxy chroots
    #   itself, so they are absolute. The <mode>, <user>, <uid>, <group> and <gid>
    #   all have the same meaning as their homonyms used by the "bind" statement. If
    #   both are specified, the "bind" statement has priority, meaning that the
    #   "unix-bind" settings may be seen as process-wide default settings.
    #
    attr_accessor :unix_bind

    #
    # maxconn <number>
    #   Sets the maximum per-process number of concurrent connections to <number>. It
    #   is equivalent to the command-line argument "-n". Proxies will stop accepting
    #   connections when this limit is reached. The "ulimit-n" parameter is
    #   automatically adjusted according to this value. See also "ulimit-n".
    #
    attr_accessor :maxconn

    #
    # maxpipes <number>
    #   Sets the maximum per-process number of pipes to <number>. Currently, pipes
    #   are only used by kernel-based tcp splicing. Since a pipe contains two file
    #   descriptors, the "ulimit-n" value will be increased accordingly. The default
    #   value is maxconn/4, which seems to be more than enough for most heavy usages.
    #   The splice code dynamically allocates and releases pipes, and can fall back
    #   to standard copy, so setting this value too low may only impact performance.
    #
    attr_accessor :maxpipes

    #
    # noepoll
    #   Disables the use of the "epoll" event polling system on Linux. It is
    #   equivalent to the command-line argument "-de". The next polling system
    #   used will generally be "poll". See also "nosepoll", and "nopoll".
    #
    attr_accessor :noepoll

    #
    # nokqueue
    #   Disables the use of the "kqueue" event polling system on BSD. It is
    #   equivalent to the command-line argument "-dk". The next polling system
    #   used will generally be "poll". See also "nopoll".
    #
    attr_accessor :nokqueue

    #
    # nopoll
    #   Disables the use of the "poll" event polling system. It is equivalent to the
    #   command-line argument "-dp". The next polling system used will be "select".
    #   It should never be needed to disable "poll" since it's available on all
    #   platforms supported by HAProxy. See also "nosepoll", and "nopoll" and
    #   "nokqueue".
    #
    attr_accessor :nopoll

    #
    # nosepoll
    #   Disables the use of the "speculative epoll" event polling system on Linux. It
    #   is equivalent to the command-line argument "-ds". The next polling system
    #   used will generally be "epoll". See also "nosepoll", and "nopoll".
    #
    attr_accessor :nosepoll

    #
    # nosplice
    #   Disables the use of kernel tcp splicing between sockets on Linux. It is
    #   equivalent to the command line argument "-dS".  Data will then be copied
    #   using conventional and more portable recv/send calls. Kernel tcp splicing is
    #   limited to some very recent instances of kernel 2.6. Most versions between
    #   2.6.25 and 2.6.28 are buggy and will forward corrupted data, so they must not
    #   be used. This option makes it easier to globally disable kernel splicing in
    #   case of doubt. See also "option splice-auto", "option splice-request" and
    #   "option splice-response".
    #
    attr_accessor :nosplice

    #
    # spread-checks <0..50, in percent>
    #   Sometimes it is desirable to avoid sending health checks to servers at exact
    #   intervals, for instance when many logical servers are located on the same
    #   physical server. With the help of this parameter, it becomes possible to add
    #   some randomness in the check interval between 0 and +/- 50%. A value between
    #   2 and 5 seems to show good results. The default value remains at 0.
    #
    attr_accessor :spread_checks

    #
    # tune.bufsize <number>
    #   Sets the buffer size to this size (in bytes). Lower values allow more
    #   sessions to coexist in the same amount of RAM, and higher values allow some
    #   applications with very large cookies to work. The default value is 16384 and
    #   can be changed at build time. It is strongly recommended not to change this
    #   from the default value, as very low values will break some services such as
    #   statistics, and values larger than default size will increase memory usage,
    #   possibly causing the system to run out of memory. At least the global maxconn
    #   parameter should be decreased by the same factor as this one is increased.
    #
    attr_accessor :tune_bufsize

    #
    # tune.chksize <number>
    #   Sets the check buffer size to this size (in bytes). Higher values may help
    #   find string or regex patterns in very large pages, though doing so may imply
    #   more memory and CPU usage. The default value is 16384 and can be changed at
    #   build time. It is not recommended to change this value, but to use better
    #   checks whenever possible.
    #
    attr_accessor :tune_chksize

    #
    # tune.maxaccept <number>
    #   Sets the maximum number of consecutive accepts that a process may perform on
    #   a single wake up. High values give higher priority to high connection rates,
    #   while lower values give higher priority to already established connections.
    #   This value is limited to 100 by default in single process mode. However, in
    #   multi-process mode (nbproc > 1), it defaults to 8 so that when one process
    #   wakes up, it does not take all incoming connections for itself and leaves a
    #   part of them to other processes. Setting this value to -1 completely disables
    #   the limitation. It should normally not be needed to tweak this value.
    #
    attr_accessor :tune_maxaccept

    #
    # tune.maxpollevents <number>
    #   Sets the maximum amount of events that can be processed at once in a call to
    #   the polling system. The default value is adapted to the operating system. It
    #   has been noticed that reducing it below 200 tends to slightly decrease
    #   latency at the expense of network bandwidth, and increasing it above 200
    #   tends to trade latency for slightly increased bandwidth.
    #
    attr_accessor :tune_maxpollevents

    #
    # tune.maxrewrite <number>
    #   Sets the reserved buffer space to this size in bytes. The reserved space is
    #   used for header rewriting or appending. The first reads on sockets will never
    #   fill more than bufsize-maxrewrite. Historically it has defaulted to half of
    #   bufsize, though that does not make much sense since there are rarely large
    #   numbers of headers to add. Setting it too high prevents processing of large
    #   requests or responses. Setting it too low prevents addition of new headers
    #   to already large requests or to POST requests. It is generally wise to set it
    #   to about 1024. It is automatically readjusted to half of bufsize if it is
    #   larger than that. This means you don't have to worry about it when changing
    #   bufsize.
    #
    attr_accessor :tune_maxrewrite

    # tune.rcvbuf.client <number>
    #   Forces the kernel socket receive buffer size on the client or the server side
    #   to the specified value in bytes. This value applies to all TCP/HTTP frontends
    #   and backends. It should normally never be set, and the default size (0) lets
    #   the kernel autotune this value depending on the amount of available memory.
    #   However it can sometimes help to set it to very low values (eg: 4096) in
    #   order to save kernel memory by preventing it from buffering too large amounts
    #   of received data. Lower values will significantly increase CPU usage though.
    #
    attr_accessor :tune_rcvbuf_client

    # tune.rcvbuf.server <number>
    #   Forces the kernel socket receive buffer size on the client or the server side
    #   to the specified value in bytes. This value applies to all TCP/HTTP frontends
    #   and backends. It should normally never be set, and the default size (0) lets
    #   the kernel autotune this value depending on the amount of available memory.
    #   However it can sometimes help to set it to very low values (eg: 4096) in
    #   order to save kernel memory by preventing it from buffering too large amounts
    #   of received data. Lower values will significantly increase CPU usage though.
    #
    attr_accessor :tune_rcvbuf_server

    #
    # tune.sndbuf.client <number>
    #   Forces the kernel socket send buffer size on the client or the server side to
    #   the specified value in bytes. This value applies to all TCP/HTTP frontends
    #   and backends. It should normally never be set, and the default size (0) lets
    #   the kernel autotune this value depending on the amount of available memory.
    #   However it can sometimes help to set it to very low values (eg: 4096) in
    #   order to save kernel memory by preventing it from buffering too large amounts
    #   of received data. Lower values will significantly increase CPU usage though.
    #   Another use case is to prevent write timeouts with extremely slow clients due
    #   to the kernel waiting for a large part of the buffer to be read before
    #   notifying haproxy again.
    #
    attr_accessor :tune_sndbuf_client

    #
    # tune.sndbuf.server <number>
    #   Forces the kernel socket send buffer size on the client or the server side to
    #   the specified value in bytes. This value applies to all TCP/HTTP frontends
    #   and backends. It should normally never be set, and the default size (0) lets
    #   the kernel autotune this value depending on the amount of available memory.
    #   However it can sometimes help to set it to very low values (eg: 4096) in
    #   order to save kernel memory by preventing it from buffering too large amounts
    #   of received data. Lower values will significantly increase CPU usage though.
    #   Another use case is to prevent write timeouts with extremely slow clients due
    #   to the kernel waiting for a large part of the buffer to be read before
    #   notifying haproxy again.
    #
    attr_accessor :tune_sndbuf_server

    #
    # debug
    #   Enables debug mode which dumps to stdout all exchanges, and disables forking
    #   into background. It is the equivalent of the command-line argument "-d". It
    #   should never be used in a production configuration since it may prevent full
    #   system startup.
    #
    attr_accessor :debug

    #
    # quiet
    #   Do not display any message during startup. It is equivalent to the command-
    #   line argument "-q".
    #
    attr_accessor :quiet

    #
    # Returns a new RhaproxyGlobal Object
    #
    def initialize()
    end

    #
    # Compile the HAproxy global configuration
    #
    def config

      conf = option_string()

      return conf

    end

    private

    def option_string()

      ostring = "  " + "global " + "\n"

      if @chroot
        ostring += "    " + "chroot " + @chroot.to_s + "\n"
      end

      if @daemon
        ostring += "    " + "daemon " + "\n"
      end

      if @gid
        ostring += "    " + "gid " + @gid.to_s + "\n"
      end

      if @group
        ostring += "    " + "group " + @group.to_s + "\n"
      end

      if @log
        ostring += "    " + "log " + @log.to_s + "\n"
      end

      if @nbproc
        ostring += "    " + "nbproc " + @nbproc.to_s + "\n"
      end

      if @pidfile
        ostring += "    " + "pidfile " + @pidfile.to_s + "\n"
      end

      if @uid
        ostring += "    " + "uid " + @uid.to_s + "\n"
      end

      if @ulimit_n
        ostring += "    " + "ulimit-n " + @ulimit_n.to_s + "\n"
      end

      if @user
        ostring += "    " + "user " + @user.to_s + "\n"
      end

      if @stats_socket
        ostring += "    " + "stats socket " + @stats_socket.to_s + "\n"
      end

      if @stats_timeout
        ostring += "    " + "stats timeout " + @stats_timeout.to_s + "\n"
      end

      if @stats_maxconn
        ostring += "    " + "stats maxconn " + @stats_maxconn.to_s + "\n"
      end

      if @node
        ostring += "    " + "node " + @node.to_s + "\n"
      end

      if @description
        ostring += "    " + "description " + @description.to_s + "\n"
      end

      if @unix_bind
        ostring += "    " + "unix-bind " + @unix_bind.to_s + "\n"
      end

      if @maxconn
        ostring += "    " + "maxconn " + @maxconn.to_s + "\n"
      end

      if @maxpipes
        ostring += "    " + "maxpipes " + @maxpipes.to_s + "\n"
      end

      if @noepoll
        ostring += "    " + "noepoll " + "\n"
      end

      if @nokqueue
        ostring += "    " + "nokqueue " + "\n"
      end

      if @nopoll
        ostring += "    " + "nopoll " + "\n"
      end

      if @nosepoll
        ostring += "    " + "nosepoll " + "\n"
      end

      if @nosplice
        ostring += "    " + "nosplice " + "\n"
      end

      if @spread_checks
        ostring += "    " + "spread-checks " + @spread_checks.to_s + "\n"
      end

      if @tune_bufsize
        ostring += "    " + "tune.bufsize " + @tune_bufsize.to_s + "\n"
      end

      if @tune_chksize
        ostring += "    " + "tune.chksize " + @tune_chksize.to_s + "\n"
      end

      if @tune_maxaccept
        ostring += "    " + "tune.maxaccept " + @tune_maxaccept.to_s + "\n"
      end

      if @tune_maxpollevents
        ostring += "    " + "tune.maxpollevents " + @tune_maxpollevents.to_s + "\n"
      end

      if @tune_maxrewrite
        ostring += "    " + "tune.maxrewrite " + @tune_maxrewrite.to_s + "\n"
      end

      if @tune_rcvbuf_client
        ostring += "    " + "tune.rcvbuf.client " + @tune_rcvbuf_client.to_s + "\n"
      end

      if @tune_rcvbuf_server
        ostring += "    " + "tune.rcvbuf.server " + @tune_rcvbuf_server.to_s + "\n"
      end

      if @tune_sndbuf_client
        ostring += "    " + "tune.sndbuf.client " + @tune_sndbuf_client.to_s + "\n"
      end

      if @tune_sndbuf_server
        ostring += "    " + "tune.sndbuf.server " + @tune_sndbuf_server.to_s + "\n"
      end

      if @debug
        ostring += "    " + "debug " + "\n"
      end

      if @quiet
        ostring += "    " + "quiet " + "\n"
      end

      ostring += "\n"

      return ostring
    end
  end

