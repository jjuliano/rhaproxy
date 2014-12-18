  # = rhaproxy - A HAproxy gem for Ruby
  #
  # Homepage::  http://github.com/jjuliano/rhaproxy
  # Author::    Joel Bryan Juliano
  # Copyright:: (cc) 2011-2015 Joel Bryan Juliano
  # License::   GNU LGPLv3

  #
  # class RhaproxyBackend.new( array, str, array)
  #

  #
  # A "backend" section describes a set of servers to which the proxy will connect
  # to forward incoming connections.
  #
  class RhaproxyBackend
    include RhaproxyKeywords,
            :exclude => [
                         :backlog,
                         :bind,
                         :capture_cookie,
                         :capture_request_header,
                         :capture_response_header,
                         :default_backend,
                         :maxconn,
                         :monitor_fail,
                         :monitor_net,
                         :monitor_uri,
                         :option_accept_invalid_http_request,
                         :option_clitcpka,
                         :option_contstats,
                         :option_dontlog_normal,
                         :option_dontlognull,
                         :option_http_use_proxy_header,
                         :option_log_separate_errors,
                         :option_logasap,
                         :option_socket_stats,
                         :option_tcp_smart_accept,
                         :rate_limit_sessions,
                         :tcp_request_connection,
                         :timeout_client,
                         :use_backend
                        ]

    #
    # Returns a new RhaproxyBackend Object
    #
    def initialize()
      @conf ||= []
      @proxy_type = "backend"
    end

  end

