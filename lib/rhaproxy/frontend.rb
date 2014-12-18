  # = rhaproxy - A HAproxy gem for Ruby
  #
  # Homepage::  http://github.com/jjuliano/rhaproxy
  # Author::    Joel Bryan Juliano
  # Copyright:: (cc) 2011-2015 Joel Bryan Juliano
  # License::   GNU LGPLv3

  #
  # class RhaproxyFrontend.new( array, str, array)
  #

  #
  # A "frontend" section describes a set of listening sockets accepting client
  # connections.
  #
  class RhaproxyFrontend
    include RhaproxyKeywords,
            :exclude => [
                         :appsession,
                         :balance,
                         :cookie,
                         :default_server,
                         :dispatch,
                         :fullconn,
                         :hash_type,
                         :http_check_disable_on_404,
                         :http_check_expect,
                         :http_check_send_state,
                         :option_abortonclose,
                         :option_accept_invalid_http_response,
                         :option_allbackups,
                         :option_checkcache,
                         :option_httpchk,
                         :option_ldap_check,
                         :option_log_health_checks,
                         :option_mysql_check,
                         :option_persist,
                         :option_redispatch,
                         :option_smtpchk,
                         :option_srvtcpka,
                         :option_ssl_hello_chk,
                         :option_tcp_smart_connect,
                         :option_transparent,
                         :persist_rdp_cookie,
                         :retries,
                         :server,
                         :source,
                         :stats_admin,
                         :stats_auth,
                         :stats_enable,
                         :stats_hide_version,
                         :stats_http_request,
                         :stats_realm,
                         :stats_refresh,
                         :stats_scope,
                         :stats_show_desc,
                         :stats_show_legends,
                         :stats_show_node,
                         :stats_uri,
                         :stick_match,
                         :stick_on,
                         :stick_store_request,
                         :stick_table,
                         :tcp_response_content,
                         :tcp_response_inspect_delay,
                         :timeout_check,
                         :timeout_connect,
                         :timeout_queue,
                         :timeout_server
                        ]

    #
    # Returns a new RhaproxyFrontend Object
    #
    def initialize()
      @conf ||= []
      @proxy_type = "frontend"
    end

  end

