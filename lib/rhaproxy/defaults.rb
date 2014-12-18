  # = rhaproxy - A HAproxy gem for Ruby
  #
  # Homepage::  http://github.com/jjuliano/rhaproxy
  # Author::    Joel Bryan Juliano
  # Copyright:: (cc) 2011-2015 Joel Bryan Juliano
  # License::   GNU LGPLv3

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
    include RhaproxyKeywords,
            :exclude => [
                         :acl,
                         :appsession,
                         :bind,
                         :block,
                         :capture_cookie,
                         :capture_request_header,
                         :capture_response_header,
                         :description,
                         :dispatch,
                         :force_persist,
                         :http_check_expect,
                         :http_request,
                         :persistent_id,
                         :ignore_persist,
                         :monitor_fail,
                         :name,
                         :redirect,
                         :reqadd,
                         :reqallow,
                         :reqdel,
                         :reqdeny,
                         :reqiallow,
                         :reqidel,
                         :reqideny,
                         :reqipass,
                         :reqirep,
                         :reqisetbe,
                         :reqitarpit,
                         :reqpass,
                         :reqrep,
                         :reqsetbe,
                         :reqtarpit,
                         :rspadd,
                         :rspdel,
                         :rspdeny,
                         :rspirep,
                         :rsprep,
                         :server,
                         :stats_admin,
                         :stats_http_request,
                         :stick_match,
                         :stick_on,
                         :stick_store_request,
                         :stick_table,
                         :stick_store_response,
                         :tcp_request_connection,
                         :tcp_request_content,
                         :tcp_request_inspect_delay,
                         :tcp_response_content,
                         :tcp_response_inspect_delay,
                         :use_backend
                        ]

    #
    # Returns a new RhaproxyDefaults Object
    #
    def initialize()
      @conf ||= []
      @proxy_type = "defaults"
      @conf.push("  " + "#{@proxy_type} " + "\n")
      @name_index = @conf.index("  " + "#{@proxy_type} " + "\n")
    end

    #
    # name <name>
    #   The defaults name is encouraged for better readability.
    #
    #   NOTE: This will clear the existing values in the array.
    #
    def name(value = nil)
      @conf.replace( [] )
      @conf.push("  " + "#{@proxy_type} " + value.to_s + "\n")
      @name_index = @conf.index("  " + "#{@proxy_type} " + value.to_s + "\n")
    end

  end

