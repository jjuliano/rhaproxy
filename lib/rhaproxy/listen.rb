  # = rhaproxy - A HAproxy gem for Ruby
  #
  # Homepage::  http://github.com/jjuliano/rhaproxy
  # Author::    Joel Bryan Juliano
  # Copyright:: (cc) 2011-2015 Joel Bryan Juliano
  # License::   GNU LGPLv3

  #
  # class RhaproxyListen.new( array, str, array)
  #

  #
  # A "listen" section defines a complete proxy with its frontend and backend
  # parts combined in one section. It is generally useful for TCP-only traffic.
  #
  class RhaproxyListen
    include RhaproxyKeywords

    #
    # Returns a new RhaproxyListen Object
    #
    def initialize()
      @conf ||= []
      @proxy_type = "listen"
    end

  end

