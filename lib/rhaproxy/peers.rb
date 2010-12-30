  # = rhaproxy - A HAproxy gem for Ruby
  #
  # Homepage::  http://github.com/jjuliano/rhaproxy
  # Author::    Joel Bryan Juliano
  # Copyright:: (cc) 2011 Joel Bryan Juliano
  # License::   MIT

  #
  # class RhaproxyPeers.new( array, str, array)
  #

  #
  # It is possible to synchronize server entries in stick tables between several
  # haproxy instances over TCP connections in a multi-master fashion. Each instance
  # pushes its local updates and insertions to remote peers. Server IDs are used to
  # identify servers remotely, so it is important that configurations look similar
  # or at least that the same IDs are forced on each server on all participants.
  # Interrupted exchanges are automatically detected and recovered from the last
  # known point. In addition, during a soft restart, the old process connects to
  # the new one using such a TCP connection to push all its entries before the new
  # process tries to connect to other peers. That ensures very fast replication
  # during a reload, it typically takes a fraction of a second even for large
  # tables.
  #
  class RhaproxyPeers

    #
    # name <peersect>
    #   Creates a new peer name <peersect>. It is an independant section,
    #   which is referenced by one or more stick-tables.
    #
    attr_accessor :name

    #
    # peers <peersect>
    #   Creates a new peer list with name <peersect>. It is an independant section,
    #   which is referenced by one or more stick-tables.
    #   This is under the peers_section.
    #
    #
    attr_accessor :peers

    #
    # peer <peername> <ip>:<port>
    #   Defines a peer inside a peers section.
    #   If <peername> is set to the local peer name (by default hostname, or forced
    #   using "-L" command line option), haproxy will listen for incoming remote peer
    #   connection on <ip>:<port>. Otherwise, <ip>:<port> defines where to connect to
    #   to join the remote peer, and <peername> is used at the protocol level to
    #   identify and validate the remote peer on the server side.
    #
    #   During a soft restart, local peer <ip>:<port> is used by the old instance to
    #   connect the new one and initiate a complete replication (teaching process).
    #
    #   It is strongly recommended to have the exact same peers declaration on all
    #   peers and to only rely on the "-L" command line argument to change the local
    #   peer name. This makes it easier to maintain coherent configuration files
    #   across all peers.
    #
    attr_accessor :peer

    #
    # Returns a new RhaproxyPeers Object
    #
    def initialize()
    end

    #
    # Compile the HAproxy peers configuration
    #
    def config

      if @name

        conf = option_string()

        return conf

      else

        puts "no peers section name defined"

        return false

      end

    end

    private

    def option_string()

      ostring = "  " + "peers " + @name.to_s + "\n"

      if @peers
        ostring += "    " + "peers " + @peers.to_s + "\n"
      end

      if @peer
        ostring += "    " + "peer " + @peer.to_s + "\n"
      end

      ostring += "\n"

      return ostring

    end

  end

