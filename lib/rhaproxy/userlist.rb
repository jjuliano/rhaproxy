  # = rhaproxy - A HAproxy gem for Ruby
  #
  # Homepage::  http://github.com/jjuliano/rhaproxy
  # Author::    Joel Bryan Juliano
  # Copyright:: (cc) 2011-2015 Joel Bryan Juliano
  # License::   GNU LGPLv3

  #
  # class RhaproxyUserlist.new( array, str, array)
  #

  #
  # It is possible to control access to frontend/backend/listen sections or to
  # http stats by allowing only authenticated and authorized users. To do this,
  # it is required to create at least one userlist and to define users.
  #
  class RhaproxyUserlist

    #
    # name <listname>
    #   Creates new userlist with name <listname>. Many independent userlists can be
    #   used to store authentication & authorization data for independent customers.
    #
    attr_accessor :name

    #
    # group <groupname> [users <user>,<user>,(...)]
    #   Adds group <groupname> to the current userlist. It is also possible to
    #   attach users to this group by using a comma separated list of names
    #   proceeded by "users" keyword.
    #
    attr_accessor :group

    #
    # user <username> [password|insecure-password <password>]
    #                 [groups <group>,<group>,(...)]
    #   Adds user <username> to the current userlist. Both secure (encrypted) and
    #   insecure (unencrypted) passwords can be used. Encrypted passwords are
    #   evaluated using the crypt(3) function so depending of the system's
    #   capabilities, different algorithms are supported. For example modern Glibc
    #   based Linux system supports MD5, SHA-256, SHA-512 and of course classic,
    #   DES-based method of crypting passwords.
    #
    attr_accessor :user

    #
    # Returns a new RhaproxyUserlist Object
    #
    def initialize()
    end

    #
    # Compile the HAproxy userlist configuration
    #
    def config

      if @name

        conf = option_string()

        return conf

      else

        puts "no userlists name defined"

        return false

      end

    end

    private

    def option_string()

      ostring = "  " + "userlist " + @name + "\n"

      if @group
        ostring += "    " + "group " + @group + "\n"
      end

      if @user
        ostring += "    " + "user " + @user + "\n"
      end

      ostring += "\n"

      return ostring

    end
  end

