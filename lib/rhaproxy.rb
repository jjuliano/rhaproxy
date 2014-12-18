  # = rhaproxy - A HAproxy gem for Ruby
  #
  # Homepage::  http://github.com/jjuliano/rhaproxy
  # Author::    Joel Bryan Juliano
  # Copyright:: (cc) 2011-2015 Joel Bryan Juliano
  # License::   GNU LGPLv3

  require File.expand_path(File.dirname(__FILE__) + '/rhaproxy/mixins.rb')
  require File.expand_path(File.dirname(__FILE__) + '/rhaproxy/keywords.rb')
  Dir[File.join(File.dirname(__FILE__), 'rhaproxy/**/*.rb')].sort.each { |lib| require lib }

