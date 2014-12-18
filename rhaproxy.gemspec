require_relative 'lib/rhaproxy/version'

Gem::Specification.new do |s|
  s.name = %q{rhaproxy}
  s.version = RHAproxy::VERSION::STRING
  s.date = Time.now
  s.authors = ["Joel Bryan Juliano"]
  s.email = %q{joelbryan.juliano@gmail.com}
  s.summary = %q{HAproxy Load Balancer for Ruby}
  s.homepage = %q{http://github.com/jjuliano/rhaproxy}
  s.description = %q{A gem providing a ruby interface to HAproxy TCP/HTTP Load Balancer}
  s.files = [ "README.md", "Changelog", "LICENSE", "setup.rb",
              "lib/rhaproxy.rb", "lib/rhaproxy/version.rb",
              "test/test_rhaproxy.rb", "test/test_helper.rb",
              "lib/rhaproxy/backend.rb", "lib/rhaproxy/global.rb",
              "lib/rhaproxy/listen.rb", "lib/rhaproxy/defaults.rb",
              "lib/rhaproxy/userlist.rb", "lib/rhaproxy/peers.rb",
              "lib/rhaproxy/frontend.rb", "lib/rhaproxy/keywords.rb",
              "lib/rhaproxy/mixins.rb"]
  s.license = "GNU LGPLv3"
end