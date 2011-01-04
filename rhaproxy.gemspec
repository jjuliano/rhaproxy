Gem::Specification.new do |s|
  s.name = %q{rhaproxy}
  s.version = "0.1.1"
  s.date = %q{2011-01-04}
  s.authors = ["Joel Bryan Juliano"]
  s.email = %q{joelbryan.juliano@gmail.com}
  s.summary = %q{A gem providing a ruby interface to HAproxy TCP/HTTP Load Balancer.}
  s.homepage = %q{http://github.com/jjuliano/rhaproxy}
  s.description = %q{A gem providing a ruby interface to HAproxy TCP/HTTP Load Balancer.}
  s.files = [ "README", "Changelog", "MIT-LICENSE", "setup.rb",
              "lib/rhaproxy.rb", "lib/rhaproxy/version.rb",
              "test/test_rhaproxy.rb", "test/test_helper.rb",
              "lib/rhaproxy/backend.rb", "lib/rhaproxy/global.rb",
              "lib/rhaproxy/listen.rb", "lib/rhaproxy/defaults.rb",
              "lib/rhaproxy/userlist.rb", "lib/rhaproxy/peers.rb",
              "lib/rhaproxy/frontend.rb", "lib/rhaproxy/keywords.rb",
              "lib/rhaproxy/mixins.rb"]
end

