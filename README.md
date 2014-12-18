Rhaproxy - HAproxy Load Balancer for Ruby
=========================================

Rhaproxy is a gem providing a ruby interface to HAproxy TCP/HTTP Load Balancer.

To install, type 'gem install rhaproxy'

### Why RHAProxy?

RHAProxy creates simple and small development tools that help you design,
develop, deploy cloud infrastractures for your enterprise software systems.

#### RHAProxy Pro: A Commercial, Supported Version of RHAProxy
RHAProxy Pro is a collection of useful functionality for the open source RHAProxy library with priority support via Remote access or Skype from the author, new features in-demand, upgrades and lots more.

Sales of RHAProxy Pro also benefit the community by ensuring that RHAProxy itself will remain well supported for the foreseeable future.

#### Licensing
RHAProxy is available under the terms of the GNU LGPLv3 license.

In addition to its useful functionality, buying RHAProxy Pro grants your organization a RHAProxy Commercial License instead of the GNU LGPL, avoiding any legal issues your lawyers might raise. Please contact joelbryan.juliano@gmail.com for further detail on licensing including options for embedding RHAProxy Pro in your own products.

#### Buy RHAProxy Pro
Contact me via joelbryan.juliano@gmail.com, and Pay via Paypal: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=GFG3UVMX2FDEY

### Usage:

```ruby
      require 'rubygems'
      require 'rhaproxy'

      global = RhaproxyGlobal.new
      global.daemon = true
      global.maxconn = 256

      defaults = RhaproxyDefaults.new
      defaults.mode("http")
      defaults.timeout_connect("5000ms")
      defaults.timeout_client("50000ms")
      defaults.timeout_server("50000ms")

      frontend = RhaproxyFrontend.new
      frontend.name("http-in")
      frontend.default_backend("servers")

      backend = RhaproxyBackend.new
      backend.name("servers")
      backend.server("server1 127.0.0.1:8000 maxconn 32")

      config = Array.new
      config.push([global.config])
      config.push([defaults.config])
      config.push([frontend.config])
      config.push([backend.config])

      haproxy_conf_file = File.new("haproxy.conf", "w+")
      haproxy_conf_file.puts(config)
      haproxy_conf_file.close
```

haproxy.conf:

```ruby
      global
        daemon
        maxconn 256

      defaults
        mode http
        timeout client 50000ms
        timeout connect 5000ms
        timeout server 50000ms

      frontend http-in
        default_backend servers

      backend servers
        server server1 127.0.0.1:8000 maxconn 32
```

### Donations

Please support independent cloud computing toolkits, also money donated to the project will benefit the community by ensuring that RHAProxy itself will remain well supported for the foreseeable future. To Donate, please visit: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=KT9CY4T7BYDM4
