class Class
  old_include = instance_method(:include)
  define_method(:include) do |*args|
    default = {:alias => {}, :exclude => []}
    hash_arg = (Hash === args.last) ? default.update(args.pop) : default
    m = Module.new
    args.each{|mod| m.module_eval{ include mod } }
    #                            ^^^^^^^^^^^^^^^
    # check for "method shadowing" here and raise an exception or
    # something if you feel like it
    hash_arg[:alias].each_pair do |old, new|
      m.module_eval{ alias_method(new, old); undef_method(old) }
    end
    excluded = (Array === hash_arg[:exclude]) ? hash_arg[:exclude] : [hash_arg[:exclude]]
    # [*hash_arg[:exclude]] won't work on 1.9 cause there's no Object#to_a
    excluded.each{|meth| m.module_eval { undef_method(meth) } }
    old_include.bind(self).call(m)
  end
end

