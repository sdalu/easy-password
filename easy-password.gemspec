# -*- encoding: utf-8 -*-

require_relative 'lib/easy-password/version'

Gem::Specification.new do |s|
    s.name        = 'easy-password'
    s.version     = EasyPassword::VERSION
    s.summary     = "Password generator, checker, hasher"
    s.description =  <<~EOF
      Ease password creation by allowing:
      * password generation
      * password weakness checking
      * hashing password to sha256, md5, sha, ntlm, lmhash
      EOF

    s.homepage    = 'https://github.com/sdalu/easy-password'
    s.license     = 'MIT'

    s.authors     = [ "Stéphane D'Alu" ]
    s.email       = [ 'stephane.dalu@insa-lyon.fr' ]

    s.files       = %w[ README.md easy-password.gemspec ] +
                    Dir['lib/**/*.rb']

    s.add_development_dependency 'yard',      '~>0'
    s.add_development_dependency 'redcarpet', '~>3'
    s.add_development_dependency 'rake',      '~>13'
end
