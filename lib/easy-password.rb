require 'openssl'

#
# Adding a simple password generator and using it by default:
#
#   # Generate 10 random alphanumeric characters
#   EasyPassword.generator :random10 do
#     SecureRandom.alphanumeric(10)
#   end
#
#   # Define the default generator
#   EasyPassword.default_generator = :random10
#
#
# Adding a checker
#
#   # Implementing classic at least 1 lowercase, 1 upercase, 1 digit
#   EasyPassword.checker :aA1 do |password, all|
#     list = { /\d/    => :digit_needed,
#              /[A-Z]/ => :upercase_needed,
#              /[a-z]/ => :lowercase_needed,
#            }.lazy.map {|regex, failure| failure if password !~ regex }
#                  .reject(&:nil?)
#     all ? list.to_a : list.first
#   end
#
#   # Looking for known bad passwords in a database (using Sequel)
#   Password.checker :hack_dictionary do |password, all|
#     ! DB[:bad_passwords].first(:password => password).nil?
#   end
#
# Creating password
#
#   password = EasyPassword.new
#   password = EasyPassword.new('foobar')
#
# Checking for weakness
#
#   password.weakness
#

class EasyPassword
    Digest = OpenSSL::Digest

    @hide              = true
    @checkers          = {}
    @generators        = {}
    @default_generator = nil
    @default_checkers  = nil

    
    # Is password value hidden when calling #to_s
    def self.hide
        @hide
    end


    # Control if password value is hidden when calling #to_s
    def self.hide=(hide)
        @hide = hide
    end


    # Define the default generator to use
    #
    # @param [Symbol] type  Generator nickname
    #
    def self.default_generator=(type)
        @default_generator = type
    end


    # Default generator
    def self.default_generator
        @default_generator
    end


    # Define the list of default checkers to use
    #
    # @param [Array<Symbol>,nil] checkers list of checkers nickname, if nil
    #                                     all available checkers will be used
    #
    def self.default_checkers=(checkers)
        @default_checkers = checkers
    end

    
    # List of default checkers to use
    def self.default_checkers
        @default_checkers
    end


    # DSL to add a new password generator
    #
    # @yieldparam [void]
    # @yieldreturn [String] plain text password
    #
    def self.generator(name, &block)
        @generators[name] = block
    end


    # DSL to ass a new password checker
    #
    # @yieldparam [String]  password  plain text password
    # @yieldparam [Boolean] all       should all weakness be listed
    # @yieldreturn [false, nil, []] if no weakness have been discovered
    # @yieldreturn [true, Symbol, Array<Symbol>] name of weakness
    #
    def self.checker(name, &block)
        @checkers[name] ||= block
    end


    # Check for weakness
    #
    # @param [String, EasyPassword] password
    # @param [Symbol]               checkers
    # @param [Boolean]              all
    #
    # @raise [KeyError] if a requested checker is not defined
    #
    # @return [Hash{Symbol=>Array<Symbol>}]
    #
    def self.weakness(password, *checkers, all: true)
        return nil              if @checkers.empty?       
        password = password.raw if password.kind_of?(EasyPassword)

        checkers = self.default_checkers if checkers.empty?
        list     = if checkers.nil? || checkers.empty?
                   then @checkers.lazy
                   else checkers.lazy.map {|n| [n, @checkers.fetch(n)] }
                   end
        list     = list.map {|name, checker|
            case r = checker.call(password, all: all)
            when Array      then [ name, r        ] unless r.empty?
            when Symbol     then [ name, [ r ]    ]
            when true       then [ name, [ name ] ]
            when nil, false
            else raise ArgumentError, 'unsupported checker return value'
            end
        }.reject(&:nil?)

        list = if all
               then Hash[list.to_a]
               else Hash[*list.first].transform_values {|v| v[0,1] }
               end
        list unless list.empty?
    end


    # Generate a plain text password string.
    #
    # @param  [Symbol] type  Generator nickname
    # @return [String]
    #
    def self.generate(type = self.default_generator)
        if type.nil?
            raise ArgumentError, 'invalid generator type'
        end
            
        @generators[type]&.call() ||
            raise("requested generator '#{type}' doesn't exist")
    end


    # Create a MD5-hashed password
    #
    # @param [String] password  plain text password
    #
    # @return [String] hashed password
    #
    def self.md5(password)
        "{MD5}"    + [Digest::MD5.digest(password)   ].pack('m0')
    end


    # Create a SHA-hashed password
    #
    # @param [String] password  plain text password
    #
    # @return [String] hashed password
    #
    def self.sha(password)
        "{SHA}"    + [Digest::SHA1.digest(password)  ].pack('m0')
    end


    # Create a SHA256-hashed password
    #
    # @param [String] password  plain text password
    #
    # @return [String] hashed password
    #
    def self.sha256(password)
        "{sha256}" + [Digest::SHA256.digest(password)].pack('m0')
    end


    # Create an NTML-hashed password
    #
    # @param [String] password  plain text password
    #
    # @return [String] hashed password
    #
    def self.ntlm(password)
        Digest::MD4.hexdigest(password.encode("utf-16le"))
    end
    

    # Create a LMHASH-hashed password
    #
    # @param [String] password  plain text password
    #
    # @return [String] hashed password
    #
    def self.lmhash(password)
        passwd = password[0..13].upcase
        passwd = passwd + "\000" * (14 - passwd.length)
        des = OpenSSL::Cipher::Cipher.new('des-ecb')
        des.encrypt
        [passwd[0..6], passwd[7..13]].collect { |key56|
            keybin = key56.unpack('B*')[0].scan(/.{7}/).collect {|k|
                k + (k.count('1') % 2 == 0 ? '1' : '0') }
            des.key = keybin.pack('B8' * 8)
            des.update('KGS!@#$%')
        }.join.unpack('C*').map { |b| '%02x' % b }.join
    end


    # Create a new EasyPassword
    def initialize(password = EasyPassword::generate)
        @passwd = password.clone.freeze
    end


    # Get the plain text password
    #
    # @return [String] plain text password
    def raw
        @passwd
    end


    # Get the SHA256-hashed password
    #
    # @return [String] hashed password
    #
    def sha
        self.class.sha(@passwd)
    end


    # Get the SHA256-hashed password
    #
    # @return [String] hashed password
    #
    def sha256
        self.class.sha256(@passwd)
    end


    # Get the MD5-hashed password
    #
    # @return [String] hashed password
    #
    def md5
        self.class.md5(@passwd)
    end


    # Get the NTLM-hashed password
    #
    # @return [String] hashed password
    #
    def ntlm
        self.class.ntlm(@passwd)
    end


    # Get the LMHASH-hashed password
    #
    # @return [String] hashed password
    #
    def lmhash
        self.class.lmhash(@passwd)
    end


    # Display password.
    # The behavior is controlled by Password.hide, so either
    # the plain text password will be displayed or ********
    #
    # @return [String]
    #
    def to_s
        self.class.hide != true ? "********" : self.raw
    end

    
    # Check for weakness
    #
    # @param [Symbol]           checkers
    # @param [Boolean]          all
    #
    # @raise [KeyError] if a requested checker is not defined
    #
    # @return [Hash{Symbol=>Array<Symbol>}]
    #
    def weakness(*checkers, all: true)
        self.class.weakness(@passwd, *checkers, all: all)
    end
    
end
