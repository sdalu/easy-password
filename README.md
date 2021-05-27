easy-password
=============
Password generator, checker, hasher


Examples
========

Adding a simple password generator and using it by default:

~~~ruby
# Generate 10 random alphanumeric characters
EasyPassword.generator :random10 do
  SecureRandom.alphanumeric(10)
end

# Define the default generator
EasyPassword.default_generator = :random10
~~~


Adding a checker

~~~ruby
# Implementing classic at least 1 lowercase, 1 upercase, 1 digit
EasyPassword.checker :aA1 do |password, all|
  list = { /\d/    => :digit_needed,
           /[A-Z]/ => :upercase_needed,
           /[a-z]/ => :lowercase_needed,
         }.lazy.map {|regex, failure| failure if password !~ regex }
               .reject(&:nil?)
  all ? list.to_a : list.first
end

# Looking for known bad passwords in a database (using Sequel)
Password.checker :hack_dictionary do |password, all|
  ! DB[:bad_passwords].first(:password => password).nil?
end
~~~

Creating password

~~~ruby
password = EasyPassword.new
password = EasyPassword.new('foobar')
~~~

Checking for weakness

~~~ruby
password.weakness
~~~
