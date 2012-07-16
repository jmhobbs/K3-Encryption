# What is this?

Occasionally, I find that I am required by a project to arbitrarily encrypt the
contents of some strings in a database.  Whatever.

So I did a lot of searchin and reading and then I wrote this little module to
use the PHP encryption "best practices" as far as I can understand them, and tie it
into Kohana.

Please bear in mind that I am not a cryptographer, and I have been known
to be "wrong" in the past, so please tell me if I have goofed somewhere.

Also, please note that I don't necessarily think this is a "good idea"
TM.

Database servers are usually further inside the network than web
servers, so the odds of data being exposed is (to me) less than the
possibility of the PHP source (and encryption key) being exposed.
Assuming you are properly using your database to prevent injection.

Whatever.

# CIPHER!

![Cipher](https://dl.dropbox.com/u/28665584/cipher.jpg)

This module uses [mcrypt](http://php.net/mcrypt) - so make sure it is
installed.

It also uses [Hash](http://php.net/hash) - so use a modern PHP.

The algoritm used is [Rijndael-256](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard) in [CBC](http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29) mode.

Your password is run through [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) a minimum of 1000 iterations to create the key.

That should be pretty good, afaik, as of 2012-07-16.

# Usage

Copy and edit <tt>config/encryption.php</tt>.  Add a good salt ( >= 8 bytes ) and your password.

Then just call the methods.

```php
$ciphertext = Encryption::encrypt('lol');
$plaintext = Encryption::decrypt($ciphertext);
```

You can also hot-swap that password for another one, if you need to.

```php
$ciphertext = Encryption::encrypt('lol', 'wut');
$plaintext = Encryption::decrypt($ciphertext, 'wut');
```

