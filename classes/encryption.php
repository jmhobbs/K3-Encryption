<?php

  /**
   * Wrapper class to assist with encryption duties, using MCrypt and Rijndael 256 in chained block mode.
   */
  class Encryption {

    /**
     * Checks that MCrypt is installed and the correct algorithm is available.
     */
    public static function check_mcrypt () {
      if( ! function_exists( 'mcrypt_encrypt' ) or ! function_exists( 'mcrypt_decrypt' ) ) {
        throw new Exception( 'MCrypt not installed.' );
      }
      if( ! in_array( 'rijndael-256', mcrypt_list_algorithms() ) or ! in_array( 'cbc', mcrypt_list_modes() ) ) {
        throw new Exception( 'Cipher not supported.' );
      }
    }

    /**
     * Get the encryption key from the config file.
     */
    protected static function get_key ( $password = null ) {
      if( is_null( $password ) ) {
        $password = Kohana::$config->load( 'encryption.key', null );
        if( is_null( $password ) ) { throw new Exception( 'Config value encryption.key is not set.' ); }
      }

      $salt = Kohana::$config->load( 'encryption.pbkdf2.salt', null );
      if( is_null( $salt ) ) { throw new Exception( 'Config value encryption.pbkdf2.salt is not set.' ); }

      $rounds = Kohana::$config->load( 'encryption.pbkdf2.rounds', null );
      if( is_null( $rounds ) ) { throw new Exception( 'Config value encryption.pbkdf2.rounds is not set.' ); }

      // Minimum of 1k rounds, otherwise, what's the point?
      $rounds = (int) $rounds;
      if( $rounds < 1000 ) { $rounds = 1000; }

      return self::pbkdf2($password, $salt, $rounds, 32, 'sha256');
    }

    /**
     * Runs a sanity check on MCrypt.
     */
    public static function sanity_check () {
      self::check_mcrypt();
      return mcrypt_module_self_test(MCRYPT_RIJNDAEL_256);
    }

    /**
     * Encrypt a some data.
     */
    public static function encrypt ( $plaintext, $password = null ) {
      self::check_mcrypt();
      $iv_size = mcrypt_get_iv_size( MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC );
      $iv = mcrypt_create_iv( $iv_size, MCRYPT_DEV_URANDOM );
      return array(
        'data' => mcrypt_encrypt( MCRYPT_RIJNDAEL_256, self::get_key( $password ), $plaintext, MCRYPT_MODE_CBC, $iv ),
        'iv'   => $iv
      );
    }

    /**
     * Decrypt some data.
     */
    public static function decrypt ( $ciphertext, $iv, $password = null ) {
      self::check_mcrypt();
      return mcrypt_decrypt( MCRYPT_RIJNDAEL_256, self::get_key( $password ), $ciphertext, MCRYPT_MODE_CBC, $iv );
    }

    /**
     *  PBKDF2 Implementation (described in RFC 2898)
     *
     *  @param string p password
     *  @param string s salt
     *  @param int c iteration count (use 1000 or higher)
     *  @param int kl derived key length
     *  @param string a hash algorithm
     *
     *  @return string derived key
     *
     *  @url http://www.itnewb.com/tutorial/Encrypting-Passwords-with-PHP-for-Storage-Using-the-RSA-PBKDF2-StandardL
    */
    public static function pbkdf2 ( $p, $s, $c, $kl, $a = 'sha256' ) {

      $hl = strlen(hash($a, null, true)); # Hash length
      $kb = ceil($kl / $hl);              # Key blocks to compute
      $dk = '';                           # Derived key

      # Create key
      for ( $block = 1; $block <= $kb; $block ++ ) {

        # Initial hash for this block
        $ib = $b = hash_hmac($a, $s . pack('N', $block), $p, true);

        # Perform block iterations
        for ( $i = 1; $i < $c; $i ++ )

          # XOR each iterate
          $ib ^= ($b = hash_hmac($a, $b, $p, true));

        $dk .= $ib; # Append iterated block
      }

      # Return derived key of correct length
      return substr($dk, 0, $kl);
    }

  }

