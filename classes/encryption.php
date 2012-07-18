<?php

  /**
   * Wrapper class to assist with encryption duties, using MCrypt and Rijndael 256 in chained block mode.
   */
  class Encryption {

    const ALGORITHIM     = MCRYPT_RIJNDAEL_256;
    const MODE           = MCRYPT_MODE_CBC;
    const ALGORITHIM_STR = 'rijndael-256';
    const MODE_STR       = 'cbc';
    const IV_SIZE        = 32;
    const KEY_SIZE       = 32;
    const RANDOM_SOURCE  = MCRYPT_DEV_URANDOM;
    const PBKDF2_HASH    = 'sha256';

    /**
     * Checks that MCrypt is installed and the correct algorithm is available.
     */
    public static function check_mcrypt () {
      if( ! function_exists( 'mcrypt_encrypt' ) or ! function_exists( 'mcrypt_decrypt' ) ) {
        throw new Exception( 'MCrypt not installed.' );
      }
      if( ! in_array( self::ALGORITHIM_STR, mcrypt_list_algorithms() ) or ! in_array( self::MODE_STR, mcrypt_list_modes() ) ) {
        throw new Exception( 'Cipher not supported.' );
      }
    }

    /**
     * Get the encryption key from the config file.
     */
    protected static function get_key ( $password = null ) {
      if( is_null( $password ) ) {
        $password = Kohana::$config->load( 'encryption.password', null );
        if( is_null( $password ) ) { throw new Exception( 'Config value encryption.password is not set.' ); }
      }

      $salt = Kohana::$config->load( 'encryption.pbkdf2.salt', null );
      if( is_null( $salt ) ) { throw new Exception( 'Config value encryption.pbkdf2.salt is not set.' ); }

      $rounds = Kohana::$config->load( 'encryption.pbkdf2.rounds', null );
      if( is_null( $rounds ) ) { throw new Exception( 'Config value encryption.pbkdf2.rounds is not set.' ); }

      // Minimum of 1k rounds, otherwise, what's the point?
      $rounds = (int) $rounds;
      if( $rounds < 1000 ) { $rounds = 1000; }

      return self::pbkdf2($password, $salt, $rounds, self::KEY_SIZE, self::PBKDF2_HASH);
    }

    /**
     * Runs a sanity check on MCrypt.
     */
    public static function sanity_check () {
      self::check_mcrypt();
      return mcrypt_module_self_test(self::ALGORITHIM);
    }

    /**
     * Encrypt a some data.
     *
     * \return A string, with the IV appended to the front of the encrypted data.
     */
    public static function encrypt ( $plaintext, $password = null ) {
      self::check_mcrypt();
      $iv_size = mcrypt_get_iv_size( self::ALGORITHIM, self::MODE );
      $iv = mcrypt_create_iv( $iv_size, self::RANDOM_SOURCE );
      return $iv . mcrypt_encrypt( self::ALGORITHIM, self::get_key( $password ), $plaintext, self::MODE, $iv );
    }

    /**
     * Decrypt some data.
     */
    public static function decrypt ( $data, $password = null ) {
      self::check_mcrypt();
      list( $iv, $ciphertext ) = str_split( $data, self::IV_SIZE );
      return rtrim( mcrypt_decrypt( self::ALGORITHIM, self::get_key( $password ), $ciphertext, self::MODE, $iv ), "\0" );
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

