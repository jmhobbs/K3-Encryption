<?php

  return array(
    // The default password for encrypting/decrypting.
    'password' => NULL,

    // The password you come up with will be mangled by PBKDF2 into a good key
    // but it needs a salt for that.
    'pbkdf2' => array(
      // At least 8 bytes, preferably not straight ASCII
      'salt' => NULL,
      // At least 1000, it won't accept less than that anyway.
      'rounds' => 10000,
    ),
  );

