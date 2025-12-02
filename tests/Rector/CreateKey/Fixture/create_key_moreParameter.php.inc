<?php

use phpseclib\Crypt\RSA;

class CreateWithExtraArguments {
  public function createWithExtraArguments() {
    $rsa = new RSA();
    extract($rsa->createKey(2048), EXTRA_STUFF);
  }
}

?>
-----
<?php

use phpseclib3\Crypt\RSA;

class CreateWithExtraArguments {
  public function createWithExtraArguments()
  {
      $rsa = RSA::createKey(2048);
  }
}

?>
