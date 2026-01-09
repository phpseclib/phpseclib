<?php

use phpseclib\Crypt\Hash;

function chainedHash() {
  $hash = new Hash('sha256');
  echo $hash->getLength()->toString();
}

?>
-----
<?php

use phpseclib3\Crypt\Hash;

function chainedHash() {
  $hash = new Hash('sha256');
  echo $hash->getLengthInBytes()->toString();
}

?>
