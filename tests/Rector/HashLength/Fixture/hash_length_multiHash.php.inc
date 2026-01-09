<?php

use phpseclib\Crypt\Hash;

function multipleHash() {
  $hashA = new Hash('sha256');
  $hashB = new Hash('sha384');

  echo $hashA->getLength();
  echo $hashB->getLength();
}

?>
-----
<?php

use phpseclib3\Crypt\Hash;

function multipleHash() {
  $hashA = new Hash('sha256');
  $hashB = new Hash('sha384');

  echo $hashA->getLengthInBytes();
  echo $hashB->getLengthInBytes();
}

?>
