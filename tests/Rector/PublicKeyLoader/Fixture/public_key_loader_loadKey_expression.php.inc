<?php

use phpseclib\Crypt\RSA as RSACrypt;

$auth = new RSACrypt();

if (!$auth->loadKey($foo->getOption('private_key'))) {
  if (!$auth->loadKey($foo->getOption('private_key'))) {
  }
}

?>
-----
<?php

use phpseclib3\Crypt\PublicKeyLoader;

if (!($auth = PublicKeyLoader::load($foo->getOption('private_key')))) {
  if (!($auth = PublicKeyLoader::load($foo->getOption('private_key')))) {
  }
}

?>
