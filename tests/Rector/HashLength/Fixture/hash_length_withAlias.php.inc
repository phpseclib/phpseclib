<?php

use phpseclib\Crypt\Hash as CryptoHash;

$hash = new CryptoHash('sha512');
echo $hash->getLength();

?>
-----
<?php

use phpseclib3\Crypt\Hash as CryptoHash;

$hash = new CryptoHash('sha512');
echo $hash->getLengthInBytes();

?>
