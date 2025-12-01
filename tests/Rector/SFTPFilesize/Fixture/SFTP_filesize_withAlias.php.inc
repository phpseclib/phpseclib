<?php

use phpseclib\Net\SFTP as Foo;

function printFilesize() {
  $sftp = new Foo('...');
  $sftp->login('username', 'password');
  echo $sftp->size('/path/to/filename.ext');
}

?>
-----
<?php

use phpseclib3\Net\SFTP as Foo;

function printFilesize() {
  $sftp = new Foo('...');
  $sftp->login('username', 'password');
  echo $sftp->filesize('/path/to/filename.ext');
}

?>