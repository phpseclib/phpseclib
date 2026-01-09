<?php

use phpseclib3\Net\SFTP;

function printFilesize() {
  $sftp = new SFTP('...');
  $sftp->login('username', 'password');
  echo $sftp->filesize('/path/to/filename.ext');
}

?>