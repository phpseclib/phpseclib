<?php

use phpseclib\Net\SFTP;

function multipleSFTP() {
  $sftpA = new SFTP('sha256');
  $sftpB = new SFTP('sha384');

  echo $sftpA->size();
  echo $sftpB->size();
}

?>
-----
<?php

use phpseclib3\Net\SFTP;

function multipleSFTP() {
  $sftpA = new SFTP('sha256');
  $sftpB = new SFTP('sha384');

  echo $sftpA->filesize();
  echo $sftpB->filesize();
}

?>
