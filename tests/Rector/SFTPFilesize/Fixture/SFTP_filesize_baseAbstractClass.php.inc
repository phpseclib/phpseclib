<?php

use phpseclib\Net\SFTP;

$sftp = new SFTP('...');
$sftp->login('username', 'password');
echo $sftp->size('/path/to/filename.ext');

abstract class BaseClass
{
    abstract public function printFilesize();
}

final class FileSizeClass extends BaseClass
{
  function printFilesize() {
      $sftp1 = new SFTP('...');
      $sftp1->login('username', 'password');
      $sftp1->size('/path/to/filename.ext');
  }
}

?>
-----
<?php

use phpseclib3\Net\SFTP;

$sftp = new SFTP('...');
$sftp->login('username', 'password');
echo $sftp->filesize('/path/to/filename.ext');

abstract class BaseClass
{
    abstract public function printFilesize();
}

final class FileSizeClass extends BaseClass
{
  function printFilesize() {
      $sftp1 = new SFTP('...');
      $sftp1->login('username', 'password');
      $sftp1->filesize('/path/to/filename.ext');
  }
}

?>
