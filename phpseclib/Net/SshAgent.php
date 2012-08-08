<?php

// RFC 4252 SSH Authentication Protocol
// RFC 4253 SSH Transport layer http://www.rfc-editor.org/rfc/rfc4253.txt 6.6

define('SSH2_AGENTC_REQUEST_IDENTITIES', 11);
define('SSH2_AGENT_IDENTITIES_ANSWER', 12);
define('SSH2_AGENTC_SIGN_REQUEST',13);
define('SSH2_AGENT_SIGN_RESPONSE',14);

define('SSH_AGENTC_LOCK',22);
define('SSH_AGENTC_UNLOCK',23);

define('SSH_AGENTC_REQUEST_RSA_IDENTITIES', 1);
define('SSH_AGENT_RSA_IDENTITIES_ANSWER', 2);
define('SSH_AGENT_FAILURE', 5);

/**
 * Description of SshAgent
 *
 * @author kea
 */
class SshAgent
{
  private $socket = null;
  private $keys = array();
  private $ssh;

  public function __construct($ssh)
  {
    $this->ssh = $ssh;
  }

  public function connect()
  {
    $socket = socket_create(AF_UNIX, SOCK_STREAM, 0);
    $address = $_SERVER['SSH_AUTH_SOCK'] ?: $_ENV['SSH_AUTH_SOCK'];

    if (!socket_connect($socket, $address)) {
      echo 'Unable to connect '.socket_strerror(socket_last_error());
      return false;
    }

    echo "Connection successful on $address\n";
    return $this->socket = $socket;
  }

  public function requestIdentities()
  {
      if (!$this->sendRequest(SSH2_AGENTC_REQUEST_IDENTITIES)) {
        echo 'Unable to request identities '.socket_strerror(socket_last_error());

        return false;
      }

      $bufferLenght = $this->readLength();
      $type = $this->readType();

      if ($type == SSH_AGENT_FAILURE) {

        return false;
      } elseif ($type != SSH_AGENT_RSA_IDENTITIES_ANSWER && $type != SSH2_AGENT_IDENTITIES_ANSWER) {
        throw new \Exception("Unknown response from agent: $type");
      }

      $buffer = socket_read($this->socket, $bufferLenght - 1);
      $keysCount = $this->binaryToLong($buffer);
      $buffer = substr($buffer, 4);

      for ($i = 0; $i < $keysCount; ++$i) {
          $blob = $this->readPacketFromBuffer($buffer);
          $this->keys[] = array(
                                'blob' => $blob,
                                'comment' => $this->readPacketFromBuffer($buffer),
                                'key' => 'ssh-rsa '.base64_encode($blob));
      }
  }

  private static function binaryToLong($binary) {

    return current(unpack('Nlong', $binary));
  }

  private function sendRequest($type, $data = '') {
      $len = strlen($data) + 1;
      $buffer = pack("NCa*", $len, $type, $data);

      return socket_write($this->socket, $buffer);
  }

  private function readLength() {
      $len = socket_read($this->socket, 4);

      return $this->binaryToLong($len);
  }

  private function readType() {
      return ord(socket_read($this->socket, 1));
  }

  private function readPacketFromBuffer(&$buffer)
  {
      $len = $this->binaryToLong($buffer);
      $packet = substr($buffer, 4, $len);
      $buffer = substr($buffer, $len + 4);

      return $packet;
  }

  public function getKeys()
  {
    return $this->keys;
  }

  function socket_can_write($socket)
  {
    $write = array($socket);
    $n = null;
    socket_select($n, $write, $n, 0);

    return (isset($write[0]) && $write[0] === $socket);
  }

  function sign($pubkeydata, $data)
  {
      /* Create a request to sign the data */
      $s = pack('CNa*Na*N',
              SSH2_AGENTC_SIGN_REQUEST,
              strlen($pubkeydata),
              $pubkeydata,
              strlen($data),
              $data,
              0);

      if (!$this->socket_can_write($this->socket)) {

        throw new Exception("Agent not connected");
      }

      $rc = socket_write($this->socket, pack("Na*", strlen($s), $s));

      if ($rc === false) {
          throw new Exception('Kaboom! '.socket_strerror(socket_last_error()));
      }

      $len = $this->readLength();

      if ($len < 8) {
        throw new Exception("Error protocol");
      }

      $type = $this->readType();

      if ($type != SSH2_AGENT_SIGN_RESPONSE) {
        throw new Exception("Error protocol");
      }

      $s = socket_read($this->socket, $len - 1);

      $signature = unpack('Nlen/a*blob', $s);

      if ($len != 5 + $signature['len']) {
        throw new Exception("Invalid sign");
      }

      return $signature['blob'];
  }
}
