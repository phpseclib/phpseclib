<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Hash;
use phpseclib\Math\BigInteger;
use phpseclib\Net\SSH2;

abstract class PhpseclibFunctionalTestCase extends PhpseclibTestCase
{
    /**
     * Cache of SSH server compatibility checks, keyed by hostname.
     *
     * The value is false if the server is compatible (or if compatibility
     * couldn't be determined) and a skip message otherwise.
     *
     * @var array
     */
    private static $sshServerCompatibility = array();

    public static function setUpBeforeClass()
    {
        if (extension_loaded('runkit')) {
            if (extension_loaded('gmp')) {
                self::ensureConstant(
                    'MATH_BIGINTEGER_MODE',
                    BigInteger::MODE_GMP
                );
            } elseif (extension_loaded('bcmath')) {
                self::ensureConstant(
                    'MATH_BIGINTEGER_MODE',
                    BigInteger::MODE_BCMATH
                );
            } else {
                self::markTestSkipped(
                    'Should have gmp or bcmath extension for functional test.'
                );
            }
            self::ensureConstant('CRYPT_HASH_MODE', Hash::MODE_HASH);
            self::reRequireFile('Math/BigInteger.php');
            self::reRequireFile('Crypt/Hash.php');
        }
        parent::setUpBeforeClass();
    }

    /**
     * @param string $variable
     * @param string|null $message
     *
     * @return null
     */
    protected function requireEnv($variable, $message = null)
    {
        if ($this->_getEnv($variable) === false) {
            $msg = $message ? $message : sprintf(
                "This test requires the '%s' environment variable.",
                $this->_prefixEnvVariable($variable)
            );
            $this->markTestSkipped($msg);
        }

        // every SSH / SFTP functional test needs SSH_HOSTNAME so this is a
        // convenient place to also make sure that phpseclib can actually
        // negotiate a key exchange algorithm with the server. eg. OpenSSH
        // 10.2 doesn't support any of the key exchange algorithms that
        // phpseclib 2.0 supports (without libsodium)
        if ($variable === 'SSH_HOSTNAME') {
            $this->requireCompatibleSSHServer($this->_getEnv($variable));
        }
    }

    /**
     * Skips the test if the SSH server doesn't support any of the key
     * exchange algorithms that phpseclib supports
     *
     * @param string $host
     *
     * @return null
     */
    protected function requireCompatibleSSHServer($host)
    {
        if (!isset(self::$sshServerCompatibility[$host])) {
            self::$sshServerCompatibility[$host] = self::_checkSSHServerCompatibility($host);
        }

        if (self::$sshServerCompatibility[$host] !== false) {
            $this->markTestSkipped(self::$sshServerCompatibility[$host]);
        }
    }

    /**
     * Returns false if the SSH server is compatible and a skip message if it isn't.
     *
     * If the server's KEXINIT can't be retrieved false is returned so that
     * the tests run (and fail) as they normally would.
     *
     * @param string $host
     * @param int $port
     *
     * @return string|false
     */
    private static function _checkSSHServerCompatibility($host, $port = 22)
    {
        $result = self::_getServerKEXAlgorithms($host, $port);
        if ($result === false) {
            return false;
        }
        list($identifier, $server_kex) = $result;

        $ssh = self::_createSSH2($host, $port);
        $client_kex = $ssh->getSupportedKEXAlgorithms();

        if (count(array_intersect($client_kex, $server_kex))) {
            return false;
        }

        return sprintf(
            'SSH server %s (%s) does not support any key exchange algorithms phpseclib supports (server: %s; phpseclib: %s)',
            $host,
            $identifier,
            implode(', ', $server_kex),
            implode(', ', $client_kex)
        );
    }

    /**
     * @param string $host
     * @param int $port
     *
     * @return SSH2
     */
    private static function _createSSH2($host, $port)
    {
        return new SSH2($host, $port);
    }

    /**
     * Connects to the SSH server and reads its SSH_MSG_KEXINIT packet
     *
     * The SSH_MSG_KEXINIT packet is sent unencrypted (RFC 4253 § 7.1) so
     * nothing more than the identification string exchange is needed
     *
     * @param string $host
     * @param int $port
     *
     * @return array|false array($server_identifier, $kex_algorithms) on success
     */
    private static function _getServerKEXAlgorithms($host, $port)
    {
        $fsock = @fsockopen($host, $port, $errno, $errstr, 10);
        if (!$fsock) {
            return false;
        }
        stream_set_timeout($fsock, 10);

        // the server MAY send other lines of data before the version string (RFC 4253 § 4.2)
        $identifier = false;
        for ($i = 0; $i < 50; $i++) {
            $line = fgets($fsock, 256);
            if ($line === false) {
                break;
            }
            if (substr($line, 0, 4) == 'SSH-') {
                $identifier = rtrim($line, "\r\n");
                break;
            }
        }
        if ($identifier === false) {
            fclose($fsock);
            return false;
        }

        fputs($fsock, "SSH-2.0-phpseclib_kex_probe\r\n");

        // uint32 packet_length, byte padding_length, byte[] payload, byte[] padding
        $header = self::_readBytes($fsock, 5);
        if (strlen($header) != 5) {
            fclose($fsock);
            return false;
        }
        $temp = unpack('Nlength', substr($header, 0, 4));
        $length = $temp['length'];
        // 1 (padding_length) + 1 (message number) + 16 (cookie) + 4 (name-list length)
        if ($length < 22 || $length > 35000) {
            fclose($fsock);
            return false;
        }
        $payload = self::_readBytes($fsock, $length - 1);
        fclose($fsock);

        if (strlen($payload) != $length - 1 || ord($payload[0]) != 20) { // NET_SSH2_MSG_KEXINIT
            return false;
        }

        $temp = unpack('Nlength', substr($payload, 17, 4));
        $kex_algorithms = substr($payload, 21, $temp['length']);
        if (strlen($kex_algorithms) != $temp['length']) {
            return false;
        }

        return array($identifier, explode(',', $kex_algorithms));
    }

    /**
     * @param resource $fsock
     * @param int $length
     *
     * @return string
     */
    private static function _readBytes($fsock, $length)
    {
        $data = '';
        while (strlen($data) < $length && !feof($fsock)) {
            $temp = fread($fsock, $length - strlen($data));
            // the socket is blocking so an empty read means a timeout or EOF
            if ($temp === false || $temp === '') {
                break;
            }
            $data .= $temp;
        }
        return $data;
    }

    /**
     * @param string $variable
     *
     * @return string
     */
    protected function getEnv($variable)
    {
        $this->requireEnv($variable);
        return $this->_getEnv($variable);
    }

    private function _getEnv($variable)
    {
        return getenv($this->_prefixEnvVariable($variable));
    }

    private function _prefixEnvVariable($variable)
    {
        return 'PHPSECLIB_' . $variable;
    }
}
