<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Pure-PHP implementations of SSHv2.
 *
 * PHP versions 4 and 5
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include('Net/SSH2.php');
 *
 *    $ssh = new Net_SSH2('www.domain.tld');
 *    if (!$ssh->login('username', 'password')) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->exec('pwd');
 *    echo $ssh->exec('ls -la');
 * ?>
 * </code>
 *
 * LICENSE: This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA  02111-1307  USA
 *
 * @category   Net
 * @package    Net_SSH2
 * @author     Jim Wigginton <terrafrost@php.net>
 * @copyright  MMVII Jim Wigginton
 * @license    http://www.gnu.org/licenses/lgpl.txt
 * @version    $Id: SSH2.php,v 1.12 2009-03-25 22:29:42 terrafrost Exp $
 * @link       http://phpseclib.sourceforge.net
 */

/**
 * Include Math_BigInteger
 *
 * Used to do Diffie-Hellman key exchange and DSA/RSA signature verification.
 */
require_once('Math/BigInteger.php');

/**
 * Include Crypt_Random
 */
require_once('Crypt/Random.php');

/**
 * Include Crypt_Hash
 */
require_once('Crypt/Hash.php');

/**
 * Include Crypt_TripleDES
 */
require_once('Crypt/TripleDES.php');

/**
 * Include Crypt_RC4
 */
require_once('Crypt/RC4.php');

/**
 * Include Crypt_AES
 */
require_once('Crypt/AES.php');

/**#@+
 * Execution Bitmap Masks
 *
 * @see Net_SSH2::bitmap
 * @access private
 */
define('NET_SSH2_MASK_CONSTRUCTOR', 0x00000001);
define('NET_SSH2_MASK_LOGIN',       0x00000002);
/**#@-*/

/**#@+
 * @access public
 * @see Net_SSH2::getLog()
 */
/**
 * Returns the message numbers
 */
define('NET_SSH2_LOG_SIMPLE',  1);
/**
 * Returns the message content
 */
define('NET_SSH2_LOG_COMPLEX', 2);
/**#@-*/

/**
 * Pure-PHP implementation of SSHv2.
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 0.1.0
 * @access  public
 * @package Net_SSH2
 */
class Net_SSH2 {
    /**
     * The SSH identifier
     *
     * @var String
     * @access private
     */
    var $identifier = 'SSH-2.0-phpseclib_0.1';

    /**
     * The Socket Object
     *
     * @var Object
     * @access private
     */
    var $fsock;

    /**
     * Execution Bitmap
     *
     * The bits that are set reprsent functions that have been called already.  This is used to determine
     * if a requisite function has been successfully executed.  If not, an error should be thrown.
     *
     * @var Boolean
     * @access private
     */
    var $bitmap = true;

    /**
     * Debug Info
     *
     * @see Net_SSH2::getDebugInfo()
     * @var String
     * @access private
     */
    var $debug_info = '';

    /**
     * Server Identifier
     *
     * @see Net_SSH2::getServerIdentification()
     * @var String
     * @access private
     */
    var $server_identifier = '';

    /**
     * Key Exchange Algorithms
     *
     * @see Net_SSH2::getKexAlgorithims()
     * @var Array
     * @access private
     */
    var $kex_algorithms;

    /**
     * Server Host Key Algorithms
     *
     * @see Net_SSH2::getServerHostKeyAlgorithms()
     * @var Array
     * @access private
     */
    var $server_host_key_algorithms;

    /**
     * Encryption Algorithms: Client to Server
     *
     * @see Net_SSH2::getEncryptionAlgorithmsClient2Server()
     * @var Array
     * @access private
     */
    var $encryption_algorithms_client_to_server;

    /**
     * Encryption Algorithms: Server to Client
     *
     * @see Net_SSH2::getEncryptionAlgorithmsServer2Client()
     * @var Array
     * @access private
     */
    var $encryption_algorithms_server_to_client;

    /**
     * MAC Algorithms: Client to Server
     *
     * @see Net_SSH2::getMACAlgorithmsClient2Server()
     * @var Array
     * @access private
     */
    var $mac_algorithms_client_to_server;

    /**
     * MAC Algorithms: Server to Client
     *
     * @see Net_SSH2::getMACAlgorithmsServer2Client()
     * @var Array
     * @access private
     */
    var $mac_algorithms_server_to_client;

    /**
     * Compression Algorithms: Client to Server
     *
     * @see Net_SSH2::getCompressionAlgorithmsClient2Server()
     * @var Array
     * @access private
     */
    var $compression_algorithms_client_to_server;

    /**
     * Compression Algorithms: Server to Client
     *
     * @see Net_SSH2::getCompressionAlgorithmsServer2Client()
     * @var Array
     * @access private
     */
    var $compression_algorithms_server_to_client;

    /**
     * Languages: Server to Client
     *
     * @see Net_SSH2::getLanguagesServer2Client()
     * @var Array
     * @access private
     */
    var $languages_server_to_client;

    /**
     * Languages: Client to Server
     *
     * @see Net_SSH2::getLanguagesClient2Server()
     * @var Array
     * @access private
     */
    var $languages_client_to_server;

    /**
     * Block Size for Server to Client Encryption
     *
     * "Note that the length of the concatenation of 'packet_length',
     *  'padding_length', 'payload', and 'random padding' MUST be a multiple
     *  of the cipher block size or 8, whichever is larger.  This constraint
     *  MUST be enforced, even when using stream ciphers."
     *
     *  -- http://tools.ietf.org/html/rfc4253#section-6
     *
     * @see Net_SSH2::Net_SSH2()
     * @see Net_SSH2::_send_binary_packet()
     * @var Integer
     * @access private
     */
    var $encrypt_block_size = 8;

    /**
     * Block Size for Client to Server Encryption
     *
     * @see Net_SSH2::Net_SSH2()
     * @see Net_SSH2::_get_binary_packet()
     * @var Integer
     * @access private
     */
    var $decrypt_block_size = 8;

    /**
     * Server to Client Encryption Object
     *
     * @see Net_SSH2::_get_binary_packet()
     * @var Object
     * @access private
     */
    var $decrypt = false;

    /**
     * Client to Server Encryption Object
     *
     * @see Net_SSH2::_send_binary_packet()
     * @var Object
     * @access private
     */
    var $encrypt = false;

    /**
     * Client to Server HMAC Object
     *
     * @see Net_SSH2::_send_binary_packet()
     * @var Object
     * @access private
     */
    var $hmac_create = false;

    /**
     * Server to Client HMAC Object
     *
     * @see Net_SSH2::_get_binary_packet()
     * @var Object
     * @access private
     */
    var $hmac_check = false;

    /**
     * Size of server to client HMAC
     *
     * We need to know how big the HMAC will be for the server to client direction so that we know how many bytes to read.
     * For the client to server side, the HMAC object will make the HMAC as long as it needs to be.  All we need to do is
     * append it.
     *
     * @see Net_SSH2::_get_binary_packet()
     * @var Integer
     * @access private
     */
    var $hmac_size = false;

    /**
     * Server Public Host Key
     *
     * @see Net_SSH2::getServerPublicHostKey()
     * @var String
     * @access private
     */
    var $server_public_host_key;

    /**
     * Session identifer
     *
     * "The exchange hash H from the first key exchange is additionally
     *  used as the session identifier, which is a unique identifier for
     *  this connection."
     *
     *  -- http://tools.ietf.org/html/rfc4253#section-7.2
     *
     * @see Net_SSH2::_key_exchange()
     * @var String
     * @access private
     */
    var $session_id = false;

    /**
     * Message Numbers
     *
     * @see Net_SSH2::Net_SSH2()
     * @var Array
     * @access private
     */
    var $message_numbers = array();

    /**
     * Disconnection Message 'reason codes' defined in RFC4253
     *
     * @see Net_SSH2::Net_SSH2()
     * @var Array
     * @access private
     */
    var $disconnect_reasons = array();

    /**
     * SSH_MSG_CHANNEL_OPEN_FAILURE 'reason codes', defined in RFC4254
     *
     * @see Net_SSH2::Net_SSH2()
     * @var Array
     * @access private
     */
    var $channel_open_failure_reasons = array();

    /**
     * Terminal Modes
     *
     * @link http://tools.ietf.org/html/rfc4254#section-8
     * @see Net_SSH2::Net_SSH2()
     * @var Array
     * @access private
     */
    var $terminal_modes = array();

    /**
     * SSH_MSG_CHANNEL_EXTENDED_DATA's data_type_codes
     *
     * @link http://tools.ietf.org/html/rfc4254#section-5.2
     * @see Net_SSH2::Net_SSH2()
     * @var Array
     * @access private
     */
    var $channel_extended_data_type_codes = array();

    /**
     * Send Sequence Number
     *
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see Net_SSH2::_send_binary_packet()
     * @var Integer
     * @access private
     */
    var $send_seq_no = 0;

    /**
     * Get Sequence Number
     *
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see Net_SSH2::_get_binary_packet()
     * @var Integer
     * @access private
     */
    var $get_seq_no = 0;

    /**
     * Message Number Log
     *
     * @see Net_SSH2::getLog()
     * @var Array
     * @access private
     */
    var $message_number_log = array();

    /**
     * Message Log
     *
     * @see Net_SSH2::getLog()
     * @var Array
     * @access private
     */
    var $message_log = array();

    /**
     * Default Constructor.
     *
     * Connects to an SSHv2 server
     *
     * @param String $host
     * @param optional Integer $port
     * @param optional Integer $timeout
     * @return Net_SSH2
     * @access public
     */
    function Net_SSH2($host, $port = 22, $timeout = 10)
    {
        $this->message_numbers = array(
            1 => 'NET_SSH2_MSG_DISCONNECT',
            2 => 'NET_SSH2_MSG_IGNORE',
            3 => 'NET_SSH2_MSG_UNIMPLEMENTED',
            4 => 'NET_SSH2_MSG_DEBUG',
            5 => 'NET_SSH2_MSG_SERVICE_REQUEST',
            6 => 'NET_SSH2_MSG_SERVICE_ACCEPT',
            20 => 'NET_SSH2_MSG_KEXINIT',
            21 => 'NET_SSH2_MSG_NEWKEYS',
            30 => 'NET_SSH2_MSG_KEXDH_INIT',
            31 => 'NET_SSH2_MSG_KEXDH_REPLY',
            50 => 'NET_SSH2_MSG_USERAUTH_REQUEST',
            51 => 'NET_SSH2_MSG_USERAUTH_FAILURE',
            52 => 'NET_SSH2_MSG_USERAUTH_SUCCESS',
            53 => 'NET_SSH2_MSG_USERAUTH_BANNER',
            60 => 'NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ',

            80 => 'NET_SSH2_MSG_GLOBAL_REQUEST',
            81 => 'NET_SSH2_MSG_REQUEST_SUCCESS',
            82 => 'NET_SSH2_MSG_REQUEST_FAILURE',
            90 => 'NET_SSH2_MSG_CHANNEL_OPEN',
            91 => 'NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION',
            92 => 'NET_SSH2_MSG_CHANNEL_OPEN_FAILURE',
            93 => 'NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST',
            94 => 'NET_SSH2_MSG_CHANNEL_DATA',
            95 => 'NET_SSH2_MSG_CHANNEL_EXTENDED_DATA',
            96 => 'NET_SSH2_MSG_CHANNEL_EOF',
            97 => 'NET_SSH2_MSG_CHANNEL_CLOSE',
            98 => 'NET_SSH2_MSG_CHANNEL_REQUEST',
            99 => 'NET_SSH2_MSG_CHANNEL_SUCCESS',
            100 => 'NET_SSH2_MSG_CHANNEL_FAILURE'
        );
        $this->disconnect_reasons = array(
            1 => 'NET_SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT',
            2 => 'NET_SSH2_DISCONNECT_PROTOCOL_ERROR',
            3 => 'NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED',
            4 => 'NET_SSH2_DISCONNECT_RESERVED',
            5 => 'NET_SSH2_DISCONNECT_MAC_ERROR',
            6 => 'NET_SSH2_DISCONNECT_COMPRESSION_ERROR',
            7 => 'NET_SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE',
            8 => 'NET_SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED',
            9 => 'NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE',
            10 => 'NET_SSH2_DISCONNECT_CONNECTION_LOST',
            11 => 'NET_SSH2_DISCONNECT_BY_APPLICATION',
            12 => 'NET_SSH2_DISCONNECT_TOO_MANY_CONNECTIONS',
            13 => 'NET_SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER',
            14 => 'NET_SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE',
            15 => 'NET_SSH2_DISCONNECT_ILLEGAL_USER_NAME'
        );
        $this->channel_open_failure_reasons = array(
            1 => 'NET_SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED'
        );
        $this->terminal_modes = array(
            0 => 'NET_SSH2_TTY_OP_END'
        );
        $this->channel_extended_data_type_codes = array(
            1 => 'NET_SSH2_EXTENDED_DATA_STDERR'
        );

        $this->_define_array(
            $this->message_numbers,
            $this->disconnect_reasons,
            $this->channel_open_failure_reasons,
            $this->terminal_modes,
            $this->channel_extended_data_type_codes
        );

        $this->fsock = fsockopen($host, $port, $errno, $errstr, $timeout);
        if (!$this->fsock) {
            user_error(rtrim("Cannot connect to $host. Error $errno. $errstr"), E_USER_NOTICE);
            return;
        }

        /* According to the SSH2 specs,

          "The server MAY send other lines of data before sending the version
           string.  Each line SHOULD be terminated by a Carriage Return and Line
           Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
           in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
           MUST be able to process such lines." */
        $temp = '';
        while (!feof($this->fsock) && !preg_match('#^SSH-(\d\.\d+)#', $temp, $matches)) {
            if (substr($temp, -2) == "\r\n") {
                $this->debug_info.= $temp;
                $temp = '';
            }
            $temp.= fgets($this->fsock, 255);
        }
        $this->server_identifier = trim($temp);
        $this->debug_info = utf8_decode($this->debug_info);

        if ($matches[1] != '1.99' && $matches[1] != '2.0') {
            user_error("Cannot connect to SSH $matches[1] servers", E_USER_NOTICE);
            return;
        }

        fputs($this->fsock, $this->identifier . "\r\n");

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server', E_USER_NOTICE);
            return;
        }

        if (ord($response[0]) != NET_SSH2_MSG_KEXINIT) {
            user_error('Expected SSH_MSG_KEXINIT', E_USER_NOTICE);
            return false;
        }

        if (!$this->_key_exchange($response)) {
            return;
        }

        $this->bitmap = NET_SSH2_MASK_CONSTRUCTOR;
    }

    /**
     * Key Exchange
     *
     * @param String $kexinit_payload_server
     * @access private
     */
    function _key_exchange($kexinit_payload_server)
    {
        static $kex_algorithms = array(
            'diffie-hellman-group1-sha1', // REQUIRED
            'diffie-hellman-group14-sha1' // REQUIRED
        );

        static $server_host_key_algorithms = array(
            'ssh-rsa', // RECOMMENDED  sign   Raw RSA Key
            'ssh-dss'  // REQUIRED     sign   Raw DSS Key
        );

        static $encryption_algorithms = array(
            'aes256-cbc', // OPTIONAL          AES in CBC mode, with a 256-bit key
            'aes192-cbc', // OPTIONAL          AES with a 192-bit key
            'aes128-cbc', // RECOMMENDED       AES with a 128-bit key
            'arcfour',    // OPTIONAL          the ARCFOUR stream cipher with a 128-bit key
            '3des-cbc',   // REQUIRED          three-key 3DES in CBC mode
            'none'        // OPTIONAL          no encryption; NOT RECOMMENDED
        );

        static $mac_algorithms = array(
            'hmac-sha1-96', // RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
            'hmac-sha1',    // REQUIRED        HMAC-SHA1 (digest length = key length = 20)
            'hmac-md5-96',  // OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
            'hmac-md5',     // OPTIONAL        HMAC-MD5 (digest length = key length = 16)
            'none'          // OPTIONAL        no MAC; NOT RECOMMENDED
        );

        static $compression_algorithms = array(
            'none', // REQUIRED        no compression
            'zlib'  // OPTIONAL        ZLIB (LZ77) compression
        );

        static $str_kex_algorithms, $str_server_host_key_algorithms,
               $encryption_algorithms_server_to_client, $mac_algorithms_server_to_client, $compression_algorithms_server_to_client,
               $encryption_algorithms_client_to_server, $mac_algorithms_client_to_server, $compression_algorithms_client_to_server;

        if (empty($str_kex_algorithms)) {
            $str_kex_algorithms = implode(',', $kex_algorithms);
            $str_server_host_key_algorithms = implode(',', $server_host_key_algorithms);
            $encryption_algorithms_server_to_client = $encryption_algorithms_client_to_server = implode(',', $encryption_algorithms);
            $mac_algorithms_server_to_client = $mac_algorithms_client_to_server = implode(',', $mac_algorithms);
            $compression_algorithms_server_to_client = $compression_algorithms_client_to_server = implode(',', $compression_algorithms);
        }

        $client_cookie = '';
        for ($i = 0; $i < 16; $i++) {
            $client_cookie.= chr(crypt_random(0, 255));
        }

        $response = $kexinit_payload_server;
        $this->_string_shift($response, 1); // skip past the message number (it should be SSH_MSG_KEXINIT)
        list(, $server_cookie) = unpack('a16', $this->_string_shift($response, 16));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->kex_algorithms = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->server_host_key_algorithms = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->encryption_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->encryption_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->mac_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->mac_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->compression_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->compression_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->languages_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->languages_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

        list(, $first_kex_packet_follows) = unpack('C', $this->_string_shift($response, 1));
        $first_kex_packet_follows = $first_kex_packet_follows != 0;

        // the sending of SSH2_MSG_KEXINIT could go in one of two places.  this is the second place.
        $kexinit_payload_client = pack('Ca*Na*Na*Na*Na*Na*Na*Na*Na*Na*Na*CN',
            NET_SSH2_MSG_KEXINIT, $client_cookie, strlen($str_kex_algorithms), $str_kex_algorithms,
            strlen($str_server_host_key_algorithms), $str_server_host_key_algorithms, strlen($encryption_algorithms_client_to_server),
            $encryption_algorithms_client_to_server, strlen($encryption_algorithms_server_to_client), $encryption_algorithms_server_to_client,
            strlen($mac_algorithms_client_to_server), $mac_algorithms_client_to_server, strlen($mac_algorithms_server_to_client),
            $mac_algorithms_server_to_client, strlen($compression_algorithms_client_to_server), $compression_algorithms_client_to_server,
            strlen($compression_algorithms_server_to_client), $compression_algorithms_server_to_client, 0, '', 0, '',
            0, 0
        );

        if (!$this->_send_binary_packet($kexinit_payload_client)) {
            return false;
        }
        // here ends the second place.

        // we need to decide upon the symmetric encryption algorithms before we do the diffie-hellman key exchange
        for ($i = 0; $i < count($encryption_algorithms) && !in_array($encryption_algorithms[$i], $this->encryption_algorithms_server_to_client); $i++);
        if ($i == count($encryption_algorithms)) {
            user_error('No compatible server to client encryption algorithms found', E_USER_NOTICE);
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        // we don't initialize any crypto-objects, yet - we do that, later. for now, we need the lengths to make the
        // diffie-hellman key exchange as fast as possible
        $decrypt = $encryption_algorithms[$i];
        switch ($decrypt) {
            case '3des-cbc':
                $decryptKeyLength = 24; // eg. 192 / 8
                break;
            case 'aes256-cbc':
                $decryptKeyLength = 32; // eg. 256 / 8
                break;
            case 'aes192-cbc':
                $decryptKeyLength = 24; // eg. 192 / 8
                break;
            case 'aes128-cbc':
                $decryptKeyLength = 16; // eg. 128 / 8
                break;
            case 'arcfour':
                $decryptKeyLength = 16; // eg. 128 / 8
                break;
            case 'none';
                $decryptKeyLength = 0;
        }

        for ($i = 0; $i < count($encryption_algorithms) && !in_array($encryption_algorithms[$i], $this->encryption_algorithms_client_to_server); $i++);
        if ($i == count($encryption_algorithms)) {
            user_error('No compatible client to server encryption algorithms found', E_USER_NOTICE);
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        $encrypt = $encryption_algorithms[$i];
        switch ($encrypt) {
            case '3des-cbc':
                $encryptKeyLength = 24;
                break;
            case 'aes256-cbc':
                $encryptKeyLength = 32;
                break;
            case 'aes192-cbc':
                $encryptKeyLength = 24;
                break;
            case 'aes128-cbc':
                $encryptKeyLength = 16;
                break;
            case 'arcfour':
                $encryptKeyLength = 16;
                break;
            case 'none';
                $encryptKeyLength = 0;
        }

        $keyLength = $decryptKeyLength > $encryptKeyLength ? $decryptKeyLength : $encryptKeyLength;

        // through diffie-hellman key exchange a symmetric key is obtained
        for ($i = 0; $i < count($kex_algorithms) && !in_array($kex_algorithms[$i], $this->kex_algorithms); $i++);
        if ($i == count($kex_algorithms)) {
            user_error('No compatible key exchange algorithms found', E_USER_NOTICE);
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        switch ($kex_algorithms[$i]) {
            // see http://tools.ietf.org/html/rfc2409#section-6.2 and 
            // http://tools.ietf.org/html/rfc2412, appendex E
            case 'diffie-hellman-group1-sha1':
                $p = pack('N32', 0xFFFFFFFF, 0xFFFFFFFF, 0xC90FDAA2, 0x2168C234, 0xC4C6628B, 0x80DC1CD1,
                                 0x29024E08, 0x8A67CC74, 0x020BBEA6, 0x3B139B22, 0x514A0879, 0x8E3404DD,
                                 0xEF9519B3, 0xCD3A431B, 0x302B0A6D, 0xF25F1437, 0x4FE1356D, 0x6D51C245,
                                 0xE485B576, 0x625E7EC6, 0xF44C42E9, 0xA637ED6B, 0x0BFF5CB6, 0xF406B7ED,
                                 0xEE386BFB, 0x5A899FA5, 0xAE9F2411, 0x7C4B1FE6, 0x49286651, 0xECE65381,
                                 0xFFFFFFFF, 0xFFFFFFFF);
                $keyLength = $keyLength < 160 ? $keyLength : 160;
                $hash = 'sha1';
                break;
            // see http://tools.ietf.org/html/rfc3526#section-3
            case 'diffie-hellman-group14-sha1':
                $p = pack('N64', 0xFFFFFFFF, 0xFFFFFFFF, 0xC90FDAA2, 0x2168C234, 0xC4C6628B, 0x80DC1CD1,
                                 0x29024E08, 0x8A67CC74, 0x020BBEA6, 0x3B139B22, 0x514A0879, 0x8E3404DD,
                                 0xEF9519B3, 0xCD3A431B, 0x302B0A6D, 0xF25F1437, 0x4FE1356D, 0x6D51C245,
                                 0xE485B576, 0x625E7EC6, 0xF44C42E9, 0xA637ED6B, 0x0BFF5CB6, 0xF406B7ED,
                                 0xEE386BFB, 0x5A899FA5, 0xAE9F2411, 0x7C4B1FE6, 0x49286651, 0xECE45B3D,
                                 0xC2007CB8, 0xA163BF05, 0x98DA4836, 0x1C55D39A, 0x69163FA8, 0xFD24CF5F,
                                 0x83655D23, 0xDCA3AD96, 0x1C62F356, 0x208552BB, 0x9ED52907, 0x7096966D,
                                 0x670C354E, 0x4ABC9804, 0xF1746C08, 0xCA18217C, 0x32905E46, 0x2E36CE3B,
                                 0xE39E772C, 0x180E8603, 0x9B2783A2, 0xEC07A28F, 0xB5C55DF0, 0x6F4C52C9,
                                 0xDE2BCBF6, 0x95581718, 0x3995497C, 0xEA956AE5, 0x15D22618, 0x98FA0510,
                                 0x15728E5A, 0x8AACAA68, 0xFFFFFFFF, 0xFFFFFFFF);
                $keyLength = $keyLength < 160 ? $keyLength : 160;
                $hash = 'sha1';
        }

        $p = new Math_BigInteger($p, 256);
        //$q = $p->bitwise_rightShift(1);

        /* To increase the speed of the key exchange, both client and server may
           reduce the size of their private exponents.  It should be at least
           twice as long as the key material that is generated from the shared
           secret.  For more details, see the paper by van Oorschot and Wiener
           [VAN-OORSCHOT].

           -- http://tools.ietf.org/html/rfc4419#section-6.2 */
        $q = new Math_BigInteger(1);
        $q = $q->bitwise_leftShift(2 * $keyLength);
        $q = $q->subtract(new Math_BigInteger(1));

        $g = new Math_BigInteger(2);
        $x = new Math_BigInteger();
        $x = $x->random(new Math_BigInteger(1), $q, 'crypt_random');
        $e = $g->modPow($x, $p);

        $eBytes = $e->toBytes(true);
        $data = pack('CNa*', NET_SSH2_MSG_KEXDH_INIT, strlen($eBytes), $eBytes);

        if (!$this->_send_binary_packet($data)) {
            user_error('Connection closed by server', E_USER_NOTICE);
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server', E_USER_NOTICE);
            return false;
        }

        list(, $type) = unpack('C', $this->_string_shift($response, 1));

        if ($type != NET_SSH2_MSG_KEXDH_REPLY) {
            user_error('Expected SSH_MSG_KEXDH_REPLY', E_USER_NOTICE);
            return false;
        }

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $this->server_public_host_key = $server_public_host_key = $this->_string_shift($response, $temp['length']);

        $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
        $public_key_format = $this->_string_shift($server_public_host_key, $temp['length']);

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $fBytes = $this->_string_shift($response, $temp['length']);
        $f = new Math_BigInteger($fBytes, -256);

        $temp = unpack('Nlength', $this->_string_shift($response, 4));
        $signature = $this->_string_shift($response, $temp['length']);

        $temp = unpack('Nlength', $this->_string_shift($signature, 4));
        $signature_format = $this->_string_shift($signature, $temp['length']);

        $key = $f->modPow($x, $p);
        $keyBytes = $key->toBytes(true);

        $source = pack('Na*Na*Na*Na*Na*Na*Na*Na*',
            strlen($this->identifier), $this->identifier, strlen($this->server_identifier), $this->server_identifier,
            strlen($kexinit_payload_client), $kexinit_payload_client, strlen($kexinit_payload_server),
            $kexinit_payload_server, strlen($this->server_public_host_key), $this->server_public_host_key, strlen($eBytes),
            $eBytes, strlen($fBytes), $fBytes, strlen($keyBytes), $keyBytes
        );

        $source = pack('H*', $hash($source));

        if ($this->session_id === false) {
            $this->session_id = $source;
        }

        // if you the server's assymetric key matches the one you have on file, then you should be able to decrypt the
        // "signature" and get something that should equal the "exchange hash", as defined in the SSH-2 specs.
        // here, we just check to see if the "signature" is good.  you can verify whether or not the assymetric key is good,
        // later, with the getServerHostKeyAlgorithm() function
        for ($i = 0; $i < count($server_host_key_algorithms) && !in_array($server_host_key_algorithms[$i], $this->server_host_key_algorithms); $i++);
        if ($i == count($server_host_key_algorithms)) {
            user_error('No compatible server host key algorithms found', E_USER_NOTICE);
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        if ($public_key_format != $server_host_key_algorithms[$i] || $signature_format != $server_host_key_algorithms[$i]) {
            user_error('Sever Host Key Algorithm Mismatch', E_USER_NOTICE);
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        switch ($server_host_key_algorithms[$i]) {
            case 'ssh-dss':
                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $p = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $q = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $g = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $y = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                /* The value for 'dss_signature_blob' is encoded as a string containing
                   r, followed by s (which are 160-bit integers, without lengths or
                   padding, unsigned, and in network byte order). */
                $temp = unpack('Nlength', $this->_string_shift($signature, 4));
                if ($temp['length'] != 40) {
                    user_error('Invalid signature', E_USER_NOTICE);
                    return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                }

                $r = new Math_BigInteger($this->_string_shift($signature, 20), 256);
                $s = new Math_BigInteger($this->_string_shift($signature, 20), 256);

                if ($r->compare($q) >= 0 || $s->compare($q) >= 0) {
                    user_error('Invalid signature', E_USER_NOTICE);
                    return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                }

                $w = $s->modInverse($q);

                $u1 = $w->multiply(new Math_BigInteger(sha1($source), 16));
                list(, $u1) = $u1->divide($q);

                $u2 = $w->multiply($r);
                list(, $u2) = $u2->divide($q);

                $g = $g->modPow($u1, $p);
                $y = $y->modPow($u2, $p);

                $v = $g->multiply($y);
                list(, $v) = $v->divide($p);
                list(, $v) = $v->divide($q);

                if ($v->compare($r) != 0) {
                    user_error('Invalid signature', E_USER_NOTICE);
                    return $this->_disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }

                break;
            case 'ssh-rsa':
                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $e = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $n = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);
                $nLength = $temp['length'];

                $temp = unpack('Nlength', $this->_string_shift($signature, 4));
                $s = new Math_BigInteger($this->_string_shift($signature, $temp['length']), 256);

                // validate an RSA signature per "8.2 RSASSA-PKCS1-v1_5", "5.2.2 RSAVP1", and "9.1 EMSA-PSS" in the
                // following URL:
                // ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf

                // also, see SSHRSA.c (rsa2_verifysig) in PuTTy's source.

                if ($s->compare(new Math_BigInteger()) < 0 || $s->compare($n->subtract(new Math_BigInteger(1))) > 0) {
                    user_error('Invalid signature', E_USER_NOTICE);
                    return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                }

                $s = $s->modPow($e, $n);
                $s = $s->toBytes();

                $h = chr(0x00) . chr(0x30) . chr(0x21) . chr(0x30) . chr(0x09) . chr(0x06) . chr(0x05) . chr(0x2B) .
                     chr(0x0E) . chr(0x03) . chr(0x02) . chr(0x1A) . chr(0x05) . chr(0x00) . chr(0x04) . chr(0x14) .
                     pack('H*', sha1($source));
                $h = chr(0x01) . str_repeat(chr(0xFF), $nLength - 3 - strlen($h)) . $h;

                if ($s != $h) {
                    user_error('Bad server signature', E_USER_NOTICE);
                    return $this->_disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }
        }

        $packet = pack('C',
            NET_SSH2_MSG_NEWKEYS
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();

        if ($response === false) {
            user_error('Connection closed by server', E_USER_NOTICE);
            return false;
        }

        list(, $type) = unpack('C', $this->_string_shift($response, 1));

        if ($type != NET_SSH2_MSG_NEWKEYS) {
            user_error('Expected SSH_MSG_NEWKEYS', E_USER_NOTICE);
            return false;
        }

        switch ($encrypt) {
            case '3des-cbc':
                $this->encrypt = new Crypt_TripleDES();
                // $this->encrypt_block_size = 64 / 8 == the default
                break;
            case 'aes256-cbc':
                $this->encrypt = new Crypt_AES();
                $this->encrypt_block_size = 16; // eg. 128 / 8
                break;
            case 'aes192-cbc':
                $this->encrypt = new Crypt_AES();
                $this->encrypt_block_size = 16;
                break;
            case 'aes128-cbc':
                $this->encrypt = new Crypt_AES();
                $this->encrypt_block_size = 16;
                break;
            case 'arcfour':
                $this->encrypt = new Crypt_RC4();
                break;
            case 'none';
                //$this->encrypt = new Crypt_Null();
        }

        switch ($decrypt) {
            case '3des-cbc':
                $this->decrypt = new Crypt_TripleDES();
                break;
            case 'aes256-cbc':
                $this->decrypt = new Crypt_AES();
                $this->decrypt_block_size = 16;
                break;
            case 'aes192-cbc':
                $this->decrypt = new Crypt_AES();
                $this->decrypt_block_size = 16;
                break;
            case 'aes128-cbc':
                $this->decrypt = new Crypt_AES();
                $this->decrypt_block_size = 16;
                break;
            case 'arcfour':
                $this->decrypt = new Crypt_RC4();
                break;
            case 'none';
                //$this->decrypt = new Crypt_Null();
        }

        $this->encrypt->enableContinuousBuffer();
        $this->decrypt->enableContinuousBuffer();

        $this->encrypt->disablePadding();
        $this->decrypt->disablePadding();

        for ($i = 0; $i < count($mac_algorithms) && !in_array($mac_algorithms[$i], $this->mac_algorithms_client_to_server); $i++);
        if ($i == count($mac_algorithms)) {
            user_error('No compatible client to server message authentication algorithms found', E_USER_NOTICE);
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        $createKeyLength = 0; // ie. $mac_algorithms[$i] == 'none'
        switch ($mac_algorithms[$i]) {
            case 'hmac-sha1':
                $this->hmac_create = new Crypt_Hash('sha1');
                $createKeyLength = 20;
                break;
            case 'hmac-sha1-96':
                $this->hmac_create = new Crypt_Hash('sha1-96');
                $createKeyLength = 20;
                break;
            case 'hmac-md5':
                $this->hmac_create = new Crypt_Hash('md5');
                $createKeyLength = 16;
                break;
            case 'hmac-md5-96':
                $this->hmac_create = new Crypt_Hash('md5-96');
                $createKeyLength = 16;
        }

        for ($i = 0; $i < count($mac_algorithms) && !in_array($mac_algorithms[$i], $this->mac_algorithms_server_to_client); $i++);
        if ($i == count($mac_algorithms)) {
            user_error('No compatible server to client message authentication algorithms found', E_USER_NOTICE);
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        $checkKeyLength = 0;
        $this->hmac_size = 0;
        switch ($mac_algorithms[$i]) {
            case 'hmac-sha1':
                $this->hmac_check = new Crypt_Hash('sha1');
                $checkKeyLength = 20;
                $this->hmac_size = 20;
                break;
            case 'hmac-sha1-96':
                $this->hmac_check = new Crypt_Hash('sha1-96');
                $checkKeyLength = 20;
                $this->hmac_size = 12;
                break;
            case 'hmac-md5':
                $this->hmac_check = new Crypt_Hash('md5');
                $checkKeyLength = 16;
                $this->hmac_size = 16;
                break;
            case 'hmac-md5-96':
                $this->hmac_check = new Crypt_Hash('md5-96');
                $checkKeyLength = 16;
                $this->hmac_size = 12;
        }

        $keyBytes = pack('Na*', strlen($keyBytes), $keyBytes);

        $iv = pack('H*', $hash($keyBytes . $source . 'A' . $this->session_id));
        while ($this->encrypt_block_size > strlen($iv)) {
            $iv.= pack('H*', $hash($keyBytes . $source . $iv));
        }
        $this->encrypt->setIV(substr($iv, 0, $this->encrypt_block_size));

        $iv = pack('H*', $hash($keyBytes . $source . 'B' . $this->session_id));
        while ($this->decrypt_block_size > strlen($iv)) {
            $iv.= pack('H*', $hash($keyBytes . $source . $iv));
        }
        $this->decrypt->setIV(substr($iv, 0, $this->decrypt_block_size));

        $key = pack('H*', $hash($keyBytes . $source . 'C' . $this->session_id));
        while ($encryptKeyLength > strlen($key)) {
            $key.= pack('H*', $hash($keyBytes . $source . $key));
        }
        $this->encrypt->setKey(substr($key, 0, $encryptKeyLength));

        $key = pack('H*', $hash($keyBytes . $source . 'D' . $this->session_id));
        while ($decryptKeyLength > strlen($key)) {
            $key.= pack('H*', $hash($keyBytes . $source . $key));
        }
        $this->decrypt->setKey(substr($key, 0, $decryptKeyLength));

        $key = pack('H*', $hash($keyBytes . $source . 'E' . $this->session_id));
        while ($createKeyLength > strlen($key)) {
            $key.= pack('H*', $hash($keyBytes . $source . $key));
        }
        $this->hmac_create->setKey(substr($key, 0, $createKeyLength));

        $key = pack('H*', $hash($keyBytes . $source . 'F' . $this->session_id));
        while ($checkKeyLength > strlen($key)) {
            $key.= pack('H*', $hash($keyBytes . $source . $key));
        }
        $this->hmac_check->setKey(substr($key, 0, $checkKeyLength));

    }

    /**
     * Login
     *
     * @param String $username
     * @param optional String $password
     * @return Boolean
     * @access public
     */
    function login($username, $password = '')
    {
        if (!($this->bitmap & NET_SSH2_MASK_CONSTRUCTOR)) {
            return false;
        }

        $packet = pack('CNa*',
            NET_SSH2_MSG_SERVICE_REQUEST, strlen('ssh-userauth'), 'ssh-userauth'
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server', E_USER_NOTICE);
            return false;
        }

        list(, $type) = unpack('C', $this->_string_shift($response, 1));

        if ($type != NET_SSH2_MSG_SERVICE_ACCEPT) {
            user_error('Expected SSH_MSG_SERVICE_ACCEPT', E_USER_NOTICE);
            return false;
        }

        // publickey authentatication is required, per the SSH-2 specs, however, we don't support it.
        $utf8_password = utf8_encode($password);
        $packet = pack('CNa*Na*Na*CNa*',
            NET_SSH2_MSG_USERAUTH_REQUEST, strlen($username), $username, strlen('ssh-connection'), 'ssh-connection',
            strlen('password'), 'password', 0, strlen($utf8_password), $utf8_password
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server', E_USER_NOTICE);
            return false;
        }

        list(, $type) = unpack('C', $this->_string_shift($response, 1));

        switch ($type) {
            case NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ: // in theory, the password can be changed
                list(, $length) = unpack('N', $this->_string_shift($response, 4));
                $this->debug_info.= "\r\n\r\nSSH_MSG_USERAUTH_PASSWD_CHANGEREQ:\r\n" . utf8_decode($this->_string_shift($response, $length));
                $this->bitmap = 0;
                return $this->_disconnect(NET_SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER);
            case NET_SSH2_MSG_USERAUTH_FAILURE:
                list(, $length) = unpack('Nlength', $this->_string_shift($response, 4));
                $this->debug_info.= "\r\n\r\nSSH_MSG_USERAUTH_FAILURE:\r\n" . $this->_string_shift($response, $length);
                $this->bitmap = 0;
                return $this->_disconnect(NET_SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER);
            case NET_SSH2_MSG_USERAUTH_SUCCESS:
                $this->bitmap |= NET_SSH2_MASK_LOGIN;
                return true;
        }

        return false;
    }

    /**
     * Execute Command
     *
     * @param String $command
     * @return String
     * @access public
     */
    function exec($command)
    {
        if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
            return false;
        }

        $client_channel = 0; // PuTTy uses 0x100
        $window_size = 0x7FFFFFFF; // eg. as close to the max window size as we can get, per http://tools.ietf.org/html/rfc4254#section-5.2
        $packet_size = 0x7FFFFFFF; // 0x4000 is the minimum max packet size, per http://tools.ietf.org/html/rfc4253#section-6.1

        $packet = pack('CNa*N3',
            NET_SSH2_MSG_CHANNEL_OPEN, strlen('session'), 'session', $client_channel, $window_size, $packet_size);

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server', E_USER_NOTICE);
            return false;
        }

        list(, $type) = unpack('C', $this->_string_shift($response, 1));

        switch ($type) {
            case NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
                $this->_string_shift($response, 4);
                list(, $server_channel) = unpack('N', $this->_string_shift($response, 4));
                break;
            case NET_SSH2_MSG_CHANNEL_OPEN_FAILURE:
                $this->bitmap = 0;
                user_error('Unable to open channel', E_USER_NOTICE);
                return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
        }

        $terminal_modes = pack('C', NET_SSH2_TTY_OP_END);
        $packet = pack('CNNa*CNa*N5a*',
            NET_SSH2_MSG_CHANNEL_REQUEST, $server_channel, strlen('pty-req'), 'pty-req', 1, strlen('vt100'), 'vt100',
            80, 24, 0, 0, strlen($terminal_modes), $terminal_modes);

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server', E_USER_NOTICE);
            return false;
        }

        list(, $type) = unpack('C', $this->_string_shift($response, 1));

        switch ($type) {
            case NET_SSH2_MSG_CHANNEL_SUCCESS:
                break;
            case NET_SSH2_MSG_CHANNEL_FAILURE:
            default:
                $this->bitmap = 0;
                user_error('Unable to request pseudo-terminal', E_USER_NOTICE);
                return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
        }

        $packet = pack('CNNa*CNa*',
            NET_SSH2_MSG_CHANNEL_REQUEST, $server_channel, strlen('exec'), 'exec', 1, strlen($command), $command);
        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server', E_USER_NOTICE);
            return false;
        }

        list(, $type) = unpack('C', $this->_string_shift($response, 1));

        switch ($type) {
            case NET_SSH2_MSG_CHANNEL_SUCCESS:
                break;
            case NET_SSH2_MSG_CHANNEL_FAILURE:
            default:
                $this->bitmap = 0;
                user_error('Unable to start execution of command', E_USER_NOTICE);
                return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
        }

        $output = '';

        while (true) {
            $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server', E_USER_NOTICE);
                return false;
            }

            list(, $type) = unpack('C', $this->_string_shift($response, 1));

            switch ($type) {
                case NET_SSH2_MSG_CHANNEL_DATA:
                    $this->_string_shift($response, 4); // skip over server channel
                    list(, $length) = unpack('N', $this->_string_shift($response, 4));
                    $output.= $this->_string_shift($response, $length);
                    break;
                case NET_SSH2_MSG_CHANNEL_EXTENDED_DATA:
                    $this->_string_shift($response, 4); // skip over server channel
                    list(, $data_type_code, $length) = unpack('N2', $this->_string_shift($response, 8));
                    $data = $this->_string_shift($response, $length);
                    switch ($data_type_code) {
                        case NET_SSH2_EXTENDED_DATA_STDERR:
                            $this->debug_info.= "\r\n\r\nSSH_MSG_CHANNEL_EXTENDED_DATA (SSH_EXTENDED_DATA_STDERR):\r\n" . $data;
                    }
                    break;
                case NET_SSH2_MSG_CHANNEL_REQUEST:
                    $this->_string_shift($response, 4); // skip over server channel
                    list(, $length) = unpack('N', $this->_string_shift($response, 4));
                    $value = $this->_string_shift($response, $length);
                    switch ($value) {
                        case 'exit-signal':
                            $this->_string_shift($response, 1);
                            list(, $length) = unpack('N', $this->_string_shift($response, 4));
                            $this->debug_info.= "\r\n\r\nSSH_MSG_CHANNEL_REQUEST (exit-signal):\r\nSIG" . $this->_string_shift($response, $length);
                            $this->_string_shift($response, 1);
                            list(, $length) = unpack('N', $this->_string_shift($response, 4));
                            $this->debug_info.= "\r\n" . $this->_string_shift($response, $length);
                        case 'exit-status':
                        default:
                            // "Some systems may not implement signals, in which case they SHOULD ignore this message."
                            //  -- http://tools.ietf.org/html/rfc4254#section-6.9
                            //break 2;
                            break;
                    }
                    break;
                case NET_SSH2_MSG_CHANNEL_CLOSE:
                    $this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $server_channel));
                    break 2;
                case NET_SSH2_MSG_CHANNEL_EOF:
                    break;
                default:
                    $this->bitmap = 0;
                    user_error('Error reading channel data', E_USER_NOTICE);
                    return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
            }
        }

        return $output;
    }

    /**
     * Disconnect
     *
     * @access public
     */
    function disconnect()
    {
        $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
    }

    /**
     * Destructor.
     *
     * Will be called, automatically, if you're supporting just PHP5.  If you're supporting PHP4, you'll need to call
     * disconnect().
     *
     * @access public
     */
    function __destruct()
    {
        $this->disconnect();
    }

    /**
     * Gets Binary Packets
     *
     * See '6. Binary Packet Protocol' of rfc4253 for more info.
     *
     * @see Net_SSH2::_send_binary_packet()
     * @return String
     * @access private
     */
    function _get_binary_packet()
    {
        if (feof($this->fsock)) {
            user_error('Connection closed prematurely', E_USER_NOTICE);
            return false;
        }

        $raw = fread($this->fsock, $this->decrypt_block_size);

        if ($this->decrypt !== false) {
            $raw = $this->decrypt->decrypt($raw);
        }

        $temp = unpack('Npacket_length/Cpadding_length', $this->_string_shift($raw, 5));
        $packet_length = $temp['packet_length'];
        $padding_length = $temp['padding_length'];

        $remaining_length = $packet_length + 4 - $this->decrypt_block_size;
        if ($remaining_length > 0) {
            $temp = fread($this->fsock, $remaining_length);
            $raw.= $this->decrypt !== false ? $this->decrypt->decrypt($temp) : $temp;
        }

        $payload = $this->_string_shift($raw, $packet_length - $padding_length - 1);
        $padding = $this->_string_shift($raw, $padding_length); // should leave $raw empty

        if ($this->hmac_check !== false) {
            $hmac = fread($this->fsock, $this->hmac_size);
            if ($hmac != $this->hmac_check->hash(pack('NNCa*', $this->get_seq_no, $packet_length, $padding_length, $payload . $padding))) {
                user_error('Invalid HMAC', E_USER_NOTICE);
                return false;
            }
        }

        $this->get_seq_no++;

        if (defined('NET_SSH2_LOGGING')) {
            $this->message_number_log[] = '<- ' . $this->message_numbers[ord($payload[0])];
            $this->message_log[] = $padding;
        }

        return $this->_filter($payload);
    }

    /**
     * Filter Binary Packets
     *
     * Because some binary packets need to be ignored...
     *
     * @see Net_SSH2::_get_binary_packet()
     * @return String
     * @access private
     */
    function _filter($payload)
    {
        switch (ord($payload[0])) {
            case NET_SSH2_MSG_DISCONNECT:
                $this->_string_shift($payload, 1);
                list(, $reason_code, $length) = unpack('N2', $this->_string_shift($payload, 8));
                $this->debug_info.= "\r\n\r\nSSH_MSG_DISCONNECT:\r\n" . $this->disconnect_reasons[$reason_code] . "\r\n" . utf8_decode($this->_string_shift($payload, $temp['length']));
                $this->bitmask = 0;
                return false;
            case NET_SSH2_MSG_IGNORE:
                $payload = $this->_get_binary_packet();
                break;
            case NET_SSH2_MSG_DEBUG:
                $this->_string_shift($payload, 2);
                list(, $length) = unpack('N', $payload);
                $this->debug_info.= "\r\n\r\nSSH_MSG_DEBUG:\r\n" . utf8_decode($this->_string_shift($payload, $length));
                $payload = $this->_get_binary_packet();
                break;
            case NET_SSH2_MSG_UNIMPLEMENTED:
                return false;
            case NET_SSH2_MSG_KEXINIT:
                if ($this->session_id !== false) {
                    if (!$this->_key_exchange($payload)) {
                        $this->bitmask = 0;
                        return false;
                    }
                    $payload = $this->_get_binary_packet();
                }
        }

        // see http://tools.ietf.org/html/rfc4252#section-5.4; only called when the encryption has been activated and when we haven't already logged in
        if (($this->bitmap & NET_SSH2_MASK_CONSTRUCTOR) && !($this->bitmap & NET_SSH2_MASK_LOGIN) && ord($payload[0]) == NET_SSH2_MSG_USERAUTH_BANNER) {
            $this->_string_shift($payload, 1);
            list(, $length) = unpack('N', $payload);
            $this->debug_info.= "\r\n\r\nSSH_MSG_USERAUTH_BANNER:\r\n" . utf8_decode($this->_string_shift($payload, $length));
            $payload = $this->_get_binary_packet();
        }

        // only called when we've already logged in
        if (($this->bitmap & NET_SSH2_MASK_CONSTRUCTOR) && ($this->bitmap & NET_SSH2_MASK_LOGIN)) {
            switch (ord($payload[0])) {
                case NET_SSH2_MSG_GLOBAL_REQUEST: // see http://tools.ietf.org/html/rfc4254#section-4
                    $this->_string_shift($payload, 1);
                    list(, $length) = unpack('N', $payload);
                    $this->debug_info.= "\r\n\r\nSSH_MSG_GLOBAL_REQUEST:\r\n" . utf8_decode($this->_string_shift($payload, $length));

                    if (!$this->_send_binary_packet(pack('C', NET_SSH2_MSG_REQUEST_FAILURE))) {
                        $this->bitmap = 0;
                        return false;
                    }

                    $payload = $this->_get_binary_packet();
                    break;
                case NET_SSH2_MSG_CHANNEL_OPEN: // see http://tools.ietf.org/html/rfc4254#section-5.1
                    $this->_string_shift($payload, 1);
                    list(, $length) = unpack('N', $payload);
                    $this->debug_info.= "\r\n\r\nSSH_MSG_CHANNEL_OPEN:\r\n" . utf8_decode($this->_string_shift($payload, $length));

                    list(, $recipient_channel) = unpack('N', $this->_string_shift($payload, 4));

                    $packet = pack('CN3a*Na*',
                        NET_SSH2_MSG_REQUEST_FAILURE, $recipient_channel, NET_SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED, 0, '', 0, '');

                    if (!$this->_send_binary_packet($packet)) {
                        $this->bitmap = 0;
                        return false;
                    }

                    $payload = $this->_get_binary_packet();
                    break;
                case NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST:
                    $payload = $this->_get_binary_packet();
            }
        }

        return $payload;
    }

    /**
     * Sends Binary Packets
     *
     * See '6. Binary Packet Protocol' of rfc4253 for more info.
     *
     * @param String $data
     * @see Net_SSH2::_get_binary_packet()
     * @return Boolean
     * @access private
     */
    function _send_binary_packet($data)
    {
        if (feof($this->fsock)) {
            user_error('Connection closed prematurely', E_USER_NOTICE);
            return false;
        }

        if (defined('NET_SSH2_LOGGING')) {
            $this->message_number_log[] = '-> ' . $this->message_numbers[ord($data[0])];
            $this->message_log[] = $data;
        }

        // 4 (packet length) + 1 (padding length) + 4 (minimal padding amount) == 9
        $packet_length = strlen($data) + 9;
        // round up to the nearest $this->encrypt_block_size
        $packet_length+= (($this->encrypt_block_size - 1) * $packet_length) % $this->encrypt_block_size;
        // subtracting strlen($data) is obvious - subtracting 5 is necessary because of packet_length and padding_length
        $padding_length = $packet_length - strlen($data) - 5;

        $padding = '';
        for ($i = 0; $i < $padding_length; $i++) {
            $padding.= chr(crypt_random(0, 255));
        }

        // we subtract 4 from packet_length because the packet_length field isn't supposed to include itself
        $packet = pack('NCa*', $packet_length - 4, $padding_length, $data . $padding);

        $hmac = $this->hmac_create !== false ? $this->hmac_create->hash(pack('Na*', $this->send_seq_no, $packet)) : '';
        $this->send_seq_no++;

        if ($this->encrypt !== false) {
            $packet = $this->encrypt->encrypt($packet);
        }

        $packet.= $hmac;

        return strlen($packet) == fputs($this->fsock, $packet);
    }

    /**
     * Disconnect
     *
     * @param Integer $reason
     * @return Boolean
     * @access private
     */
    function _disconnect($reason)
    {
        if ($this->bitmap) {
            $data = pack('CNNa*Na*', NET_SSH2_MSG_DISCONNECT, $reason, 0, '', 0, '');
            $this->_send_binary_packet($data);
            $this->bitmap = 0;
            fclose($this->fsock);
            return false;
        }
    }

    /**
     * String Shift
     *
     * Inspired by array_shift
     *
     * @param String $string
     * @param optional Integer $index
     * @return String
     * @access private
     */
    function _string_shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }

    /**
     * Define Array
     *
     * Takes any number of arrays whose indices are integers and whose values are strings and defines a bunch of
     * named constants from it, using the value as the name of the constant and the index as the value of the constant.
     * If any of the constants that would be defined already exists, none of the constants will be defined.
     *
     * @param Array $array
     * @access private
     */
    function _define_array()
    {
        $args = func_get_args();
        foreach ($args as $arg) {
            foreach ($arg as $key=>$value) {
                if (!defined($value)) {
                    define($value, $key);
                } else {
                    break 2;
                }
            }
        }
    }

    /**
     * Returns a log of the packets that have been sent and received.
     *
     * $type can be either NET_SSH2_LOG_SIMPLE or NET_SSH2_LOG_COMPLEX.  NET_SSH2_LOG_COMPLEX
     * will contain your severs password, so don't distribute log files produced with it unless
     * you've redacted the password.
     *
     * @param Integer $type
     * @access public
     * @return String or Array
     */
    function getLog($type = NET_SSH2_LOG_SIMPLE)
    {
        if ($type != NET_SSH2_LOG_COMPLEX) {
            return $this->message_number_log;
        }

        $boundary = ':';
        $long_width = 65;
        $short_width = 15;

        $output = '';
        for ($i = 0; $i < count($this->message_log); $i++) {
            $output.= $this->message_number_log[$i] . "\r\n";
            do {
                $fragment = $this->_string_shift($this->message_log[$i], $short_width);
                $hex = substr(
                           preg_replace(
                               '#(.)#es',
                               '"' . $boundary . '" . str_pad(dechex(ord(substr("\\1", -1))), 2, "0", STR_PAD_LEFT)',
                               $fragment),
                           strlen($boundary)
                       );
                // replace non ASCII printable characters with dots
                // http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters
                $raw = preg_replace('#[^\x20-\x7E]#', '.', $fragment);
                $output.= str_pad($hex, $long_width - $short_width, ' ') . $raw . "\r\n";
            } while (!empty($this->message_log[$i]));
            $output.= "\r\n";
        }

        return $output;
    }

    /**
     * Returns Debug Information
     *
     * If any debug information is sent by the server, this function can be used to access it.
     *
     * @return String
     * @access public
     */
    function getDebugInfo()
    {
        return $this->debug_info;
    }

    /**
     * Return the server identification.
     *
     * @return String
     * @access public
     */
    function getServerIdentification()
    {
        return $this->server_identifier;
    }

    /**
     * Return a list of the key exchange algorithms the server supports.
     *
     * @return Array
     * @access public
     */
    function getKexAlgorithms()
    {
        return $this->kex_algorithms;
    }

    /**
     * Return a list of the host key (public key) algorithms the server supports.
     *
     * @return Array
     * @access public
     */
    function getServerHostKeyAlgorithms()
    {
        return $this->server_host_key_algorithms;
    }

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     * @access public
     */
    function getEncryptionAlgorithmsClient2Server()
    {
        return $this->encryption_algorithms_client_to_server;
    }

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     * @access public
     */
    function getEncryptionAlgorithmsServer2Client()
    {
        return $this->encryption_algorithms_server_to_client;
    }

    /**
     * Return a list of the MAC algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     * @access public
     */
    function getMACAlgorithmsClient2Server()
    {
        return $this->mac_algorithms_client_to_server;
    }

    /**
     * Return a list of the MAC algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     * @access public
     */
    function getMACAlgorithmsServer2Client()
    {
        return $this->mac_algorithms_server_to_client;
    }

    /**
     * Return a list of the compression algorithms the server supports, when receiving stuff from the client.
     *
     * @return Array
     * @access public
     */
    function getCompressionAlgorithmsClient2Server()
    {
        return $this->compression_algorithms_client_to_server;
    }

    /**
     * Return a list of the compression algorithms the server supports, when sending stuff to the client.
     *
     * @return Array
     * @access public
     */
    function getCompressionAlgorithmsServer2Client()
    {
        return $this->compression_algorithms_server_to_client;
    }

    /**
     * Return a list of the languages the server supports, when sending stuff to the client.
     *
     * @return Array
     * @access public
     */
    function getLanguagesServer2Client()
    {
        return $this->languages_server_to_client;
    }

    /**
     * Return a list of the languages the server supports, when receiving stuff from the client.
     *
     * @return Array
     * @access public
     */
    function getLanguagesClient2Server()
    {
        return $this->languages_client_to_server;
    }

    /**
     * Returns the server public host key.
     *
     * Caching this the first time you connect to a server and checking the result on subsequent connections
     * is recommended.
     *
     * @return Array
     * @access public
     */
    function getServerPublicHostKey()
    {
        return $this->server_public_host_key;
    }
}
?>