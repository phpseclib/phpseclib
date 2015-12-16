<?php

/**
 * Pure-PHP implementation of SSHv2.
 *
 * PHP versions 4 and 5
 *
 * Here are some examples of how to use this library:
 * <code>
 * <?php
 *    include 'Net/SSH2.php';
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
 * <code>
 * <?php
 *    include 'Crypt/RSA.php';
 *    include 'Net/SSH2.php';
 *
 *    $key = new Crypt_RSA();
 *    //$key->setPassword('whatever');
 *    $key->loadKey(file_get_contents('privatekey'));
 *
 *    $ssh = new Net_SSH2('www.domain.tld');
 *    if (!$ssh->login('username', $key)) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->read('username@username:~$');
 *    $ssh->write("ls -la\n");
 *    echo $ssh->read('username@username:~$');
 * ?>
 * </code>
 *
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @category  Net
 * @package   Net_SSH2
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

/**#@+
 * Execution Bitmap Masks
 *
 * @see self::bitmap
 * @access private
 */
define('NET_SSH2_MASK_CONSTRUCTOR',   0x00000001);
define('NET_SSH2_MASK_CONNECTED',     0x00000002);
define('NET_SSH2_MASK_LOGIN_REQ',     0x00000004);
define('NET_SSH2_MASK_LOGIN',         0x00000008);
define('NET_SSH2_MASK_SHELL',         0x00000010);
define('NET_SSH2_MASK_WINDOW_ADJUST', 0x00000020);
/**#@-*/

/**#@+
 * Channel constants
 *
 * RFC4254 refers not to client and server channels but rather to sender and recipient channels.  we don't refer
 * to them in that way because RFC4254 toggles the meaning. the client sends a SSH_MSG_CHANNEL_OPEN message with
 * a sender channel and the server sends a SSH_MSG_CHANNEL_OPEN_CONFIRMATION in response, with a sender and a
 * recepient channel.  at first glance, you might conclude that SSH_MSG_CHANNEL_OPEN_CONFIRMATION's sender channel
 * would be the same thing as SSH_MSG_CHANNEL_OPEN's sender channel, but it's not, per this snipet:
 *     The 'recipient channel' is the channel number given in the original
 *     open request, and 'sender channel' is the channel number allocated by
 *     the other side.
 *
 * @see self::_send_channel_packet()
 * @see self::_get_channel_packet()
 * @access private
 */
define('NET_SSH2_CHANNEL_EXEC',      0); // PuTTy uses 0x100
define('NET_SSH2_CHANNEL_SHELL',     1);
define('NET_SSH2_CHANNEL_SUBSYSTEM', 2);
define('NET_SSH2_CHANNEL_AGENT_FORWARD', 3);
/**#@-*/

/**#@+
 * @access public
 * @see self::getLog()
 */
/**
 * Returns the message numbers
 */
define('NET_SSH2_LOG_SIMPLE',  1);
/**
 * Returns the message content
 */
define('NET_SSH2_LOG_COMPLEX', 2);
/**
 * Outputs the content real-time
 */
define('NET_SSH2_LOG_REALTIME', 3);
/**
 * Dumps the content real-time to a file
 */
define('NET_SSH2_LOG_REALTIME_FILE', 4);
/**#@-*/

/**#@+
 * @access public
 * @see self::read()
 */
/**
 * Returns when a string matching $expect exactly is found
 */
define('NET_SSH2_READ_SIMPLE',  1);
/**
 * Returns when a string matching the regular expression $expect is found
 */
define('NET_SSH2_READ_REGEX', 2);
/**
 * Make sure that the log never gets larger than this
 */
define('NET_SSH2_LOG_MAX_SIZE', 1024 * 1024);
/**#@-*/

/**
 * Pure-PHP implementation of SSHv2.
 *
 * @package Net_SSH2
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class Net_SSH2
{
    /**
     * The SSH identifier
     *
     * @var string
     * @access private
     */
    var $identifier;

    /**
     * The Socket Object
     *
     * @var object
     * @access private
     */
    var $fsock;

    /**
     * Execution Bitmap
     *
     * The bits that are set represent functions that have been called already.  This is used to determine
     * if a requisite function has been successfully executed.  If not, an error should be thrown.
     *
     * @var int
     * @access private
     */
    var $bitmap = 0;

    /**
     * Error information
     *
     * @see self::getErrors()
     * @see self::getLastError()
     * @var string
     * @access private
     */
    var $errors = array();

    /**
     * Server Identifier
     *
     * @see self::getServerIdentification()
     * @var array|false
     * @access private
     */
    var $server_identifier = false;

    /**
     * Key Exchange Algorithms
     *
     * @see self::getKexAlgorithims()
     * @var array|false
     * @access private
     */
    var $kex_algorithms = false;

    /**
     * Minimum Diffie-Hellman Group Bit Size in RFC 4419 Key Exchange Methods
     *
     * @see self::_key_exchange()
     * @var int
     * @access private
     */
    var $kex_dh_group_size_min = 1536;

    /**
     * Preferred Diffie-Hellman Group Bit Size in RFC 4419 Key Exchange Methods
     *
     * @see self::_key_exchange()
     * @var int
     * @access private
     */
    var $kex_dh_group_size_preferred = 2048;

    /**
     * Maximum Diffie-Hellman Group Bit Size in RFC 4419 Key Exchange Methods
     *
     * @see self::_key_exchange()
     * @var int
     * @access private
     */
    var $kex_dh_group_size_max = 4096;

    /**
     * Server Host Key Algorithms
     *
     * @see self::getServerHostKeyAlgorithms()
     * @var array|false
     * @access private
     */
    var $server_host_key_algorithms = false;

    /**
     * Encryption Algorithms: Client to Server
     *
     * @see self::getEncryptionAlgorithmsClient2Server()
     * @var array|false
     * @access private
     */
    var $encryption_algorithms_client_to_server = false;

    /**
     * Encryption Algorithms: Server to Client
     *
     * @see self::getEncryptionAlgorithmsServer2Client()
     * @var array|false
     * @access private
     */
    var $encryption_algorithms_server_to_client = false;

    /**
     * MAC Algorithms: Client to Server
     *
     * @see self::getMACAlgorithmsClient2Server()
     * @var array|false
     * @access private
     */
    var $mac_algorithms_client_to_server = false;

    /**
     * MAC Algorithms: Server to Client
     *
     * @see self::getMACAlgorithmsServer2Client()
     * @var array|false
     * @access private
     */
    var $mac_algorithms_server_to_client = false;

    /**
     * Compression Algorithms: Client to Server
     *
     * @see self::getCompressionAlgorithmsClient2Server()
     * @var array|false
     * @access private
     */
    var $compression_algorithms_client_to_server = false;

    /**
     * Compression Algorithms: Server to Client
     *
     * @see self::getCompressionAlgorithmsServer2Client()
     * @var array|false
     * @access private
     */
    var $compression_algorithms_server_to_client = false;

    /**
     * Languages: Server to Client
     *
     * @see self::getLanguagesServer2Client()
     * @var array|false
     * @access private
     */
    var $languages_server_to_client = false;

    /**
     * Languages: Client to Server
     *
     * @see self::getLanguagesClient2Server()
     * @var array|false
     * @access private
     */
    var $languages_client_to_server = false;

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
     * @see self::Net_SSH2()
     * @see self::_send_binary_packet()
     * @var int
     * @access private
     */
    var $encrypt_block_size = 8;

    /**
     * Block Size for Client to Server Encryption
     *
     * @see self::Net_SSH2()
     * @see self::_get_binary_packet()
     * @var int
     * @access private
     */
    var $decrypt_block_size = 8;

    /**
     * Server to Client Encryption Object
     *
     * @see self::_get_binary_packet()
     * @var object
     * @access private
     */
    var $decrypt = false;

    /**
     * Client to Server Encryption Object
     *
     * @see self::_send_binary_packet()
     * @var object
     * @access private
     */
    var $encrypt = false;

    /**
     * Client to Server HMAC Object
     *
     * @see self::_send_binary_packet()
     * @var object
     * @access private
     */
    var $hmac_create = false;

    /**
     * Server to Client HMAC Object
     *
     * @see self::_get_binary_packet()
     * @var object
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
     * @see self::_get_binary_packet()
     * @var int
     * @access private
     */
    var $hmac_size = false;

    /**
     * Server Public Host Key
     *
     * @see self::getServerPublicHostKey()
     * @var string
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
     * @see self::_key_exchange()
     * @var string
     * @access private
     */
    var $session_id = false;

    /**
     * Exchange hash
     *
     * The current exchange hash
     *
     * @see self::_key_exchange()
     * @var string
     * @access private
     */
    var $exchange_hash = false;

    /**
     * Message Numbers
     *
     * @see self::Net_SSH2()
     * @var array
     * @access private
     */
    var $message_numbers = array();

    /**
     * Disconnection Message 'reason codes' defined in RFC4253
     *
     * @see self::Net_SSH2()
     * @var array
     * @access private
     */
    var $disconnect_reasons = array();

    /**
     * SSH_MSG_CHANNEL_OPEN_FAILURE 'reason codes', defined in RFC4254
     *
     * @see self::Net_SSH2()
     * @var array
     * @access private
     */
    var $channel_open_failure_reasons = array();

    /**
     * Terminal Modes
     *
     * @link http://tools.ietf.org/html/rfc4254#section-8
     * @see self::Net_SSH2()
     * @var array
     * @access private
     */
    var $terminal_modes = array();

    /**
     * SSH_MSG_CHANNEL_EXTENDED_DATA's data_type_codes
     *
     * @link http://tools.ietf.org/html/rfc4254#section-5.2
     * @see self::Net_SSH2()
     * @var array
     * @access private
     */
    var $channel_extended_data_type_codes = array();

    /**
     * Send Sequence Number
     *
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see self::_send_binary_packet()
     * @var int
     * @access private
     */
    var $send_seq_no = 0;

    /**
     * Get Sequence Number
     *
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see self::_get_binary_packet()
     * @var int
     * @access private
     */
    var $get_seq_no = 0;

    /**
     * Server Channels
     *
     * Maps client channels to server channels
     *
     * @see self::_get_channel_packet()
     * @see self::exec()
     * @var array
     * @access private
     */
    var $server_channels = array();

    /**
     * Channel Buffers
     *
     * If a client requests a packet from one channel but receives two packets from another those packets should
     * be placed in a buffer
     *
     * @see self::_get_channel_packet()
     * @see self::exec()
     * @var array
     * @access private
     */
    var $channel_buffers = array();

    /**
     * Channel Status
     *
     * Contains the type of the last sent message
     *
     * @see self::_get_channel_packet()
     * @var array
     * @access private
     */
    var $channel_status = array();

    /**
     * Packet Size
     *
     * Maximum packet size indexed by channel
     *
     * @see self::_send_channel_packet()
     * @var array
     * @access private
     */
    var $packet_size_client_to_server = array();

    /**
     * Message Number Log
     *
     * @see self::getLog()
     * @var array
     * @access private
     */
    var $message_number_log = array();

    /**
     * Message Log
     *
     * @see self::getLog()
     * @var array
     * @access private
     */
    var $message_log = array();

    /**
     * The Window Size
     *
     * Bytes the other party can send before it must wait for the window to be adjusted (0x7FFFFFFF = 2GB)
     *
     * @var int
     * @see self::_send_channel_packet()
     * @see self::exec()
     * @access private
     */
    var $window_size = 0x7FFFFFFF;

    /**
     * Window size, server to client
     *
     * Window size indexed by channel
     *
     * @see self::_send_channel_packet()
     * @var array
     * @access private
     */
    var $window_size_server_to_client = array();

    /**
     * Window size, client to server
     *
     * Window size indexed by channel
     *
     * @see self::_get_channel_packet()
     * @var array
     * @access private
     */
    var $window_size_client_to_server = array();

    /**
     * Server signature
     *
     * Verified against $this->session_id
     *
     * @see self::getServerPublicHostKey()
     * @var string
     * @access private
     */
    var $signature = '';

    /**
     * Server signature format
     *
     * ssh-rsa or ssh-dss.
     *
     * @see self::getServerPublicHostKey()
     * @var string
     * @access private
     */
    var $signature_format = '';

    /**
     * Interactive Buffer
     *
     * @see self::read()
     * @var array
     * @access private
     */
    var $interactiveBuffer = '';

    /**
     * Current log size
     *
     * Should never exceed NET_SSH2_LOG_MAX_SIZE
     *
     * @see self::_send_binary_packet()
     * @see self::_get_binary_packet()
     * @var int
     * @access private
     */
    var $log_size;

    /**
     * Timeout
     *
     * @see self::setTimeout()
     * @access private
     */
    var $timeout;

    /**
     * Current Timeout
     *
     * @see self::_get_channel_packet()
     * @access private
     */
    var $curTimeout;

    /**
     * Real-time log file pointer
     *
     * @see self::_append_log()
     * @var resource
     * @access private
     */
    var $realtime_log_file;

    /**
     * Real-time log file size
     *
     * @see self::_append_log()
     * @var int
     * @access private
     */
    var $realtime_log_size;

    /**
     * Has the signature been validated?
     *
     * @see self::getServerPublicHostKey()
     * @var bool
     * @access private
     */
    var $signature_validated = false;

    /**
     * Real-time log file wrap boolean
     *
     * @see self::_append_log()
     * @access private
     */
    var $realtime_log_wrap;

    /**
     * Flag to suppress stderr from output
     *
     * @see self::enableQuietMode()
     * @access private
     */
    var $quiet_mode = false;

    /**
     * Time of first network activity
     *
     * @var int
     * @access private
     */
    var $last_packet;

    /**
     * Exit status returned from ssh if any
     *
     * @var int
     * @access private
     */
    var $exit_status;

    /**
     * Flag to request a PTY when using exec()
     *
     * @var bool
     * @see self::enablePTY()
     * @access private
     */
    var $request_pty = false;

    /**
     * Flag set while exec() is running when using enablePTY()
     *
     * @var bool
     * @access private
     */
    var $in_request_pty_exec = false;

    /**
     * Flag set after startSubsystem() is called
     *
     * @var bool
     * @access private
     */
    var $in_subsystem;

    /**
     * Contents of stdError
     *
     * @var string
     * @access private
     */
    var $stdErrorLog;

    /**
     * The Last Interactive Response
     *
     * @see self::_keyboard_interactive_process()
     * @var string
     * @access private
     */
    var $last_interactive_response = '';

    /**
     * Keyboard Interactive Request / Responses
     *
     * @see self::_keyboard_interactive_process()
     * @var array
     * @access private
     */
    var $keyboard_requests_responses = array();

    /**
     * Banner Message
     *
     * Quoting from the RFC, "in some jurisdictions, sending a warning message before
     * authentication may be relevant for getting legal protection."
     *
     * @see self::_filter()
     * @see self::getBannerMessage()
     * @var string
     * @access private
     */
    var $banner_message = '';

    /**
     * Did read() timeout or return normally?
     *
     * @see self::isTimeout()
     * @var bool
     * @access private
     */
    var $is_timeout = false;

    /**
     * Log Boundary
     *
     * @see self::_format_log()
     * @var string
     * @access private
     */
    var $log_boundary = ':';

    /**
     * Log Long Width
     *
     * @see self::_format_log()
     * @var int
     * @access private
     */
    var $log_long_width = 65;

    /**
     * Log Short Width
     *
     * @see self::_format_log()
     * @var int
     * @access private
     */
    var $log_short_width = 16;

    /**
     * Hostname
     *
     * @see self::Net_SSH2()
     * @see self::_connect()
     * @var string
     * @access private
     */
    var $host;

    /**
     * Port Number
     *
     * @see self::Net_SSH2()
     * @see self::_connect()
     * @var int
     * @access private
     */
    var $port;

    /**
     * Number of columns for terminal window size
     *
     * @see self::getWindowColumns()
     * @see self::setWindowColumns()
     * @see self::setWindowSize()
     * @var int
     * @access private
     */
    var $windowColumns = 80;

    /**
     * Number of columns for terminal window size
     *
     * @see self::getWindowRows()
     * @see self::setWindowRows()
     * @see self::setWindowSize()
     * @var int
     * @access private
     */
    var $windowRows = 24;

    /**
     * Crypto Engine
     *
     * @see self::setCryptoEngine()
     * @see self::_key_exchange()
     * @var int
     * @access private
     */
    var $crypto_engine = false;

    /**
     * A System_SSH_Agent for use in the SSH2 Agent Forwarding scenario
     *
     * @var System_SSH_Agent
     * @access private
     */
    var $agent;

    /**
     * Default Constructor.
     *
     * $host can either be a string, representing the host, or a stream resource.
     *
     * @param mixed $host
     * @param int $port
     * @param int $timeout
     * @see self::login()
     * @return Net_SSH2
     * @access public
     */
    function Net_SSH2($host, $port = 22, $timeout = 10)
    {
        // Include Math_BigInteger
        // Used to do Diffie-Hellman key exchange and DSA/RSA signature verification.
        if (!class_exists('Math_BigInteger')) {
            include_once 'Math/BigInteger.php';
        }

        if (!function_exists('crypt_random_string')) {
            include_once 'Crypt/Random.php';
        }

        if (!class_exists('Crypt_Hash')) {
            include_once 'Crypt/Hash.php';
        }

        // include Crypt_Base so constants can be defined for setCryptoEngine()
        if (!class_exists('Crypt_Base')) {
            include_once 'Crypt/Base.php';
        }

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
            $this->channel_extended_data_type_codes,
            array(60 => 'NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ'),
            array(60 => 'NET_SSH2_MSG_USERAUTH_PK_OK'),
            array(60 => 'NET_SSH2_MSG_USERAUTH_INFO_REQUEST',
                  61 => 'NET_SSH2_MSG_USERAUTH_INFO_RESPONSE'),
            // RFC 4419 - diffie-hellman-group-exchange-sha{1,256}
            array(30 => 'NET_SSH2_MSG_KEXDH_GEX_REQUEST_OLD',
                  31 => 'NET_SSH2_MSG_KEXDH_GEX_GROUP',
                  32 => 'NET_SSH2_MSG_KEXDH_GEX_INIT',
                  33 => 'NET_SSH2_MSG_KEXDH_GEX_REPLY',
                  34 => 'NET_SSH2_MSG_KEXDH_GEX_REQUEST')
        );

        if (is_resource($host)) {
            $this->fsock = $host;
            return;
        }

        if (is_string($host)) {
            $this->host = $host;
            $this->port = $port;
            $this->timeout = $timeout;
        }
    }

    /**
     * Set Crypto Engine Mode
     *
     * Possible $engine values:
     * CRYPT_MODE_INTERNAL, CRYPT_MODE_MCRYPT
     *
     * @param int $engine
     * @access private
     */
    function setCryptoEngine($engine)
    {
        $this->crypto_engine = $engine;
    }

    /**
     * Connect to an SSHv2 server
     *
     * @return bool
     * @access private
     */
    function _connect()
    {
        if ($this->bitmap & NET_SSH2_MASK_CONSTRUCTOR) {
            return false;
        }

        $this->bitmap |= NET_SSH2_MASK_CONSTRUCTOR;

        $this->curTimeout = $this->timeout;

        $this->last_packet = strtok(microtime(), ' ') + strtok(''); // == microtime(true) in PHP5

        if (!is_resource($this->fsock)) {
            $start = strtok(microtime(), ' ') + strtok(''); // http://php.net/microtime#61838
            $this->fsock = @fsockopen($this->host, $this->port, $errno, $errstr, $this->curTimeout);
            if (!$this->fsock) {
                $host = $this->host . ':' . $this->port;
                user_error(rtrim("Cannot connect to $host. Error $errno. $errstr"));
                return false;
            }
            $elapsed = strtok(microtime(), ' ') + strtok('') - $start;

            $this->curTimeout-= $elapsed;

            if ($this->curTimeout <= 0) {
                $this->is_timeout = true;
                return false;
            }
        }

        /* According to the SSH2 specs,

          "The server MAY send other lines of data before sending the version
           string.  Each line SHOULD be terminated by a Carriage Return and Line
           Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
           in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
           MUST be able to process such lines." */
        $temp = '';
        $extra = '';
        while (!feof($this->fsock) && !preg_match('#^SSH-(\d\.\d+)#', $temp, $matches)) {
            if (substr($temp, -2) == "\r\n") {
                $extra.= $temp;
                $temp = '';
            }

            if ($this->curTimeout) {
                if ($this->curTimeout < 0) {
                    $this->is_timeout = true;
                    return false;
                }
                $read = array($this->fsock);
                $write = $except = null;
                $start = strtok(microtime(), ' ') + strtok('');
                $sec = floor($this->curTimeout);
                $usec = 1000000 * ($this->curTimeout - $sec);
                // on windows this returns a "Warning: Invalid CRT parameters detected" error
                // the !count() is done as a workaround for <https://bugs.php.net/42682>
                if (!@stream_select($read, $write, $except, $sec, $usec) && !count($read)) {
                    $this->is_timeout = true;
                    return false;
                }
                $elapsed = strtok(microtime(), ' ') + strtok('') - $start;
                $this->curTimeout-= $elapsed;
            }

            $temp.= fgets($this->fsock, 255);
        }

        if (feof($this->fsock)) {
            user_error('Connection closed by server');
            return false;
        }

        $this->identifier = $this->_generate_identifier();

        if (defined('NET_SSH2_LOGGING')) {
            $this->_append_log('<-', $extra . $temp);
            $this->_append_log('->', $this->identifier . "\r\n");
        }

        $this->server_identifier = trim($temp, "\r\n");
        if (strlen($extra)) {
            $this->errors[] = utf8_decode($extra);
        }

        if ($matches[1] != '1.99' && $matches[1] != '2.0') {
            user_error("Cannot connect to SSH $matches[1] servers");
            return false;
        }

        fputs($this->fsock, $this->identifier . "\r\n");

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }

        if (ord($response[0]) != NET_SSH2_MSG_KEXINIT) {
            user_error('Expected SSH_MSG_KEXINIT');
            return false;
        }

        if (!$this->_key_exchange($response)) {
            return false;
        }

        $this->bitmap|= NET_SSH2_MASK_CONNECTED;

        return true;
    }

    /**
     * Generates the SSH identifier
     *
     * You should overwrite this method in your own class if you want to use another identifier
     *
     * @access protected
     * @return string
     */
    function _generate_identifier()
    {
        $identifier = 'SSH-2.0-phpseclib_1.0';

        $ext = array();
        if (extension_loaded('openssl')) {
            $ext[] = 'openssl';
        } elseif (extension_loaded('mcrypt')) {
            $ext[] = 'mcrypt';
        }

        if (extension_loaded('gmp')) {
            $ext[] = 'gmp';
        } elseif (extension_loaded('bcmath')) {
            $ext[] = 'bcmath';
        }

        if (!empty($ext)) {
            $identifier .= ' (' . implode(', ', $ext) . ')';
        }

        return $identifier;
    }

    /**
     * Key Exchange
     *
     * @param string $kexinit_payload_server
     * @access private
     */
    function _key_exchange($kexinit_payload_server)
    {
        static $kex_algorithms = array(
            'diffie-hellman-group1-sha1', // REQUIRED
            'diffie-hellman-group14-sha1', // REQUIRED
            'diffie-hellman-group-exchange-sha1', // RFC 4419
            'diffie-hellman-group-exchange-sha256', // RFC 4419
        );

        static $server_host_key_algorithms = array(
            'ssh-rsa', // RECOMMENDED  sign   Raw RSA Key
            'ssh-dss'  // REQUIRED     sign   Raw DSS Key
        );

        static $encryption_algorithms = false;
        if ($encryption_algorithms === false) {
            $encryption_algorithms = array(
                // from <http://tools.ietf.org/html/rfc4345#section-4>:
                'arcfour256',
                'arcfour128',

                //'arcfour',      // OPTIONAL          the ARCFOUR stream cipher with a 128-bit key

                // CTR modes from <http://tools.ietf.org/html/rfc4344#section-4>:
                'aes128-ctr',     // RECOMMENDED       AES (Rijndael) in SDCTR mode, with 128-bit key
                'aes192-ctr',     // RECOMMENDED       AES with 192-bit key
                'aes256-ctr',     // RECOMMENDED       AES with 256-bit key

                'twofish128-ctr', // OPTIONAL          Twofish in SDCTR mode, with 128-bit key
                'twofish192-ctr', // OPTIONAL          Twofish with 192-bit key
                'twofish256-ctr', // OPTIONAL          Twofish with 256-bit key

                'aes128-cbc',     // RECOMMENDED       AES with a 128-bit key
                'aes192-cbc',     // OPTIONAL          AES with a 192-bit key
                'aes256-cbc',     // OPTIONAL          AES in CBC mode, with a 256-bit key

                'twofish128-cbc', // OPTIONAL          Twofish with a 128-bit key
                'twofish192-cbc', // OPTIONAL          Twofish with a 192-bit key
                'twofish256-cbc',
                'twofish-cbc',    // OPTIONAL          alias for "twofish256-cbc"
                                  //                   (this is being retained for historical reasons)

                'blowfish-ctr',   // OPTIONAL          Blowfish in SDCTR mode

                'blowfish-cbc',   // OPTIONAL          Blowfish in CBC mode

                '3des-ctr',       // RECOMMENDED       Three-key 3DES in SDCTR mode

                '3des-cbc',       // REQUIRED          three-key 3DES in CBC mode
                 //'none'         // OPTIONAL          no encryption; NOT RECOMMENDED
            );

            if (extension_loaded('openssl') && !extension_loaded('mcrypt')) {
                // OpenSSL does not support arcfour256 in any capacity and arcfour128 / arcfour support is limited to
                // instances that do not use continuous buffers
                $encryption_algorithms = array_diff(
                    $encryption_algorithms,
                    array('arcfour256', 'arcfour128', 'arcfour')
                );
            }

            if (phpseclib_resolve_include_path('Crypt/RC4.php') === false) {
                $encryption_algorithms = array_diff(
                    $encryption_algorithms,
                    array('arcfour256', 'arcfour128', 'arcfour')
                );
            }
            if (phpseclib_resolve_include_path('Crypt/Rijndael.php') === false) {
                $encryption_algorithms = array_diff(
                    $encryption_algorithms,
                    array('aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc')
                );
            }
            if (phpseclib_resolve_include_path('Crypt/Twofish.php') === false) {
                $encryption_algorithms = array_diff(
                    $encryption_algorithms,
                    array('twofish128-ctr', 'twofish192-ctr', 'twofish256-ctr', 'twofish128-cbc', 'twofish192-cbc', 'twofish256-cbc', 'twofish-cbc')
                );
            }
            if (phpseclib_resolve_include_path('Crypt/Blowfish.php') === false) {
                $encryption_algorithms = array_diff(
                    $encryption_algorithms,
                    array('blowfish-ctr', 'blowfish-cbc')
                );
            }
            if (phpseclib_resolve_include_path('Crypt/TripleDES.php') === false) {
                $encryption_algorithms = array_diff(
                    $encryption_algorithms,
                    array('3des-ctr', '3des-cbc')
                );
            }
            $encryption_algorithms = array_values($encryption_algorithms);
        }

        $mac_algorithms = array(
            // from <http://www.ietf.org/rfc/rfc6668.txt>:
            'hmac-sha2-256',// RECOMMENDED     HMAC-SHA256 (digest length = key length = 32)

            'hmac-sha1-96', // RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
            'hmac-sha1',    // REQUIRED        HMAC-SHA1 (digest length = key length = 20)
            'hmac-md5-96',  // OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
            'hmac-md5',     // OPTIONAL        HMAC-MD5 (digest length = key length = 16)
            //'none'          // OPTIONAL        no MAC; NOT RECOMMENDED
        );

        static $compression_algorithms = array(
            'none'   // REQUIRED        no compression
            //'zlib' // OPTIONAL        ZLIB (LZ77) compression
        );

        // some SSH servers have buggy implementations of some of the above algorithms
        switch ($this->server_identifier) {
            case 'SSH-2.0-SSHD':
                $mac_algorithms = array_values(array_diff(
                    $mac_algorithms,
                    array('hmac-sha1-96', 'hmac-md5-96')
                ));
        }

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

        $client_cookie = crypt_random_string(16);

        $response = $kexinit_payload_server;
        $this->_string_shift($response, 1); // skip past the message number (it should be SSH_MSG_KEXINIT)
        $server_cookie = $this->_string_shift($response, 16);

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

        extract(unpack('Cfirst_kex_packet_follows', $this->_string_shift($response, 1)));
        $first_kex_packet_follows = $first_kex_packet_follows != 0;

        // the sending of SSH2_MSG_KEXINIT could go in one of two places.  this is the second place.
        $kexinit_payload_client = pack(
            'Ca*Na*Na*Na*Na*Na*Na*Na*Na*Na*Na*CN',
            NET_SSH2_MSG_KEXINIT,
            $client_cookie,
            strlen($str_kex_algorithms),
            $str_kex_algorithms,
            strlen($str_server_host_key_algorithms),
            $str_server_host_key_algorithms,
            strlen($encryption_algorithms_client_to_server),
            $encryption_algorithms_client_to_server,
            strlen($encryption_algorithms_server_to_client),
            $encryption_algorithms_server_to_client,
            strlen($mac_algorithms_client_to_server),
            $mac_algorithms_client_to_server,
            strlen($mac_algorithms_server_to_client),
            $mac_algorithms_server_to_client,
            strlen($compression_algorithms_client_to_server),
            $compression_algorithms_client_to_server,
            strlen($compression_algorithms_server_to_client),
            $compression_algorithms_server_to_client,
            0,
            '',
            0,
            '',
            0,
            0
        );

        if (!$this->_send_binary_packet($kexinit_payload_client)) {
            return false;
        }
        // here ends the second place.

        // we need to decide upon the symmetric encryption algorithms before we do the diffie-hellman key exchange
        // we don't initialize any crypto-objects, yet - we do that, later. for now, we need the lengths to make the
        // diffie-hellman key exchange as fast as possible
        $decrypt = $this->_array_intersect_first($encryption_algorithms, $this->encryption_algorithms_server_to_client);
        $decryptKeyLength = $this->_encryption_algorithm_to_key_size($decrypt);
        if ($decryptKeyLength === null) {
            user_error('No compatible server to client encryption algorithms found');
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        $encrypt = $this->_array_intersect_first($encryption_algorithms, $this->encryption_algorithms_client_to_server);
        $encryptKeyLength = $this->_encryption_algorithm_to_key_size($encrypt);
        if ($encryptKeyLength === null) {
            user_error('No compatible client to server encryption algorithms found');
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        $keyLength = $decryptKeyLength > $encryptKeyLength ? $decryptKeyLength : $encryptKeyLength;

        // through diffie-hellman key exchange a symmetric key is obtained
        $kex_algorithm = $this->_array_intersect_first($kex_algorithms, $this->kex_algorithms);
        if ($kex_algorithm === false) {
            user_error('No compatible key exchange algorithms found');
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }
        if (strpos($kex_algorithm, 'diffie-hellman-group-exchange') === 0) {
            $dh_group_sizes_packed = pack(
                'NNN',
                $this->kex_dh_group_size_min,
                $this->kex_dh_group_size_preferred,
                $this->kex_dh_group_size_max
            );
            $packet = pack(
                'Ca*',
                NET_SSH2_MSG_KEXDH_GEX_REQUEST,
                $dh_group_sizes_packed
            );
            if (!$this->_send_binary_packet($packet)) {
                return false;
            }

            $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server');
                return false;
            }
            extract(unpack('Ctype', $this->_string_shift($response, 1)));
            if ($type != NET_SSH2_MSG_KEXDH_GEX_GROUP) {
                user_error('Expected SSH_MSG_KEX_DH_GEX_GROUP');
                return false;
            }

            extract(unpack('NprimeLength', $this->_string_shift($response, 4)));
            $primeBytes = $this->_string_shift($response, $primeLength);
            $prime = new Math_BigInteger($primeBytes, -256);

            extract(unpack('NgLength', $this->_string_shift($response, 4)));
            $gBytes = $this->_string_shift($response, $gLength);
            $g = new Math_BigInteger($gBytes, -256);

            $exchange_hash_rfc4419 = pack(
                'a*Na*Na*',
                $dh_group_sizes_packed,
                $primeLength,
                $primeBytes,
                $gLength,
                $gBytes
            );

            $clientKexInitMessage = NET_SSH2_MSG_KEXDH_GEX_INIT;
            $serverKexReplyMessage = NET_SSH2_MSG_KEXDH_GEX_REPLY;
        } else {
            switch ($kex_algorithm) {
                // see http://tools.ietf.org/html/rfc2409#section-6.2 and
                // http://tools.ietf.org/html/rfc2412, appendex E
                case 'diffie-hellman-group1-sha1':
                    $prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
                            '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
                            '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
                            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF';
                    break;
                // see http://tools.ietf.org/html/rfc3526#section-3
                case 'diffie-hellman-group14-sha1':
                    $prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
                            '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
                            '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
                            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' .
                            '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' .
                            '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
                            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' .
                            '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF';
                    break;
            }
            // For both diffie-hellman-group1-sha1 and diffie-hellman-group14-sha1
            // the generator field element is 2 (decimal) and the hash function is sha1.
            $g = new Math_BigInteger(2);
            $prime = new Math_BigInteger($prime, 16);
            $exchange_hash_rfc4419 = '';
            $clientKexInitMessage = NET_SSH2_MSG_KEXDH_INIT;
            $serverKexReplyMessage = NET_SSH2_MSG_KEXDH_REPLY;
        }

        switch ($kex_algorithm) {
            case 'diffie-hellman-group-exchange-sha256':
                $kexHash = new Crypt_Hash('sha256');
                break;
            default:
                $kexHash = new Crypt_Hash('sha1');
        }

        /* To increase the speed of the key exchange, both client and server may
           reduce the size of their private exponents.  It should be at least
           twice as long as the key material that is generated from the shared
           secret.  For more details, see the paper by van Oorschot and Wiener
           [VAN-OORSCHOT].

           -- http://tools.ietf.org/html/rfc4419#section-6.2 */
        $one = new Math_BigInteger(1);
        $keyLength = min($keyLength, $kexHash->getLength());
        $max = $one->bitwise_leftShift(16 * $keyLength); // 2 * 8 * $keyLength
        $max = $max->subtract($one);

        $x = $one->random($one, $max);
        $e = $g->modPow($x, $prime);

        $eBytes = $e->toBytes(true);
        $data = pack('CNa*', $clientKexInitMessage, strlen($eBytes), $eBytes);

        if (!$this->_send_binary_packet($data)) {
            user_error('Connection closed by server');
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }
        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        if ($type != $serverKexReplyMessage) {
            user_error('Expected SSH_MSG_KEXDH_REPLY');
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
        $this->signature = $this->_string_shift($response, $temp['length']);

        $temp = unpack('Nlength', $this->_string_shift($this->signature, 4));
        $this->signature_format = $this->_string_shift($this->signature, $temp['length']);

        $key = $f->modPow($x, $prime);
        $keyBytes = $key->toBytes(true);

        $this->exchange_hash = pack(
            'Na*Na*Na*Na*Na*a*Na*Na*Na*',
            strlen($this->identifier),
            $this->identifier,
            strlen($this->server_identifier),
            $this->server_identifier,
            strlen($kexinit_payload_client),
            $kexinit_payload_client,
            strlen($kexinit_payload_server),
            $kexinit_payload_server,
            strlen($this->server_public_host_key),
            $this->server_public_host_key,
            $exchange_hash_rfc4419,
            strlen($eBytes),
            $eBytes,
            strlen($fBytes),
            $fBytes,
            strlen($keyBytes),
            $keyBytes
        );

        $this->exchange_hash = $kexHash->hash($this->exchange_hash);

        if ($this->session_id === false) {
            $this->session_id = $this->exchange_hash;
        }

        $server_host_key_algorithm = $this->_array_intersect_first($server_host_key_algorithms, $this->server_host_key_algorithms);
        if ($server_host_key_algorithm === false) {
            user_error('No compatible server host key algorithms found');
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        if ($public_key_format != $server_host_key_algorithm || $this->signature_format != $server_host_key_algorithm) {
            user_error('Server Host Key Algorithm Mismatch');
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        $packet = pack(
            'C',
            NET_SSH2_MSG_NEWKEYS
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();

        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        if ($type != NET_SSH2_MSG_NEWKEYS) {
            user_error('Expected SSH_MSG_NEWKEYS');
            return false;
        }

        switch ($encrypt) {
            case '3des-cbc':
                if (!class_exists('Crypt_TripleDES')) {
                    include_once 'Crypt/TripleDES.php';
                }
                $this->encrypt = new Crypt_TripleDES();
                // $this->encrypt_block_size = 64 / 8 == the default
                break;
            case '3des-ctr':
                if (!class_exists('Crypt_TripleDES')) {
                    include_once 'Crypt/TripleDES.php';
                }
                $this->encrypt = new Crypt_TripleDES(CRYPT_DES_MODE_CTR);
                // $this->encrypt_block_size = 64 / 8 == the default
                break;
            case 'aes256-cbc':
            case 'aes192-cbc':
            case 'aes128-cbc':
                if (!class_exists('Crypt_Rijndael')) {
                    include_once 'Crypt/Rijndael.php';
                }
                $this->encrypt = new Crypt_Rijndael();
                $this->encrypt_block_size = 16; // eg. 128 / 8
                break;
            case 'aes256-ctr':
            case 'aes192-ctr':
            case 'aes128-ctr':
                if (!class_exists('Crypt_Rijndael')) {
                    include_once 'Crypt/Rijndael.php';
                }
                $this->encrypt = new Crypt_Rijndael(CRYPT_RIJNDAEL_MODE_CTR);
                $this->encrypt_block_size = 16; // eg. 128 / 8
                break;
            case 'blowfish-cbc':
                if (!class_exists('Crypt_Blowfish')) {
                    include_once 'Crypt/Blowfish.php';
                }
                $this->encrypt = new Crypt_Blowfish();
                $this->encrypt_block_size = 8;
                break;
            case 'blowfish-ctr':
                if (!class_exists('Crypt_Blowfish')) {
                    include_once 'Crypt/Blowfish.php';
                }
                $this->encrypt = new Crypt_Blowfish(CRYPT_BLOWFISH_MODE_CTR);
                $this->encrypt_block_size = 8;
                break;
            case 'twofish128-cbc':
            case 'twofish192-cbc':
            case 'twofish256-cbc':
            case 'twofish-cbc':
                if (!class_exists('Crypt_Twofish')) {
                    include_once 'Crypt/Twofish.php';
                }
                $this->encrypt = new Crypt_Twofish();
                $this->encrypt_block_size = 16;
                break;
            case 'twofish128-ctr':
            case 'twofish192-ctr':
            case 'twofish256-ctr':
                if (!class_exists('Crypt_Twofish')) {
                    include_once 'Crypt/Twofish.php';
                }
                $this->encrypt = new Crypt_Twofish(CRYPT_TWOFISH_MODE_CTR);
                $this->encrypt_block_size = 16;
                break;
            case 'arcfour':
            case 'arcfour128':
            case 'arcfour256':
                if (!class_exists('Crypt_RC4')) {
                    include_once 'Crypt/RC4.php';
                }
                $this->encrypt = new Crypt_RC4();
                break;
            case 'none':
                //$this->encrypt = new Crypt_Null();
        }

        switch ($decrypt) {
            case '3des-cbc':
                if (!class_exists('Crypt_TripleDES')) {
                    include_once 'Crypt/TripleDES.php';
                }
                $this->decrypt = new Crypt_TripleDES();
                break;
            case '3des-ctr':
                if (!class_exists('Crypt_TripleDES')) {
                    include_once 'Crypt/TripleDES.php';
                }
                $this->decrypt = new Crypt_TripleDES(CRYPT_DES_MODE_CTR);
                break;
            case 'aes256-cbc':
            case 'aes192-cbc':
            case 'aes128-cbc':
                if (!class_exists('Crypt_Rijndael')) {
                    include_once 'Crypt/Rijndael.php';
                }
                $this->decrypt = new Crypt_Rijndael();
                $this->decrypt_block_size = 16;
                break;
            case 'aes256-ctr':
            case 'aes192-ctr':
            case 'aes128-ctr':
                if (!class_exists('Crypt_Rijndael')) {
                    include_once 'Crypt/Rijndael.php';
                }
                $this->decrypt = new Crypt_Rijndael(CRYPT_RIJNDAEL_MODE_CTR);
                $this->decrypt_block_size = 16;
                break;
            case 'blowfish-cbc':
                if (!class_exists('Crypt_Blowfish')) {
                    include_once 'Crypt/Blowfish.php';
                }
                $this->decrypt = new Crypt_Blowfish();
                $this->decrypt_block_size = 8;
                break;
            case 'blowfish-ctr':
                if (!class_exists('Crypt_Blowfish')) {
                    include_once 'Crypt/Blowfish.php';
                }
                $this->decrypt = new Crypt_Blowfish(CRYPT_BLOWFISH_MODE_CTR);
                $this->decrypt_block_size = 8;
                break;
            case 'twofish128-cbc':
            case 'twofish192-cbc':
            case 'twofish256-cbc':
            case 'twofish-cbc':
                if (!class_exists('Crypt_Twofish')) {
                    include_once 'Crypt/Twofish.php';
                }
                $this->decrypt = new Crypt_Twofish();
                $this->decrypt_block_size = 16;
                break;
            case 'twofish128-ctr':
            case 'twofish192-ctr':
            case 'twofish256-ctr':
                if (!class_exists('Crypt_Twofish')) {
                    include_once 'Crypt/Twofish.php';
                }
                $this->decrypt = new Crypt_Twofish(CRYPT_TWOFISH_MODE_CTR);
                $this->decrypt_block_size = 16;
                break;
            case 'arcfour':
            case 'arcfour128':
            case 'arcfour256':
                if (!class_exists('Crypt_RC4')) {
                    include_once 'Crypt/RC4.php';
                }
                $this->decrypt = new Crypt_RC4();
                break;
            case 'none':
                //$this->decrypt = new Crypt_Null();
        }

        $keyBytes = pack('Na*', strlen($keyBytes), $keyBytes);

        if ($this->encrypt) {
            if ($this->crypto_engine) {
                $this->encrypt->setEngine($this->crypto_engine);
            }
            $this->encrypt->enableContinuousBuffer();
            $this->encrypt->disablePadding();

            $iv = $kexHash->hash($keyBytes . $this->exchange_hash . 'A' . $this->session_id);
            while ($this->encrypt_block_size > strlen($iv)) {
                $iv.= $kexHash->hash($keyBytes . $this->exchange_hash . $iv);
            }
            $this->encrypt->setIV(substr($iv, 0, $this->encrypt_block_size));

            $key = $kexHash->hash($keyBytes . $this->exchange_hash . 'C' . $this->session_id);
            while ($encryptKeyLength > strlen($key)) {
                $key.= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
            }
            $this->encrypt->setKey(substr($key, 0, $encryptKeyLength));
        }

        if ($this->decrypt) {
            if ($this->crypto_engine) {
                $this->decrypt->setEngine($this->crypto_engine);
            }
            $this->decrypt->enableContinuousBuffer();
            $this->decrypt->disablePadding();

            $iv = $kexHash->hash($keyBytes . $this->exchange_hash . 'B' . $this->session_id);
            while ($this->decrypt_block_size > strlen($iv)) {
                $iv.= $kexHash->hash($keyBytes . $this->exchange_hash . $iv);
            }
            $this->decrypt->setIV(substr($iv, 0, $this->decrypt_block_size));

            $key = $kexHash->hash($keyBytes . $this->exchange_hash . 'D' . $this->session_id);
            while ($decryptKeyLength > strlen($key)) {
                $key.= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
            }
            $this->decrypt->setKey(substr($key, 0, $decryptKeyLength));
        }

        /* The "arcfour128" algorithm is the RC4 cipher, as described in
           [SCHNEIER], using a 128-bit key.  The first 1536 bytes of keystream
           generated by the cipher MUST be discarded, and the first byte of the
           first encrypted packet MUST be encrypted using the 1537th byte of
           keystream.

           -- http://tools.ietf.org/html/rfc4345#section-4 */
        if ($encrypt == 'arcfour128' || $encrypt == 'arcfour256') {
            $this->encrypt->encrypt(str_repeat("\0", 1536));
        }
        if ($decrypt == 'arcfour128' || $decrypt == 'arcfour256') {
            $this->decrypt->decrypt(str_repeat("\0", 1536));
        }

        $mac_algorithm = $this->_array_intersect_first($mac_algorithms, $this->mac_algorithms_client_to_server);
        if ($mac_algorithm === false) {
            user_error('No compatible client to server message authentication algorithms found');
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        $createKeyLength = 0; // ie. $mac_algorithm == 'none'
        switch ($mac_algorithm) {
            case 'hmac-sha2-256':
                $this->hmac_create = new Crypt_Hash('sha256');
                $createKeyLength = 32;
                break;
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

        $mac_algorithm = $this->_array_intersect_first($mac_algorithms, $this->mac_algorithms_server_to_client);
        if ($mac_algorithm === false) {
            user_error('No compatible server to client message authentication algorithms found');
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }

        $checkKeyLength = 0;
        $this->hmac_size = 0;
        switch ($mac_algorithm) {
            case 'hmac-sha2-256':
                $this->hmac_check = new Crypt_Hash('sha256');
                $checkKeyLength = 32;
                $this->hmac_size = 32;
                break;
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

        $key = $kexHash->hash($keyBytes . $this->exchange_hash . 'E' . $this->session_id);
        while ($createKeyLength > strlen($key)) {
            $key.= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
        }
        $this->hmac_create->setKey(substr($key, 0, $createKeyLength));

        $key = $kexHash->hash($keyBytes . $this->exchange_hash . 'F' . $this->session_id);
        while ($checkKeyLength > strlen($key)) {
            $key.= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
        }
        $this->hmac_check->setKey(substr($key, 0, $checkKeyLength));

        $compression_algorithm = $this->_array_intersect_first($compression_algorithms, $this->compression_algorithms_server_to_client);
        if ($compression_algorithm === false) {
            user_error('No compatible server to client compression algorithms found');
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }
        $this->decompress = $compression_algorithm == 'zlib';

        $compression_algorithm = $this->_array_intersect_first($compression_algorithms, $this->compression_algorithms_client_to_server);
        if ($compression_algorithm === false) {
            user_error('No compatible client to server compression algorithms found');
            return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
        }
        $this->compress = $compression_algorithm == 'zlib';

        return true;
    }

    /**
     * Maps an encryption algorithm name to the number of key bytes.
     *
     * @param string $algorithm Name of the encryption algorithm
     * @return int|null Number of bytes as an integer or null for unknown
     * @access private
     */
    function _encryption_algorithm_to_key_size($algorithm)
    {
        switch ($algorithm) {
            case 'none':
                return 0;
            case 'aes128-cbc':
            case 'aes128-ctr':
            case 'arcfour':
            case 'arcfour128':
            case 'blowfish-cbc':
            case 'blowfish-ctr':
            case 'twofish128-cbc':
            case 'twofish128-ctr':
                return 16;
            case '3des-cbc':
            case '3des-ctr':
            case 'aes192-cbc':
            case 'aes192-ctr':
            case 'twofish192-cbc':
            case 'twofish192-ctr':
                return 24;
            case 'aes256-cbc':
            case 'aes256-ctr':
            case 'arcfour256':
            case 'twofish-cbc':
            case 'twofish256-cbc':
            case 'twofish256-ctr':
                return 32;
        }
        return null;
    }

    /**
     * Login
     *
     * The $password parameter can be a plaintext password, a Crypt_RSA object or an array
     *
     * @param string $username
     * @param mixed $password
     * @param mixed $...
     * @return bool
     * @see self::_login()
     * @access public
     */
    function login($username)
    {
        $args = func_get_args();
        return call_user_func_array(array(&$this, '_login'), $args);
    }

    /**
     * Login Helper
     *
     * @param string $username
     * @param mixed $password
     * @param mixed $...
     * @return bool
     * @see self::_login_helper()
     * @access private
     */
    function _login($username)
    {
        if (!($this->bitmap & NET_SSH2_MASK_CONSTRUCTOR)) {
            if (!$this->_connect()) {
                return false;
            }
        }

        $args = array_slice(func_get_args(), 1);
        if (empty($args)) {
            return $this->_login_helper($username);
        }

        foreach ($args as $arg) {
            if ($this->_login_helper($username, $arg)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Login Helper
     *
     * @param string $username
     * @param string $password
     * @return bool
     * @access private
     * @internal It might be worthwhile, at some point, to protect against {@link http://tools.ietf.org/html/rfc4251#section-9.3.9 traffic analysis}
     *           by sending dummy SSH_MSG_IGNORE messages.
     */
    function _login_helper($username, $password = null)
    {
        if (!($this->bitmap & NET_SSH2_MASK_CONNECTED)) {
            return false;
        }

        if (!($this->bitmap & NET_SSH2_MASK_LOGIN_REQ)) {
            $packet = pack(
                'CNa*',
                NET_SSH2_MSG_SERVICE_REQUEST,
                strlen('ssh-userauth'),
                'ssh-userauth'
            );

            if (!$this->_send_binary_packet($packet)) {
                return false;
            }

            $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server');
                return false;
            }

            extract(unpack('Ctype', $this->_string_shift($response, 1)));

            if ($type != NET_SSH2_MSG_SERVICE_ACCEPT) {
                user_error('Expected SSH_MSG_SERVICE_ACCEPT');
                return false;
            }
            $this->bitmap |= NET_SSH2_MASK_LOGIN_REQ;
        }

        if (strlen($this->last_interactive_response)) {
            return !is_string($password) && !is_array($password) ? false : $this->_keyboard_interactive_process($password);
        }

        // although PHP5's get_class() preserves the case, PHP4's does not
        if (is_object($password)) {
            switch (strtolower(get_class($password))) {
                case 'crypt_rsa':
                    return $this->_privatekey_login($username, $password);
                case 'system_ssh_agent':
                    return $this->_ssh_agent_login($username, $password);
            }
        }

        if (is_array($password)) {
            if ($this->_keyboard_interactive_login($username, $password)) {
                $this->bitmap |= NET_SSH2_MASK_LOGIN;
                return true;
            }
            return false;
        }

        if (!isset($password)) {
            $packet = pack(
                'CNa*Na*Na*',
                NET_SSH2_MSG_USERAUTH_REQUEST,
                strlen($username),
                $username,
                strlen('ssh-connection'),
                'ssh-connection',
                strlen('none'),
                'none'
            );

            if (!$this->_send_binary_packet($packet)) {
                return false;
            }

            $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server');
                return false;
            }

            extract(unpack('Ctype', $this->_string_shift($response, 1)));

            switch ($type) {
                case NET_SSH2_MSG_USERAUTH_SUCCESS:
                    $this->bitmap |= NET_SSH2_MASK_LOGIN;
                    return true;
                //case NET_SSH2_MSG_USERAUTH_FAILURE:
                default:
                    return false;
            }
        }

        $packet = pack(
            'CNa*Na*Na*CNa*',
            NET_SSH2_MSG_USERAUTH_REQUEST,
            strlen($username),
            $username,
            strlen('ssh-connection'),
            'ssh-connection',
            strlen('password'),
            'password',
            0,
            strlen($password),
            $password
        );

        // remove the username and password from the logged packet
        if (!defined('NET_SSH2_LOGGING')) {
            $logged = null;
        } else {
            $logged = pack(
                'CNa*Na*Na*CNa*',
                NET_SSH2_MSG_USERAUTH_REQUEST,
                strlen('username'),
                'username',
                strlen('ssh-connection'),
                'ssh-connection',
                strlen('password'),
                'password',
                0,
                strlen('password'),
                'password'
            );
        }

        if (!$this->_send_binary_packet($packet, $logged)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        switch ($type) {
            case NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ: // in theory, the password can be changed
                if (defined('NET_SSH2_LOGGING')) {
                    $this->message_number_log[count($this->message_number_log) - 1] = 'NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ';
                }
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $this->errors[] = 'SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: ' . utf8_decode($this->_string_shift($response, $length));
                return $this->_disconnect(NET_SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER);
            case NET_SSH2_MSG_USERAUTH_FAILURE:
                // can we use keyboard-interactive authentication?  if not then either the login is bad or the server employees
                // multi-factor authentication
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $auth_methods = explode(',', $this->_string_shift($response, $length));
                extract(unpack('Cpartial_success', $this->_string_shift($response, 1)));
                $partial_success = $partial_success != 0;

                if (!$partial_success && in_array('keyboard-interactive', $auth_methods)) {
                    if ($this->_keyboard_interactive_login($username, $password)) {
                        $this->bitmap |= NET_SSH2_MASK_LOGIN;
                        return true;
                    }
                    return false;
                }
                return false;
            case NET_SSH2_MSG_USERAUTH_SUCCESS:
                $this->bitmap |= NET_SSH2_MASK_LOGIN;
                return true;
        }

        return false;
    }

    /**
     * Login via keyboard-interactive authentication
     *
     * See {@link http://tools.ietf.org/html/rfc4256 RFC4256} for details.  This is not a full-featured keyboard-interactive authenticator.
     *
     * @param string $username
     * @param string $password
     * @return bool
     * @access private
     */
    function _keyboard_interactive_login($username, $password)
    {
        $packet = pack(
            'CNa*Na*Na*Na*Na*',
            NET_SSH2_MSG_USERAUTH_REQUEST,
            strlen($username),
            $username,
            strlen('ssh-connection'),
            'ssh-connection',
            strlen('keyboard-interactive'),
            'keyboard-interactive',
            0,
            '',
            0,
            ''
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        return $this->_keyboard_interactive_process($password);
    }

    /**
     * Handle the keyboard-interactive requests / responses.
     *
     * @param string $responses...
     * @return bool
     * @access private
     */
    function _keyboard_interactive_process()
    {
        $responses = func_get_args();

        if (strlen($this->last_interactive_response)) {
            $response = $this->last_interactive_response;
        } else {
            $orig = $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server');
                return false;
            }
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        switch ($type) {
            case NET_SSH2_MSG_USERAUTH_INFO_REQUEST:
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $this->_string_shift($response, $length); // name; may be empty
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $this->_string_shift($response, $length); // instruction; may be empty
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $this->_string_shift($response, $length); // language tag; may be empty
                extract(unpack('Nnum_prompts', $this->_string_shift($response, 4)));

                for ($i = 0; $i < count($responses); $i++) {
                    if (is_array($responses[$i])) {
                        foreach ($responses[$i] as $key => $value) {
                            $this->keyboard_requests_responses[$key] = $value;
                        }
                        unset($responses[$i]);
                    }
                }
                $responses = array_values($responses);

                if (isset($this->keyboard_requests_responses)) {
                    for ($i = 0; $i < $num_prompts; $i++) {
                        extract(unpack('Nlength', $this->_string_shift($response, 4)));
                        // prompt - ie. "Password: "; must not be empty
                        $prompt = $this->_string_shift($response, $length);
                        //$echo = $this->_string_shift($response) != chr(0);
                        foreach ($this->keyboard_requests_responses as $key => $value) {
                            if (substr($prompt, 0, strlen($key)) == $key) {
                                $responses[] = $value;
                                break;
                            }
                        }
                    }
                }

                // see http://tools.ietf.org/html/rfc4256#section-3.2
                if (strlen($this->last_interactive_response)) {
                    $this->last_interactive_response = '';
                } elseif (defined('NET_SSH2_LOGGING')) {
                    $this->message_number_log[count($this->message_number_log) - 1] = str_replace(
                        'UNKNOWN',
                        'NET_SSH2_MSG_USERAUTH_INFO_REQUEST',
                        $this->message_number_log[count($this->message_number_log) - 1]
                    );
                }

                if (!count($responses) && $num_prompts) {
                    $this->last_interactive_response = $orig;
                    return false;
                }

                /*
                   After obtaining the requested information from the user, the client
                   MUST respond with an SSH_MSG_USERAUTH_INFO_RESPONSE message.
                */
                // see http://tools.ietf.org/html/rfc4256#section-3.4
                $packet = $logged = pack('CN', NET_SSH2_MSG_USERAUTH_INFO_RESPONSE, count($responses));
                for ($i = 0; $i < count($responses); $i++) {
                    $packet.= pack('Na*', strlen($responses[$i]), $responses[$i]);
                    $logged.= pack('Na*', strlen('dummy-answer'), 'dummy-answer');
                }

                if (!$this->_send_binary_packet($packet, $logged)) {
                    return false;
                }

                if (defined('NET_SSH2_LOGGING') && NET_SSH2_LOGGING == NET_SSH2_LOG_COMPLEX) {
                    $this->message_number_log[count($this->message_number_log) - 1] = str_replace(
                        'UNKNOWN',
                        'NET_SSH2_MSG_USERAUTH_INFO_RESPONSE',
                        $this->message_number_log[count($this->message_number_log) - 1]
                    );
                }

                /*
                   After receiving the response, the server MUST send either an
                   SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE, or another
                   SSH_MSG_USERAUTH_INFO_REQUEST message.
                */
                // maybe phpseclib should force close the connection after x request / responses?  unless something like that is done
                // there could be an infinite loop of request / responses.
                return $this->_keyboard_interactive_process();
            case NET_SSH2_MSG_USERAUTH_SUCCESS:
                return true;
            case NET_SSH2_MSG_USERAUTH_FAILURE:
                return false;
        }

        return false;
    }

    /**
     * Login with an ssh-agent provided key
     *
     * @param string $username
     * @param System_SSH_Agent $agent
     * @return bool
     * @access private
     */
    function _ssh_agent_login($username, $agent)
    {
        $this->agent = $agent;
        $keys = $agent->requestIdentities();
        foreach ($keys as $key) {
            if ($this->_privatekey_login($username, $key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Login with an RSA private key
     *
     * @param string $username
     * @param Crypt_RSA $password
     * @return bool
     * @access private
     * @internal It might be worthwhile, at some point, to protect against {@link http://tools.ietf.org/html/rfc4251#section-9.3.9 traffic analysis}
     *           by sending dummy SSH_MSG_IGNORE messages.
     */
    function _privatekey_login($username, $privatekey)
    {
        // see http://tools.ietf.org/html/rfc4253#page-15
        $publickey = $privatekey->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_RAW);
        if ($publickey === false) {
            return false;
        }

        $publickey = array(
            'e' => $publickey['e']->toBytes(true),
            'n' => $publickey['n']->toBytes(true)
        );
        $publickey = pack(
            'Na*Na*Na*',
            strlen('ssh-rsa'),
            'ssh-rsa',
            strlen($publickey['e']),
            $publickey['e'],
            strlen($publickey['n']),
            $publickey['n']
        );

        $part1 = pack(
            'CNa*Na*Na*',
            NET_SSH2_MSG_USERAUTH_REQUEST,
            strlen($username),
            $username,
            strlen('ssh-connection'),
            'ssh-connection',
            strlen('publickey'),
            'publickey'
        );
        $part2 = pack('Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($publickey), $publickey);

        $packet = $part1 . chr(0) . $part2;
        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        switch ($type) {
            case NET_SSH2_MSG_USERAUTH_FAILURE:
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
                $this->errors[] = 'SSH_MSG_USERAUTH_FAILURE: ' . $this->_string_shift($response, $length);
                return false;
            case NET_SSH2_MSG_USERAUTH_PK_OK:
                // we'll just take it on faith that the public key blob and the public key algorithm name are as
                // they should be
                if (defined('NET_SSH2_LOGGING') && NET_SSH2_LOGGING == NET_SSH2_LOG_COMPLEX) {
                    $this->message_number_log[count($this->message_number_log) - 1] = str_replace(
                        'UNKNOWN',
                        'NET_SSH2_MSG_USERAUTH_PK_OK',
                        $this->message_number_log[count($this->message_number_log) - 1]
                    );
                }
        }

        $packet = $part1 . chr(1) . $part2;
        $privatekey->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
        $signature = $privatekey->sign(pack('Na*a*', strlen($this->session_id), $this->session_id, $packet));
        $signature = pack('Na*Na*', strlen('ssh-rsa'), 'ssh-rsa', strlen($signature), $signature);
        $packet.= pack('Na*', strlen($signature), $signature);

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }

        extract(unpack('Ctype', $this->_string_shift($response, 1)));

        switch ($type) {
            case NET_SSH2_MSG_USERAUTH_FAILURE:
                // either the login is bad or the server employs multi-factor authentication
                return false;
            case NET_SSH2_MSG_USERAUTH_SUCCESS:
                $this->bitmap |= NET_SSH2_MASK_LOGIN;
                return true;
        }

        return false;
    }

    /**
     * Set Timeout
     *
     * $ssh->exec('ping 127.0.0.1'); on a Linux host will never return and will run indefinitely.  setTimeout() makes it so it'll timeout.
     * Setting $timeout to false or 0 will mean there is no timeout.
     *
     * @param mixed $timeout
     * @access public
     */
    function setTimeout($timeout)
    {
        $this->timeout = $this->curTimeout = $timeout;
    }

    /**
     * Get the output from stdError
     *
     * @access public
     */
    function getStdError()
    {
        return $this->stdErrorLog;
    }

    /**
     * Execute Command
     *
     * If $callback is set to false then Net_SSH2::_get_channel_packet(NET_SSH2_CHANNEL_EXEC) will need to be called manually.
     * In all likelihood, this is not a feature you want to be taking advantage of.
     *
     * @param string $command
     * @param Callback $callback
     * @return string
     * @access public
     */
    function exec($command, $callback = null)
    {
        $this->curTimeout = $this->timeout;
        $this->is_timeout = false;
        $this->stdErrorLog = '';

        if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
            return false;
        }

        // RFC4254 defines the (client) window size as "bytes the other party can send before it must wait for the window to
        // be adjusted".  0x7FFFFFFF is, at 2GB, the max size.  technically, it should probably be decremented, but,
        // honestly, if you're transfering more than 2GB, you probably shouldn't be using phpseclib, anyway.
        // see http://tools.ietf.org/html/rfc4254#section-5.2 for more info
        $this->window_size_server_to_client[NET_SSH2_CHANNEL_EXEC] = $this->window_size;
        // 0x8000 is the maximum max packet size, per http://tools.ietf.org/html/rfc4253#section-6.1, although since PuTTy
        // uses 0x4000, that's what will be used here, as well.
        $packet_size = 0x4000;

        $packet = pack(
            'CNa*N3',
            NET_SSH2_MSG_CHANNEL_OPEN,
            strlen('session'),
            'session',
            NET_SSH2_CHANNEL_EXEC,
            $this->window_size_server_to_client[NET_SSH2_CHANNEL_EXEC],
            $packet_size
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[NET_SSH2_CHANNEL_EXEC] = NET_SSH2_MSG_CHANNEL_OPEN;

        $response = $this->_get_channel_packet(NET_SSH2_CHANNEL_EXEC);
        if ($response === false) {
            return false;
        }

        if ($this->request_pty === true) {
            $terminal_modes = pack('C', NET_SSH2_TTY_OP_END);
            $packet = pack(
                'CNNa*CNa*N5a*',
                NET_SSH2_MSG_CHANNEL_REQUEST,
                $this->server_channels[NET_SSH2_CHANNEL_EXEC],
                strlen('pty-req'),
                'pty-req',
                1,
                strlen('vt100'),
                'vt100',
                $this->windowColumns,
                $this->windowRows,
                0,
                0,
                strlen($terminal_modes),
                $terminal_modes
            );

            if (!$this->_send_binary_packet($packet)) {
                return false;
            }

            $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server');
                return false;
            }

            list(, $type) = unpack('C', $this->_string_shift($response, 1));

            switch ($type) {
                case NET_SSH2_MSG_CHANNEL_SUCCESS:
                    break;
                case NET_SSH2_MSG_CHANNEL_FAILURE:
                default:
                    user_error('Unable to request pseudo-terminal');
                    return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
            }
            $this->in_request_pty_exec = true;
        }

        // sending a pty-req SSH_MSG_CHANNEL_REQUEST message is unnecessary and, in fact, in most cases, slows things
        // down.  the one place where it might be desirable is if you're doing something like Net_SSH2::exec('ping localhost &').
        // with a pty-req SSH_MSG_CHANNEL_REQUEST, exec() will return immediately and the ping process will then
        // then immediately terminate.  without such a request exec() will loop indefinitely.  the ping process won't end but
        // neither will your script.

        // although, in theory, the size of SSH_MSG_CHANNEL_REQUEST could exceed the maximum packet size established by
        // SSH_MSG_CHANNEL_OPEN_CONFIRMATION, RFC4254#section-5.1 states that the "maximum packet size" refers to the
        // "maximum size of an individual data packet". ie. SSH_MSG_CHANNEL_DATA.  RFC4254#section-5.2 corroborates.
        $packet = pack(
            'CNNa*CNa*',
            NET_SSH2_MSG_CHANNEL_REQUEST,
            $this->server_channels[NET_SSH2_CHANNEL_EXEC],
            strlen('exec'),
            'exec',
            1,
            strlen($command),
            $command
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[NET_SSH2_CHANNEL_EXEC] = NET_SSH2_MSG_CHANNEL_REQUEST;

        $response = $this->_get_channel_packet(NET_SSH2_CHANNEL_EXEC);
        if ($response === false) {
            return false;
        }

        $this->channel_status[NET_SSH2_CHANNEL_EXEC] = NET_SSH2_MSG_CHANNEL_DATA;

        if ($callback === false || $this->in_request_pty_exec) {
            return true;
        }

        $output = '';
        while (true) {
            $temp = $this->_get_channel_packet(NET_SSH2_CHANNEL_EXEC);
            switch (true) {
                case $temp === true:
                    return is_callable($callback) ? true : $output;
                case $temp === false:
                    return false;
                default:
                    if (is_callable($callback)) {
                        if (call_user_func($callback, $temp) === true) {
                            $this->_close_channel(NET_SSH2_CHANNEL_EXEC);
                            return true;
                        }
                    } else {
                        $output.= $temp;
                    }
            }
        }
    }

    /**
     * Creates an interactive shell
     *
     * @see self::read()
     * @see self::write()
     * @return bool
     * @access private
     */
    function _initShell()
    {
        if ($this->in_request_pty_exec === true) {
            return true;
        }

        $this->window_size_server_to_client[NET_SSH2_CHANNEL_SHELL] = $this->window_size;
        $packet_size = 0x4000;

        $packet = pack(
            'CNa*N3',
            NET_SSH2_MSG_CHANNEL_OPEN,
            strlen('session'),
            'session',
            NET_SSH2_CHANNEL_SHELL,
            $this->window_size_server_to_client[NET_SSH2_CHANNEL_SHELL],
            $packet_size
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[NET_SSH2_CHANNEL_SHELL] = NET_SSH2_MSG_CHANNEL_OPEN;

        $response = $this->_get_channel_packet(NET_SSH2_CHANNEL_SHELL);
        if ($response === false) {
            return false;
        }

        $terminal_modes = pack('C', NET_SSH2_TTY_OP_END);
        $packet = pack(
            'CNNa*CNa*N5a*',
            NET_SSH2_MSG_CHANNEL_REQUEST,
            $this->server_channels[NET_SSH2_CHANNEL_SHELL],
            strlen('pty-req'),
            'pty-req',
            1,
            strlen('vt100'),
            'vt100',
            $this->windowColumns,
            $this->windowRows,
            0,
            0,
            strlen($terminal_modes),
            $terminal_modes
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $response = $this->_get_binary_packet();
        if ($response === false) {
            user_error('Connection closed by server');
            return false;
        }

        list(, $type) = unpack('C', $this->_string_shift($response, 1));

        switch ($type) {
            case NET_SSH2_MSG_CHANNEL_SUCCESS:
            // if a pty can't be opened maybe commands can still be executed
            case NET_SSH2_MSG_CHANNEL_FAILURE:
                break;
            default:
                user_error('Unable to request pseudo-terminal');
                return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
        }

        $packet = pack(
            'CNNa*C',
            NET_SSH2_MSG_CHANNEL_REQUEST,
            $this->server_channels[NET_SSH2_CHANNEL_SHELL],
            strlen('shell'),
            'shell',
            1
        );
        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[NET_SSH2_CHANNEL_SHELL] = NET_SSH2_MSG_CHANNEL_REQUEST;

        $response = $this->_get_channel_packet(NET_SSH2_CHANNEL_SHELL);
        if ($response === false) {
            return false;
        }

        $this->channel_status[NET_SSH2_CHANNEL_SHELL] = NET_SSH2_MSG_CHANNEL_DATA;

        $this->bitmap |= NET_SSH2_MASK_SHELL;

        return true;
    }

    /**
     * Return the channel to be used with read() / write()
     *
     * @see self::read()
     * @see self::write()
     * @return int
     * @access public
     */
    function _get_interactive_channel()
    {
        switch (true) {
            case $this->in_subsystem:
                return NET_SSH2_CHANNEL_SUBSYSTEM;
            case $this->in_request_pty_exec:
                return NET_SSH2_CHANNEL_EXEC;
            default:
                return NET_SSH2_CHANNEL_SHELL;
        }
    }

    /**
     * Return an available open channel
     *
     * @return int
     * @access public
     */
    function _get_open_channel()
    {
        $channel = NET_SSH2_CHANNEL_EXEC;
        do {
            if (isset($this->channel_status[$channel]) && $this->channel_status[$channel] == NET_SSH2_MSG_CHANNEL_OPEN) {
                return $channel;
            }
        } while ($channel++ < NET_SSH2_CHANNEL_SUBSYSTEM);

        return false;
    }

    /**
     * Returns the output of an interactive shell
     *
     * Returns when there's a match for $expect, which can take the form of a string literal or,
     * if $mode == NET_SSH2_READ_REGEX, a regular expression.
     *
     * @see self::write()
     * @param string $expect
     * @param int $mode
     * @return string
     * @access public
     */
    function read($expect = '', $mode = NET_SSH2_READ_SIMPLE)
    {
        $this->curTimeout = $this->timeout;
        $this->is_timeout = false;

        if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
            user_error('Operation disallowed prior to login()');
            return false;
        }

        if (!($this->bitmap & NET_SSH2_MASK_SHELL) && !$this->_initShell()) {
            user_error('Unable to initiate an interactive shell session');
            return false;
        }

        $channel = $this->_get_interactive_channel();

        $match = $expect;
        while (true) {
            if ($mode == NET_SSH2_READ_REGEX) {
                preg_match($expect, substr($this->interactiveBuffer, -1024), $matches);
                $match = isset($matches[0]) ? $matches[0] : '';
            }
            $pos = strlen($match) ? strpos($this->interactiveBuffer, $match) : false;
            if ($pos !== false) {
                return $this->_string_shift($this->interactiveBuffer, $pos + strlen($match));
            }
            $response = $this->_get_channel_packet($channel);
            if (is_bool($response)) {
                $this->in_request_pty_exec = false;
                return $response ? $this->_string_shift($this->interactiveBuffer, strlen($this->interactiveBuffer)) : false;
            }

            $this->interactiveBuffer.= $response;
        }
    }

    /**
     * Inputs a command into an interactive shell.
     *
     * @see self::read()
     * @param string $cmd
     * @return bool
     * @access public
     */
    function write($cmd)
    {
        if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
            user_error('Operation disallowed prior to login()');
            return false;
        }

        if (!($this->bitmap & NET_SSH2_MASK_SHELL) && !$this->_initShell()) {
            user_error('Unable to initiate an interactive shell session');
            return false;
        }

        return $this->_send_channel_packet($this->_get_interactive_channel(), $cmd);
    }

    /**
     * Start a subsystem.
     *
     * Right now only one subsystem at a time is supported. To support multiple subsystem's stopSubsystem() could accept
     * a string that contained the name of the subsystem, but at that point, only one subsystem of each type could be opened.
     * To support multiple subsystem's of the same name maybe it'd be best if startSubsystem() generated a new channel id and
     * returns that and then that that was passed into stopSubsystem() but that'll be saved for a future date and implemented
     * if there's sufficient demand for such a feature.
     *
     * @see self::stopSubsystem()
     * @param string $subsystem
     * @return bool
     * @access public
     */
    function startSubsystem($subsystem)
    {
        $this->window_size_server_to_client[NET_SSH2_CHANNEL_SUBSYSTEM] = $this->window_size;

        $packet = pack(
            'CNa*N3',
            NET_SSH2_MSG_CHANNEL_OPEN,
            strlen('session'),
            'session',
            NET_SSH2_CHANNEL_SUBSYSTEM,
            $this->window_size,
            0x4000
        );

        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[NET_SSH2_CHANNEL_SUBSYSTEM] = NET_SSH2_MSG_CHANNEL_OPEN;

        $response = $this->_get_channel_packet(NET_SSH2_CHANNEL_SUBSYSTEM);
        if ($response === false) {
            return false;
        }

        $packet = pack(
            'CNNa*CNa*',
            NET_SSH2_MSG_CHANNEL_REQUEST,
            $this->server_channels[NET_SSH2_CHANNEL_SUBSYSTEM],
            strlen('subsystem'),
            'subsystem',
            1,
            strlen($subsystem),
            $subsystem
        );
        if (!$this->_send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[NET_SSH2_CHANNEL_SUBSYSTEM] = NET_SSH2_MSG_CHANNEL_REQUEST;

        $response = $this->_get_channel_packet(NET_SSH2_CHANNEL_SUBSYSTEM);

        if ($response === false) {
            return false;
        }

        $this->channel_status[NET_SSH2_CHANNEL_SUBSYSTEM] = NET_SSH2_MSG_CHANNEL_DATA;

        $this->bitmap |= NET_SSH2_MASK_SHELL;
        $this->in_subsystem = true;

        return true;
    }

    /**
     * Stops a subsystem.
     *
     * @see self::startSubsystem()
     * @return bool
     * @access public
     */
    function stopSubsystem()
    {
        $this->in_subsystem = false;
        $this->_close_channel(NET_SSH2_CHANNEL_SUBSYSTEM);
        return true;
    }

    /**
     * Closes a channel
     *
     * If read() timed out you might want to just close the channel and have it auto-restart on the next read() call
     *
     * @access public
     */
    function reset()
    {
        $this->_close_channel($this->_get_interactive_channel());
    }

    /**
     * Is timeout?
     *
     * Did exec() or read() return because they timed out or because they encountered the end?
     *
     * @access public
     */
    function isTimeout()
    {
        return $this->is_timeout;
    }

    /**
     * Disconnect
     *
     * @access public
     */
    function disconnect()
    {
        $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
        if (isset($this->realtime_log_file) && is_resource($this->realtime_log_file)) {
            fclose($this->realtime_log_file);
        }
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
     * Is the connection still active?
     *
     * @return bool
     * @access public
     */
    function isConnected()
    {
        return (bool) ($this->bitmap & NET_SSH2_MASK_CONNECTED);
    }

    /**
     * Have you successfully been logged in?
     *
     * @return bool
     * @access public
     */
    function isAuthenticated()
    {
        return (bool) ($this->bitmap & NET_SSH2_MASK_LOGIN);
    }

    /**
     * Gets Binary Packets
     *
     * See '6. Binary Packet Protocol' of rfc4253 for more info.
     *
     * @see self::_send_binary_packet()
     * @return string
     * @access private
     */
    function _get_binary_packet()
    {
        if (!is_resource($this->fsock) || feof($this->fsock)) {
            user_error('Connection closed prematurely');
            $this->bitmap = 0;
            return false;
        }

        $start = strtok(microtime(), ' ') + strtok(''); // http://php.net/microtime#61838
        $raw = fread($this->fsock, $this->decrypt_block_size);

        if (!strlen($raw)) {
            return '';
        }

        if ($this->decrypt !== false) {
            $raw = $this->decrypt->decrypt($raw);
        }
        if ($raw === false) {
            user_error('Unable to decrypt content');
            return false;
        }

        extract(unpack('Npacket_length/Cpadding_length', $this->_string_shift($raw, 5)));

        $remaining_length = $packet_length + 4 - $this->decrypt_block_size;

        // quoting <http://tools.ietf.org/html/rfc4253#section-6.1>,
        // "implementations SHOULD check that the packet length is reasonable"
        // PuTTY uses 0x9000 as the actual max packet size and so to shall we
        if ($remaining_length < -$this->decrypt_block_size || $remaining_length > 0x9000 || $remaining_length % $this->decrypt_block_size != 0) {
            user_error('Invalid size');
            return false;
        }

        $buffer = '';
        while ($remaining_length > 0) {
            $temp = fread($this->fsock, $remaining_length);
            if ($temp === false || feof($this->fsock)) {
                user_error('Error reading from socket');
                $this->bitmap = 0;
                return false;
            }
            $buffer.= $temp;
            $remaining_length-= strlen($temp);
        }
        $stop = strtok(microtime(), ' ') + strtok('');
        if (strlen($buffer)) {
            $raw.= $this->decrypt !== false ? $this->decrypt->decrypt($buffer) : $buffer;
        }

        $payload = $this->_string_shift($raw, $packet_length - $padding_length - 1);
        $padding = $this->_string_shift($raw, $padding_length); // should leave $raw empty

        if ($this->hmac_check !== false) {
            $hmac = fread($this->fsock, $this->hmac_size);
            if ($hmac === false || strlen($hmac) != $this->hmac_size) {
                user_error('Error reading socket');
                $this->bitmap = 0;
                return false;
            } elseif ($hmac != $this->hmac_check->hash(pack('NNCa*', $this->get_seq_no, $packet_length, $padding_length, $payload . $padding))) {
                user_error('Invalid HMAC');
                return false;
            }
        }

        //if ($this->decompress) {
        //    $payload = gzinflate(substr($payload, 2));
        //}

        $this->get_seq_no++;

        if (defined('NET_SSH2_LOGGING')) {
            $current = strtok(microtime(), ' ') + strtok('');
            $message_number = isset($this->message_numbers[ord($payload[0])]) ? $this->message_numbers[ord($payload[0])] : 'UNKNOWN (' . ord($payload[0]) . ')';
            $message_number = '<- ' . $message_number .
                              ' (since last: ' . round($current - $this->last_packet, 4) . ', network: ' . round($stop - $start, 4) . 's)';
            $this->_append_log($message_number, $payload);
            $this->last_packet = $current;
        }

        return $this->_filter($payload);
    }

    /**
     * Filter Binary Packets
     *
     * Because some binary packets need to be ignored...
     *
     * @see self::_get_binary_packet()
     * @return string
     * @access private
     */
    function _filter($payload)
    {
        switch (ord($payload[0])) {
            case NET_SSH2_MSG_DISCONNECT:
                $this->_string_shift($payload, 1);
                extract(unpack('Nreason_code/Nlength', $this->_string_shift($payload, 8)));
                $this->errors[] = 'SSH_MSG_DISCONNECT: ' . $this->disconnect_reasons[$reason_code] . "\r\n" . utf8_decode($this->_string_shift($payload, $length));
                $this->bitmap = 0;
                return false;
            case NET_SSH2_MSG_IGNORE:
                $payload = $this->_get_binary_packet();
                break;
            case NET_SSH2_MSG_DEBUG:
                $this->_string_shift($payload, 2);
                extract(unpack('Nlength', $this->_string_shift($payload, 4)));
                $this->errors[] = 'SSH_MSG_DEBUG: ' . utf8_decode($this->_string_shift($payload, $length));
                $payload = $this->_get_binary_packet();
                break;
            case NET_SSH2_MSG_UNIMPLEMENTED:
                return false;
            case NET_SSH2_MSG_KEXINIT:
                if ($this->session_id !== false) {
                    if (!$this->_key_exchange($payload)) {
                        $this->bitmap = 0;
                        return false;
                    }
                    $payload = $this->_get_binary_packet();
                }
        }

        // see http://tools.ietf.org/html/rfc4252#section-5.4; only called when the encryption has been activated and when we haven't already logged in
        if (($this->bitmap & NET_SSH2_MASK_CONNECTED) && !($this->bitmap & NET_SSH2_MASK_LOGIN) && ord($payload[0]) == NET_SSH2_MSG_USERAUTH_BANNER) {
            $this->_string_shift($payload, 1);
            extract(unpack('Nlength', $this->_string_shift($payload, 4)));
            $this->banner_message = utf8_decode($this->_string_shift($payload, $length));
            $payload = $this->_get_binary_packet();
        }

        // only called when we've already logged in
        if (($this->bitmap & NET_SSH2_MASK_CONNECTED) && ($this->bitmap & NET_SSH2_MASK_LOGIN)) {
            switch (ord($payload[0])) {
                case NET_SSH2_MSG_GLOBAL_REQUEST: // see http://tools.ietf.org/html/rfc4254#section-4
                    extract(unpack('Nlength', $this->_string_shift($payload, 4)));
                    $this->errors[] = 'SSH_MSG_GLOBAL_REQUEST: ' . $this->_string_shift($payload, $length);

                    if (!$this->_send_binary_packet(pack('C', NET_SSH2_MSG_REQUEST_FAILURE))) {
                        return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
                    }

                    $payload = $this->_get_binary_packet();
                    break;
                case NET_SSH2_MSG_CHANNEL_OPEN: // see http://tools.ietf.org/html/rfc4254#section-5.1
                    $this->_string_shift($payload, 1);
                    extract(unpack('Nlength', $this->_string_shift($payload, 4)));
                    $data = $this->_string_shift($payload, $length);
                    extract(unpack('Nserver_channel', $this->_string_shift($payload, 4)));
                    switch ($data) {
                        case 'auth-agent':
                        case 'auth-agent@openssh.com':
                            if (isset($this->agent)) {
                                $new_channel = NET_SSH2_CHANNEL_AGENT_FORWARD;

                                extract(unpack('Nremote_window_size', $this->_string_shift($payload, 4)));
                                extract(unpack('Nremote_maximum_packet_size', $this->_string_shift($payload, 4)));

                                $this->packet_size_client_to_server[$new_channel] = $remote_window_size;
                                $this->window_size_server_to_client[$new_channel] = $remote_maximum_packet_size;
                                $this->window_size_client_to_server[$new_channel] = $this->window_size;

                                $packet_size = 0x4000;

                                $packet = pack(
                                    'CN4',
                                    NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION,
                                    $server_channel,
                                    $new_channel,
                                    $packet_size,
                                    $packet_size
                                );

                                $this->server_channels[$new_channel] = $server_channel;
                                $this->channel_status[$new_channel] = NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION;
                                if (!$this->_send_binary_packet($packet)) {
                                    return false;
                                }
                            }
                            break;
                        default:
                            $packet = pack(
                                'CN3a*Na*',
                                NET_SSH2_MSG_REQUEST_FAILURE,
                                $server_channel,
                                NET_SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED,
                                0,
                                '',
                                0,
                                ''
                            );

                            if (!$this->_send_binary_packet($packet)) {
                                return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
                            }
                    }
                    $payload = $this->_get_binary_packet();
                    break;
                case NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST:
                    $this->_string_shift($payload, 1);
                    extract(unpack('Nchannel', $this->_string_shift($payload, 4)));
                    extract(unpack('Nwindow_size', $this->_string_shift($payload, 4)));
                    $this->window_size_client_to_server[$channel]+= $window_size;

                    $payload = ($this->bitmap & NET_SSH2_MASK_WINDOW_ADJUST) ? true : $this->_get_binary_packet();
            }
        }

        return $payload;
    }

    /**
     * Enable Quiet Mode
     *
     * Suppress stderr from output
     *
     * @access public
     */
    function enableQuietMode()
    {
        $this->quiet_mode = true;
    }

    /**
     * Disable Quiet Mode
     *
     * Show stderr in output
     *
     * @access public
     */
    function disableQuietMode()
    {
        $this->quiet_mode = false;
    }

    /**
     * Returns whether Quiet Mode is enabled or not
     *
     * @see self::enableQuietMode()
     * @see self::disableQuietMode()
     *
     * @access public
     * @return bool
     */
    function isQuietModeEnabled()
    {
        return $this->quiet_mode;
    }

    /**
     * Enable request-pty when using exec()
     *
     * @access public
     */
    function enablePTY()
    {
        $this->request_pty = true;
    }

    /**
     * Disable request-pty when using exec()
     *
     * @access public
     */
    function disablePTY()
    {
        $this->request_pty = false;
    }

    /**
     * Returns whether request-pty is enabled or not
     *
     * @see self::enablePTY()
     * @see self::disablePTY()
     *
     * @access public
     * @return bool
     */
    function isPTYEnabled()
    {
        return $this->request_pty;
    }

    /**
     * Gets channel data
     *
     * Returns the data as a string if it's available and false if not.
     *
     * @param $client_channel
     * @return mixed
     * @access private
     */
    function _get_channel_packet($client_channel, $skip_extended = false)
    {
        if (!empty($this->channel_buffers[$client_channel])) {
            return array_shift($this->channel_buffers[$client_channel]);
        }

        while (true) {
            if ($this->curTimeout) {
                if ($this->curTimeout < 0) {
                    $this->is_timeout = true;
                    return true;
                }

                $read = array($this->fsock);
                $write = $except = null;

                $start = strtok(microtime(), ' ') + strtok(''); // http://php.net/microtime#61838
                $sec = floor($this->curTimeout);
                $usec = 1000000 * ($this->curTimeout - $sec);
                // on windows this returns a "Warning: Invalid CRT parameters detected" error
                if (!@stream_select($read, $write, $except, $sec, $usec) && !count($read)) {
                    $this->is_timeout = true;
                    return true;
                }
                $elapsed = strtok(microtime(), ' ') + strtok('') - $start;
                $this->curTimeout-= $elapsed;
            }

            $response = $this->_get_binary_packet();
            if ($response === false) {
                user_error('Connection closed by server');
                return false;
            }
            if ($client_channel == -1 && $response === true) {
                return true;
            }
            if (!strlen($response)) {
                return '';
            }

            extract(unpack('Ctype', $this->_string_shift($response, 1)));

            if ($type == NET_SSH2_MSG_CHANNEL_OPEN) {
                extract(unpack('Nlength', $this->_string_shift($response, 4)));
            } else {
                extract(unpack('Nchannel', $this->_string_shift($response, 4)));
            }

            // will not be setup yet on incoming channel open request
            if (isset($channel) && isset($this->channel_status[$channel]) && isset($this->window_size_server_to_client[$channel])) {
                $this->window_size_server_to_client[$channel]-= strlen($response);

                // resize the window, if appropriate
                if ($this->window_size_server_to_client[$channel] < 0) {
                    $packet = pack('CNN', NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST, $this->server_channels[$channel], $this->window_size);
                    if (!$this->_send_binary_packet($packet)) {
                        return false;
                    }
                    $this->window_size_server_to_client[$channel]+= $this->window_size;
                }

                switch ($this->channel_status[$channel]) {
                    case NET_SSH2_MSG_CHANNEL_OPEN:
                        switch ($type) {
                            case NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
                                extract(unpack('Nserver_channel', $this->_string_shift($response, 4)));
                                $this->server_channels[$channel] = $server_channel;
                                extract(unpack('Nwindow_size', $this->_string_shift($response, 4)));
                                if ($window_size < 0) {
                                    $window_size&= 0x7FFFFFFF;
                                    $window_size+= 0x80000000;
                                }
                                $this->window_size_client_to_server[$channel] = $window_size;
                                $temp = unpack('Npacket_size_client_to_server', $this->_string_shift($response, 4));
                                $this->packet_size_client_to_server[$channel] = $temp['packet_size_client_to_server'];
                                $result = $client_channel == $channel ? true : $this->_get_channel_packet($client_channel, $skip_extended);
                                $this->_on_channel_open();
                                return $result;
                            //case NET_SSH2_MSG_CHANNEL_OPEN_FAILURE:
                            default:
                                user_error('Unable to open channel');
                                return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
                        }
                        break;
                    case NET_SSH2_MSG_CHANNEL_REQUEST:
                        switch ($type) {
                            case NET_SSH2_MSG_CHANNEL_SUCCESS:
                                return true;
                            case NET_SSH2_MSG_CHANNEL_FAILURE:
                                return false;
                            default:
                                user_error('Unable to fulfill channel request');
                                return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
                        }
                    case NET_SSH2_MSG_CHANNEL_CLOSE:
                        return $type == NET_SSH2_MSG_CHANNEL_CLOSE ? true : $this->_get_channel_packet($client_channel, $skip_extended);
                }
            }

            // ie. $this->channel_status[$channel] == NET_SSH2_MSG_CHANNEL_DATA

            switch ($type) {
                case NET_SSH2_MSG_CHANNEL_DATA:
                    /*
                    if ($channel == NET_SSH2_CHANNEL_EXEC) {
                        // SCP requires null packets, such as this, be sent.  further, in the case of the ssh.com SSH server
                        // this actually seems to make things twice as fast.  more to the point, the message right after
                        // SSH_MSG_CHANNEL_DATA (usually SSH_MSG_IGNORE) won't block for as long as it would have otherwise.
                        // in OpenSSH it slows things down but only by a couple thousandths of a second.
                        $this->_send_channel_packet($channel, chr(0));
                    }
                    */
                    extract(unpack('Nlength', $this->_string_shift($response, 4)));
                    $data = $this->_string_shift($response, $length);

                    if ($channel == NET_SSH2_CHANNEL_AGENT_FORWARD) {
                        $agent_response = $this->agent->_forward_data($data);
                        if (!is_bool($agent_response)) {
                            $this->_send_channel_packet($channel, $agent_response);
                        }
                        break;
                    }

                    if ($client_channel == $channel) {
                        return $data;
                    }
                    if (!isset($this->channel_buffers[$channel])) {
                        $this->channel_buffers[$channel] = array();
                    }
                    $this->channel_buffers[$channel][] = $data;
                    break;
                case NET_SSH2_MSG_CHANNEL_EXTENDED_DATA:
                    /*
                    if ($client_channel == NET_SSH2_CHANNEL_EXEC) {
                        $this->_send_channel_packet($client_channel, chr(0));
                    }
                    */
                    // currently, there's only one possible value for $data_type_code: NET_SSH2_EXTENDED_DATA_STDERR
                    extract(unpack('Ndata_type_code/Nlength', $this->_string_shift($response, 8)));
                    $data = $this->_string_shift($response, $length);
                    $this->stdErrorLog.= $data;
                    if ($skip_extended || $this->quiet_mode) {
                        break;
                    }
                    if ($client_channel == $channel) {
                        return $data;
                    }
                    if (!isset($this->channel_buffers[$channel])) {
                        $this->channel_buffers[$channel] = array();
                    }
                    $this->channel_buffers[$channel][] = $data;
                    break;
                case NET_SSH2_MSG_CHANNEL_REQUEST:
                    extract(unpack('Nlength', $this->_string_shift($response, 4)));
                    $value = $this->_string_shift($response, $length);
                    switch ($value) {
                        case 'exit-signal':
                            $this->_string_shift($response, 1);
                            extract(unpack('Nlength', $this->_string_shift($response, 4)));
                            $this->errors[] = 'SSH_MSG_CHANNEL_REQUEST (exit-signal): ' . $this->_string_shift($response, $length);
                            $this->_string_shift($response, 1);
                            extract(unpack('Nlength', $this->_string_shift($response, 4)));
                            if ($length) {
                                $this->errors[count($this->errors)].= "\r\n" . $this->_string_shift($response, $length);
                            }

                            $this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_EOF, $this->server_channels[$client_channel]));
                            $this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));

                            $this->channel_status[$channel] = NET_SSH2_MSG_CHANNEL_EOF;

                            break;
                        case 'exit-status':
                            extract(unpack('Cfalse/Nexit_status', $this->_string_shift($response, 5)));
                            $this->exit_status = $exit_status;

                            // "The client MAY ignore these messages."
                            // -- http://tools.ietf.org/html/rfc4254#section-6.10

                            break;
                        default:
                            // "Some systems may not implement signals, in which case they SHOULD ignore this message."
                            //  -- http://tools.ietf.org/html/rfc4254#section-6.9
                            break;
                    }
                    break;
                case NET_SSH2_MSG_CHANNEL_CLOSE:
                    $this->curTimeout = 0;

                    if ($this->bitmap & NET_SSH2_MASK_SHELL) {
                        $this->bitmap&= ~NET_SSH2_MASK_SHELL;
                    }
                    if ($this->channel_status[$channel] != NET_SSH2_MSG_CHANNEL_EOF) {
                        $this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));
                    }

                    $this->channel_status[$channel] = NET_SSH2_MSG_CHANNEL_CLOSE;
                    return true;
                case NET_SSH2_MSG_CHANNEL_EOF:
                    break;
                default:
                    user_error('Error reading channel data');
                    return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
            }
        }
    }

    /**
     * Sends Binary Packets
     *
     * See '6. Binary Packet Protocol' of rfc4253 for more info.
     *
     * @param string $data
     * @param string $logged
     * @see self::_get_binary_packet()
     * @return bool
     * @access private
     */
    function _send_binary_packet($data, $logged = null)
    {
        if (!is_resource($this->fsock) || feof($this->fsock)) {
            user_error('Connection closed prematurely');
            $this->bitmap = 0;
            return false;
        }

        //if ($this->compress) {
        //    // the -4 removes the checksum:
        //    // http://php.net/function.gzcompress#57710
        //    $data = substr(gzcompress($data), 0, -4);
        //}

        // 4 (packet length) + 1 (padding length) + 4 (minimal padding amount) == 9
        $packet_length = strlen($data) + 9;
        // round up to the nearest $this->encrypt_block_size
        $packet_length+= (($this->encrypt_block_size - 1) * $packet_length) % $this->encrypt_block_size;
        // subtracting strlen($data) is obvious - subtracting 5 is necessary because of packet_length and padding_length
        $padding_length = $packet_length - strlen($data) - 5;
        $padding = crypt_random_string($padding_length);

        // we subtract 4 from packet_length because the packet_length field isn't supposed to include itself
        $packet = pack('NCa*', $packet_length - 4, $padding_length, $data . $padding);

        $hmac = $this->hmac_create !== false ? $this->hmac_create->hash(pack('Na*', $this->send_seq_no, $packet)) : '';
        $this->send_seq_no++;

        if ($this->encrypt !== false) {
            $packet = $this->encrypt->encrypt($packet);
        }

        $packet.= $hmac;

        $start = strtok(microtime(), ' ') + strtok(''); // http://php.net/microtime#61838
        $result = strlen($packet) == fputs($this->fsock, $packet);
        $stop = strtok(microtime(), ' ') + strtok('');

        if (defined('NET_SSH2_LOGGING')) {
            $current = strtok(microtime(), ' ') + strtok('');
            $message_number = isset($this->message_numbers[ord($data[0])]) ? $this->message_numbers[ord($data[0])] : 'UNKNOWN (' . ord($data[0]) . ')';
            $message_number = '-> ' . $message_number .
                              ' (since last: ' . round($current - $this->last_packet, 4) . ', network: ' . round($stop - $start, 4) . 's)';
            $this->_append_log($message_number, isset($logged) ? $logged : $data);
            $this->last_packet = $current;
        }

        return $result;
    }

    /**
     * Logs data packets
     *
     * Makes sure that only the last 1MB worth of packets will be logged
     *
     * @param string $data
     * @access private
     */
    function _append_log($message_number, $message)
    {
        // remove the byte identifying the message type from all but the first two messages (ie. the identification strings)
        if (strlen($message_number) > 2) {
            $this->_string_shift($message);
        }

        switch (NET_SSH2_LOGGING) {
            // useful for benchmarks
            case NET_SSH2_LOG_SIMPLE:
                $this->message_number_log[] = $message_number;
                break;
            // the most useful log for SSH2
            case NET_SSH2_LOG_COMPLEX:
                $this->message_number_log[] = $message_number;
                $this->log_size+= strlen($message);
                $this->message_log[] = $message;
                while ($this->log_size > NET_SSH2_LOG_MAX_SIZE) {
                    $this->log_size-= strlen(array_shift($this->message_log));
                    array_shift($this->message_number_log);
                }
                break;
            // dump the output out realtime; packets may be interspersed with non packets,
            // passwords won't be filtered out and select other packets may not be correctly
            // identified
            case NET_SSH2_LOG_REALTIME:
                switch (PHP_SAPI) {
                    case 'cli':
                        $start = $stop = "\r\n";
                        break;
                    default:
                        $start = '<pre>';
                        $stop = '</pre>';
                }
                echo $start . $this->_format_log(array($message), array($message_number)) . $stop;
                @flush();
                @ob_flush();
                break;
            // basically the same thing as NET_SSH2_LOG_REALTIME with the caveat that NET_SSH2_LOG_REALTIME_FILE
            // needs to be defined and that the resultant log file will be capped out at NET_SSH2_LOG_MAX_SIZE.
            // the earliest part of the log file is denoted by the first <<< START >>> and is not going to necessarily
            // at the beginning of the file
            case NET_SSH2_LOG_REALTIME_FILE:
                if (!isset($this->realtime_log_file)) {
                    // PHP doesn't seem to like using constants in fopen()
                    $filename = NET_SSH2_LOG_REALTIME_FILENAME;
                    $fp = fopen($filename, 'w');
                    $this->realtime_log_file = $fp;
                }
                if (!is_resource($this->realtime_log_file)) {
                    break;
                }
                $entry = $this->_format_log(array($message), array($message_number));
                if ($this->realtime_log_wrap) {
                    $temp = "<<< START >>>\r\n";
                    $entry.= $temp;
                    fseek($this->realtime_log_file, ftell($this->realtime_log_file) - strlen($temp));
                }
                $this->realtime_log_size+= strlen($entry);
                if ($this->realtime_log_size > NET_SSH2_LOG_MAX_SIZE) {
                    fseek($this->realtime_log_file, 0);
                    $this->realtime_log_size = strlen($entry);
                    $this->realtime_log_wrap = true;
                }
                fputs($this->realtime_log_file, $entry);
        }
    }

    /**
     * Sends channel data
     *
     * Spans multiple SSH_MSG_CHANNEL_DATAs if appropriate
     *
     * @param int $client_channel
     * @param string $data
     * @return bool
     * @access private
     */
    function _send_channel_packet($client_channel, $data)
    {
        while (strlen($data)) {
            if (!$this->window_size_client_to_server[$client_channel]) {
                $this->bitmap^= NET_SSH2_MASK_WINDOW_ADJUST;
                // using an invalid channel will let the buffers be built up for the valid channels
                $this->_get_channel_packet(-1);
                $this->bitmap^= NET_SSH2_MASK_WINDOW_ADJUST;
            }

            /* The maximum amount of data allowed is determined by the maximum
               packet size for the channel, and the current window size, whichever
               is smaller.
                 -- http://tools.ietf.org/html/rfc4254#section-5.2 */
            $max_size = min(
                $this->packet_size_client_to_server[$client_channel],
                $this->window_size_client_to_server[$client_channel]
            );

            $temp = $this->_string_shift($data, $max_size);
            $packet = pack(
                'CN2a*',
                NET_SSH2_MSG_CHANNEL_DATA,
                $this->server_channels[$client_channel],
                strlen($temp),
                $temp
            );
            $this->window_size_client_to_server[$client_channel]-= strlen($temp);
            if (!$this->_send_binary_packet($packet)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Closes and flushes a channel
     *
     * Net_SSH2 doesn't properly close most channels.  For exec() channels are normally closed by the server
     * and for SFTP channels are presumably closed when the client disconnects.  This functions is intended
     * for SCP more than anything.
     *
     * @param int $client_channel
     * @param bool $want_reply
     * @return bool
     * @access private
     */
    function _close_channel($client_channel, $want_reply = false)
    {
        // see http://tools.ietf.org/html/rfc4254#section-5.3

        $this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_EOF, $this->server_channels[$client_channel]));

        if (!$want_reply) {
            $this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$client_channel]));
        }

        $this->channel_status[$client_channel] = NET_SSH2_MSG_CHANNEL_CLOSE;

        $this->curTimeout = 0;

        while (!is_bool($this->_get_channel_packet($client_channel))) {
        }

        if ($want_reply) {
            $this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$client_channel]));
        }

        if ($this->bitmap & NET_SSH2_MASK_SHELL) {
            $this->bitmap&= ~NET_SSH2_MASK_SHELL;
        }
    }

    /**
     * Disconnect
     *
     * @param int $reason
     * @return bool
     * @access private
     */
    function _disconnect($reason)
    {
        if ($this->bitmap & NET_SSH2_MASK_CONNECTED) {
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
     * @param string $string
     * @param int $index
     * @return string
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
     * @param array $array
     * @access private
     */
    function _define_array()
    {
        $args = func_get_args();
        foreach ($args as $arg) {
            foreach ($arg as $key => $value) {
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
     * Returns a string if NET_SSH2_LOGGING == NET_SSH2_LOG_COMPLEX, an array if NET_SSH2_LOGGING == NET_SSH2_LOG_SIMPLE and false if !defined('NET_SSH2_LOGGING')
     *
     * @access public
     * @return array|false|string
     */
    function getLog()
    {
        if (!defined('NET_SSH2_LOGGING')) {
            return false;
        }

        switch (NET_SSH2_LOGGING) {
            case NET_SSH2_LOG_SIMPLE:
                return $this->message_number_log;
                break;
            case NET_SSH2_LOG_COMPLEX:
                return $this->_format_log($this->message_log, $this->message_number_log);
                break;
            default:
                return false;
        }
    }

    /**
     * Formats a log for printing
     *
     * @param array $message_log
     * @param array $message_number_log
     * @access private
     * @return string
     */
    function _format_log($message_log, $message_number_log)
    {
        $output = '';
        for ($i = 0; $i < count($message_log); $i++) {
            $output.= $message_number_log[$i] . "\r\n";
            $current_log = $message_log[$i];
            $j = 0;
            do {
                if (strlen($current_log)) {
                    $output.= str_pad(dechex($j), 7, '0', STR_PAD_LEFT) . '0  ';
                }
                $fragment = $this->_string_shift($current_log, $this->log_short_width);
                $hex = substr(preg_replace_callback('#.#s', array($this, '_format_log_helper'), $fragment), strlen($this->log_boundary));
                // replace non ASCII printable characters with dots
                // http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters
                // also replace < with a . since < messes up the output on web browsers
                $raw = preg_replace('#[^\x20-\x7E]|<#', '.', $fragment);
                $output.= str_pad($hex, $this->log_long_width - $this->log_short_width, ' ') . $raw . "\r\n";
                $j++;
            } while (strlen($current_log));
            $output.= "\r\n";
        }

        return $output;
    }

    /**
     * Helper function for _format_log
     *
     * For use with preg_replace_callback()
     *
     * @param array $matches
     * @access private
     * @return string
     */
    function _format_log_helper($matches)
    {
        return $this->log_boundary . str_pad(dechex(ord($matches[0])), 2, '0', STR_PAD_LEFT);
    }

    /**
     * Helper function for agent->_on_channel_open()
     *
     * Used when channels are created to inform agent
     * of said channel opening. Must be called after
     * channel open confirmation received
     *
     * @access private
     */
    function _on_channel_open()
    {
        if (isset($this->agent)) {
            $this->agent->_on_channel_open($this);
        }
    }

    /**
     * Returns the first value of the intersection of two arrays or false if
     * the intersection is empty. The order is defined by the first parameter.
     *
     * @param array $array1
     * @param array $array2
     * @return mixed False if intersection is empty, else intersected value.
     * @access private
     */
    function _array_intersect_first($array1, $array2)
    {
        foreach ($array1 as $value) {
            if (in_array($value, $array2)) {
                return $value;
            }
        }
        return false;
    }

    /**
     * Returns all errors
     *
     * @return string
     * @access public
     */
    function getErrors()
    {
        return $this->errors;
    }

    /**
     * Returns the last error
     *
     * @return string
     * @access public
     */
    function getLastError()
    {
        $count = count($this->errors);

        if ($count > 0) {
            return $this->errors[$count - 1];
        }
    }

    /**
     * Return the server identification.
     *
     * @return string
     * @access public
     */
    function getServerIdentification()
    {
        $this->_connect();

        return $this->server_identifier;
    }

    /**
     * Return a list of the key exchange algorithms the server supports.
     *
     * @return array
     * @access public
     */
    function getKexAlgorithms()
    {
        $this->_connect();

        return $this->kex_algorithms;
    }

    /**
     * Return a list of the host key (public key) algorithms the server supports.
     *
     * @return array
     * @access public
     */
    function getServerHostKeyAlgorithms()
    {
        $this->_connect();

        return $this->server_host_key_algorithms;
    }

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when receiving stuff from the client.
     *
     * @return array
     * @access public
     */
    function getEncryptionAlgorithmsClient2Server()
    {
        $this->_connect();

        return $this->encryption_algorithms_client_to_server;
    }

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when sending stuff to the client.
     *
     * @return array
     * @access public
     */
    function getEncryptionAlgorithmsServer2Client()
    {
        $this->_connect();

        return $this->encryption_algorithms_server_to_client;
    }

    /**
     * Return a list of the MAC algorithms the server supports, when receiving stuff from the client.
     *
     * @return array
     * @access public
     */
    function getMACAlgorithmsClient2Server()
    {
        $this->_connect();

        return $this->mac_algorithms_client_to_server;
    }

    /**
     * Return a list of the MAC algorithms the server supports, when sending stuff to the client.
     *
     * @return array
     * @access public
     */
    function getMACAlgorithmsServer2Client()
    {
        $this->_connect();

        return $this->mac_algorithms_server_to_client;
    }

    /**
     * Return a list of the compression algorithms the server supports, when receiving stuff from the client.
     *
     * @return array
     * @access public
     */
    function getCompressionAlgorithmsClient2Server()
    {
        $this->_connect();

        return $this->compression_algorithms_client_to_server;
    }

    /**
     * Return a list of the compression algorithms the server supports, when sending stuff to the client.
     *
     * @return array
     * @access public
     */
    function getCompressionAlgorithmsServer2Client()
    {
        $this->_connect();

        return $this->compression_algorithms_server_to_client;
    }

    /**
     * Return a list of the languages the server supports, when sending stuff to the client.
     *
     * @return array
     * @access public
     */
    function getLanguagesServer2Client()
    {
        $this->_connect();

        return $this->languages_server_to_client;
    }

    /**
     * Return a list of the languages the server supports, when receiving stuff from the client.
     *
     * @return array
     * @access public
     */
    function getLanguagesClient2Server()
    {
        $this->_connect();

        return $this->languages_client_to_server;
    }

    /**
     * Returns the banner message.
     *
     * Quoting from the RFC, "in some jurisdictions, sending a warning message before
     * authentication may be relevant for getting legal protection."
     *
     * @return string
     * @access public
     */
    function getBannerMessage()
    {
        return $this->banner_message;
    }

    /**
     * Returns the server public host key.
     *
     * Caching this the first time you connect to a server and checking the result on subsequent connections
     * is recommended.  Returns false if the server signature is not signed correctly with the public host key.
     *
     * @return mixed
     * @access public
     */
    function getServerPublicHostKey()
    {
        if (!($this->bitmap & NET_SSH2_MASK_CONSTRUCTOR)) {
            if (!$this->_connect()) {
                return false;
            }
        }

        $signature = $this->signature;
        $server_public_host_key = $this->server_public_host_key;

        extract(unpack('Nlength', $this->_string_shift($server_public_host_key, 4)));
        $this->_string_shift($server_public_host_key, $length);

        if ($this->signature_validated) {
            return $this->bitmap ?
                $this->signature_format . ' ' . base64_encode($this->server_public_host_key) :
                false;
        }

        $this->signature_validated = true;

        switch ($this->signature_format) {
            case 'ssh-dss':
                $zero = new Math_BigInteger();

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
                    user_error('Invalid signature');
                    return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                }

                $r = new Math_BigInteger($this->_string_shift($signature, 20), 256);
                $s = new Math_BigInteger($this->_string_shift($signature, 20), 256);

                switch (true) {
                    case $r->equals($zero):
                    case $r->compare($q) >= 0:
                    case $s->equals($zero):
                    case $s->compare($q) >= 0:
                        user_error('Invalid signature');
                        return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                }

                $w = $s->modInverse($q);

                $u1 = $w->multiply(new Math_BigInteger(sha1($this->exchange_hash), 16));
                list(, $u1) = $u1->divide($q);

                $u2 = $w->multiply($r);
                list(, $u2) = $u2->divide($q);

                $g = $g->modPow($u1, $p);
                $y = $y->modPow($u2, $p);

                $v = $g->multiply($y);
                list(, $v) = $v->divide($p);
                list(, $v) = $v->divide($q);

                if (!$v->equals($r)) {
                    user_error('Bad server signature');
                    return $this->_disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }

                break;
            case 'ssh-rsa':
                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $e = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

                $temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
                $rawN = $this->_string_shift($server_public_host_key, $temp['length']);
                $n = new Math_BigInteger($rawN, -256);
                $nLength = strlen(ltrim($rawN, "\0"));

                /*
                $temp = unpack('Nlength', $this->_string_shift($signature, 4));
                $signature = $this->_string_shift($signature, $temp['length']);

                if (!class_exists('Crypt_RSA')) {
                    include_once 'Crypt/RSA.php';
                }

                $rsa = new Crypt_RSA();
                $rsa->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
                $rsa->loadKey(array('e' => $e, 'n' => $n), CRYPT_RSA_PUBLIC_FORMAT_RAW);
                if (!$rsa->verify($this->exchange_hash, $signature)) {
                    user_error('Bad server signature');
                    return $this->_disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }
                */

                $temp = unpack('Nlength', $this->_string_shift($signature, 4));
                $s = new Math_BigInteger($this->_string_shift($signature, $temp['length']), 256);

                // validate an RSA signature per "8.2 RSASSA-PKCS1-v1_5", "5.2.2 RSAVP1", and "9.1 EMSA-PSS" in the
                // following URL:
                // ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf

                // also, see SSHRSA.c (rsa2_verifysig) in PuTTy's source.

                if ($s->compare(new Math_BigInteger()) < 0 || $s->compare($n->subtract(new Math_BigInteger(1))) > 0) {
                    user_error('Invalid signature');
                    return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                }

                $s = $s->modPow($e, $n);
                $s = $s->toBytes();

                $h = pack('N4H*', 0x00302130, 0x0906052B, 0x0E03021A, 0x05000414, sha1($this->exchange_hash));
                $h = chr(0x01) . str_repeat(chr(0xFF), $nLength - 2 - strlen($h)) . $h;

                if ($s != $h) {
                    user_error('Bad server signature');
                    return $this->_disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }
                break;
            default:
                user_error('Unsupported signature format');
                return $this->_disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
        }

        return $this->signature_format . ' ' . base64_encode($this->server_public_host_key);
    }

    /**
     * Returns the exit status of an SSH command or false.
     *
     * @return false|int
     * @access public
     */
    function getExitStatus()
    {
        if (is_null($this->exit_status)) {
            return false;
        }
        return $this->exit_status;
    }

    /**
     * Returns the number of columns for the terminal window size.
     *
     * @return int
     * @access public
     */
    function getWindowColumns()
    {
        return $this->windowColumns;
    }

    /**
     * Returns the number of rows for the terminal window size.
     *
     * @return int
     * @access public
     */
    function getWindowRows()
    {
        return $this->windowRows;
    }

    /**
     * Sets the number of columns for the terminal window size.
     *
     * @param int $value
     * @access public
     */
    function setWindowColumns($value)
    {
        $this->windowColumns = $value;
    }

    /**
     * Sets the number of rows for the terminal window size.
     *
     * @param int $value
     * @access public
     */
    function setWindowRows($value)
    {
        $this->windowRows = $value;
    }

    /**
     * Sets the number of columns and rows for the terminal window size.
     *
     * @param int $columns
     * @param int $rows
     * @access public
     */
    function setWindowSize($columns = 80, $rows = 24)
    {
        $this->windowColumns = $columns;
        $this->windowRows = $rows;
    }
}
