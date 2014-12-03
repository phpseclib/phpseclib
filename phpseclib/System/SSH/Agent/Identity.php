<?php
/**
 * Pure-PHP ssh-agent client.
 *
 * PHP versions 4 and 5
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
 * @category  System
 * @package   System_SSH_Agent
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright MMXIV Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 * @internal  See http://api.libssh.org/rfc/PROTOCOL.agent
 */

/**
 * Pure-PHP ssh-agent client identity object
 *
 * Instantiation should only be performed by System_SSH_Agent class.
 * This could be thought of as implementing an interface that Crypt_RSA
 * implements. ie. maybe a Net_SSH_Auth_PublicKey interface or something.
 * The methods in this interface would be getPublicKey, setSignatureMode
 * and sign since those are the methods phpseclib looks for to perform
 * public key authentication.
 *
 * @package System_SSH_Agent
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  internal
 */
class System_SSH_Agent_Identity
{
    /**
     * Key Object
     *
     * @var Crypt_RSA
     * @access private
     * @see System_SSH_Agent_Identity::getPublicKey()
     */
    var $key;

    /**
     * Key Blob
     *
     * @var String
     * @access private
     * @see System_SSH_Agent_Identity::sign()
     */
    var $key_blob;

    /**
     * Socket Resource
     *
     * @var Resource
     * @access private
     * @see System_SSH_Agent_Identity::sign()
     */
    var $fsock;

    /**
     * Default Constructor.
     *
     * @param Resource $fsock
     * @return System_SSH_Agent_Identity
     * @access private
     */
    function __construct($fsock)
    {
        $this->fsock = $fsock;
    }

    /**
     * Set Public Key
     *
     * Called by System_SSH_Agent::requestIdentities()
     *
     * @param Crypt_RSA $key
     * @access private
     */
    function setPublicKey($key)
    {
        $this->key = $key;
        $this->key->setPublicKey();
    }

    /**
     * Set Public Key
     *
     * Called by System_SSH_Agent::requestIdentities(). The key blob could be extracted from $this->key
     * but this saves a small amount of computation.
     *
     * @param String $key_blob
     * @access private
     */
    function setPublicKeyBlob($key_blob)
    {
        $this->key_blob = $key_blob;
    }

    /**
     * Get Public Key
     *
     * Wrapper for $this->key->getPublicKey()
     *
     * @param Integer $format optional
     * @return Mixed
     * @access public
     */
    function getPublicKey($format = null)
    {
        return !isset($format) ? $this->key->getPublicKey() : $this->key->getPublicKey($format);
    }

    /**
     * Set Signature Mode
     *
     * Doesn't do anything as ssh-agent doesn't let you pick and choose the signature mode. ie.
     * ssh-agent's only supported mode is CRYPT_RSA_SIGNATURE_PKCS1
     *
     * @param Integer $mode
     * @access public
     */
    function setSignatureMode($mode)
    {
    }

    /**
     * Create a signature
     *
     * See "2.6.2 Protocol 2 private key signature request"
     *
     * @param String $message
     * @return String
     * @access public
     */
    function sign($message)
    {
        // the last parameter (currently 0) is for flags and ssh-agent only defines one flag (for ssh-dss): SSH_AGENT_OLD_SIGNATURE
        $packet = pack('CNa*Na*N', SYSTEM_SSH_AGENTC_SIGN_REQUEST, strlen($this->key_blob), $this->key_blob, strlen($message), $message, 0);
        $packet = pack('Na*', strlen($packet), $packet);
        if (strlen($packet) != fputs($this->fsock, $packet)) {
            user_error('Connection closed during signing');
        }

        $length = current(unpack('N', fread($this->fsock, 4)));
        $type = ord(fread($this->fsock, 1));
        if ($type != SYSTEM_SSH_AGENT_SIGN_RESPONSE) {
            user_error('Unable to retreive signature');
        }

        $signature_blob = fread($this->fsock, $length - 1);
        // the only other signature format defined - ssh-dss - is the same length as ssh-rsa
        // the + 12 is for the other various SSH added length fields
        return substr($signature_blob, strlen('ssh-rsa') + 12);
    }
}
