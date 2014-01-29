<?php
/**
 * @author     Marc Scholten <marc@pedigital.de>
 * @copyright  MMXIII Marc Scholten
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

abstract class Net_Logger_Abstract
{
    /**
     * Message Number Log
     *
     * @var Array
     * @access protected
     */
    var $message_number_log = array();

    /**
     * Message Log
     *
     * @var Array
     * @access protected
     */
    var $message_log = array();


    /**
     * Logs a package
     *
     * @param string $message_number The message number of the package, for example NET_SSH2_MSG_DISCONNECT
     * @param string $message The packet content itself
     *
     * @access public
     */
    abstract public function log($message_number, $message);

    /**
     * Returns the logged messages.
     * The return type of this method is defined by the implementing class.
     *
     * @access public
     */
    abstract public function getLog();

    /**
     * This method is basically a hack for beeing backwards compatible with the old logging. It will replace the
     * string 'UNKOWN' in the last logged packet with the given name. It's useful if you logged a packet with an unknown type
     * but now know the type of this packet.
     *
     * @access public
     */
    function updateLastPacketName($name)
    {
        $this->message_number_log[count($this->message_number_log) - 1] = str_replace(
            'UNKNOWN',
            $name,
            $this->message_number_log[count($this->message_number_log) - 1]
        );
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
}
