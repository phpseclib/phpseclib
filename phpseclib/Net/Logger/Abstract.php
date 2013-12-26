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

    abstract public function log($message_number, $message);
    abstract public function getLog();

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
