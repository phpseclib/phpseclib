<?php
/**
 * @author     Marc Scholten <marc@pedigital.de>
 * @copyright  MMXIII Marc Scholten
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * This logger is for the case you want to disable logging at all.
 * Every call to the log method of this logger will just do nothing at all.
 */
class Net_Logger_Null extends Net_Logger_Abstract
{
    /**
     * Do nothing
     * @access public
     */
    function log($message_number, $message)
    {
    }

    /**
     * Return nothing because this logger doesn't log anything
     * @access public
     */
    function getLog()
    {
        return null;
    }
}