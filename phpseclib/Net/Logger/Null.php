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
    function log($message_number, $message)
    {
        // do nothing
    }

    function getLog()
    {
        return null;
    }
}