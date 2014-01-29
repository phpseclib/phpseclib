<?php
/**
 * @author     Marc Scholten <marc@pedigital.de>
 * @copyright  MMXIII Marc Scholten
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Net_Logger_Simple extends Net_Logger_Abstract
{
    function log($message_number, $message)
    {
        $this->message_number_log[] = $message_number;
    }

    /**
     * Returns a list of packets that have been sent and received
     *
     * @return array
     */
    function getLog()
    {
        return $this->message_number_log;
    }
}
