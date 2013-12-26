<?php
/**
 * @author     Marc Scholten <marc@pedigital.de>
 * @copyright  MMXIII Marc Scholten
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Net_Logger_Simple extends Net_Logger_Abstract
{
    public function log($message_number, $message)
    {
        $this->message_number_log[] = $message_number;
    }

    public function getLog()
    {
        return $this->message_number_log;
    }
}
