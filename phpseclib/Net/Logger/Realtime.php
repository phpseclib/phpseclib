<?php
/**
 * @author     Marc Scholten <marc@pedigital.de>
 * @copyright  MMXIII Marc Scholten
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Net_Logger_Realtime extends Net_Logger_Abstract
{
    /**
     * @var Net_Logger_Formatter
     * @access protected
     */
    var $formatter;

    function __construct($formatter = null)
    {
        if ($formatter == null) {
            $formatter = new Net_Logger_Formatter();
        }

        $this->formatter = $formatter;
    }

    public function log($message_number, $message)
    {
        // remove the byte identifying the message type from all but the first two messages (ie. the identification strings)
        if (strlen($message_number) > 2) {
            $this->_string_shift($message);
        }

        // dump the output out realtime; packets may be interspersed with non packets,
        // passwords won't be filtered out and select other packets may not be correctly
        // identified

        switch (PHP_SAPI) {
            case 'cli':
                $start = $stop = "\r\n";
                break;
            default:
                $start = '<pre>';
                $stop = '</pre>';
        }

        $this->_flush($start . $this->formatter->format(array($message), array($message_number)) . $stop);
    }

    /**
     * @access private
     */
    function _flush($string)
    {
        echo $string;
        @flush();
        @ob_flush();
    }

    function getLog()
    {
        return null;
    }
}
