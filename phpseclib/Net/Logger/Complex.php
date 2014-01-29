<?php
/**
 * @author     Marc Scholten <marc@pedigital.de>
 * @copyright  MMXIII Marc Scholten
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

class Net_Logger_Complex extends Net_Logger_Simple
{
    var $log_size;
    var $max_size;
    var $formatter;

    /**
     * @param int $max_size Default value is 1mb (1024 * 1024)
     * @param Net_Logger_Formatter|null $formatter If null the default Net_Logger_Formatter object will be used for formatting
     */
    function __construct($max_size = 1048576, $formatter = null)
    {
        if($formatter == null) {
            $formatter = new Net_Logger_Formatter();
        }

        $this->formatter = $formatter;
        $this->max_size = $max_size;
    }

    function log($message_number, $message)
    {
        parent::log($message_number, $message);

        // remove the byte identifying the message type from all but the first two messages (ie. the identification strings)
        if (strlen($message_number) > 2) {
            $this->_string_shift($message);
        }

        $this->log_size += strlen($message);
        $this->message_log[] = $message;

        $this->checkSize();
    }

    /**
     * If the memory used by this class is greater than $max_size, some of the last messages will be removed
     * @access private
     */
    function checkSize()
    {
        while ($this->log_size > $this->max_size) {
            $this->log_size -= strlen(array_shift($this->message_log));
            array_shift($this->message_number_log);
        }
    }

    /**
     * Returns the logged message formatted by the given formatter.
     *
     * Be aware that this method may not give you all message.
     * @see checkSize()
     *
     * @access public
     * @return string
     */
    function getLog()
    {
        return $this->formatter->format($this->message_log, $this->message_number_log);
    }
}
