<?php
/**
 * @author     Marc Scholten <marc@pedigital.de>
 * @copyright  MMXIII Marc Scholten
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Basically the same thing as Net_Logger_Realtime with the caveat that the resultant
 * log file will be capped out at $max_size.
 * The earliest part of the log file is denoted by the first <<< START >>> and is not going to necessarily
 * at the beginning of the file
 */
class Net_Logger_RealtimeFile extends Net_Logger_Realtime
{
    /**
     * @var String
     * @access private
     */
    var $filename;
    /**
     * Real-time log file pointer
     *
     * @var Resource
     * @access private
     */
    var $file;
    /**
     * Real-time log file size
     *
     * @var Integer
     * @access private
     */
    var $log_size;
    /**
     * Real-time log file wrap boolean
     *
     * @access private
     */
    var $wrap = false;
    var $max_size;

    /**
     * @param null $filename
     * @param int $max_size Default value is 1mb (1024 * 1024)
     * @param null $formatter
     */
    function __construct($filename, $max_size = 1048576, $formatter = null)
    {
        parent::__construct($formatter);
        $this->filename = $filename;
        $this->max_size = $max_size;

        $fp = fopen($this->filename, 'w');
        $this->file = $fp;
    }

    function log($message_number, $message)
    {
        // remove the byte identifying the message type from all but the first two messages (ie. the identification strings)
        if (strlen($message_number) > 2) {
            $this->_string_shift($message);
        }
        
        $entry = $this->formatter->format(array($message), array($message_number));
        if ($this->wrap) {
            $temp = "<<< START >>>\r\n";
            $entry .= $temp;
            fseek($this->file, ftell($this->file) - strlen($temp));
        }
        $this->log_size += strlen($entry);
        if ($this->log_size > $this->max_size) {
            fseek($this->file, 0);
            $this->log_size = strlen($entry);
            $this->wrap = true;
        }
        fputs($this->file, $entry);
    }

    /**
     * Return nothing
     * 
     * @access public
     */
    function getLog()
    {
        return null;
    }
}
