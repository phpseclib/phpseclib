<?php

use phpseclib\Net\SSH2;

/**
 * Created: sasf54
 * License: MIT
 * Date: 2016.10.04
 *
 * SSH2_Bash: Will use an existing SSH2 connection, and will execute commands in a batch fashion.
 * Will use single session unless SSH2::execute.
 * Will wait for the commands to finish, unless a logout command is issued to close the ssh connection.
 * You can send multiple commands at once, and this class will make sure, that it will stay connected until
 * the commands are all executed / failed. Set timeout to an acceptable low value (0.1).
 * This class will execute batched commands in order, and in whole. You only have the opportunity to check the output
 * at the read() for errors.
 *
 * Example code:
 * // initializing ssh2 connection
 * $ssh2 = new SSH2($server_hostname, $server_port);
 * if ( !$ssh2->login($username, $password)) {
 *     echo var_export($ssh2, true);
 *     return 'Was not able to login to the server';
 * }
 *
 * $ssh2_bash = new SSH2_BASH($ssh2,false,0.1);
 * // executing commands (as they are processed)
 * $ssh2_bash->sshWrite("sleep 1");
 * $ssh2_bash->sshWrite("echo \"finished\"");
 * $ssh2_bash->sshWrite("exit");
 * echo $ssh2_bash->read();
 *
 * $ssh2->->disconnect();
 *
 */
class SSH2_Batch {
    /**
     * @var $ssh2 SSH2, connection to in the class
     */
    var $ssh;
    /**
     * @var bool $debug Do you want to enable debugging (will echo everything)
     */
    var $debug;

    /**
     * @var int $echo Does echo expected (0 for no, 1 is for yes)
     */
    var $echo = 1;

    /**
     * SiteManager constructor.
     * @param $ssh2 SSH2 Existing ssh2 connection
     * @param $debug boolean On debug, will echo everything (echoed input, and the output)
     * @param int $echo Does the ssh conneciton has echo (writes back the stdin)
     */
    public function __construct($ssh2, $debug = false, $echo = 1) {
        $this->ssh = $ssh2;
        $this->debug = $debug;
        $this->echo = $echo;
    }


    /**Writes an ssh command into the SSH tunnel
     * @param $command String command to execute, without trailing NEW_LINE
     */
    public function sshWrite($command) {
        $result = $this->ssh->write($command."\n");
        if ($this->debug)
            echo $result;
    }

    /**Reads the ssh command / waits for commands to finish
     * Marks the end of current execution queue, and waits, until the server reaches to process it.
     * Does this 2 times: (depending on $echo)
     * 1. it should be the stdin echoed (as typed)
     * 2. it should be the command echo
     */
    public function sshRead() {
        $result = '';
        $currentEndWrite = "End of current process **".$this::generateRandomString()."**";
        $this->sshWrite("echo ================================================");
        $this->sshWrite("echo '".$currentEndWrite."'");
        $this->sshWrite("echo ================================================");
        $bytesRead = 0;
        $found = 0;
        do {
            $current_result = $this->ssh->read();
            $bytesRead += strlen($result);
            if ($this->debug) {
                echo $current_result;
            }
            $result .= $current_result;
            // found end write string
            // first occurrence on console in
            // second occurrence on console out
            if ($this::contains($current_result, $currentEndWrite)) {
                $found++;
                // checking
                $result_rest = substr($current_result, strpos($current_result, $currentEndWrite) + strlen($currentEndWrite));
                if ($this::contains($result_rest, $currentEndWrite)) {
                    $found++;
                }
            }
        } while ($found < ($this->echo + 1));

        if ($this->debug)
            echo "bytes read:".$bytesRead.'<br/>';

        return $result;
    }


    public function setDebug($result) {
        if ($this->debug)
            echo $result;
    }

    /**
     * Generates a random string for marking the end of
     * @return string a 20 long random character chain
     */
    public function generateRandomString() {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $randomString = '';
        $length = 20;
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, strlen($characters) - 1)];
        }
        return $randomString;
    }

    /**
     * @param $haystack String What are you searching IN
     * @param $needle String What are you searcing FOR
     * @return bool The haystack contains the string
     */
    private function contains($haystack, $needle){
        return strpos($haystack,$needle)>-1;
    }

}

