<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * SFTP Stream Wrapper
 *
 * Creates an sftp:// protocol handler that can be used with, for example, fopen(), dir(), etc.
 *
 * PHP version 5
 *
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @category   Net
 * @package    Net_SFTP_Stream
 * @author     Jim Wigginton <terrafrost@php.net>
 * @copyright  MMXIII Jim Wigginton
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link       http://phpseclib.sourceforge.net
 */

/**
 * Include Net_SSH2
 */
if (!class_exists('Net_SSH2')) {
    require_once('../Net/SSH2.php');
}

/**
 * SFTP Stream Wrapper
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 0.3.2
 * @access  public
 * @package Net_SFTP_Stream
 */
class Net_SFTP_Stream {
    /**
     * SFTP instances
     *
     * Rather than re-create the connection we re-use instances if possible
     *
     * @var Array
     * @access static
     */
    static $instances;

    /**
     * SFTP instance
     *
     * @var Object
     * @access private
     */
    var $sftp;

    /**
     * Path
     *
     * @var String
     * @access private
     */
    var $path;

    /**
     * Mode
     *
     * @var String
     * @access private
     */
    var $mode;

    /**
     * Position
     *
     * @var Integer
     * @access private
     */
    var $pos;

    /**
     * Size
     *
     * @var Integer
     * @access private
     */
    var $size;

    /**
     * Directory entries
     *
     * @var Array
     * @access private
     */
    var $entries;

    /**
     * EOF flag
     *
     * @var Boolean
     * @access private
     */
    var $eof;

    /**
     * Context resource
     *
     * Technically this needs to be publically accessible so PHP can set it directly
     *
     * @var Resource
     * @access public
     */
    var $context;

    /**
     * Path Parser
     *
     * Extract a path from a URI and actually connect to an SSH server if appropriate
     *
     * @param String $path
     * @return String
     * @access private
     */
    function _parse_path($path)
    {
        extract(parse_url($path));

        if (!isset($host)) {
            return false;
        }

        if ($host[0] == '$') {
            $host = substr($host, 1);
            global $$host;
            if (!is_object($$host) || get_class($$host) != 'Net_sFTP') {
                return false;
            }
            $this->sftp = $$host;
        } else {
            $context = stream_context_get_options($this->context);
            if (isset($context['sftp']['session'])) {
                $sftp = $context['sftp']['session'];
            }
            if (isset($context['sftp']['sftp'])) {
                $sftp = $context['sftp']['sftp'];
            }
            if (isset($sftp) && is_object($sftp) && get_class($sftp) == 'Net_SFTP') {
                $this->sftp = $sftp;
                return $path;
            }
            if (isset($context['sftp']['username'])) {
                $user = $context['sftp']['username'];
            }
            if (isset($context['sftp']['password'])) {
                $pass = $context['sftp']['password'];
            }
            if (isset($context['sftp']['privkey']) && is_object($context['sftp']['privkey']) && get_Class($context['sftp']['privkey']) == 'Crypt_RSA') {
                $pass = $context['sftp']['privkey'];
            }

            if (!isset($user) || !isset($pass)) {
                return false;
            }

            // casting $pass to a string is necessary in the event that it's a Crypt_RSA object
            if (isset(self::$instances[$host][$port][$user][(string) $pass])) {
                $this->sftp = self::$instances[$host][$port][$user][(string) $pass];
            } else {
                $this->sftp = new Net_SFTP($host, isset($port) ? $port : 22);
                if (!$this->sftp->login($user, $pass)) {
                    return false;
                }
                self::$instances[$host][$port][$user][(string) $pass] = $this->sftp;
            }
        }

        return $path;
    }

    /**
     * Opens file or URL
     *
     * @param String $path
     * @param String $mode
     * @param Integer $options
     * @param String $opened_path
     * @return Boolean
     * @access public
     */
    function stream_open($path, $mode, $options, &$opened_path)
    {
        $path = $this->_parse_path($path);

        if ($path === false) {
            return false;
        }
        $this->path = $path;

        $this->size = $this->sftp->size($path);
        $this->mode = preg_replace('#[bt]$#', '', $mode);

        if ($this->size === false) {
            if ($this->mode[0] == 'r') {
                return false;
            }
        } else {
            switch ($this->mode[0]) {
                case 'x':
                    return false;
                case 'w':
                case 'c':
                    $this->sftp->truncate($path, 0);
            }
        }

        $this->pos = $this->mode[0] != 'a' ? 0 : $size;

        return true;
    }

    /**
     * Read from stream
     *
     * @param Integer $count
     * @return Mixed
     * @access public
     */
    function stream_read($count)
    {
        switch ($this->mode) {
            case 'w':
            case 'a':
            case 'x':
            case 'c':
                return false;
        }

        // commented out because some files - eg. /dev/urandom - will say their size is 0 when in fact it's kinda infinite
        //if ($this->pos >= $this->size) {
        //    $this->eof = true;
        //    return false;
        //}

        $result = $this->sftp->get($this->path, false, $this->pos, $count);
        if (empty($result)) {
            $this->eof = true;
            return false;
        }
        $this->pos+= strlen($result);

        return $result;
    }

    /**
     * Write to stream
     *
     * @param String $data
     * @return Mixed
     * @access public
     */
    function stream_write($data)
    {
        switch ($this->mode) {
            case 'r':
                return false;
        }

        $result = $this->sftp->put($this->path, $data, NET_SFTP_STRING, $this->pos);
        if ($result === false) {
            return false;
        }
        $this->pos+= strlen($data);
        if ($this->pos > $this->size) {
            $this->size = $this->pos;
        }
        $this->eof = false;
        return strlen($data);
    }

    /**
     * Retrieve the current position of a stream
     *
     * @return Integer
     * @access public
     */
    function stream_tell()
    {
        return $this->pos;
    }

    /**
     * Tests for end-of-file on a file pointer
     *
     * In my testing there are four classes functions that normally effect the pointer:
     * fseek, fputs  / fwrite, fgets / fread and ftruncate.
     *
     * Only fgets / fread, however, results in feof() returning true. do fputs($fp, 'aaa') on a blank file and feof()
     * will return false. do fread($fp, 1) and feof() will then return true. do fseek($fp, 10) on ablank file and feof()
     * will return false. do fread($fp, 1) and feof() will then return true.
     *
     * @return Boolean
     * @access public
     */
    function stream_eof()
    {
        return $this->eof;
    }

    /**
     * Seeks to specific location in a stream
     *
     * @param Integer $offset
     * @param Integer $whence
     * @return Boolean
     * @access public
     */
    function stream_seek($offset, $whence)
    {
        switch ($whence) {
            case SEEK_SET:
                if ($offset >= $this->size || $offset < 0) {
                    return false;
                }
                break;
            case SEEK_CUR:
                $offset+= $this->pos;
                break;
            case SEEK_END:
                $offset+= $this->size;
        }

        $this->pos = $offset;
        $this->eof = false;
        return true;
    }

    /**
     * Change stream options
     *
     * @param String $path
     * @param Integer $option
     * @param Mixed $var
     * @return Boolean
     * @access public
     */
    function stream_metadata($path, $option, $var)
    {
        $path = $this->_parse_path($path);
        if ($path === false) {
            return false;
        }

        // stream_metadata was introduced in PHP 5.4.0 but as of 5.4.11 the constants haven't been defined
        // see http://www.php.net/streamwrapper.stream-metadata and https://bugs.php.net/64246
        //     and https://github.com/php/php-src/blob/master/main/php_streams.h#L592
        switch ($option) {
            case 1: // PHP_STREAM_META_TOUCH
                return $this->sftp->touch($path, $var[0], $var[1]);
            case 2: // PHP_STREAM_OWNER_NAME
            case 3: // PHP_STREAM_GROUP_NAME
                return false;
            case 4: // PHP_STREAM_META_OWNER
                return $this->sftp->chown($path, $var);
            case 5: // PHP_STREAM_META_GROUP
                return $this->sftp->chgrp($path, $var);
            case 6: // PHP_STREAM_META_ACCESS
                return $this->sftp->chmod($path, $var) !== false;
        }
    }

    /**
     * Retrieve the underlaying resource
     *
     * @param Integer $cast_as
     * @return Resource
     * @access public
     */
    function stream_cast($cast_as)
    {
        return $this->sftp->fsock;
    }

    /**
     * Advisory file locking
     *
     * @param Integer $operation
     * @return Boolean
     * @access public
     */
    function stream_lock($operation)
    {
        return false;
    }

    /**
     * Renames a file or directory
     *
     * Attempts to rename oldname to newname, moving it between directories if necessary.
     * If newname exists, it will be overwritten.  This is a departure from what Net_SFTP
     * does.
     *
     * @param String $path_from
     * @param String $path_to
     * @return Boolean
     * @access public
     */
    function rename($path_from, $path_to)
    {
        $path1 = parse_url($path_from);
        $path2 = parse_url($path_to);
        unset($path1['path'], $path2['path']);
        if ($path1 != $path2) {
            return false;
        }

        $path_from = $this->_parse_path($path_from);
        $path_to = parse_url($path_to);
        if ($path_from == false) {
            return false;
        }

        $path_to = $path_to['path']; // the $component part of parse_url() was added in PHP 5.1.2
        // "It is an error if there already exists a file with the name specified by newpath."
        //  -- http://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-6.5
        if (!$this->sftp->rename($path_from, $path_to)) {
            if ($this->sftp->stat($path_to)) {
                return $this->sftp->delete($path_to, true) && $this->sftp->rename($path_from, $path_to);
            }
            return false;
        }

        return true;
    }

    /**
     * Open directory handle
     *
     * The only $options is "whether or not to enforce safe_mode (0x04)". Since safe mode was deprecated in 5.3 and
     * removed in 5.4 I'm just going to ignore it 
     *
     * @param String $path
     * @param Integer $options
     * @return Boolean
     * @access public
     */
    function dir_opendir($path, $options)
    {
        $path = $this->_parse_path($path);
        if ($path === false) {
            return false;
        }
        $this->pos = 0;
        $this->entries = $this->sftp->nlist($path);
        return $this->entries !== false;
    }

    /**
     * Read entry from directory handle
     *
     * @return Mixed
     * @access public
     */
    function dir_readdir()
    {
        if (isset($this->entries[$this->pos])) {
            return $this->entries[$this->pos++];
        }
        return false;
    }

    /**
     * Rewind directory handle
     *
     * @return Boolean
     * @access public
     */
    function dir_rewinddir()
    {
        $this->pos = 0;
        return true;
    }

    /**
     * Close directory handle
     *
     * @return Boolean
     * @access public
     */
    function dir_closedir()
    {
        return true;
    }

    /**
     * Create a directory
     *
     * Only valid $options is STREAM_MKDIR_RECURSIVE
     *
     * @param String $path
     * @param Integer $mode
     * @param Integer $options
     * @return Boolean
     * @access public
     */
    function mkdir($path, $mode, $options)
    {
        $path = $this->_parse_path($path);
        if ($path === false) {
            return false;
        }

        return $this->sftp->mkdir($path, $mode, $options & STREAM_MKDIR_RECURSIVE);
    }

    /**
     * Removes a directory
     *
     * Only valid $options is STREAM_MKDIR_RECURSIVE per <http://php.net/streamwrapper.rmdir>, however,
     * <http://php.net/rmdir>  does not have a $recursive parameter as mkdir() does so I don't know how
     * STREAM_MKDIR_RECURSIVE is supposed to be set. Also, when I try it out with rmdir() I get 8 as
     * $options. What does 8 correspond to?
     *
     * @param String $path
     * @param Integer $mode
     * @param Integer $options
     * @return Boolean
     * @access public
     */
    function rmdir($path, $options)
    {
        $path = $this->_parse_path($path);
        if ($path === false) {
            return false;
        }

        return $this->sftp->rmdir($path);
    }

    /**
     * Flushes the output
     *
     * See <http://php.net/fflush>. Always returns true because Net_SFTP doesn't cache stuff before writing
     *
     * @return Boolean
     * @access public
     */
    function stream_flush()
    {
        return true;
    }

    /**
     * Retrieve information about a file resource
     *
     * @return Mixed
     * @access public
     */
    function stream_stat()
    {
        $results = $this->sftp->stat($this->path);
        if ($results === false) {
            return false;
        }
        return $results;
    }

    /**
     * Delete a file
     *
     * @param String $path
     * @return Boolean
     * @access public
     */
    function unlink($path)
    {
        $path = $this->_parse_path($path);
        if ($path === false) {
            return false;
        }

        return $this->sftp->delete($path, false);
    }

    /**
     * Retrieve information about a file
     *
     * Ignores the STREAM_URL_STAT_QUIET flag because the entirety of Net_SFTP_Stream is quiet by default
     * might be worthwhile to reconstruct bits 12-16 (ie. the file type) if mode doesn't have them but we'll
     * cross that bridge when and if it's reached
     *
     * @param String $path
     * @param Integer $flags
     * @return Mixed
     * @access public
     */
    function url_stat($path, $flags)
    {
        $path = $this->_parse_path($path);
        if ($path === false) {
            return false;
        }

        $results = $flags & STREAM_URL_STAT_LINK ? $this->sftp->lstat($path) : $this->sftp->stat($path);
        if ($results === false) {
            return false;
        }

        return $results;
    }

    /**
     * Truncate stream
     *
     * @param Integer $new_size
     * @return Boolean
     * @access public
     */
    function stream_truncate($new_size)
    {
        if (!$this->sftp->truncate($this->path, $new_size)) {
            return false;
        }

        $this->eof = false;
        $this->size = $new_size;

        return true;
    }

    /**
     * Change stream options
     *
     * STREAM_OPTION_WRITE_BUFFER isn't supported for the same reason stream_flush isn't.
     * The other two aren't supported because of limitations in Net_SFTP.
     *
     * @param Integer $option
     * @param Integer $arg1
     * @param Integer $arg2
     * @return Boolean
     * @access public
     */
    function stream_set_option($option, $arg1, $arg2)
    {
        return false;
    }
}

stream_wrapper_register('sftp', 'Net_SFTP_Stream');
