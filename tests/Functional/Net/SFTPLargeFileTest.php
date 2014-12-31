<?php
echo "LOADING LARGE FILE TEST\r\n";

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'Crypt/Base.php';
require_once 'Math/BigInteger.php';
require_once 'Crypt/Hash.php';

class Functional_Net_SFTPLargeFileTest extends PhpseclibFunctionalTestCase
{
    protected $sftp;
    protected $scratchDir;

    static public function setUpBeforeClass()
    {
echo "SETTING UP BEFORE CLASS\r\n";
        if (!extension_loaded('mcrypt') && !extension_loaded('openssl')) {
            self::markTestSkipped('This test depends on mcrypt or openssl for performance.');
        }
        parent::setUpBeforeClass();
echo "SETUP BEFORE CLASS DONE\r\n";
    }


}
