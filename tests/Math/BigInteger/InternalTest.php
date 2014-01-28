<?php
/**
 * @author     Andreas Fischer <bantu@phpbb.com>
 * @copyright  MMXIII Andreas Fischer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib\Math\BigInteger;
 
class InternalTest extends \phpseclib\Math\BigIntegerTest
{
    static public function setUpBeforeClass()
    {
        
        parent::setUpBeforeClass();

        BigIntger::setMode(BigInteger::MODE_INTERNAL);
        BigIntger::setOpenSslEnabled(false);
    }
}
