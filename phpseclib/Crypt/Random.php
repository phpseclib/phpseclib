<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Random Number Generator
 *
 * PHP versions 4 and 5
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include('Crypt/Random.php');
 *
 *    echo crypt_random();
 * ?>
 * </code>
 *
 * LICENSE: This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA  02111-1307  USA
 *
 * @category   Crypt
 * @package    Crypt_Random
 * @author     Jim Wigginton <terrafrost@php.net>
 * @copyright  MMVII Jim Wigginton
 * @license    http://www.gnu.org/licenses/lgpl.txt
 * @version    $Id: Random.php,v 1.4 2008-05-21 05:15:32 terrafrost Exp $
 * @link       http://phpseclib.sourceforge.net
 */

/**
 * Generate a random value.  Feel free to replace this function with a cryptographically secure PRNG.
 *
 * @param optional Integer $min
 * @param optional Integer $max
 * @param optional String $randomness_path
 * @return Integer
 * @access public
 */
function crypt_random($min = 0, $max = 0x7FFFFFFF, $randomness_path = '/dev/urandom')
{
    static $seeded = false;

    if (!$seeded) {
        $seeded = true;
        if (file_exists($randomness_path)) {
            $fp = fopen($randomness_path, 'r');
            $temp = unpack('Nint', fread($fp, 4));
            mt_srand($temp['int']);
            fclose($fp);
        } else {
            list($sec, $usec) = explode(' ', microtime());
            mt_srand((float) $sec + ((float) $usec * 100000));
        }
    }

    return mt_rand($min, $max);
}
?>