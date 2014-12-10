<?php
/**
 * Pure-PHP ASN.1 Parser
 *
 * PHP versions 4 and 5
 *
 * @category  File
 * @package   File_ASN1
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2012 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

/**
 * ASN.1 Element
 *
 * Bypass normal encoding rules in File_ASN1::encodeDER()
 *
 * @package File_ASN1
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class File_ASN1_Element
{
    /**
     * Raw element value
     *
     * @var String
     * @access private
     */
    var $element;

    /**
     * Constructor
     *
     * @param String $encoded
     * @return File_ASN1_Element
     * @access public
     */
    function __construct($encoded)
    {
        $this->element = $encoded;
    }
}
