<?php

namespace phpseclib\File\ASN1;

/**
 * ASN.1 Element
 *
 * Bypass normal encoding rules in File\ASN1::encodeDER()
 *
 * @package File\ASN1
 * @author  Jim Wigginton <terrafrost@php.net>
 * @version 0.3.0
 * @access  public
 */
class Element
{
    /**
     * Raw element value
     *
     * @var String
     * @access private
     */
    private $element;

    /**
     * Constructor
     *
     * @param String $encoded
     * @return File\ASN1\Element
     * @access public
     */
    public function __construct($encoded)
    {
        $this->element = $encoded;
    }
}