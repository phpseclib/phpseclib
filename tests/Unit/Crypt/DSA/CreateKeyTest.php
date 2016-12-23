<?php

/**
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\DSA;

/**
 * @requires PHP 7.0
 */
class Unit_Crypt_DSA_CreateKeyTest extends PhpseclibTestCase
{
    public function testCreateParameters()
    {
        $dsa = DSA::createParameters();
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $dsa);
        $this->assertRegexp('#BEGIN DSA PARAMETERS#', "$dsa");

        $dsa = DSA::createParameters(100, 100);
        $this->assertFalse($dsa);

        $dsa = DSA::createParameters(512, 160);
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $dsa);
        $this->assertRegexp('#BEGIN DSA PARAMETERS#', "$dsa");

        return $dsa;
    }

    /**
     * @depends testCreateParameters
     */
    public function testCreateKey($params)
    {
        extract(DSA::createKey());
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $privatekey);
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $publickey);

        extract(DSA::createKey($params));
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $privatekey);
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $publickey);

        extract(DSA::createKey(512, 160));
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $privatekey);
        $this->assertInstanceOf('\phpseclib\Crypt\DSA', $publickey);
    }
}

