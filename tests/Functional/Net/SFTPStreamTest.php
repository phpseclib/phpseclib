<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2015 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

// Registers sftp:// as a side effect.
require_once 'Net/SFTP/Stream.php';

class Functional_Net_SFTPStreamTest extends Functional_Net_SFTPTestCase
{
    public function testFopenFcloseCreatesFile()
    {
        $context = stream_context_create(array(
            'sftp' => array('session' => $this->sftp),
        ));
        $fp = fopen($this->buildUrl('fooo.txt'), 'wb', false, $context);
        $this->assertTrue(is_resource($fp));
        fclose($fp);
        $this->assertSame(0, $this->sftp->size('fooo.txt'));
    }

    /**
     * @group github778
     */
    public function testFilenameWithHash()
    {
        $context = stream_context_create(array(
            'sftp' => array('session' => $this->sftp),
        ));
        $fp = fopen($this->buildUrl('te#st.txt'), 'wb', false, $context);
        fputs($fp, 'zzzz');
        fclose($fp);

        $this->assertTrue(in_array('te#st.txt', $this->sftp->nlist()));
    }

    protected function buildUrl($suffix)
    {
        return sprintf(
            'sftp://via-context/%s/%s',
            $this->sftp->pwd(),
            $suffix
        );
    }
}
