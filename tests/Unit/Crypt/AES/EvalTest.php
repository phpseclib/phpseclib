<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\AES;

class EvalTest extends TestCase
{
    protected function setUp(): void
    {
        $this->engine = 'Eval';
    }
}
