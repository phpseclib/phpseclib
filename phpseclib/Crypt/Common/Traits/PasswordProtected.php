<?php

/**
 * Password Protected Trait for Private Keys
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\Common\Traits;

/**
 * Password Protected Trait for Private Keys
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
trait PasswordProtected
{
    /**
     * @var string|null
     */
    private $password = null;

    /**
     * Sets the password
     *
     * Private keys can be encrypted with a password.  To unset the password, pass in the empty string or false.
     * Or rather, pass in $password such that empty($password) && !is_string($password) is true.
     *
     * @see self::createKey()
     * @see self::load()
     *
     * @return static
     */
    public function withPassword(#[SensitiveParameter] ?string $password = null): self
    {
        $new = clone $this;
        $new->password = $password;
        return $new;
    }

    public function withoutPassword(): self
    {
        return $this->withPassword();
    }

    public function hasPassword(): bool
    {
        return isset($this->password);
    }
}
