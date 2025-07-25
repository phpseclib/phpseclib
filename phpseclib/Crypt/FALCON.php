<?php

declare(strict_types=1);

namespace phpseclib3\Crypt;

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\FALCON\PrivateKey;
use phpseclib3\Crypt\FALCON\PublicKey;
use phpseclib3\Exception\UnsupportedAlgorithmException;

abstract class FALCON extends AsymmetricKey
{
    public const ALGORITHM = 'FALCON';

    protected string $pem;

    protected function __construct()
    {
        parent::__construct();
        $this->hash = new Hash('sha512');
    }

    protected static function onLoad(array $components)
    {
        $key = $components['isPublicKey'] ?
            new PublicKey() :
            new PrivateKey();

        if (isset($components['pem'])) {
            $key->pem = $components['pem'];
        }

        return $key;
    }

    public function withHash(string $hash): AsymmetricKey
    {
        if ($hash != 'sha512') {
            throw new UnsupportedAlgorithmException('Post-quantum algorithm only supports sha512 as a hash');
        }

        return parent::withHash($hash);
    }
}
