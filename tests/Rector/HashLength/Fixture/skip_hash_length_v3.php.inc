<?php

use phpseclib3\Crypt\Hash;

class aleadyV3Class
{
    public function v3()
    {
        $hash = new Hash('sha512');
        echo $hash->getLengthInBytes();
    }
}

?>
