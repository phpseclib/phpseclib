<?php

namespace phpseclib\Net;

use phpseclib\Common\Enum;

class SSH_OPEN extends Enum
{
    const ADMINISTRATIVELY_PROHIBITED = 1;
    const CONNECT_FAILED              = 2;
    const UNKNOWN_CHANNEL_TYPE        = 3;
    const RESOURCE_SHORTAGE           = 4;
}
