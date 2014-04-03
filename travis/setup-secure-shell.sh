#!/bin/sh
#
# This file is part of the phpseclib project.
#
# (c) Andreas Fischer <bantu@phpbb.com>
#
# For the full copyright and license information, please view the LICENSE
# file that was distributed with this source code.
#
set -e
set -x

USERNAME='phpseclib'
PASSWORD='EePoov8po1aethu2kied1ne0'

sudo useradd --create-home --base-dir /home "$USERNAME"
echo "$USERNAME:$PASSWORD" | sudo chpasswd
