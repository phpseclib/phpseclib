# Changelog

## 1.0.20 - 2021-12-28

SFTP:
- speed up uploads (by changing SFTP upload packet size from 4KB to 32KB)
- add support for SFTPv4/5/6
- add enableDatePreservation() / disableDatePreservation() (#1496)
- uploads on low speed networks could get in infinite loop (#1507)
- "fix" rare resource not closed error (#1510)
- progress callback should report actual downloaded bytes (#1543)
- add stream to get method (#1546)
- fix undefined index notice in stream touch() (#1615)
- digit only filenames were converted to integers by php (#1623)
- Stream: make it so you can write past the end of a file (#1618)
- reopen channel on channel closure (#1654)
- don't check SFTP packet size after SFTP initialization (#1606)
- return false if get_channel_packet returns false (#1678)
- timeout during SFTP init should return false (#1684)
- add option to allow arbitrary length packets (#1691)

SSH2:
- add support for zlib and zlib@openssh.com compression
- add "smart multi factor" login mode (enabled by default) (#1648)
- don't try to login as none auth method for CoreFTP server (#1488)
- when building algo list look at if crypto engine is set (#1500)
- suppress 'broken pipe' errors (#1511)
- add setKeepAlive() method (#1529)
- behave like putty with broken publickey auth (#1572)
- don't close channel on unexpected response to channel request (#1631)
- add getAuthMethodsToContinue() method (#1648)
- fix issue with key re-exchange (#1644)
- fix PHP7.4 errors about accessing bool as string (#1656)
- end connection faster for algorithm mismatch

X509:
- really looong base64 encoded strings broke extractBER() (#1486)
- only parse the first cert of a multi-cert PEMs (#1542, #1568)

ASN1:
- fix timezone issue when non-utc time is given (#1562)
- return false when not enough bytes are available (#1676)

RSA:
- ssh-keygen -yf private.key fails if \r is present (#1698)

BigInteger:
- fix issue with toBits on 32-bit PHP 8 installs

Crypt/Base:
- use a custom error handler for mcrypt

## 1.0.19 - 2020-07-07

- SSH2: arcfour128 / arcfour256 were being included twice
- SSH2: make window resizing behave more consistently with PuTTY (#1421)
- SSH2: logging enhancements
- SSH2: try logging in with none as an auth method first (#1454)
- SFTP: change the mode with a SETSTAT instead of MKDIR (#1463)
- SFTP: make it so extending SFTP class doesn't cause a segfault (#1465)
- SFTP: realpath('') produced an error (#1474)
- SFTP: if /path/to/file is a file then /path/to/file/whatever errors (#1475)
- RSA: make PSS verification work for key length that aren't a power of 2 (#1423)
- ASN1: fix for malformed ASN1 strings (#1456)
- ANSI: fix "Number of elements can't be negative" error

## 1.0.18 - 2019-09-16

- SSH2: fix regression for connecting to servers with bad hostnames (#1405)

## 1.0.17 - 2019-09-15

- SSH2: backport setPreferredAlgorithms() / getAlgorithmsNegotiated (#1156)
- SSH2 / SFTP: fix issues with ping() (#1402)
- SSH2: only auto close the channel for exec() timeouts (#1384)
- SSH2 / SFTP: fix issues with ping() (#1402)
- SFTP: add progress callback to get() (#1375)
- SFTP: fix array_merge(): Argument #1 is not an array error (#1379)
- X509: IPs in nameconstraints extension include netmask (#1387)
- X509: fix issue with explicit time tags whose maps expect implicit (#1388)
- BigInteger: fix issues with divide method
- BigInteger: fix bug with toBytes() with fixed precision negative numbers
- fix PHP 7.4 deprecations

## 1.0.16 - 2019-06-13

- BigInteger: new BigInteger('-0') caused issues with GMP
- BigInteger: new BigInteger('00') caused issues with GMP
- BigInteger: GMP engine didn't always return 1 or -1
- ASN1: revamp how OIDs are handled (#1367)
- ASN1: correctly handle long tags
- SSH2: fix issue with reconnecting via ping() (#1353)
- SSH2: close channel when a timeout occurs (#1378)
- SFTP: improve handling of malformed packets (#1371)
- RSA: add support for OpenSSH private keys (#1372)
- RSA: use hash_equals if available

## 1.0.15 - 2019-03-10

- SFTP: make it so get() can correctly handle out of order responses (#1343)
- Crypt: avoid bogus IV errors in ECB mode with OpenSSL (#1087)
- RSA: protect against possible timing attack during OAEP decryption
- RSA: fix possible memory leak with XML keys (#1346)
- Hash: fix issues with the mode
- SCP: issue error if remote_file is empty in put() call (#1335)
- X509: whitelist OID 1.3.6.1.4.1.11129.2.4.2 (#1341)

## 1.0.14 - 2019-01-27

- SSH2: ssh-rsa is sometimes incorrectly used instead of rsa-sha2-256 (#1331)
- SSH2: more strictly adhere to RFC8332 for rsa-sha2-256/512 (#1332)

## 1.0.13 - 2018-12-16

- SSH2: fix order of user_error() / bitmap reset (#1314)
- SSH2: setTimeout(0) didn't work as intended (#1116)
- Agent: add support for rsa-sha2-256 / rsa-sha2-512 (#1319)
- Agent: add parameter to constructor (#1319)

## 1.0.12 - 2018-11-04

- SSH2: fixes relating to delayed global requests (#1271)
- SSH2: setEngine -> setPreferredEngine (#1294)
- SSH2: reset $this->bitmap when the connection fails (#1298)
- SSH2: add ping() method (#1298)
- SSH2: add support for rsa-sha2-256 / rsa-sha2-512 (RFC8332)
- SFTP: make rawlist give same result regardless of stat cache (#1287)
- Hash: save hashed keys for re-use

## 1.0.11 - 2018-04-15

- X509: auto download intermediate certs
- BigInteger: fix for (new BigInteger(48))->toString(true)) (#1264)
- ASN1: class is never set as key in _decode_ber

## 1.0.10 - 2018-02-08

- BigInteger: fix issue with bitwise_xor (#1245)
- Crypt: some of the minimum lengths were off
- SFTP: update stat cache accordingly when file becomes a directory (#1235)
- SFTP: fix issue with extended attributes on 64-bit PHP installs (#1248)
- SSH2: more channel handling updates (#1200)
- X509: use anonymous functions in PHP >= 5.3.0
- X509: revise logic for validateSignature (#1213)
- X509: fix 7.2 error when extensions were removed and new ones added (#1243)
- fix float to int conversions on ARM CPU's (#1220)

## 1.0.9 - 2017-11-29

- SSH2: fix issue with key re-exchange
- SSH2: updates to dealing with extraneous channel packets
- X509: URL validation didn't work (#1203)

## 1.0.8 - 2017-10-22

- SSH2:
  - add new READ_NEXT mode (#1140)
  - add sendIdentificationStringFirst()
  - add sendKEXINITFirst()
  - add sendIdentificationStringLast()
  - add sendKEXINITLast() (#1162)
  - assume any SSH server >= 1.99 supports SSH2 (#1170)
  - workaround for bad arcfour256 implementations (#1171)
  - don't choke when getting response from diff channel in exec() (#1167)
- SFTP:
  - add enablePathCanonicalization()
  - add disablePathCanonicalization() (#1137)
  - fix put() with remote file stream resource (#1177)
- ANSI: misc fixes (#1150, #1161)
- X509: use DateTime instead of unix time (#1166)
- Ciphers: use eval() instead of create_function() for >= 5.3

## 1.0.7 - 2017-06-05

- Crypt: fix OpenSSL engine on <= PHP 5.3.6 (#1122)
- Random: suppress possible E_DEPRECATED errors
- RSA: reset variables if bad key was loaded

## 1.0.6 - 2017-05-07

- SSH2: don't use timeout value of 0 for fsockopen (#775)
- SSH2: make it so disabling PTY closes exec() channel if it's open (#1009)
- SSH2: include `<pre>` tags in getLog result when SAPI isn't CLI
- SFTP: don't assume current directory when $path parameter for delete is null (#1059)
- SFTP: fix put() with php://input as source (#1119)
- ASN1: fix UTCTime parsing (#1110)
- X509: ignore certificate transparency extension (#1073)
- Crypt: OpenSSL apparently supports variable size keys (#1085)

## 1.0.5 - 2016-10-22

- fix issue preventing installation of 1.0.x via Composer (#1048)

## 1.0.4 - 2016-10-03

- fix E_DEPRECATED errors on PHP 7.0 and 7.1 (#1041)
- fix float to int conversions on 32-bit Linux pre-PHP 5.3 (#1038, #1034)
- SFTP: speed up downloads (#945)
- SFTP: fix infinite loop when uploading empty file (#995)
- ASN1: fix possible infinite loop in decode (#1027)

## 1.0.3 - 2016-08-18

- BigInteger/RSA: don't compare openssl versions > 1.0 (#946)
- RSA: don't attempt to use the CRT when zero value components exist (#980)
- RSA: zero salt length RSA signatures don't work (#1002)
- ASN1: fix PHP Warning on PHP 7.1 (#1013)
- X509: set parameter fields to null for CSR's / RSA (#914)
- CRL optimizations (#1000)
- SSH2: fix "Expected SSH_FXP_STATUS or ..." error (#999)
- SFTP: make symlinks support relative target's (#1004)
- SFTP: fix sending stream resulting in zero byte file (#995)

## 1.0.2 - 2016-05-07

- All Ciphers: fix issue with CBC mode / OpenSSL / continuous buffers / decryption (#938)
- Random: fix issues with serialize() (#932)
- RC2: fix issue with decrypting
- RC4: fix issue with key not being truncated correctly
- SFTP: nlist() on a non-existent directory resulted in error
- SFTP: add is_writable, is_writeable, is_readable
- RSA: fix PHP4 compatibility issue

## 1.0.1 - 2016-01-18

- RSA: fix regression in PSS mode ([#769](https://github.com/phpseclib/phpseclib/pull/769))
- RSA: fix issue loading PKCS8 specific keys ([#861](https://github.com/phpseclib/phpseclib/pull/861))
- X509: add getOID() method ([#789](https://github.com/phpseclib/phpseclib/pull/789))
- X509: improve base64-encoded detection rules ([#855](https://github.com/phpseclib/phpseclib/pull/855))
- SFTP: fix quirky behavior with put() ([#830](https://github.com/phpseclib/phpseclib/pull/830))
- SFTP: fix E_NOTICE ([#883](https://github.com/phpseclib/phpseclib/pull/883))
- SFTP/Stream: fix issue with filenames with hashes ([#901](https://github.com/phpseclib/phpseclib/pull/901))
- SSH2: add isAuthenticated() method ([#897](https://github.com/phpseclib/phpseclib/pull/897))
- SSH/Agent: fix possible PHP warning ([#923](https://github.com/phpseclib/phpseclib/issues/923))
- BigInteger: add __debugInfo() magic method ([#881](https://github.com/phpseclib/phpseclib/pull/881))
- BigInteger: fix issue with doing bitwise not on 0
- add getBlockLength() method to symmetric ciphers

## 1.0.0 - 2015-08-02

- OpenSSL support for symmetric ciphers ([#507](https://github.com/phpseclib/phpseclib/pull/507))
- rewritten vt100 terminal emulator (File_ANSI) ([#689](https://github.com/phpseclib/phpseclib/pull/689))
- agent-forwarding support (System_SSH_Agent) ([#592](https://github.com/phpseclib/phpseclib/pull/592))
- Net_SSH2 improvements
  - diffie-hellman-group-exchange-sha1/sha256 support ([#714](https://github.com/phpseclib/phpseclib/pull/714))
  - window size handling updates ([#717](https://github.com/phpseclib/phpseclib/pull/717))
- Net_SFTP improvements
  - add callback support to put() ([#655](https://github.com/phpseclib/phpseclib/pull/655))
  - stat cache fixes ([#743](https://github.com/phpseclib/phpseclib/issues/743), [#730](https://github.com/phpseclib/phpseclib/issues/730), [#709](https://github.com/phpseclib/phpseclib/issues/709), [#726](https://github.com/phpseclib/phpseclib/issues/726))
- add "none" encryption mode to Crypt_RSA ([#692](https://github.com/phpseclib/phpseclib/pull/692))
- misc ASN.1 / X.509 parsing fixes ([#721](https://github.com/phpseclib/phpseclib/pull/721), [#627](https://github.com/phpseclib/phpseclib/pull/627))
- use a random serial number for new X509 certs ([#740](https://github.com/phpseclib/phpseclib/pull/740))
- add getPublicKeyFingerprint() to Crypt_RSA ([#677](https://github.com/phpseclib/phpseclib/pull/677))

## 0.3.10 - 2015-02-04

- simplify SSH2 window size handling ([#538](https://github.com/phpseclib/phpseclib/pull/538))
- slightly relax the conditions under which OpenSSL is used ([#598](https://github.com/phpseclib/phpseclib/pull/598))
- fix issue with empty constructed context-specific tags in ASN1 ([#606](https://github.com/phpseclib/phpseclib/pull/606))

## 0.3.9 - 2014-11-09

- PHP 5.6 improvements ([#482](https://github.com/phpseclib/phpseclib/pull/482), [#491](https://github.com/phpseclib/phpseclib/issues/491))

## 0.3.8 - 2014-09-12

- improve support for indef lengths in File_ASN1
- add hmac-sha2-256 support to Net_SSH2
- make it so negotiated algorithms can be seen before Net_SSH2 login
- add sha256-96 and sha512-96 to Crypt_Hash
- window size handling adjustments in Net_SSH2

## 0.3.7 - 2014-07-05

- auto-detect public vs private keys
- add file_exists, is_dir, is_file, readlink and symlink to Net_SFTP
- add support for recursive nlist and rawlist
- make it so nlist and rawlist can return pre-sorted output
- make it so callback functions can make exec() return early
- add signSPKAC and saveSPKAC methods to File_X509
- add support for PKCS8 keys in Crypt_RSA
- add pbkdf1 support to setPassword() in Crypt_Base
- add getWindowColumns, getWindowRows, setWindowColumns, setWindowRows to Net_SSH2
- add support for filenames with spaces in them to Net_SCP

## 0.3.6 - 2014-02-23

- add preliminary support for custom SSH subsystems
- add ssh-agent support

## 0.3.5 - 2013-07-11

- numerous SFTP changes:
  - chown
  - chgrp
  - truncate
  - improved file type detection
  - put() can write to the middle of a file
  - mkdir accepts the same parameters that PHP's mkdir does
  - the ability to upload/download 2GB files
- across-the-board speedups for the various encryption algorithms
- multi-factor authentication support for Net_SSH2
- a $callback parameter for Net_SSH2::exec
- new classes:
  - Net_SFTP_StreamWrapper
  - Net_SCP
  - Crypt_Twofish
  - Crypt_Blowfish

## 0.3.1 - 2012-11-20

- add Net_SSH2::enableQuietMode() for suppressing stderr
- add Crypt_RSA::__toString() and Crypt_RSA::getSize()
- fix problems with File_X509::validateDate(), File_X509::sign() and Crypt_RSA::verify()
- use OpenSSL to speed up modular exponention in Math_BigInteger
- improved timeout functionality in Net_SSH2
- add support for SFTPv2
- add support for CRLs in File_X509
- SSH-2.0-SSH doesn't implement hmac-*-96 correctly

## 0.3.0 - 2012-07-08

- add support for reuming Net_SFTP::put()
- add support for recursive deletes and recursive chmods to Net_SFTP
- add setTimeout() to Net_SSH2
- add support for PBKDF2 to the various Crypt_* classes via setPassword()
- add File_X509 and File_ASN1
- add the ability to decode various formats in Crypt_RSA
- make Net_SSH2::getServerPublicHostKey() return a printer-friendly version of the public key

## 0.2.2 - 2011-05-09

- CFB and OFB modes were added to all block ciphers
- support for interactive mode was added to Net_SSH2
- Net_SSH2 now has limited keyboard_interactive authentication support
- support was added for PuTTY formatted RSA private keys and XML formatted RSA private keys
- Crypt_RSA::loadKey() will now try all key types automatically
- add support for AES-128-CBC and DES-EDE3-CFB encrypted RSA private keys
- add Net_SFTP::stat(), Net_SFTP::lstat() and Net_SFTP::rawlist()
- logging was added to Net_SSH1
- the license was changed to the less restrictive MIT license
