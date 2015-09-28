<?php
namespace Jagger\oidc;
use phpseclib;

class Jwk
{

    var $components = array();

    public function __construct($components = array()) {
        if (!array_key_exists('kty', $components)) {
            throw new \Exception('"kty" is required');
        }
        $this->components = $components;

    }

    public function toKey() {

        switch ($this->components['kty']) {
            case 'RSA':
                $rsa = new phpseclib\Crypt\RSA();
                $modulus = new phpseclib\Math\BigInteger('0x' . bin2hex(self::base64UrlDecode($this->components['n'])), 16);
                $exponent = new phpseclib\Math\BigInteger('0x' . bin2hex(self::base64UrlDecode($this->components['e'])), 16);
                if (array_key_exists('d', $this->components)) {
                    throw new \Exception('RSA private key isn\'t supported');
                } else {
                    $pemStr = $rsa->_convertPublicKey($modulus, $exponent);
                }
                $rsa->loadKey($pemStr);
                return $rsa;
            case 'EC':
                throw new \Exception('Elliptic Curve not supported');
            default:
                throw new \Exception('ffff');
        }
    }


    public function toString()
    {
        return json_encode($this->components);

    }
    public function __toString()
    {
        return $this->toString();
    }


    public static function base64UrlDecode($input) {
        return base64_decode(strtr($input, '-_,', '+/='));
    }


}
