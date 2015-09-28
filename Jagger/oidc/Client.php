<?php
namespace Jagger\oidc;

use Lcobucci;

class Client
{
    private $sessionFlowId = 'joidc';

    private $clientSecret;
    private $clientID;
    private $clientName;
    private $rpRedirectURL;
    private $opConfig = array();
    private $scopes = array('openid');
    protected $configuration;
    protected $jwks;
    protected $authzparams = array();
    const OPCONFURI = '/.well-known/openid-configuration';


    public function __construct(array $openidconf = null) {
        if (is_array($openidconf)) {
            $this->opConfig = $openidconf;
        }

    }

    public function setProviderURL($opURL) {
        $this->opConfig['issuer'] = $opURL;
        $_SESSION['joidc_issuer'] = $opURL;
    }

    public function setClientSecret($clientSecret) {
        $this->clientSecret = $clientSecret;
    }

    public function setClientID($clientID) {
        $this->clientID = $clientID;
    }

    public function generateRandStr() {
        $randstr = sha1(openssl_random_pseudo_bytes(1024));
        return $randstr;
    }

    /**
     * @param array $params
     */
    public function addAuthzParams(array $params) {
        $this->authzparams = array_merge($params);
    }

    public function getAutzParams() {
        return $this->authzparams;
    }

    public function addScope($scope) {
        $this->scopes = array_merge($this->scopes, (array)$scope);
        $this->scopes = array_unique($this->scopes);
    }

    public function setRedirectURL($url) {
        if (filter_var($url, FILTER_VALIDATE_URL) !== false) {
            $this->rpRedirectURL = $url;
        }
    }


    public function getProviderURL() {
        if (!isset($this->opConfig['issuer'])) {
            throw new \Exception('The provider URL has not been set');
        } else {
            return $this->opConfig['issuer'];
        }
    }

    public function getScopes() {
        return $this->scopes;
    }

    public function getOPConfigValue($param) {
        if (!isset($this->opConfig['' . $param . ''])) {
            $wellKnownConfigUrl = rtrim($this->getProviderURL(), '/') . self::OPCONFURI;
            $value = json_decode($this->runHttpRequest($wellKnownConfigUrl), null)->{$param};
            if ($value) {
                $this->opConfig[$param] = $value;
            } else {
                throw new \Exception('The provider .well-known URL not found');
            }

        }
        return $this->opConfig[$param];
    }

    public function getOPConfiguration() {

    }

    public function getRedirectURL() {
        return $this->rpRedirectURL;
    }


    public function setOnceSession($once = null) {
        if ($once === null) {
            $once = $this->generateRandStr();
        }
        $_SESSION['joidc_once'] = $once;
    }

    public function setStateSession($state = null) {
        if ($state === null) {
            $state = $this->generateRandStr();
        }
        $_SESSION['joidc_state'] = $state;
    }

    private function getStateSession() {
        if (!isset($_SESSION['joidc_state'])) {
            $this->setStateSession();
        }
        return $_SESSION['joidc_state'];
    }

    private function getOnceSession() {
        if (!isset($_SESSION['joidc_once'])) {
            $this->setOnceSession();
        }
        return $_SESSION['joidc_once'];
    }

    private function getLoginHint() {
        return null;
    }


    public function generateAuthzRequest($responseType = 'code') {
        $issuerURL = $this->getProviderURL();
        $authzURL = $this->getOPConfigValue('authorization_endpoint');
        $params = array(
            'client_id' => $this->clientID,
            'response_type' => $responseType,
            'scope' => '' . implode(' ', $this->getScopes()) . '',
            'redirect_uri' => $this->getRedirectURL(),
            'state' => $this->getStateSession(),
            'once' => $this->getOnceSession(),
            'login_hint' => $this->getLoginHint()
        );
        $params = array_merge($params, $this->getAutzParams());
        $url = $authzURL . '?' . http_build_query($params, null, '&');
        return $url;

    }


    private function runHttpRequest($url, $postBody = null) {
        $curl = curl_init();
        if ($postBody != null) {
            curl_setopt($curl, CURLOPT_POST, 1);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $postBody);
            $content_type = 'application/x-www-form-urlencoded';
            if (is_object(json_decode($postBody))) {
                $content_type = 'application/json';
            }
            curl_setopt($curl, CURLOPT_HTTPHEADER, array(
                "Content-Type: {$content_type}",
                'Content-Length: ' . strlen($postBody)
            ));
        }
        curl_setopt($curl, CURLOPT_URL, $url);
        if (isset($this->httpProxy)) {
            curl_setopt($curl, CURLOPT_PROXY, $this->httpProxy);
        }
        curl_setopt($curl, CURLOPT_HEADER, 0);
        if (isset($this->certPath)) {
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($curl, CURLOPT_CAINFO, $this->certPath);
        } else {
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        }
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 15);
        $output = curl_exec($curl);
        if (curl_exec($curl) === false) {
            throw new \Exception('Curl error: ' . curl_error($curl));
        }
        curl_close($curl);
        return $output;
    }

    public function redirect($url) {
        header('Location: ' . $url);
        exit;
    }


    public function authenticate() {
        // parse response
        $code = null;
        $state = null;

        if (isset($_GET['error'])) {
            throw new \Exception('Response from Authorization Server: ' . $_GET['error']);
        }

        if (isset($_GET['code'])) {
            $code = $_GET['code'];
        }
        if (isset($_GET['state'])) {
            $state = $_GET['state'];
        }
        $existingState = $this->getStateSession();
        if ($existingState !== $state) {
            throw new \Exception('Broken authorization flow - state mismatch');
        }
        if ($code === null) {
            throw new \Exception('"code" param has not been received from Authorization Server');
        }
        $authorizationCode = $this->requestTokens($code);
        if (isset($authorizationCode->error)) {
            throw new \Exception($authorizationCode->error_description);
        }
        if (!isset($authorizationCode->id_token)) {
            throw new \Exception('id_token has not been received from Authorization Server');
        }
        $tmpimpl = count(explode('.', $authorizationCode->id_token));
        if ($tmpimpl != 3 && $tmpimpl != 5) {
            throw new \Exception('Incorrect id_token received from Authorization Server');
        }
        if ($tmpimpl == 5) {
            throw new \Exception('Encrypted JWT is not supported yet');
        }


        $parser = new Lcobucci\JWT\Parser();
        $token = $parser->parse($authorizationCode->id_token);
        $alg = $token->getHeader('alg');
        if ($alg !== 'RS256') {
            throw new \Exception('Only alg RS256 is accepted');
        }
        $kid = $token->getHeader('kid');

        $validationData = new Lcobucci\JWT\ValidationData();

        $validationData->setIssuer($this->getProviderURL());
        $validationData->setAudience($this->clientID);

        $isValidToken = $token->validate($validationData);
        if (!$isValidToken) {
            throw new \Exception('Received "id_token" is not valid - propbably expired');
        }
        // verify sig

        $jwks_uri = $this->getOPConfigValue('jwks_uri');
        $jwks_body = $this->runHttpRequest($jwks_uri);

        $this->jwks = json_decode($jwks_body, true);

        if (!is_array($this->jwks) || !array_key_exists('keys', $this->jwks)) {
            throw new \Exception('JWKS not found, cannot verify signature');
        }

        $keyVer = null;
        foreach ($this->jwks['keys'] as $key => $val) {

            if ($val['kid'] === $kid && $val['use'] === 'sig') {
                $keyVer = $this->jwks['keys'][$key];
                break;
            }

        }
        if ($keyVer === null) {
            throw new \Exception('JWK not found, cannot verify signature');
        }

        $jwkObj = new Jwk($keyVer);

        $signer = new Lcobucci\JWT\Signer\Rsa\Sha256();
        $keychain = new Lcobucci\JWT\Signer\Keychain();
        $sigValid = $token->verify($signer, $keychain->getPublicKey($jwkObj->toKey()));

        if ($sigValid !== true) {
            throw new \Exception('Received "id_token" is not valid. Signature validation failed');
        }
        /**
         * @var Lcobucci\JWT\Claim\Basic[] $claimsObj
         */
        $claimsObj = $token->getClaims();
        $claims = array();
        foreach ($claimsObj as $cl) {

            if ($cl instanceof Lcobucci\JWT\Claim\Basic) {
                $claims['' . $cl->getName() . ''] = $cl->getValue();
            }

        }
        $claims['iss'] = $token->getClaim('iss');
        unset($_SESSION['joidc_once']);
        unset($_SESSION['joidc_state']);
        unset($_SESSION['joidc_issuer']);
        return $claims;

    }


    private function requestTokens($code) {
        $tokenEndpoint = $this->getOPConfigValue('token_endpoint');
        $token_params = array(
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->getRedirectURL(),
            'client_id' => $this->clientID,
            'client_secret' => $this->clientSecret
        );
        // Convert token params to string format
        $token_params = http_build_query($token_params, null, '&');
        return json_decode($this->runHttpRequest($tokenEndpoint, $token_params));
    }


    private function urlsafeB64Decode($input) {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    private function urlsafeB64Encode($input) {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }
}
