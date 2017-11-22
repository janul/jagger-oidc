<?php

namespace Jagger\oidc;

use Lcobucci;

class Client extends Lcobucci\JWT\Token
{
    private $sessionFlowId = 'joidc';

    private $clientSecret;
    private $clientID;
    private $clientName;
    private $rpRedirectURL;
    private $opConfig = array();
    private $scopes = array('openid');
    private $claimsRequest = array();
    private $access_token;
    protected $configuration;
    protected $jwks;
    protected $authzparams = array();
    const OPCONFURI = '/.well-known/openid-configuration';


    public function __construct(array $openidconf = null)
    {
        if (is_array($openidconf)) {
            $this->opConfig = $openidconf;
        }

    }

    public function setProviderURL($opURL)
    {
        $this->opConfig['issuer'] = $opURL;
        $_SESSION['joidc_issuer'] = $opURL;
    }

    public function setClientSecret($clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    public function setClientID($clientID)
    {
        $this->clientID = $clientID;
    }

    public function generateRandStr()
    {
        $randstr = sha1(openssl_random_pseudo_bytes(1024));
        return $randstr;
    }

    /**
     * @param array $params
     */
    public function addAuthzParams(array $params)
    {
        $this->authzparams = array_merge($params);
    }

    public function getAutzParams()
    {
        return $this->authzparams;
    }

    public function addScope($scope)
    {
        $this->scopes = array_merge($this->scopes, (array)$scope);
        $this->scopes = array_unique($this->scopes);
    }


    public function setClaimRequest($claims){
        $this->claimsRequest = $claims;
    }


    public function setRedirectURL($url)
    {
        if (filter_var($url, FILTER_VALIDATE_URL) !== false) {
            $this->rpRedirectURL = $url;
        }
    }


    public function getProviderURL()
    {
        if (!isset($this->opConfig['issuer'])) {
            throw new \Exception('The provider URL has not been set');
        } else {
            return $this->opConfig['issuer'];
        }
    }

    public function getScopes()
    {
        return $this->scopes;
    }
    public function getClaimRequest(){
        return $this->claimsRequest;
    }

    public function getOPConfigValue($param)
    {
        if (!isset($this->opConfig['' . $param . ''])) {
            $wellKnownConfigUrl = rtrim($this->getProviderURL(), '/') . self::OPCONFURI;
            $value = json_decode($this->runHttpRequest($wellKnownConfigUrl, array(), null), null)->{$param};
            if ($value) {
                $this->opConfig[$param] = $value;
            } else {
                throw new \Exception('The provider .well-known URL not found');
            }

        }
        return $this->opConfig[$param];
    }

    public function getOPConfiguration()
    {

    }

    public function getRedirectURL()
    {
        return $this->rpRedirectURL;
    }


    public function setOnceSession($once = null)
    {
        if ($once === null) {
            $once = $this->generateRandStr();
        }
        $_SESSION['joidc_once'] = $once;
    }

    public function setStateSession($state = null)
    {
        if ($state === null) {
            $state = $this->generateRandStr();
        }
        $_SESSION['joidc_state'] = $state;
    }

    private function getStateSession()
    {
        if (!isset($_SESSION['joidc_state'])) {
            $this->setStateSession();
        }
        return $_SESSION['joidc_state'];
    }

    private function getOnceSession()
    {
        if (!isset($_SESSION['joidc_once'])) {
            $this->setOnceSession();
        }
        return $_SESSION['joidc_once'];
    }

    private function getLoginHint()
    {
        return null;
    }


    public function generateAuthzRequest($responseType = 'code')
    {
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
        $claimsParams = '';

        $claimRequests = $this->getClaimRequest();


        if(count($claimRequests)>0){
            $claimsParams = 'claims='.json_encode($claimRequests);
        }
        $params = array_merge($params, $this->getAutzParams());
        $url = $authzURL . '?' . http_build_query($params, null, '&');
        return $url.'&'.$claimsParams;

    }


    /**
     * @param $url
     * @param array $headers
     * @param $postBody
     * @return mixed
     * @throws \Exception
     */
    private function runHttpRequest($url, array $headers, $postBody)
    {
        $inHeaders = array();
        $curl = curl_init();
        if ($postBody !== null) {
            curl_setopt($curl, CURLOPT_POST, 1);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $postBody);
            $content_type = 'application/x-www-form-urlencoded';
            if (is_object(json_decode($postBody))) {
                $content_type = 'application/json';
            }
            $inHeaders = array(
                "Content-Type: {$content_type}",
                'Content-Length: ' . strlen($postBody),
            );
        }
        foreach ($headers as $k => $v) {
            $inHeaders[] = trim('' . $k . ': ' . $v . '');
        }
        curl_setopt($curl, CURLOPT_HTTPHEADER, $inHeaders);
        curl_setopt($curl, CURLOPT_URL, $url);
        if (isset($this->httpProxy)) {
            curl_setopt($curl, CURLOPT_PROXY, $this->httpProxy);
        }

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

    public function redirect($url)
    {
        header('Location: ' . $url);
        exit;
    }


    public function authenticate()
    {
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
        $token = $this->requestTokens($code);

        if (isset($token->error)) {
            throw new \Exception($token->error_description);
        }
        if(!isset($token->access_token)){
             throw new \Exception('access_token has not been received from Authorization Server');
        }
        if (!isset($token->id_token)) {
            throw new \Exception('id_token has not been received from Authorization Server');
        }
        $tmpimpl = count(explode('.', $token->id_token));
        if ($tmpimpl != 3 && $tmpimpl != 5) {
            throw new \Exception('Incorrect id_token received from Authorization Server');
        }
        if ($tmpimpl == 5) {
            throw new \Exception('Encrypted JWT is not supported yet');
        }



        $parser = new Lcobucci\JWT\Parser();
        $id_token = $parser->parse($token->id_token);
        $this->access_token = $token->access_token;




        $alg = $id_token->getHeader('alg');

        if ($alg !== 'RS256') {
            throw new \Exception('Only alg RS256 is accepted');
        }
        $kid = null;
        try {
            $kid = $id_token->getHeader('kid');
        } catch (\OutOfBoundsException $e) {
            log_message('debug', 'kid not found');
        }


        /**
         * need to use sleep 1 sec; third lib using (int) to compare iat claim
         */
        sleep(1);
        $validationData = new Lcobucci\JWT\ValidationData();

        $validationData->setIssuer($this->getProviderURL());
        //$validationData->setAudience($this->clientID);
        /**
         * @todo workournd about aud
         */

        $isValidToken = $id_token->validate($validationData);

        if (!$isValidToken) {
            throw new \Exception('Received "id_token" is not valid - propbably expired');
        }
        // verify sig

        $jwks_uri = $this->getOPConfigValue('jwks_uri');
        $jwks_body = $this->runHttpRequest($jwks_uri, array(), null);

        $this->jwks = json_decode($jwks_body, true);

        if (!is_array($this->jwks) || !array_key_exists('keys', $this->jwks)) {
            throw new \Exception('JWKS not found, cannot verify signature');
        }

        $keyVer = null;
        if ($kid !== null) {
            foreach ($this->jwks['keys'] as $key => $val) {

                if (isset($val['kid']) && $val['kid'] === $kid && $val['use'] === 'sig') {
                    $keyVer = $this->jwks['keys'][$key];
                    break;
                }

            }
        } else {
            foreach ($this->jwks['keys'] as $key => $val) {
                /**
                 * use first found sig
                 */
                if (isset($val['use']) && $val['use'] === 'sig') {
                    $keyVer = $this->jwks['keys'][$key];
                    break;
                }
            }
        }

        if ($keyVer === null) {
            throw new \Exception('JWK not found, cannot verify signature');
        }

        $jwkObj = new Jwk($keyVer);

        $signer = new Lcobucci\JWT\Signer\Rsa\Sha256();
        $keychain = new Lcobucci\JWT\Signer\Keychain();
        $sigValid = $id_token->verify($signer, $keychain->getPublicKey($jwkObj->toKey()));

        if ($sigValid !== true) {
            throw new \Exception('Received "id_token" is not valid. Signature validation failed');
        }
        /**
         * @var Lcobucci\JWT\Claim\Basic[] $claimsObj
         */
        $claimsObj = $id_token->getClaims();
        $claims = array();
        foreach ($claimsObj as $cl) {

            if ($cl instanceof Lcobucci\JWT\Claim\Basic) {
                $claims['' . $cl->getName() . ''] = $cl->getValue();
            }

        }
        $claims['iss'] = $id_token->getClaim('iss');
        unset($_SESSION['joidc_once']);
        unset($_SESSION['joidc_state']);
        unset($_SESSION['joidc_issuer']);


        return $claims;

    }


    private function requestTokens($code)
    {
        $tokenEndpoint = $this->getOPConfigValue('token_endpoint');
        $authMethod = 'client_secret_basic';
        $authMethodConf = $this->getOPConfigValue('token_endpoint_auth_methods_supported');
        if (!is_array($authMethodConf)) {
            $authMethod = 'client_secret_basic';
        } elseif (!in_array($authMethod, $authMethodConf, true) && in_array('client_secret_post', $authMethodConf, true)) {

            $authMethod = 'client_secret_post';
        }


        if ($authMethod === 'client_secret_post') {
            $token_params = array(
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->getRedirectURL(),
                'client_id' => $this->clientID,
                'client_secret' => $this->clientSecret
            );
            $headers = array();
        } else {
            $token_params = array(
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->getRedirectURL(),
                'client_id' => $this->clientID
            );
            $headers = array('Authorization' => 'Basic ' . $this->urlsafeB64Encode($this->clientID . ':' . $this->clientSecret) . '');
        }

        // Convert token params to string format
        $token_params = http_build_query($token_params, null, '&');
        return json_decode($this->runHttpRequest($tokenEndpoint, $headers, $token_params));
    }

    public function requestUserinfo(){
        $url = $this->getOPConfigValue('userinfo_endpoint');
        log_message('debug','Bearer: '.$this->access_token);
        $headers = array(
            'Authorization' => 'Bearer '. $this->access_token.'',
        );
        return json_decode($this->runHttpRequest($url, $headers, null));



    }


    private function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    private function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }
}
