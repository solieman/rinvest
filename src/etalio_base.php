<?php
namespace Etalio;
require_once('etalio_api_exception.php');

if (!function_exists('curl_init')) {
  throw new Exception('Etalio needs the CURL PHP extension.');
}
if (!function_exists('json_decode')) {
  throw new Exception('Etalio needs the JSON PHP extension.');
}


/**
 * Provides access to the Etalio Platform.  This class provides
 * a majority of the functionality needed for handshaking, but the class is abstract
 * because it is designed to be sub-classed.  The subclass must
 * implement the four abstract methods listed at the bottom of
 * the file.
 */
abstract class EtalioBase
{
  /**
   * Server Url
   */
  const BASE_URL = "https://api-etalio.3fs.si";

  /**
   * Version of this SDK
   */
  const VERSION = '0.3.0';

  /**
   * The string to look for when an access token has expired
   */
  const EXPIRED_ACCESS_TOKEN_STRING = 'The access token provided has expired';

  /**
   * Default options for curl.
   *
   * @var Array
   */
  protected $curlOpts;

  /**
   * Maps aliases to Etalio domains.
   *
   * @var Array
   */
  protected $domainMap;
  /**
   * The Application ID.
   *
   * @var string
   */
  protected $appId;

  /**
   * The Application App Secret.
   *
   * @var string
   */
  protected $appSecret;

  /**
   * A CSRF state variable to assist in the defense against CSRF attacks.
   *
   * @var string
   */
  protected $state;

  /**
   * The OAuth access_token received in exchange for a valid authorization code.
   *
   * @var string
   */
  protected $accessToken;

  /**
   * The refreshtoken that can be exchanged for a valid access_token
   *
   * @var string
   */
  protected $refreshToken;

  /**
   * The uri that handles callbacks from OAuth
   *
   * @var string
   */
  protected $redirectUri;

  /**
   * If debug functions should be activated
   *
   * @var bool
   */
  protected $debug = false;

  /**
   * Initialize a Etalio Application.
   *
   * The configuration:
   * - appId: the application ID
   * - secret: the application secret
   * - redirect_uri: the uri that handles OAauth callbacks
   * - debug: if Etalio should be more verbose for debugging purposes
   *
   * @param Array $config   The application configuration (optional)
   */
  public function __construct(Array $config = []) {
    if(isset($config['appId']))         $this->setAppId($config['appId']);
    if(isset($config['secret']))        $this->setAppSecret($config['secret']);
    if(isset($config['redirect_uri']))  $this->setRedirectUri($config['redirect_uri']);
    if(isset($config['debug']))         $this->debug = $config['debug'];

    //Populate with bare minimum of Etalio functionality, add more in sub classes
    $this->domainMap = array(
      'api'               => self::BASE_URL,
      'www'               => 'http://www.etalio.com',
      'oauth2'            => self::BASE_URL . '/oauth2',
      'token'             => self::BASE_URL . '/oauth2/token',
    );

    $this->curlOpts = array(
      CURLOPT_CONNECTTIMEOUT => 10,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT        => 60,
      CURLOPT_USERAGENT      => 'etalio-php-'.self::VERSION,
      CURLOPT_VERBOSE        => $this->debug,
    );

    $this->accessToken = $this->getPersistentData('access_token');
    $this->refreshToken = $this->getPersistentData('refresh_token');
    $state = $this->getPersistentData('state');
    if (!$this->isEmptyString($state)) {
      $this->state = $state;
    }
    $this->debug("Etalio SDK initated");
  }

  /**
   * Get a Login URL for use with redirects. By default, full page redirect is
   * assumed. If you are using the generated URL with a window.open() call in
   * JavaScript, you can pass in display=popup as part of the $params.
   *
   * @param array $params   Provide custom parameters for the url (optional)
   * @return string         The URL for the login flow
   */
  public function getLoginUrl(Array $params = []) {
    $this->establishCSRFTokenState();
    // if 'scope' is passed as an array, convert to comma separated list
    $scopeParams = isset($params['scope']) ? $params['scope'] : null;
    if ($scopeParams && is_array($scopeParams)) {
      $params['scope'] = implode(',', $scopeParams);
    }

    return $this->getUrl(
      'oauth2',
      array_merge(
        [
          'client_id'     => $this->appId,
          'state'         => $this->state,
          'redirect_uri'  => $this->redirectUri,
          'sdk'           => 'php-sdk-'.self::VERSION,
          'response_type' => 'code',
        ],
        $params
      ));
  }

  /**
   * AuthenticateUser, the main entry for the handshake
   *
   * @return mixed    false or the access_token
   */
  public function authenticateUser() {
    $this->debug("Authenticating user");
    if($this->isEmptyString([$this->accessToken,$this->refreshToken])) {
      $this->debug("Trying to authenticate user from code");
      return $this->getAccessTokenFromCode();
    } elseif (!$this->isEmptyString($this->refreshToken)) {
      $this->debug("No access_token but a refresh_token, trying to refresh...");
      return $this->refreshAccessToken();
    } else {
      $this->debug("No access_token or refresh_token");
      return false;
    }
    $this->debug("New access_token: ".$this->accessToken);
    return $this->accessToken;
  }

  /**
   * Calls an end point in the Etalio API
   *
   * @param string    $url The path (required)
   * @param string    $method GET, POST, PUT or DELETE (optional)
   * @param array     $params The query/post data (optional)
   * @param array     $headers The header data (optional)
   * @return mixed    false or the answer from the api as an associative array
   */
  public function apiCall($path, $method = 'GET', Array $params = [], Array $headers = []) {
    $this->debug("Calling API: ".$path);
    if($this->isEmptyString($this->accessToken)) {
      $this->debug("Empty access_token, can not access API");
      return false;
    }
    //If no method is defined but params, move arguments one step
    if (is_array($method) && empty($params)) {
      $params = $method;
      $method = 'GET';
    }
    // json_encode all params values that are not strings
    foreach ($params as $key => $value) {
      if (!is_string($value)) {
        $params[$key] = json_encode($value);
      }
    }
    $result = json_decode($this->authorizedRequest(
      $this->getUrl($path, $params),
      $method,
      $headers
    ), true);

    // results are returned, errors are thrown
    if (is_array($result) && isset($result['error'])) {
      $this->throwAPIException($result);
    }
    return $result;
  }

  /**
   * Set the Application ID.
   *
   * @param string $appId The Application ID
   * @return EtalioLoginBase
   */
  public function setAppId($appId) {
    $this->appId = $appId;
    return $this;
  }

  /**
   * Set the parameters that Curl will use
   *
   * @param array $val The configuration options for curl
   * @return EtalioLoginBase
   */
  public function setCurlOpts($val) {
    $this->curlOpts = $val;
    return $this;
  }

  /**
   * Set the App Secret.
   *
   * @param string $appSecret The App Secret
   * @return EtalioLoginBase
   */
  public function setAppSecret($appSecret) {
    $this->appSecret = $appSecret;
    return $this;
  }

  /**
   * Set the redirect uri
   *
   * @param string $uri the redirect uri
   * @return EtalioLoginBase
   */
  public function setRedirectUri($uri) {
    $this->redirectUri = $uri;
    return $this;
  }

  /**
   * Determines the access_token that should be used for API calls.
   *
   * @return string The access_token
   */
  public function getAccessToken() {
    if($this->accessToken == null)
      return $this->getPersistentData('access_token');
    return $this->accessToken;
  }



  /*************************************************************************
   *                     PROTECTED METHODS STARTS HERE                     *
   *************************************************************************/

  /**
   * Stores the refresh_token in both object and persistent store
   *
   * @param string $token the refresh_token
   */
  protected function setRefreshToken($token) {
    $this->refreshToken = $token;
    $this->setPersistentData('refresh_token',$token);
  }
  /**
   * Stores the access_token in both object and persistent store
   *
   * @param string $token the access_token
   */
  protected function setAccessToken($token) {
    $this->accessToken = $token;
    $this->setPersistentData('access_token',$token);
  }

  /**
   * Determines and returns the user access_token, first using
   * the signed request if present, and then falling back on
   * the authorization code if present.  The intent is to
   * return a valid user access_token, or false if one is determined
   * to not be available.
   *
   * @return mixed    false or a valid user access_token, or false if
   *                  one could not be determined.
   */
  protected function getAccessTokenFromCode() {
    $code = $this->getCodeFromRequest();
    if ($code) {
      $access_token = $this->requestAccessTokenFromCode($code);
      if ($access_token) {
        return $access_token;
      }
      // code was bogus, so everything based on it should be invalidated.
      $this->clearAllPersistentData();
      return false;
    }
    return $this->accessToken;
  }


  /**
   * Get the authorization code from $_REQUEST and the query parameters, if it exists,
   * and otherwise return false to signal no authorization code was
   * discoverable.
   *
   * @return mixed    false or the authorization code, or false if the authorization
   *                  code could not be determined.
   */
  protected function getCodeFromRequest() {
    if (isset($_REQUEST['code'])) {
      if ($this->state !== null &&
          isset($_REQUEST['state']) &&
          $this->state === $_REQUEST['state']) {

        // CSRF state has done its job, so clear it
        $this->state = null;
        $this->clearPersistentData('state');
        return $_REQUEST['code'];
      } else {
        $this->errorLog('CSRF state token does not match one provided.');
        return false;
      }
    }

    return false;
  }

  /**
   * Lays down a CSRF state token for this process.
   */
  protected function establishCSRFTokenState() {
    if ($this->state === null) {
      $this->state = md5(uniqid(mt_rand(), true));
      $this->setPersistentData('state', $this->state);
    }
  }

  /**
   * Requests to exchange the OAuth code for access and refresh_token
   * Stores both values using their setters
   *
   * @param string $code    The code from an oauth handshake
   * @return mixed          false or the access_token
   */
  protected function requestAccessTokenFromCode($code) {
    $this->debug("Requesting access_token from code");
    if ($this->isEmptyString([$code,$this->appId,$this->appSecret])) {
      $this->debug("Code, AppId or AppSecret is empty, can not request code.");
      return false;
    }

    try {
      // need to circumvent json_decode by calling makeRequest
      // directly, since response isn't JSON format.
      $access_token_response =
        $this->makeRequest(
          $this->getUrl('token'),
          "POST",
          $params = [
                      'client_id' => $this->appId,
                      'client_secret' => $this->appSecret,
                      'redirect_uri' => $this->redirectUri,
                      'grant_type' => 'authorization_code',
                      'code' => $code,
                    ]
        );
    } catch (EtalioApiException $e) {
      // most likely that user very recently revoked authorization.
      // In any event, we don't have an access_token, so say so.
      return false;
    }

    if (empty($access_token_response)) {
      return false;
    }

    $response_params = json_decode($access_token_response,true);
    if (!isset($response_params['access_token']) || !isset($response_params['refresh_token'])) {
      return false;
    }
    $this->setAccessToken($response_params['access_token']);
    $this->setRefreshToken($response_params['refresh_token']);
    return $response_params['access_token'];
  }

  /**
   * Requests to exchange the refreshToken stored in the persistent store for
   * a new access_token. Stores both values using their setters
   *
   * @return mixed        false or the new access_token
   */
  protected function refreshAccessToken() {
    $this->debug("Refreshing accessToken: ".$this->accessToken." with: ".$this->refreshToken);
    if($this->isEmptyString($this->refreshToken)) {
      $this->debug("RefreshToken is empty, can not refresh accessToken.");
      return false;
    }
    try {
      // need to circumvent json_decode by calling _oauthRequest
      // directly, since response isn't JSON format.
      $params = [
                  'client_id' => $this->appId,
                  'client_secret' => $this->appSecret,
                  'refresh_token' => $this->refreshToken,
                  'grant_type' => 'refresh_token',
                ];
      $access_token_response =
        $this->makeRequest($this->getUrl('token'),"POST",$params);
    } catch (EtalioApiException $e) {
      // most likely that user very recently revoked authorization.
      // In any event, we don't have an access_token, so say so.
      return false;
    }

    if (empty($access_token_response)) {
      return false;
    }

    $response_params = json_decode($access_token_response,true);
    if (!isset($response_params['access_token'])) {
      return false;
    }
    $this->setAccessToken($response_params['access_token']);
    return $response_params['access_token'];
  }

  /**
   * Make a OAuth Request. Adds the authorization parameter to the request
   *
   * @param string $url           The path (required)
   * @param string $method        GET, POST, PUT or DELETE
   * @param array $params         The query/post data
   * @param array $headers        The header data
   * @throws EtalioApiException   If error is thrown
   * @return string               The decoded response object
   */
  protected function authorizedRequest($url, $method = "GET", Array $params = [], Array $orgHeaders=[]) {
    $this->debug("Making an authorized request using token: ".$this->accessToken." ");
    if($this->isEmptyString($this->getAccessToken())) {
      $this->debug("AccessToken is empty, can not request anything");
      return false;
    }
    $headers = $orgHeaders;
    array_push($headers,"Authorization: Bearer ".$this->getAccessToken());
    $result = $this->makeRequest($url, $method, $params, $headers);
    if((strpos($result, self::EXPIRED_ACCESS_TOKEN_STRING) !== false)) {
      $this->debug("The accessToken was expired, trying to do a refresh...");
      if($this->refreshAccessToken()) {
        $this->debug("New accessToken recieved, trying the authorized request again.");
        $headers = $orgHeaders;
        array_push($headers,"Authorization: Bearer ".$this->getAccessToken());
        $result = $this->makeRequest($url, $method, $params, $headers);
      }
    }
    return $result;
  }
  /**
   * Makes an HTTP request. This method can be overridden by subclasses if
   * developers want to do fancier things or use something other than curl to
   * make the request.
   *
   * @param string $url           The path (required)
   * @param string $method        GET, POST, PUT or DELETE
   * @param array $params         The query/post data
   * @param array $headers        The header data
   * @throws EtalioApiException   If error is thrown
   * @return string               The response text unformatted
   */
  protected function makeRequest($url, $method = "GET", Array $params = [], Array $headers=[]) {
    $this->debug("Making request: ".$method." ".$url);
    $ch = curl_init();
    $opts = $this->curlOpts;
    $opts[CURLOPT_CUSTOMREQUEST] = $method;
    // If method is POST store all parameters as POST Fields
    // instead of URL parameters
    if($method == "POST") {
      $opts[CURLOPT_POSTFIELDS] = http_build_query($params, null, '&');
      $opts[CURLOPT_URL] = $url;
    } else {
      $opts[CURLOPT_URL] = $url.http_build_query($params, null, '&');
    }
    if (isset($opts[CURLOPT_HTTPHEADER])) {
      $opts[CURLOPT_HTTPHEADER] = array_merge($opts[CURLOPT_HTTPHEADER],$headers);
    } else {
      $opts[CURLOPT_HTTPHEADER] = $headers;
    }
    curl_setopt_array($ch, $opts);
    $result = curl_exec($ch);

    $errno = curl_errno($ch);

    // With dual stacked DNS responses, it's possible for a server to
    // have IPv6 enabled but not have IPv6 connectivity.  If this is
    // the case, curl will try IPv4 first and if that fails, then it will
    // fall back to IPv6 and the error EHOSTUNREACH is returned by the
    // operating system.
    if ($result === false && empty($opts[CURLOPT_IPRESOLVE])) {
        $matches = array();
        $regex = '/Failed to connect to ([^:].*): Network is unreachable/';
        if (preg_match($regex, curl_error($ch), $matches)) {
          if (strlen(@inet_pton($matches[1])) === 16) {
            $this->errorLog('Invalid IPv6 configuration on server, '.
                           'Please disable or get native IPv6 on your server.');
            self::$curlOpts[CURLOPT_IPRESOLVE] = CURL_IPRESOLVE_V4;
            curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
            $result = curl_exec($ch);
          }
        }
    }
    $this->debug("Data recieved from ".$method." ".$url.": ".$result);
    if ($result === false) {
      $e = new EtalioApiException([
        'error_code' => curl_errno($ch),
        'error' => [
          'message' => curl_error($ch),
          'type' => 'CurlException',
        ],
      ]);
      curl_close($ch);
      throw $e;
    }
    curl_close($ch);
    return $result;
  }

  /**
   * Build the URL for given domain alias, path and parameters.
   *
   * @param $name string      The name of the domain
   * @param $path string      Optional path (without a leading slash)
   * @param $params array     Optional query parameters
   * @return string           The URL for the given parameters
   */
  protected function getUrl($name, Array $params = []) {
    $url = $this->domainMap[$name];
    if ($params) {
      $url .= '?' . http_build_query($params, null, '&');
    }
    return $url;
  }

  /**
   * Analyzes the supplied result to see if it was thrown
   * because the access_token is no longer valid.  If that is
   * the case, then we destroy the session.
   *
   * @param $result array           A record storing the error message
   *                                returned by a failed API call.
   * @throws EtalioApiException     If error is thrown
   */
  protected function throwAPIException($result) {
    $e = new EtalioApiException($result);
    switch ($e->getType()) {
      // OAuth 2.0 Draft 00 style
      case 'OAuthException':
        // OAuth 2.0 Draft 10 style
      case 'invalid_token':
        // REST server errors are just Exceptions
      case 'Exception':
        $message = $e->getMessage();
        if ((strpos($message, 'Error validating access_token') !== false) ||
            (strpos($message, 'Invalid OAuth access_token') !== false) ||
            (strpos($message, 'An active access_token must be used') !== false)
        ) {
          $this->destroySession();
        }
        break;
    }

    throw $e;
  }

  /**
   * Prints to the error log if you aren't in command line mode.
   *
   * @param string $msg     Log message
   */
  protected function errorLog($msg) {
    // disable error log if we are running in a CLI environment
    // @codeCoverageIgnoreStart
    if ($this->debug && php_sapi_name() != 'cli') {
      error_log($msg);
    }
    // uncomment this if you want to see the errors on the page
    // print 'error_log: '.$msg."\n";
    // @codeCoverageIgnoreEnd
  }

  /**
   * Prints to the error log if you aren't in command line mode.
   *
   * @param string $msg     Debug message
   */
  protected function debug($msg) {
    // disable error log if we are running in a CLI environment
    // @codeCoverageIgnoreStart
    if ($this->debug && php_sapi_name() != 'cli') {
      $date = date('Y-m-d H:i:s');
      $log = "[etalio-sdk][".self::VERSION."][debug][".$date."]".$msg."\n";
      $out = fopen('php://stderr', 'w');
      fwrite($out,$log);
      fflush($out);
      fclose($out);
    }
    // uncomment this if you want to see the errors on the page
    // print 'error_log: '.$msg."\n";
    // @codeCoverageIgnoreEnd
  }
  /**
   * Destroy the current session
   */
  public function destroySession() {
    $this->debug("Destroying session");
    $this->accessToken = null;
    $this->refreshToken = null;
    $this->code = null;
    $this->clearAllPersistentData();
  }

  /**
   * If one or more strings are null or empty
   *
   * @param string or array of strings
   */
  private function isEmptyString($str) {
    if(is_array($str)) {
      foreach ($str as $s) {
        if($s == null || strlen($s) == 0) return true;
      }
      return false;
    }
    return $str == null || strlen($str) == 0;
  }

  /**
   * Each of the following four methods should be overridden in
   * a concrete subclass, as they are in the provided EtalioLogin class.
   * The EtalioLogin class uses PHP sessions to provide a primitive
   * persistent store, but another subclass--one that you implement--
   * might use a database, memcache, or an in-memory cache.
   *
   * @see EtalioWithSessionStore
   */

  /**
   * Stores the given ($key, $value) pair, so that future calls to
   * getPersistentData($key) return $value. This call may be in another request.
   *
   * @param string $key
   * @param array $value
   *
   * @return void
   */
  abstract protected function setPersistentData($key, $value);

  /**
   * Get the data for $key, persisted by BaseEtalio::setPersistentData()
   *
   * @param string $key The key of the data to retrieve
   * @param boolean $default The default value to return if $key is not found
   *
   * @return mixed
   */
  abstract protected function getPersistentData($key, $default = false);

  /**
   * Clear the data with $key from the persistent storage
   *
   * @param string $key
   * @return void
   */
  abstract protected function clearPersistentData($key);

  /**
   * Clear all data from the persistent storage
   *
   * @return void
   */
  abstract protected function clearAllPersistentData();
}
