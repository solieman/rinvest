<?php
namespace Etalio;

class PHPSDKTestCase extends \PHPUnit_Framework_TestCase {
  const APP_ID = '117743971608120';
  const SECRET = '9c8ea2071859659bea1246d33a9207cf';
  const REDIRECT_URI = 'https://www.test.com/unit-tests.php';

  const MIGRATED_APP_ID = '174236045938435';
  const MIGRATED_SECRET = '0073dce2d95c4a5c2922d1827ea0cca6';

  const TEST_USER   = 499834690;
  const TEST_USER_2 = 499835484;

  private static $kExpiredAccessToken = 'AAABrFmeaJjgBAIshbq5ZBqZBICsmveZCZBi6O4w9HSTkFI73VMtmkL9jLuWsZBZC9QMHvJFtSulZAqonZBRIByzGooCZC8DWr0t1M4BL9FARdQwPWPnIqCiFQ';

  private static function kSignedRequestWithEmptyValue() {
    return '';
  }

  private static function kSignedRequestWithBogusSignature() {
    $etalio = new ETALIOPublic(array(
      'appId'  => self::APP_ID,
      'secret' => 'bogus',
    ));
    return $etalio->publicMakeSignedRequest(
      array(
        'algorithm' => 'HMAC-SHA256',
      )
    );
  }

  private static function kSignedRequestWithWrongAlgo() {
    $etalio = new ETALIOPublic(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $data['algorithm'] = 'foo';
    $json = json_encode($data);
    $b64 = $etalio->publicBase64UrlEncode($json);
    $raw_sig = hash_hmac('sha256', $b64, self::SECRET, $raw = true);
    $sig = $etalio->publicBase64UrlEncode($raw_sig);
    return $sig.'.'.$b64;
  }

  public function testConstructor() {
    $etalio = new TransientEtalio(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $this->assertEquals($etalio->getAppId(), self::APP_ID,
                        'Expect the App ID to be set.');
    $this->assertEquals($etalio->getAppSecret(), self::SECRET,
                        'Expect the API secret to be set.');
  }

  public function testSetAppId() {
    $etalio = new TransientEtalio(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $etalio->setAppId('dummy');
    $this->assertEquals($etalio->getAppId(), 'dummy',
                        'Expect the App ID to be dummy.');
  }

  public function testSetAPPSecret() {
    $etalio = new TransientEtalio(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $etalio->setAppSecret('dummy');
    $this->assertEquals($etalio->getAppSecret(), 'dummy',
                        'Expect the API secret to be dummy.');
  }

  public function testSetAccessToken() {
    $etalio = new TransientEtalio(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));

    $etalio->setAccessToken('saltydog');
    $this->assertEquals($etalio->getAccessToken(), 'saltydog',
                        'Expect installed access token to remain \'saltydog\'');
  }

  public function testGetLoginURL() {
    $etalio = new EtalioWithSessionStore(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));

    // fake the HPHP $_SERVER globals
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php';
    $login_url = parse_url($etalio->getLoginUrl());
    $this->assertEquals($login_url['scheme'], 'https');
    $this->assertEquals($login_url['host'], 'api-etalio.3fs.si');
    $this->assertEquals($login_url['path'], '/oauth2');
    $expected_login_params =
      array('client_id' => self::APP_ID,
            'redirect_uri' => self::REDIRECT_URI);

    $query_map = array();
    parse_str($login_url['query'], $query_map);
    $this->assertIsSubset($expected_login_params, $query_map);
    // we don't know what the state is, but we know it's an md5 and should
    // be 32 characters long.
    $this->assertEquals(strlen($query_map['state']), $num_characters = 32);
  }

  public function testGetLoginURLWithExtraParams() {
    $etalio = new EtalioWithSessionStore(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));

    // fake the HPHP $_SERVER globals
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php';
    $extra_params = array('scope' => 'email, sms',
                          'nonsense' => 'nonsense');
    $login_url = parse_url($etalio->getLoginUrl($extra_params));
    $this->assertEquals($login_url['scheme'], 'https');
    $this->assertEquals($login_url['host'], 'api-etalio.3fs.si');
    $this->assertEquals($login_url['path'], '/oauth2');
    $expected_login_params =
      array_merge(
        array('client_id' => self::APP_ID,
              'redirect_uri' => 'https://www.test.com/unit-tests.php'),
        $extra_params);
    $query_map = array();
    parse_str($login_url['query'], $query_map);
    $this->assertIsSubset($expected_login_params, $query_map);
    // we don't know what the state is, but we know it's an md5 and should
    // be 32 characters long.
    $this->assertEquals(strlen($query_map['state']), $num_characters = 32);
  }

  public function testGetLoginURLWithScopeParamsAsArray() {
    $etalio = new EtalioWithSessionStore(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));

    // fake the HPHP $_SERVER globals
    $_SERVER['HTTP_HOST'] = 'www.test.com';
    $_SERVER['REQUEST_URI'] = '/unit-tests.php';
    $scope_params_as_array = array('email','sms','read_stream');
    $extra_params = array('scope' => $scope_params_as_array,
                          'nonsense' => 'nonsense');
    $login_url = parse_url($etalio->getLoginUrl($extra_params));
    $this->assertEquals($login_url['scheme'], 'https');
    $this->assertEquals($login_url['host'], 'api-etalio.3fs.si');
    $this->assertEquals($login_url['path'], '/oauth2');
    // expect api to flatten array params to comma separated list
    // should do the same here before asserting to make sure API is behaving
    // correctly;
    $extra_params['scope'] = implode(',', $scope_params_as_array);
    $expected_login_params =
      array_merge(
        array('client_id' => self::APP_ID,
              'redirect_uri' => 'https://www.test.com/unit-tests.php'),
        $extra_params);
    $query_map = array();
    parse_str($login_url['query'], $query_map);
    $this->assertIsSubset($expected_login_params, $query_map);
    // we don't know what the state is, but we know it's an md5 and should
    // be 32 characters long.
    $this->assertEquals(strlen($query_map['state']), $num_characters = 32);
  }

  public function testGetCodeWithValidCSRFState() {
    $etalio = new ETALIOCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));

    $etalio->setCSRFStateToken();
    $code = $_REQUEST['code'] = $this->generateMD5HashOfRandomValue();
    $_REQUEST['state'] = $etalio->getCSRFStateToken();
    $this->assertEquals($code,
                        $etalio->publicGetCode(),
                        'Expect code to be pulled from $_REQUEST[\'code\']');
  }

  public function testGetCodeWithInvalidCSRFState() {
    $etalio = new ETALIOCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));

    $etalio->setCSRFStateToken();
    $code = $_REQUEST['code'] = $this->generateMD5HashOfRandomValue();
    $_REQUEST['state'] = $etalio->getCSRFStateToken().'forgery!!!';
    $this->assertFalse($etalio->publicGetCode(),
                       'Expect getCode to fail, CSRF state should not match.');
  }

  public function testGetCodeWithMissingCSRFState() {
    $etalio = new ETALIOCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));

    $code = $_REQUEST['code'] = $this->generateMD5HashOfRandomValue();
    // intentionally don't set CSRF token at all
    $this->assertFalse($etalio->publicGetCode(),
                       'Expect getCode to fail, CSRF state not sent back.');
  }

  public function testPersistentCSRFState()
  {
    $etalio = new ETALIOCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $etalio->setCSRFStateToken();
    $code = $etalio->getCSRFStateToken();

    $etalio = new ETALIOCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));

    $this->assertEquals($code, $etalio->publicGetState(),
            'Persisted CSRF state token not loaded correctly');
  }

  public function testLoginURLDefaults() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $etalio = new TransientEtalio(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $encodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertNotNull(strpos($etalio->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
  }

  public function testLoginURLCustomNext() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $etalio = new TransientEtalio(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $next = 'http://fbrell.com/custom';
    $loginUrl = $etalio->getLoginUrl(array(
      'redirect_uri' => $next,
      'cancel_url' => $next
    ));
    $currentEncodedUrl = rawurlencode('http://fbrell.com/examples');
    $expectedEncodedUrl = rawurlencode($next);
    $this->assertNotNull(strpos($loginUrl, $expectedEncodedUrl),
                         'Expect the custom url to exist.');
    $this->assertFalse(strpos($loginUrl, $currentEncodedUrl),
                      'Expect the current url to not exist.');
  }

  public function testNonDefaultPort() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com:8080';
    $_SERVER['REQUEST_URI'] = '/examples';
    $etalio = new TransientEtalio(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $encodedUrl = rawurlencode('http://fbrell.com:8080/examples');
    $this->assertNotNull(strpos($etalio->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
  }

  public function testSecureCurrentUrl() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $_SERVER['HTTPS'] = 'on';
    $etalio = new TransientEtalio(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $encodedUrl = rawurlencode('https://fbrell.com/examples');
    $this->assertNotNull(strpos($etalio->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
  }

  public function testSecureCurrentUrlWithNonDefaultPort() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com:8080';
    $_SERVER['REQUEST_URI'] = '/examples';
    $_SERVER['HTTPS'] = 'on';
    $etalio = new TransientEtalio(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $encodedUrl = rawurlencode('https://fbrell.com:8080/examples');
    $this->assertNotNull(strpos($etalio->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
  }

  public function testGetUserAndAccessTokenFromSession() {
    $etalio = new PersistentETALIOPublic(array(
     'appId'  => self::APP_ID,
     'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));

    $etalio->publicSetPersistentData('access_token',
                                       self::$kExpiredAccessToken);
    $etalio->publicSetPersistentData('user_id', 12345);
    $this->assertEquals(self::$kExpiredAccessToken,
                        $etalio->getAccessToken(),
                        'Get access token from persistent store.');
  }

  public function testGetUserWithoutCodeOrSignedRequestOrSession() {
    $etalio = new PersistentETALIOPublic(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
  ));

    // deliberately leave $_REQUEST and _$SESSION empty
    $this->assertEmpty($_REQUEST,
                       'GET, POST, and COOKIE params exist even though '.
                       'they should.  Test cannot succeed unless all of '.
                       '$_REQUEST is empty.');
    $this->assertEmpty($_SESSION,
                       'Session is carrying state and should not be.');
  }

  public function testEmptyCodeReturnsFalse() {
    $etalio = new ETALIOPublicGetAccessTokenFromCode(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $this->assertFalse($etalio->publicRequestAccessTokenFromCode(''));
    $this->assertFalse($etalio->publicRequestAccessTokenFromCode(null));
    $this->assertFalse($etalio->publicRequestAccessTokenFromCode(false));
  }


  public function testExistingStateRestoredInConstructor() {
    $etalio = new ETALIOPublicState(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $this->assertEquals(ETALIOPublicState::STATE, $etalio->publicGetState());
  }

  public function testExceptionConstructorWithErrorCode() {
    $code = 404;
    $e = new EtalioApiException(array('error_code' => $code));
    $this->assertEquals($code, $e->getCode());
  }

  // this happens often despite the fact that it is useless
  public function testExceptionTypeFalse() {
    $e = new EtalioApiException(false);
    $this->assertEquals('Exception', $e->getType());
  }

  public function testExceptionTypeMixedDraft00() {
    $e = new EtalioApiException(array('error' => array('message' => 'foo')));
    $this->assertEquals('Exception', $e->getType());
  }

  public function testExceptionTypeDraft00() {
    $error = 'foo';
    $e = new EtalioApiException(
      array('error' => array('type' => $error, 'message' => 'hello world')));
    $this->assertEquals($error, $e->getType());
  }

  public function testExceptionTypeDraft10() {
    $error = 'foo';
    $e = new EtalioApiException(array('error' => $error));
    $this->assertEquals($error, $e->getType());
  }

  public function testExceptionTypeDefault() {
    $e = new EtalioApiException(array('error' => false));
    $this->assertEquals('Exception', $e->getType());
  }

  public function testExceptionToString() {
    $e = new EtalioApiException(array(
      'error_code' => 1,
      'error_description' => 'foo',
    ));
    $this->assertEquals('Exception: 1: foo', (string) $e);
  }


  public function testSessionBackedEtalio() {
    $etalio = new PersistentETALIOPublic(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $key = 'state';
    $val = 'foo';
    $etalio->publicSetPersistentData($key, $val);
    $this->assertEquals(
      $val,
      $_SESSION[sprintf('etalio_%s_%s', self::APP_ID, $key)]
    );
    $this->assertEquals(
      $val,
      $etalio->publicGetPersistentData($key)
    );
  }

  public function testSessionBackedEtalioIgnoresUnsupportedKey() {
    $etalio = new PersistentETALIOPublic(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $key = '--invalid--';
    $val = 'foo';
    $etalio->publicSetPersistentData($key, $val);
    $this->assertFalse(
      array_key_exists(
        sprintf('etalio_%s_%s', self::APP_ID, $key),
        $_SESSION
      )
    );
    $this->assertFalse($etalio->publicGetPersistentData($key));
  }

  public function testClearSessionBackedEtalio() {
    $etalio = new PersistentETALIOPublic(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $key = 'state';
    $val = 'foo';
    $etalio->publicSetPersistentData($key, $val);
    $this->assertEquals(
      $val,
      $_SESSION[sprintf('etalio_%s_%s', self::APP_ID, $key)]
    );
    $this->assertEquals(
      $val,
      $etalio->publicGetPersistentData($key)
    );
    $etalio->publicClearPersistentData($key);
    $this->assertFalse(
      array_key_exists(
        sprintf('fb_%s_%s', self::APP_ID, $key),
        $_SESSION
      )
    );
    $this->assertFalse($etalio->publicGetPersistentData($key));
  }

  public function testSessionBackedEtalioIgnoresUnsupportedKeyInClear() {
    $etalio = new PersistentETALIOPublic(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $key = '--invalid--';
    $val = 'foo';
    $session_var_name = sprintf('etalio_%s_%s', self::APP_ID, $key);
    $_SESSION[$session_var_name] = $val;
    $etalio->publicClearPersistentData($key);
    $this->assertTrue(array_key_exists($session_var_name, $_SESSION));
    $this->assertFalse($etalio->publicGetPersistentData($key));
  }

  public function testClearAllSessionBackedEtalio() {
    $etalio = new PersistentETALIOPublic(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'redirect_uri' => self::REDIRECT_URI,
    ));
    $key = 'state';
    $val = 'foo';
    $session_var_name = sprintf('etalio_%s_%s', self::APP_ID, $key);
    $etalio->publicSetPersistentData($key, $val);
    $this->assertEquals($val, $_SESSION[$session_var_name]);
    $this->assertEquals($val, $etalio->publicGetPersistentData($key));
    $etalio->publicClearAllPersistentData();
    $this->assertFalse(array_key_exists($session_var_name, $_SESSION));
    $this->assertFalse($etalio->publicGetPersistentData($key));
  }

  public function provideEndsWith() {
    return array(
      array('', '', true),
      array('', 'a', false),
      array('a', '', true),
      array('a', 'b', false),
      array('a', 'a', true),
      array('aa', 'a', true),
      array('ab', 'a', false),
      array('ba', 'a', true),
    );
  }

  // /**
  //  * @dataProvider provideIsAllowedDomain
  //  */
  // public function testIsAllowedDomain($big, $small, $result) {
  //   $this->assertEquals(
  //     $result,
  //     PersistentETALIOPublic::publicIsAllowedDomain($big, $small)
  //   );
  // }

  public function provideIsAllowedDomain() {
    return array(
      array('fbrell.com', 'fbrell.com', true),
      array('foo.fbrell.com', 'fbrell.com', true),
      array('foofbrell.com', 'fbrell.com', false),
      array('evil.com', 'fbrell.com', false),
      array('foo.fbrell.com', 'bar.fbrell.com', false),
    );
  }

  protected function generateMD5HashOfRandomValue() {
    return md5(uniqid(mt_rand(), true));
  }

  protected function setUp() {
    parent::setUp();
  }

  protected function tearDown() {
    $this->clearSuperGlobals();
    parent::tearDown();
  }

  protected function clearSuperGlobals() {
    unset($_SERVER['HTTPS']);
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
    $_SESSION = array();
    $_COOKIE = array();
    $_REQUEST = array();
    $_POST = array();
    $_GET = array();
    if (session_id()) {
      session_destroy();
    }
  }

  /**
   * Checks that the correct args are a subset of the returned obj
   * @param  array $correct The correct array values
   * @param  array $actual  The values in practice
   * @param  string $message to be shown on failure
   */
  protected function assertIsSubset($correct, $actual, $msg='') {
    foreach ($correct as $key => $value) {
      $actual_value = $actual[$key];
      $newMsg = (strlen($msg) ? ($msg.' ') : '').'Key: '.$key;
      $this->assertEquals($value, $actual_value, $newMsg);
    }
  }
}

class TransientEtalio extends EtalioBase {
  protected function setPersistentData($key, $value) {}
  protected function getPersistentData($key, $default = false) {
    return $default;
  }
  protected function clearPersistentData($key) {}
  protected function clearAllPersistentData() {}
  public function getAppId() {
    return $this->appId;
  }
  public function getAppSecret() {
    return $this->appSecret;
  }
  public function setAccessToken($tkn) {
    parent::setAccessToken($tkn);
  }
}

class ETALIORecordURL extends TransientEtalio {
  private $url;

  protected function _oauthRequest($url, $method = 'GET', Array $params = array(), Array $headers = array()) {
    $this->url = $url;
  }

  public function getRequestedURL() {
    return $this->url;
  }
}

class ETALIORecordMakeRequest extends TransientEtalio {
  private $requests = array();

  protected function makeRequest($url, $method = 'GET', Array $params = array(), Array $headers = array()) {
    $this->requests[] = array(
      'url' => $url,
      'params' => $params,
    );
    return parent::makeRequest($url, $method, $params, $headers);
  }

  public function publicGetRequests() {
    return $this->requests;
  }
}

class PersistentETALIOPublic extends EtalioWithSessionStore {
  public function publicParseSignedRequest($input) {
    return $this->parseSignedRequest($input);
  }

  public function publicSetPersistentData($key, $value) {
    $this->setPersistentData($key, $value);
  }

  public function publicGetPersistentData($key, $default = false) {
    return $this->getPersistentData($key, $default);
  }

  public function publicClearPersistentData($key) {
    return $this->clearPersistentData($key);
  }

  public function publicClearAllPersistentData() {
    return $this->clearAllPersistentData();
  }

  public function publicGetSharedSessionID() {
    return $this->sharedSessionID;
  }

  public static function publicIsAllowedDomain($big, $small) {
    return self::isAllowedDomain($big, $small);
  }

  public function publicGetSharedSessionCookieName() {
    return $this->getSharedSessionCookieName();
  }
}

class ETALIOCode extends EtalioWithSessionStore {
  public function publicGetCode() {
    return $this->getCodeFromRequest();
  }

  public function publicGetState() {
    return $this->state;
  }

  public function setCSRFStateToken() {
    $this->establishCSRFTokenState();
  }

  public function getCSRFStateToken() {
    return $this->getPersistentData('state');
  }
}

class ETALIOPublicGetAccessTokenFromCode extends TransientEtalio {
  public function publicRequestAccessTokenFromCode($code, $redirect_uri = null) {
    return $this->requestAccessTokenFromCode($code, $redirect_uri);
  }
}

class ETALIOPublicState extends TransientEtalio {
  const STATE = 'foo';
  protected function getPersistentData($key, $default = false) {
    if ($key === 'state') {
      return self::STATE;
    }
    return parent::getPersistentData($key, $default);
  }

  public function publicGetState() {
    return $this->state;
  }
}
