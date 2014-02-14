<?php
namespace Etalio;
require_once "etalio_api.php";

/**
 * Extends the EtalioLoginBase class with the intent of using
 * PHP sessions to store user ids and access tokens.
 */
class EtalioWithSessionStore extends EtalioApi
{
  // We can set this to a high number because the main session
  // expiration will trump this.
  const ETALIOSS_COOKIE_EXPIRE = 31556926; // 1 year

  // Keys we support to store in the persistent data
  protected static $kSupportedKeys = array('state', 'access_token', 'refresh_token');

  /**
   * Identical to the parent constructor, except that
   * we start a PHP session to store the user ID and
   * access token if during the course of execution
   * we discover them.
   * @see EtalioApi::__construct in etalio_api.php
   */
  public function __construct(Array $config = []) {
    if (!session_id()) {
      session_start();
    }
    parent::__construct($config);
  }

  /**
   * Provides the implementations of the inherited abstract
   * methods.  The implementation uses PHP sessions to maintain
   * a store for CSRF states, refresh tokens and access tokens.
   */
  protected function setPersistentData($key, $value) {
    $this->debug("Setting persistent data: ".$key.":".$value);
    if (!in_array($key, self::$kSupportedKeys)) {
      self::errorLog('Unsupported key passed to setPersistentData: '.$key.$value);
      return;
    }
    $session_var_name = $this->constructSessionVariableName($key);
    $_SESSION[$session_var_name] = $value;
  }

  protected function getPersistentData($key, $default = false) {
    if (!in_array($key, self::$kSupportedKeys)) {
      self::errorLog('Unsupported key passed to getPersistentData: '.$key);
      return $default;
    }
    $session_var_name = $this->constructSessionVariableName($key);
    $val = isset($_SESSION[$session_var_name]) ? $_SESSION[$session_var_name] : $default;
    $this->debug("Reading persistent data: ".$session_var_name.":".$key.":".$val);
    return $val;
  }

  protected function clearPersistentData($key) {
    $this->debug("Clearing persistent data: ".$key);
    if (!in_array($key, self::$kSupportedKeys)) {
      self::errorLog('Unsupported key passed to clearPersistentData: '.$key);
      return;
    }

    $session_var_name = $this->constructSessionVariableName($key);
    if (isset($_SESSION[$session_var_name])) {
      unset($_SESSION[$session_var_name]);
    }
  }

  protected function clearAllPersistentData() {
    foreach (self::$kSupportedKeys as $key) {
      $this->clearPersistentData($key);
    }
  }

  protected function constructSessionVariableName($key) {
    return implode('_', ['etalio', $this->appId, $key]);
  }
}
