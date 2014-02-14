<?php
namespace Etalio;
require_once "etalio_base.php";

/**
 * Extends the EtalioLogin class and adds helper methods for the Etalio Api
 */
abstract class EtalioApi extends EtalioBase
{

  /**
   * APi version
   */
  const API_VERSION = "v1";

  protected $currentProfile;

  /**
   * Identical to the parent constructor, except that
   * we start a PHP session to store the user ID and
   * access token if during the course of execution
   * we discover them.
   * @see EtalioBase::__construct in etalio_base.php
   */
  public function __construct(Array $config = []) {
    parent::__construct($config);
    $this->domainMap = array_merge($this->domainMap, [
      'myprofile'         => self::BASE_URL . '/' . self::API_VERSION . '/profile/me',
      'profile'           => self::BASE_URL . '/' . self::API_VERSION . '/profile',
      'application'       => self::BASE_URL . '/' . self::API_VERSION . '/application',
      'applications'      => self::BASE_URL . '/' . self::API_VERSION . '/applications',
      'applicationKeys'   => self::BASE_URL . '/' . self::API_VERSION . '/applications',

    ]);
  }

  public function isAuthenticated(){
    return ($this->getCurrentProfile())?true:false;
  }

  public function getCurrentProfile(){
    if(!isset($this->currentProfile)) {
      $profile = $this->apiCall('myprofile');
      if($profile && isset($profile['id'])) {
        $this->currentProfile = $profile;
      } else {
        return false;
      }
    }
    return (Array)$this->currentProfile;
  }

  public function updateCurrentProfile(Array $profile){
    return $this->apiCall('myprofile','PUT',$profile);
  }

  public function getCurrentProfileApplications(){

  }

  public function deleteCurrentProfileApplication($applicationId){

  }

  public function getProfile($profileId){
    $this->setDomainPath('profile-'.$profileId, $this->domainMap['profile']."/".$profileId);
    $profile = $this->apiCall('profile-'.$profileId);
    if($profile && isset($profile['id'])) {
      return $profile;
    }
    return false;
  }

  public function createProfile($payload){

  }

  public function updateProfile($profileId, $payload){

  }

  public function getProfileApplications($profileId){

  }

  public function getApplications($userId){
    $app = $this->apiCall('applications',['user_id' => $userId]); //TODO correct url
    if(isset($app['id']))
      return $app;
    return false;
  }

  public function getApplication($id){
    $this->setDomainPath('application-'.$id, $this->domainMap['application']."/".$id);
    $application = $this->apiCall('application-'.$id);
    if($application && isset($application['id'])) {
      return $application;
    }
    return false;
  }

  public function createApplication($payload){

  }

  public function updateApplication($applicationId, $payload){

  }

  public function deleteApplication($applicationId){

  }

  public function setApplicationImage($applicationId, $image){

  }

  public function deleteApplicationImage($applicationId){

  }

  public function getApplicationKey($applicationId, $keyId){

  }

  public function createApplicationKey($applicationId){

  }

  public function updateApplicationKey($applciationId, $keyId, $payload){

  }

  public function deleteApplicationKey($applicationId, $keyId){

  }

  public function getApplicationKeys($id){
    $this->setDomainPath('application-keys-'.$id, $this->domainMap['application']."/".$id."/keys");
    $keys = $this->apiCall('application-keys-'.$id);
    if($keys && isset($keys) && is_array($keys)) {
      return $keys;
    }
    return false;
  }

  private function setDomainPath($key,$value) {
    $this->domainMap = array_merge($this->domainMap, [
      $key => $value,
    ]);
  }
}
?>