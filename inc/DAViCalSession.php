<?php
/**
* DAViCal extensions to AWL Session handling
*
* @package   davical
* @subpackage   DAViCalSession
* @author Andrew McMillan <andrew@mcmillan.net.nz>
* @copyright Catalyst .Net Ltd, Morphoss Ltd <http://www.morphoss.com/>
* @license   http://gnu.org/copyleft/gpl.html GNU GPL v2
*/

/**
* @global resource $session
* @name $session
* The session object is global.
*/
$session = 1;  // Fake initialisation

// The Session object uses some (optional) configurable SQL to load
// the records related to the logged-on user...  (the where clause gets added).
// It's very important that someone not be able to externally control this,
// so we make it a function rather than a variable.
/**
* @todo Make this a defined constant
*/
function local_session_sql() {
  $sql = <<<EOSQL
SELECT session.*, usr.*, principal.*
        FROM session JOIN usr USING(user_no) JOIN principal USING(user_no)
EOSQL;
  return $sql;
}

/**
* We extend the AWL Session class.
*/
require('Session.php');
include_once('DAVResource.php');
include_once('httpful.phar');

#@Session::_CheckLogout();

/**
* A class for creating and holding session information.
*
* @package   davical
*/
class DAViCalSession extends Session
{

  public $principal_id;
  private $privilege_resources = array();
  
  /**
  * Create a new DAViCalSession object.
  *
  * We create a Session and extend it with some additional useful DAViCal 
  * related information.
  *
  * @param string $sid A session identifier.
  */
  function __construct( $sid='' ) {
    $this->principal_id = null;
    $this->Session($sid);
  }


  /**
  * Internal function used to assign the session details to a user's new session.
  * @param object $u The user+session object we (probably) read from the database.
  */
  function AssignSessionDetails( $u ) {
    if ( !isset($u->principal_id) ) {
      // If they don't have a principal_id set then we should re-read from our local database
      $qry = new AwlQuery('SELECT * FROM dav_principal WHERE username = :username', array(':username' => $u->username) );
      if ( $qry->Exec() && $qry->rows() == 1 ) {
        $u = $qry->Fetch();
      }
    }

    parent::AssignSessionDetails( $u );
    $this->GetRoles();
    if ( function_exists('awl_set_locale') && isset($this->locale) && $this->locale != '' ) {
      awl_set_locale($this->locale);
    }
  }


  /**
  * Method used to get the user's roles
  */
  function GetRoles () {
    $this->roles = array();
    $sql = 'SELECT role_name FROM roles JOIN role_member ON roles.role_no=role_member.role_no WHERE user_no = '.$this->user_no;
    $qry = new AwlQuery( $sql );
    if ( $qry->Exec('DAViCalSession') && $qry->rows() > 0 ) {
      while( $role = $qry->Fetch() ) {
        $this->roles[$role->role_name] = 1;
      }
    }
  }


  /**
   * Does the user have the privileges to do what is requested.
   * @param $do_what mixed The request privilege name, or array of privilege names, to be checked.
   * @param $path string The path we want that permission for
   * @param $any boolean Whether we accept any of the privileges. The default is true, unless the requested privilege is 'all', when it is false.
   * @return boolean Whether they do have one of those privileges against the specified path.
   */
  function HavePrivilegeTo( $do_what, $path, $any = null ) {
    if ( $this->AllowedTo('Admin') ) return true;
    if ( !isset($this->privilege_resources[$path]) ) {
      $this->privilege_resources[$path] = new DAVResource($path);
    }
    $resource = $this->privilege_resources[$path];
    if ( isset($resource) && $resource->Exists() ) {
      return $resource->HavePrivilegeTo($do_what,$any);
    }
    return false;
  }



  /**
  * Checks that this user is logged in, and presents a login screen if they aren't.
  *
  * The function can optionally confirm whether they are a member of one of a list
  * of roles, and deny access if they are not a member of any of them.
  *
  * @param string $roles The list of roles that the user must be a member of one of to be allowed to proceed.
  * @return boolean Whether or not the user is logged in and is a member of one of the required roles.
  */
  function LoginRequired( $roles = '' ) {
    global $c, $session, $main_menu, $sub_menu, $tab_menu;

    $current_domain = (isset($_SERVER['SERVER_NAME'])?$_SERVER['SERVER_NAME']:$_SERVER['SERVER_ADDR']);
    if ( (isset($c->restrict_admin_domain) && $c->restrict_admin_domain != $current_domain)
      || (isset($c->restrict_admin_port) && $c->restrict_admin_port != $_SERVER['SERVER_PORT'] ) ) {
      header('Location: caldav.php');
      dbg_error_log( 'LOG WARNING', 'Access to "%s" via "%s:%d" rejected.', $_SERVER['REQUEST_URI'], $current_domain, $_SERVER['SERVER_PORT'] );
      @ob_flush(); exit(0);
    }
    if ( isset($c->restrict_admin_roles) && $roles == '' ) $roles = $c->restrict_admin_roles;
    if ( $this->logged_in && $roles == '' ) return;

    /**
     * We allow basic auth to apply also, if present, though we check everything else first...
     */

    $basicLogin = isset($_SERVER['PHP_AUTH_USER']) && $_SERVER['PHP_AUTH_USER'] != "" && $_SERVER['PHP_AUTH_PW'] != "";
    $openIdLogin = $c->authenticate_hook['call']=='openid' && isset($_GET['code']) && isset($_GET['state']);

    if ( !$this->logged_in && !isset( $_COOKIE['NoAutoLogin'])) {
      if ( $basicLogin && $this->Login($_SERVER['PHP_AUTH_USER'],$_SERVER['PHP_AUTH_PW'],false)) {
        setcookie('NoAutoLogin',1,0);
        return;
      }
      else if ( $openIdLogin && $this->AttemptLoginOpenId())
      {
        setcookie('NoAutoLogin',1,0);
        return;
      }
    }
    if ( ! $this->logged_in ) {
      $c->messages[] = i18n('You must log in to use this system.');
      include_once('page-header.php');
      if ( function_exists('local_index_not_logged_in') ) {
        local_index_not_logged_in();
      }
      else {
        if ( $this->login_failed ) {
          $c->messages[] = i18n('Invalid user name or password.');
        }
        echo '<h1>'.translate('Log On Please')."</h1>\n";
        echo '<p>'.translate('For access to the')
                  .' '.translate($c->system_name).' '
                  .translate('you should log on with the username and password that have been issued to you.')
            ."</p>\n";
        echo '<p>'.translate('If you would like to request access, please e-mail').' '.$c->admin_email."</p>\n";
        echo $this->RenderLoginPanel();
      }
    }
    else {
      $valid_roles = explode(',', $roles);
      foreach( $valid_roles AS $k => $v ) {
        if ( $this->AllowedTo($v) ) return;
      }
      $c->messages[] = i18n('You are not authorised to use this function.');
      include_once('page-header.php');
    }

    include('page-footer.php');
    @ob_flush(); exit(0);
  }

  /*
   * Override RenderLoginPanel to have customized login panels.
  */
  function RenderLoginPanel()
  {
    global $c;

    if ($c->authenticate_hook['call']=='openid')
    {
      return $this->RenderOpenIdLoginPanel();
    }
    else
      return parent::RenderLoginPanel();
  }

  function AttemptLoginOpenId()
  {
    global $c;
    $rc = false;
    dbg_error_log( "Login", " Login: Attempting login" );
    if ( isset($usr)) unset($usr); /** In case register_globals on */

    if ( (! isset($authenticated)) || (!$authenticated))
    {
      $config = $c->authenticate_hook['config'];

      $req_code=$_GET['code'];
      $req_state=$_GET['state'];
      $json='{"grant_type":"authorization_code","redirect_uri":"'.$config['callback_url'].'","client_id":"'.$config['client_id'].'","client_secret":"'.$config['client_secret'].'","code":"'.$req_code.'"}';

      $reponse_json = \Httpful\Request::post($config['token_url'])->sendsJson()->body($json)->send();

      if ($reponse_json===null)
      {
        $rc=false;
        $this->cause="login failed";
        return $rc;
      }
      $parsed_json = json_decode($reponse_json);
      if (!isset($parsed_json->{"access_token"}))
      {
        $rc=false;
        $this->cause="no login";
        return $rc;
      }

      $access_token = $parsed_json->{"access_token"};
      $token_type = $parsed_json->{"token_type"};
      $expires_in = $parsed_json->{"expires_in"};
      $id_token = $parsed_json->{"id_token"};

      $reponse_json = \Httpful\Request::get($config['userinfo_url'].'?schema=openid')->addHeader('Authorization','Bearer '.$access_token)->send();
      $parsed_json = json_decode($reponse_json);
      $anniv = $parsed_json->{"birthdate"};
      $prenom = $parsed_json->{"given_name"};
      $nom = $parsed_json->{"family_name"};

      dbg_error_log("Login", "for user ".$nom." ".$prenom);

      if ($this->LoginOpenId($nom,$prenom,$anniv))
      {
        setcookie('cookie_session', openssl_random_pseudo_bytes(10), time()+3600, '/');
        $authenticated = true;
        $rc = true;
        return $rc;
      }
    }
     
    $this->Log("Login failure: $this->cause" );
    $this->login_failed = true;
    $rc = false;
    return $rc;
  }

  function LoginOpenId($nom, $prenom, $anniv)
  {
    global $session;

    $username = $nom.$prenom.$anniv;

    $sql = "SELECT * FROM usr WHERE lower(username) = text(?) AND active";
    $qry = new AwlQuery( $sql, strtolower($username) );
    if ( $qry->Exec('Login',__LINE__,__FILE__) && $qry->rows()==0) {
      $sql2 = "INSERT into usr (email_ok, updated, last_used, username, password, fullname, email, config_data, locale) VALUES (now(), now(), now(), ?, '', ?, '', '', 'fr')";
      $qry2 = new AwlQuery( $sql2, $username, $username);
      
      if ($qry2->Exec('Usr'))
      {
        $qry = new AwlQuery($sql, strtolower($username));
        $qry->Exec('Login',__LINE__,__FILE__);
        $usr = $qry->Fetch();
        $user_no = ( method_exists( $usr, 'user_no' ) ? $usr->user_no() : $usr->user_no );

        $sql2 = "INSERT into role_member (role_no, user_no) VALUES (3, ?)";
        $qry2 = new AwlQuery( $sql2, $user_no);
        $qry2->Exec('Role_member',__LINE__,__FILE__);

        $sql2 = "INSERT into principal (type_id, user_no, displayname, default_privileges) VALUES (1, ?, ?, ?)";
        $qry2 = new AwlQuery( $sql2, $user_no,$nom.' '.$prenom,'000000000000000000000000');
        $qry2->Exec('Principal',__LINE__,__FILE__);
      }
      else
      {
        $this->cause = "ERR : could not insert into database";
        $rc = false;
        return $rc;
      }
    } else
    {
       $usr = $qry->Fetch();
       $user_no = ( method_exists( $usr, 'user_no' ) ? $usr->user_no() : $usr->user_no );
    }

    // Now get the next session ID to create one from...
    $qry = new AwlQuery( "SELECT nextval('session_session_id_seq')" );
    if ( $qry->Exec('Login') && $qry->rows() == 1 ) 
    {
          $seq = $qry->Fetch();
          $session_id = $seq->nextval;
          $session_key = md5( rand(1010101,1999999999) . microtime() );  // just some random shite
          dbg_error_log( "Login", " Login: Valid username/password for $username ($user_no)" );

          // Set the last_used timestamp to match the previous login.
          $qry = new AwlQuery('UPDATE usr SET last_used = (SELECT session_start FROM session WHERE session.user_no = ? ORDER BY session_id DESC LIMIT 1) WHERE user_no = ?;', $usr->user_no, $usr->user_no);
          $qry->Exec('Session');

          // And create a session
          $sql = "INSERT INTO session (session_id, user_no, session_key) VALUES( ?, ?, ? )";
          $qry = new AwlQuery( $sql, $session_id, $user_no, $session_key );
          if ( $qry->Exec('Login') )
          {
            // Assign our session ID variable
            $sid = "$session_id;$session_key";

            //  Create a cookie for the sesssion
            setcookie('sid',$sid, 0,'/');
            // Recognise that we have started a session now too...
            $this->Session($sid);
            dbg_error_log( "Login", " Login: New session $session_id started for $username ($user_no)" );
            if ( isset($_POST['remember']) && intval($_POST['remember']) > 0 )
            {
              $cookie = md5( $user_no ) . ";";
              $cookie .= session_salted_md5($user_no . $usr->username . $usr->password);
              $GLOBALS['lsid'] = $cookie;
              setcookie( "lsid", $cookie, time() + (86400 * 3600), "/" );   // will expire in ten or so years
            }
            $this->just_logged_in = true;

// Unset all of the submitted values, so we don't accidentally submit an unexpected form.
            unset($_POST['username']);
            unset($_POST['password']);
            unset($_POST['submit']);
            unset($_GET['submit']);
            unset($GLOBALS['submit']);

            if ( function_exists('local_session_sql') ) {
              $sql = local_session_sql();
            }
            else {
              $sql = "SELECT session.*, usr.* FROM session JOIN usr USING ( user_no )";
            }
            $sql .= " WHERE session.session_id = ? AND (md5(session.session_start::text) = ? OR session.session_key = ?) ORDER BY session.session_start DESC LIMIT 2";

            $qry = new AwlQuery($sql, $session_id, $session_key, $session_key);
            if ( $qry->Exec('Session') ) { //&& 1 == $qry->rows() ) {
              $row = $qry->Fetch();
              $this->AssignSessionDetails( $row );
            }

            $rc = true;
            return $rc;
         }
 // else ...
          $this->cause = 'ERR: Could not create new session.';
        }
        else {
          $this->cause = 'ERR: Could not increment session sequence.';
        }

    $this->Log( "Login failure: $this->cause" );
    $this->login_failed = true;
    $rc = false;

    return $rc;
  }

  function RenderOpenIdLoginPanel()
  {
    global $c;
    $config = $c->authenticate_hook['config'];

    if (isset($_COOKIE['cookie_session']))
    {
       $html = <<<EOTEXT
       <div>
       <h1>Session active.</h1>
       </div>
EOTEXT;
       return $html;
    }
    else
    {
       $state_aleatoire = openssl_random_pseudo_bytes(10);
       $nonce_aleatoire = openssl_random_pseudo_bytes(10);
       $url = $config['authorization_url'].'?response_type=code&client_id='.$config['client_id'].'&redirect_uri='.$config['callback_url'].'&scope=openid%20profile&state='.$state_aleatoire.'&nonce='.$nonce_aleatoire;

       $html = <<<EOTEXT
       <div>
       <h1>No active Session</h1>
       </div>
       <br>
       <div>
       <a href="$url">Connexion</a>
       </div>
EOTEXT;
       return $html;
    }
  }

  static function _CheckLogout()
  {
    global $c;
    if (isset($_GET['logout']))
    {
      setcookie('cookie_session','',0, '/');
      setcookie('NoAutoLogin','',0,'/');
      $url = $c->authenticate_hook['config']['logout_url'];
      parent::_CheckLogout();
      header('Location: '.$url);
      exit();
    }
  }
}
@DAViCalSession::_CheckLogout();

$session = new DAViCalSession();
$session->_CheckLogin();

