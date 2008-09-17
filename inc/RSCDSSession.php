<?php
/**
* DAViCal extensions to AWL Session handling
*
* @package   davical
* @subpackage   RSCDSSession
* @author    Andrew McMillan <andrew@catalyst.net.nz>
* @copyright Catalyst .Net Ltd
* @license   http://gnu.org/copyleft/gpl.html GNU GPL v2
*/

/**
* All session data is held in the database.
*/
require_once('PgQuery.php');

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
SELECT session.*, usr.*
        FROM session JOIN usr USING(user_no)
EOSQL;
  return $sql;
}

/**
* We extend the AWL Session class.
*/
require_once('Session.php');

Session::_CheckLogout();

/**
* A class for creating and holding session information.
*
* @package   davical
*/
class RSCDSSession extends Session
{

  /**
  * Create a new RSCDSSession object.
  *
  * We create a Session and extend it with some additional useful RSCDS
  * related information.
  *
  * @param string $sid A session identifier.
  */
  function RSCDSSession( $sid="" ) {
    $this->Session($sid);
  }


  /**
  * Internal function used to assign the session details to a user's new session.
  * @param object $u The user+session object we (probably) read from the database.
  */
  function AssignSessionDetails( $u ) {
    parent::AssignSessionDetails( $u );
    $this->GetRoles();
    $this->GetRelationships();
    if ( function_exists("awl_set_locale") && isset($this->locale) && $this->locale != "" ) {
      awl_set_locale($this->locale);
    }
  }


  /**
  * Method used to get the user's roles
  */
  function GetRoles () {
    $this->roles = array();
    $sql = 'SELECT role_name FROM roles JOIN role_member ON roles.role_no=role_member.role_no WHERE user_no = '.$this->user_no.';';
    $qry = new PgQuery( $sql );
    if ( $qry->Exec('RSCDSSession') && $qry->rows > 0 ) {
      while( $role = $qry->Fetch() ) {
        $this->roles[$role->role_name] = 1;
      }
    }
  }


/**
* Method used to get the user's relationships
*/
  function GetRelationships () {
    $this->relationships = array();
    $sql = 'SELECT relationship.rt_id, rt_name, confers FROM relationship JOIN relationship_type USING (rt_id) WHERE from_user = '.$this->user_no;
    $qry = new PgQuery( $sql );
    if ( $qry->Exec('RSCDSSession') && $qry->rows > 0 ) {
      while( $relationship = $qry->Fetch() ) {
        $this->relationships[$relationship->rt_id] = $relationship;
        dbg_error_log( "RSCDSSession", "Relationships: %d - %s - %d - %s - %s -", $relationship->rt_id, $relationship->rt_name, $relationship->confers );
      }
    }
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
  function LoginRequired( $roles = "" ) {
    global $c, $session, $main_menu, $sub_menu, $tab_menu;

    if ( $this->logged_in && $roles == "" ) return;
    if ( ! $this->logged_in ) {
      $c->messages[] = i18n("You must log in to use this system.");
      include_once("page-header.php");
      if ( function_exists("local_index_not_logged_in") ) {
        local_index_not_logged_in();
      }
      else {
        if ( $this->login_failed ) {
          $c->messages[] = i18n("Invalid user name or password.");
        }
        echo "<h1>".translate("Log On Please")."</h1>\n";
        echo "<p>".translate("For access to the")
                  ." ".translate($c->system_name)." "
                  .translate("you should log on with the username and password that have been issued to you.")
            ."</p>\n";
        echo "<p>".translate("If you would like to request access, please e-mail")." ".$c->admin_email."</p>\n";
        echo $this->RenderLoginPanel();
      }
    }
    else {
      $valid_roles = split(",", $roles);
      foreach( $valid_roles AS $k => $v ) {
        if ( $this->AllowedTo($v) ) return;
      }
      $c->messages[] = i18n("You are not authorised to use this function.");
      include_once("page-header.php");
    }

    include("page-footer.php");
    exit;
  }
}

$session = new RSCDSSession();
$session->_CheckLogin();

?>
