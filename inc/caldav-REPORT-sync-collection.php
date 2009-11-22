<?php
/**
* CalDAV Server - handle sync-collection report (draft-daboo-webdav-sync-01)
*
* @package   davical
* @subpackage   caldav
* @author    Andrew McMillan <andrew@mcmillan.net.nz>
* @copyright Morphoss Ltd - http://www.morphoss.com/
* @license   http://gnu.org/copyleft/gpl.html GNU GPL v2 or later
*/

require("DAVResource.php");
$responses = array();

/**
 * Build the array of properties to include in the report output
 */
$sync_tokens = $xmltree->GetPath('/DAV::sync-collection/DAV::sync-token');
$sync_token = $sync_tokens[0]->GetContent();
if ( !isset($sync_token) ) $sync_token = 0;
$sync_token = intval($sync_token);
dbg_error_log( 'sync', " sync-token: %s", $sync_token );


$props = $xmltree->GetElements('DAV::prop');
$v = $props[0];
$props = $v->GetContent();
$proplist = array();
foreach( $props AS $k => $v ) {
  $proplist[] = $v->GetTag();
}

function display_status( $status_code ) {
  return sprintf( 'HTTP/1.1 %03d %s', intval($status_code), getStatusMessage($status_code) );
}

$sql = "SELECT new_sync_token(?,?)";
$qry = new PgQuery($sql, $sync_token, $request->CollectionId());
if ( !$qry->Exec("REPORT",__LINE__,__FILE__) || $qry->rows <= 0 ) {
  $request->DoResponse( 500, translate("Database error") );
}
$row = $qry->Fetch();
$new_token = $row->new_sync_token;

if ( $sync_token == 0 ) {
  $sql = <<<EOSQL
SELECT *, 201 AS sync_status FROM collection
            LEFT JOIN caldav_data USING (collection_id)
            LEFT JOIN calendar_item USING (dav_id)
     WHERE collection.collection_id = ?
   ORDER BY collection.collection_id, caldav_data.dav_id
EOSQL;
  $qry = new PgQuery($sql, $request->CollectionId());
}
else {
  $sql = <<<EOSQL
SELECT * FROM collection LEFT JOIN sync_changes USING(collection_id)
                         LEFT JOIN calendar_item USING (collection_id,dav_id)
                         LEFT JOIN caldav_data USING (collection_id,dav_id)
     WHERE collection.collection_id = ?
       AND sync_time > (SELECT modification_time FROM sync_tokens WHERE sync_token = ?)
   ORDER BY collection.collection_id, sync_changes.dav_id, sync_changes.sync_time
EOSQL;
  $qry = new PgQuery($sql, $request->CollectionId(), $sync_token);
}

$last_dav_id = -1;
$first_status = 0;

if ( $qry->Exec("REPORT",__LINE__,__FILE__) ) {
  while( $object = $qry->Fetch() ) {
    if ( $object->dav_id == $last_dav_id ) {
      /** The complex case: this is the second or subsequent for this dav_id */
      if ( $object->sync_status == 404 ) {
        if ( $first_action == 201 ) {
          array_pop($responses);
          $last_dav_id = -1;
          $first_status = 0;
        }
        else {
          array_pop($responses);
          $resultset = array(
            new XMLElement( 'href', ConstructURL($object->dav_name) ),
            new XMLElement( 'status', display_status($object->sync_status) )
          );
          $responses[] = new XMLElement( 'sync-response', $resultset );
          $first_status = 404;
        }
      }
      /** Else:
       *    the object existed at start and we have multiple modifications,
       *  or,
       *    the object didn't exist at start and we have subsequent modifications,
       *  but:
       *    in either case we simply stick with our first report.
       */
    }
    else {
      /** The simple case: this is the first one for this dav_id */
      $resultset = array(
        new XMLElement( 'href', ConstructURL($object->dav_name) ),
        new XMLElement( 'status', display_status($object->sync_status) )
      );
      if ( $object->sync_status != 404 ) {
        $dav_resource = new DAVResource($object);
        $resultset = array_merge( $resultset, $dav_resource->GetPropStat($proplist,$reply) );
      }
      $responses[] = new XMLElement( 'sync-response', $resultset );
      $first_status = $object->sync_status;
      $last_dav_id  = $object->dav_id;
    }
  }
  $responses[] = new XMLElement( 'sync-token', $new_token );
}
else {
  $request->DoResponse( 500, translate("Database error") );
}

$multistatus = new XMLElement( "multistatus", $responses, $reply->GetXmlNsArray() );

$request->XMLResponse( 207, $multistatus );