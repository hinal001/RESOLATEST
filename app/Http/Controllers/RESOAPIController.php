<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use App\Classes\RESOService;

class RESOAPIController extends Controller
{
	public $service;
	
	public function __construct(RESOService $service)
	{
                $this->service = $service;
	}


function getjsondata()
{
/*	// Set the variables
$id = $service::setClientId($client_id);
$secret = $service::setClientSecret($client_secret);
$url = $service::setAPIAuthUrl($api_auth_url);
$tokenurl = $service::setAPITokenUrl($api_token_url);
$requesturl = $service::setAPIRequestUrl($api_request_url);
*/

$username = "trestle_TerabitzIncTerabitz20191106022917";
$password = "66431b29f97c46768eee35abb9b4692f";

$id = $this->service::setClientId($username);
$secret = $this->service::setClientSecret($password);
$url = $this->service::setAPIAuthUrl('https://api-prod.corelogic.com/trestle/oidc/connect/token');
$tokenurl = $this->service::setAPITokenUrl('https://api-prod.corelogic.com/trestle/oidc/connect/token');
$requesturl = $this->service::setAPIRequestUrl('https://api-prod.corelogic.com/trestle/odata/');


$this->service::setAcceptType("json");


$class = "Property?";
//$data = $this->service::requestdata("Property?\$top=10", "json", true);
//$data = $this->service::requestdata("Property?\$filter=OriginatingSystemName eq 'SAV'" , "json", true);
//$data = $this->service::requestdata("Property?\$filter=OriginatingSystemName eq 'SAV'&\$top=2 " , "json", true);
//$data = $this->service::requestdata("Property?\$filter=OriginatingSystemName eq 'SAV'&\$filer=StandardStatus eq 'ComingSoon' or StandardStatus eq 'Active'");
//$data = $this->service::requestdata("Property?\$filter=OriginatingSystemName eq 'SAV'&\$select=StandardStatus,ListingId");
$data = $this->service::addGetParamFromUrl($class,'$filter',"OriginatingSystemName eq 'SAV'");
$data = $this->service::addGetParamFromUrl($data,'$select','StandardStatus,ListingId');
//$data = $this->service::addGetParamFromUrl($data,'$expand','Media($select=ShortDescription,LongDescription,MediaCategory,Order,MediaURL;$orderby=Order)');
$data = $this->service::requestdata($data, "json", true);
// Display records
//echo "Records retrieved from RESO API: ".count($data["value"])."\n\nRecords:\n";
print_r($data);

// Save output to file
//$this->service::requestToFile("checkjsondata.json","Property?\$filter=OriginatingSystemName eq 'SAV'&\$select=StandardStatus,ListingId" , "json", true , "json");
}


}

