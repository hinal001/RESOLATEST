<?php

namespace App\Classes;


class RESOService
{
	public static $validOutputFormats = array("json", "xml");
    	public static $requestAcceptType = "json";
	public static $validInputNamesUsername = array("username", "j_username", "user", "email");
	public static $validInputNamesPassword = array("password", "j_password", "pass");
	public static $isMbstringAvailable = null;
    	public static $isDomAvailable = null;
    	public static $isXmlAvailable = null;
   	

    	public static $curl = null;
    	public static $isCurlAvailable = null;
    	public static $defaultOptions;
    	public $userAgentInfo;
    	public static $cookieFile = ".resocookie";
    	const DEFAULT_TIMEOUT = 80;
    	const DEFAULT_CONNECT_TIMEOUT = 30;
    	const SDK_VERSION = '1.0.0';
    	public static $timeout = self::DEFAULT_TIMEOUT;
    	public static $connectTimeout = self::DEFAULT_CONNECT_TIMEOUT;


	 // @var string The RESO API client_id to be used for auth and query requests.
    public static $clientId;

    // @var string The RESO API client_secret to be used for auth and query requests.
    public static $clientSecret;

    // @var string The RESO API access token.
    public static $accessToken;

    // @var string The authentication / authorization URL for RESO API Auth service.
    public static $apiAuthUrl = '';

    // @var string The token request URL for RESO API Auth service.
    public static $apiTokenUrl = '';

    // @var string The base URL for RESO API Request service.
    public static $apiRequestUrl = '';

    // @var boolean Defaults to false.
    public static $verifySslCerts = false;

	// @var bool Logging (overall) enabled / disabled.
    public static $logEnabled = true;

    // @var bool Logging to console enabled / disabled.
    public static $logToConsole = true;

    // @var bool Logging to file enabled / disabled.
    public static $logToFile = true;

    // @var string Log file name enabled / disabled.
    public static $logFileName = 'out.log';



	 /**
     * Sets the RESO API client_id to be used for auth and query requests.
     *
     * @param string $clientId
     */
	
	

    public static function setClientId($clientId)
    {
        self::logMessage("Setting RESO API client id to '".$clientId."'.");
        self::$clientId = $clientId;
	//echo "</br> Client ID :: ". self::$clientId ."</br>";
    }


    public static function getClientId()
    {
        if(!self::$clientId) echo ("</br> API client_id is not set.");
        return self::$clientId;
    }

	/**
     * Sets the RESO API client_secret to be used for requests.
     *
     * @param string $clientSecret
     */
    public static function setClientSecret($clientSecret)
    {
        self::logMessage("Setting RESO API client secret.");
        self::$clientSecret = $clientSecret;

	//echo "</br> Client Secret :: ". self::$clientSecret ."</br>";
    }

    /**
     * @return string The RESO API client_secret used for auth and query requests.
     */
    public static function getClientSecret()
    {
        if(!self::$clientSecret) echo ("</br> API client_secret is not set.");
      	echo "</br>Get Client Secret :: ". self::$clientSecret ."</br>";
	  return self::$clientSecret;
    }

	/**
     * Sets the RESO API access token.
     *
     * @param string $accessToken
     */
    public static function setAccessToken($accessToken)
    {
        self::logMessage("Setting RESO API access token.");
        self::$accessToken = $accessToken;
	echo "</br> Access Token :: ". self::$accessToken ."</br>";
    }
	
    /**
     * @return string The RESO API access token.
     */
    public static function getAccessToken()
    {
	echo "</br>Get Access Token :: ". self::$accessToken ."</br>";
        return self::$accessToken;
    }

	/**
     * Sets the RESO API auth endpoint URL.
     *
     * @param string $apiAuthUrl
     */
    public static function setAPIAuthUrl($apiAuthUrl)
    {
        self::logMessage("Setting RESO API auth URL to '".$apiAuthUrl."'.");
        self::$apiAuthUrl = $apiAuthUrl;
    }

    /**
     * @return string The RESO API auth endpoint URL.
     */
    public static function getAPIAuthUrl()
    {
        if(!self::$apiAuthUrl) echo ("</br> API auth endpoint URL is not set.");
      	echo "</br> API Auth URL :: ". self::$apiAuthUrl ."</br>";
	return self::$apiAuthUrl;
    }

	/**
     * Sets the RESO API token endpoint URL.
     *
     * @param string $apiTokenUrl
     */
    public static function setAPITokenUrl($apiTokenUrl)
    {
        self::logMessage("Setting RESO API token URL to '".$apiTokenUrl."'.");
        self::$apiTokenUrl = $apiTokenUrl;
	//echo "</br> API Token URL :: ". self::$apiTokenUrl ."</br>";
    }


    /**
     * @return string The RESO API token endpoint URL.
     */
    public static function getAPITokenUrl()
    {
        if(!self::$apiTokenUrl) echo ("</br> API token endpoint URL is not set.");
	echo "</br> API Token URL :: ". self::$apiTokenUrl ."</br>";
        return self::$apiTokenUrl;
    }

	/**
     * Sets the RESO API request endpoint URL.
     *
     * @param string $apiRequestUrl
     */
    public static function setAPIRequestUrl($apiRequestUrl)
    {
        self::logMessage("Setting RESO API request URL to '".$apiRequestUrl."'.");
        self::$apiRequestUrl = $apiRequestUrl;
	//echo "</br> API Request URL :: ". self::$apiRequestUrl ."</br>";
    }


    /**
     * @return string The RESO API request endpoint URL.
     */
    public static function getAPIRequestUrl()
    {
        if(!self::$apiRequestUrl) echo ("</br> API request endpoint URL is not set.");
        return self::$apiRequestUrl;
    }


    /**
     * @return string The RESO API SDK version.
     */
    public static function getApiSdkVersion()
    {
        return self::$apiSdkVersion;
    }

	/**
     * Sets true / false to verify SSL certs in cURL requests.
     *
     * @param boolean $bool
     */
    public static function setVerifySslCerts($bool)
    {
        self::logMessage("Setting SSL certificate verification to '".(string)$bool."'.");
        self::$verifySslCerts = $bool;
    }


    /**
     * @return boolean True / false to verify SSL certs in cURL requests.
     */
    public static function getVerifySslCerts()
    {
        return self::$verifySslCerts;
    }

	/**
     * Sets true / false to enable logging to console.
     *
     * @param boolean $bool
     */
    public static function setLogConsole($bool) {
        self::$logToConsole = $bool;
    }


	/**
     * @return boolean True / false if output logging to console.
     */
    public static function getLogConsole() {
        return self::$logToConsole;
    }

	/**
     * Sets true / false to enable logging to file.
     *
     * @param boolean $bool
     */
    public static function setLogFile($bool) {
        self::$logToFile = $bool;
    }


	/**
     * @return boolean True / false if output logging to file.
     */
    public static function getLogFile() {
        return self::$logToFile;
    }

	/**
     * Sets log file name (if logging to file).
     *
     * @param string $file_name
     */
    public static function setLogFileName($file_name) {
        self::$logFileName = $file_name;
    }


	/**
     * @return string File path of the log file (if logging to file).
     */
    public static function getLogFileName() {
        return self::$logFileName;
    }





/**
get json formated data info => access token , URL 
*/

public static function getToken()
{
$url = "https://api-prod.corelogic.com/trestle/oidc/connect/token";
$username = "trestle_TerabitzIncTerabitz20190902044333";
$password = "8cca0eb5e93a4df18e59bfe937f0f7d9";
$jsonfile = "data.json";
$ch = curl_init($url);
$fh = fopen($jsonfile,'w') or die($php_errormsg);
$content = "grant_type=client_credentials&scope=api&client_id=".$username;
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_USERPWD, "$username:$password");
curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/x-www-form-urlencoded;charset=UTF-8','cache-control: no-cache'));
curl_setopt($ch, CURLOPT_POSTFIELDS, $content);
$data = curl_exec($ch);
$response = json_decode($data, true);


$http_status = curl_getinfo($ch);
echo '<pre>';
echo '</pre>';
curl_close ($ch);

         if(!$response || !is_array($response) || !isset($response["access_token"]))
                echo ("Failed to obtain access token.");

        //echo "</br> Access Token" . $response["access_token"] . "</br>";
        return $response["access_token"];
	//return $response;

}


	
	/**
     * Sends GET request and returns output in specified format.
     *
     * @param string $request
     * @param string $output_format
     * @param string $decode_json
     * @param string $accept_format
     *
     * @return mixed API Request response in requested data format.
     */
    public static function requestdata($request, $output_format = "json", $decode_json = true)
    {
        self::logMessage("Sending request '".$request."' to RESO API.");

        // Get variables
        $api_request_url = self::getAPIRequestUrl();
	$token = self::getToken();

        if(!in_array($output_format, self::$validOutputFormats)) {
            $output_format = "json";
        }

	
	echo ("</br> REQUEST :: ". $request);
        // Parse and validate request parameters
        $request = self::formatRequestParameters($request);
	
	echo ("</br> REQUEST AFTER FORMAT :: ". $request."</br> </br>");
        // Build request URL
        $url = rtrim($api_request_url, "/") . "/" . $request;

        // Set the accept type
        if(self::$requestAcceptType) {
            $accept = "application/".self::$requestAcceptType;
        } else {
            $accept = "*/*";
        }

        // Set headers
        $headers = array(
            "Accept: ".$accept,
            "Authorization: Bearer ".$token
        );

        // Send request
        $response = self::request("post", $url, $headers, null, false,);
        if(!$response || !is_array($response) || $response[1] != 200) {
            switch($response[1]) {
                case "406":
                    echo ("</br> API returned HTTP code 406 - Not Acceptable. Please, setup a valid Accept type using Request::setAcceptType(). Request URL: " . $api_request_url . "; Request string: " . $request . "; Response: " . $response[1]);
                default:
                    echo ("</br> Could not retrieve API response. Request URL: " . $api_request_url . "; Request string: " . $request . "; Response: " . $response[1]);
            }
        }

        // Decode the JSON response to PHP array, if $decode_json == true
        $is_json = self::isJson($response[0]);
        if($is_json && $output_format == "json" && $decode_json) {
            $return = json_decode($response[0], true);
            if(!is_array($response))
                echo ("</br> Could not decode API response. Request URL: ".$api_request_url."; Request string: ".$request."; Response: ".$response[0]);
        } elseif($is_json && $output_format == "xml") {
            $return = self::arrayToXml(json_decode($response[0], true));
        } else {
            $return = $response[0];
        }

        return $return;
    }

    /**
     * Sends POST request with specified parameters.
     *
     * @param string $request
     * @param array $params
     * @param string $accept_format
     *
     * @return mixed API Request response.
     */
    public static function requestPost($request, $params = array())
    {
        self::logMessage("Sending POST request '".$request."' to RESO API.");

        // Get variables
        $api_request_url = self::getAPIRequestUrl();
        $token = self::getToken();


        // Build request URL
        $url = rtrim($api_request_url, "/") . "/" . $request;

        // Set the accept type
        if(self::$requestAcceptType) {
            $accept = "application/".self::$requestAcceptType;
        } else {
            $accept = "*/*";
        }

        $headers = array(
            "Accept: ".$accept,
            "Authorization: Bearer ".$token
        );

        // Send request
        $response = $this->service::request("post", $url, $headers, $params, false);
        if(!$response || !is_array($response) || $response[1] != 200) {
            switch($response[1]) {
                case "406":
                    echo ("</br> API returned HTTP code 406 - Not Acceptable. Please, setup a valid Accept type using Request::setAcceptType(). Request URL: " . $api_request_url . "; Request string: " . $request . "; Response: " . $response[1]);
                default:
                    echo ("</br> Could not retrieve API response. Request URL: " . $api_request_url . "; Request string: " . $request . "; Response: " . $response[0]);
            }
        }

        // Decode the JSON response
        $is_json = self::isJson($response[0]);
        if($is_json) {
            $return = json_decode($response[0], true);
        } else {
            $return = $response[0];
        }

        return $return;
    }

    /**
     * Requests RESO API output and saves the output to file.
     *
     * @param string $file_name
     * @param string $request
     * @param string $output_format
     * @param bool $overwrite
     *
     * @return True / false output saved to file.
     */
    public static function requestToFile($file_name, $request, $output_format = "json", $overwrite = false, $accept_format = "json") {
        self::logMessage("Sending request '".$request."' to RESO API and storing output to file '".$file_name."'.");

        if(!$overwrite && is_file($file_name)) {
            echo ("</br> File '".$file_name."' already exists. Use variable 'overwrite' to overwrite the output file.");
        }

        if(!is_dir(dirname($file_name))) {
            echo ("</br> Directory '".dir($file_name)."' does not exist.");
        }

        $output_data = self::requestdata($request, $output_format, false, $accept_format);
        if(!$output_data) {
            self::logMessage("Request output save to file failed - empty or erroneous data.");
            return false;
        }

        file_put_contents($file_name, $output_data);
        if(!is_file($file_name)) {
            self::logMessage("Request output save to file failed - could not create output file.");
            return false;
        }

        self::logMessage("Request output save to file succeeded.");
        return true;
    }

    /**
     * Requests RESO API metadata output.
     *
     * @return Metadata request output.
     */
    public static function requestMetadata() {
        self::logMessage("Requesting resource metadata.");
        return self::requestdata("\$metadata");
    }

    /**
     * Sets accept Accept content type in all requests.
     *
     * @param string
     */
    public static function setAcceptType($type = "") {
        if(in_array($type, self::$validOutputFormats)) {
            self::$requestAcceptType = $type;
        }
    }

    /**
     * Formats request parameters to compatible string
     *
     * @param string
     */
    public static function formatRequestParameters($parameters_string) {
        parse_str($parameters_string, $parsed);
        if(!is_array($parsed) || empty($parsed)) {
            echo ("</br> Could not parse the request parameters.");
        }

        $params = array();
        foreach($parsed as $key => $param) {
            if($param) {
                $params[] = $key . "=" . rawurlencode($param);
            } else {
                $params[] = $key;
            }
        }

        return implode("&", $params);
    }

    /**
     * Retrieves RESO API auth login page URL.
     *
     * @param string $redirect_uri
     * @param string $scope
     *
     * @return string RESO API auth login page URL.
     */
    public static function getLoginUrl($redirect_uri, $scope = "api")
    {
        // Get variables
        $api_auth_url = self::getAPIAuthUrl();
        $client_id = self::getClientId();

        // Authentication request parameters
        $params = array(
            "client_id" => $client_id,
            "scope" => $scope,
            "redirect_uri" => $redirect_uri,
            "response_type" => "code"
        );
	
	echo ($api_auth_url . "?" . http_build_query($params));
        return $api_auth_url . '?' . http_build_query($params);
    }

	/**
     * @param array $array
     * @param SimpleXMLElement &$xml
     *
     * @return bool True if the string is JSON, otherwise - False.
     */
    public static function _arrayToXml($array, &$xml) {
        foreach ($array as $key => $value) {
            if(is_array($value)){
                if(is_int($key)){
                    $key = "e";
                }
                $label = $xml->addChild($key);
                self::_arrayToXml($value, $label);
            }
            else {
                $xml->addChild($key, htmlspecialchars($value));
            }
        }
    }

/**
     * @param array $array
     *
     * @return string Returns XML formatted string.
     */
    public static function arrayToXml($array) {
        if (self::$isXmlAvailable === null) {
            self::$isXmlAvailable = function_exists('simplexml_load_file');

            if (!self::$isXmlAvailable) {
                echo ("</br> It looks like the XML extension is not enabled. " .
                    "XML extension is required to use the RESO API , if the request response format is set to XML.");
            }
        }

        $xml = new \SimpleXMLElement('<root/>');
        self::_arrayToXml($array, $xml);
        return $xml->asXML();
    }

 /**
     * @param string $string
     *
     * @return bool True if the string is JSON, otherwise - False.
     */
    public static function isJson($string) {
        if(is_numeric($string)) return false;
        json_decode($string);
        return (json_last_error() == JSON_ERROR_NONE);
    }


 /**
     * @param array $arr A map of param keys to values.
     * @param string|null $prefix
     *
     * @return string A querystring, essentially.
     */
    public static function urlEncode($arr, $prefix = null)
    {
        if (!is_array($arr)) {
            return $arr;
        }

        $r = array();
        foreach ($arr as $k => $v) {
            if (is_null($v)) {
                continue;
            }

            if ($prefix) {
                if ($k !== null && (!is_int($k) || is_array($v))) {
                    $k = $prefix."[".$k."]";
                } else {
                    $k = $prefix."[]";
                }
            }

            if (is_array($v)) {
                $enc = self::urlEncode($v, $k);
                if ($enc) {
                    $r[] = $enc;
                }
            } else {
                $r[] = urlencode($k)."=".urlencode($v);
            }
        }

        return implode("&", $r);
    }


	/**
     * @param string|mixed $value A string to UTF8-encode.
     *
     * @return string|mixed The UTF8-encoded string, or the object passed in if
     *    it wasn't a string.
     */
    public static function utf8($value)
    {
        if (self::$isMbstringAvailable === null) {
            self::$isMbstringAvailable = function_exists('mb_detect_encoding');

            if (!self::$isMbstringAvailable) {
                trigger_error("It looks like the mbstring extension is not enabled. " .
                    "UTF-8 strings will not properly be encoded.", E_USER_WARNING);
            }
        }

        if (is_string($value) && self::$isMbstringAvailable && mb_detect_encoding($value, "UTF-8", true) != "UTF-8") {
            return utf8_encode($value);
        } else {
            return $value;
        }
    }

	/**
     * Sets true / false to enable logging (overall).
     *
     * @param boolean $bool
     */
    public static function setLogEnabled($bool) {
        self::$logEnabled = $bool;
    }

	/**
     * @return boolean True / false if logging (overall) is enabled.
     */
    public static function getLogEnabled() {
        return self::$logEnabled;
    }


	public static function getTimeString() {
        return "[".date("c")."]";
    }

	public static function logMessage($message) {
        if(!self::getLogEnabled()) {
            return false;
        }

        if(self::getLogConsole()) {
            self::logConsole($message);
        }

        if(self::getLogFile() && self::getLogFileName()) {
            self::logFile(self::getLogFileName(), $message);
        }
    }

    public static function logConsole($message) {
        $message = self::getTimeString()." ".$message;
        echo("</br>". $message."</br>");
        return true;
    }

    public static function logFile($file_name, $message) {
        $message = self::getTimeString()." ".$message;
        if(is_dir(dirname($file_name))) {
            file_put_contents($file_name, $message . "</br>", FILE_APPEND);
            return true;
        } else {
            return false;
        }
    }

    public function initUserAgentInfo()
    {
        $curlVersion = curl_version();
	echo ("</br> CURL VERSION ::: ".$curlVersion."</br>");
        $this->userAgentInfo = array(
            'httplib' =>  'curl ' . $curlVersion['version'],
            'ssllib'  => $curlVersion['ssl_version'],
            'sdkInfo' => "RESO-RETS-SDK/" . self::SDK_VERSION
        );
	var_dump($this->userAgentInfo);
    }

    public function getUserAgentInfo()
    {
        return $this->userAgentInfo;
    }

    public function setTimeout($seconds)
    {
        $this->timeout = (int) max($seconds, 0);
        return $this;
    }

    public function setConnectTimeout($seconds)
    {
        $this->connectTimeout = (int) max($seconds, 0);
        return $this;
    }

    public function getTimeout()
    {
        return $this->timeout;
    }

    public function getConnectTimeout()
    {
        return $this->connectTimeout;
    }

   public static function addGetParamFromUrl(&$url, $varName, $value)
                {
                        try
                        {
                                if (strpos($url, "?"))
                                {
                           $str = $url  . "&" . $varName . "=" . $value;
                                }
                                else
                                {
                           $str = $url  . "?" . $varName . "=" . $value;

                                }
                                return $str;
                        }
                        catch(Exception $e)
                        {
                                return $e->getMessage();
                        }
                }

	
    public static function request($method, $absUrl, $headers, $params, $hasFile)
    {

        if($headers == null || !is_array($headers)) {
            $headers = array();
        }

        if(!static::$curl) {
            static::$curl = curl_init();
        }

        $method = strtolower($method);

        $opts = array();
	
	$opts = self::$defaultOptions;
        if ($method == 'get') {
            if ($hasFile) {
                echo (
                    "</br> Issuing a GET request with a file parameter"
                );
            }
            $opts[CURLOPT_HTTPGET] = 1;
            if (is_array($params) && count($params) > 0) {
                $encoded = self::urlEncode($params);
                $absUrl = "$absUrl?$encoded";
            }
        } elseif ($method == 'post') {
		if (is_array($params) && count($params) > 0) {
            $opts[CURLOPT_POST] = count($params);
            $opts[CURLOPT_POSTFIELDS] = $hasFile ? $params : self::urlEncode($params);
		echo ("OPTS ::: ");
		}
        } else {
            echo ("</br> Unrecognized method $method");
        }

        // Create a callback to capture HTTP headers for the response
        $rheaders = array();
        $headerCallback = function ($curl, $header_line) use (&$rheaders) {
            // Ignore the HTTP request line (HTTP/1.1 200 OK)
            if (strpos($header_line, ":") === false) {
                return strlen($header_line);
            }
            list($key, $value) = explode(":", trim($header_line), 2);
            $rheaders[trim($key)] = trim($value);
            return strlen($header_line);
        };

        $absUrl = self::utf8($absUrl);
        $opts[CURLOPT_URL] = $absUrl;
        $opts[CURLOPT_RETURNTRANSFER] = 1;
        $opts[CURLOPT_FOLLOWLOCATION] = true;
        $opts[CURLOPT_AUTOREFERER] = true;
        $opts[CURLOPT_COOKIESESSION] = true;
        $opts[CURLOPT_COOKIEJAR] = ".resocookie";
        $opts[CURLOPT_COOKIEFILE] = ".resocookie";
        $opts[CURLOPT_CONNECTTIMEOUT] = 30;
        $opts[CURLOPT_TIMEOUT] = 80;
        $opts[CURLOPT_HEADERFUNCTION] = $headerCallback;
        if($headers) {
		$opts[CURLOPT_HTTPHEADER] = $headers;
        }
        if (!self::$verifySslCerts) {
            $opts[CURLOPT_SSL_VERIFYHOST] = false;
            $opts[CURLOPT_SSL_VERIFYPEER] = false;
        }

	 curl_setopt_array(self::$curl, $opts);
        $rbody = curl_exec(self::$curl);
	var_dump($rbody);
	$curlerror = curl_error(self::$curl);
        if ($rbody === false) {
            $errno = curl_errno(self::$curl);
            $message = curl_error(self::$curl);
        }

        $curlInfo = curl_getinfo(self::$curl);
	var_dump($curlInfo);
        return array($rbody, $curlInfo["http_code"], $rheaders, $curlInfo);
    }

    public function close() {
        if($this->curl) {
            curl_close($this->curl);
            $this->curl = null;
        }
    }
	

}


