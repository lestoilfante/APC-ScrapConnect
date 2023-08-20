<?php
/**
 * APC-ScrapConnect
 *
 * APC-ScrapConnect is an utility script made to interact with APC SmartConnect cloud platform.
 * Since APC doesn't provide (yet?!) an API this program runs through platform's [SUPEREVIL] login
 * process and retrieve available devices data.
 * Session cookies are reused whenever possible but kept unique for each device.
 *
 * Usage:
 *  # Return a basic subset of properties for each device registered on platform
 *      APC-ScrapConnect.php <username> <password> list
 *  # Return log events since datetime(ISO8601 UTC format) for all devices, defaults to last hour
 *      APC-ScrapConnect.php <username> <password> events [datetime]
 *  # Return generic info for supplied device_id
 *      APC-ScrapConnect.php <username> <password> gwinfo <device_id>
 *  # Return detailed status for supplied device_id
 *      APC-ScrapConnect.php <username> <password> gwdetails <device_id>
 *  # Return log events since datetime(ISO8601 UTC format) for supplied device_id, defaults to last hour
 *      APC-ScrapConnect.php <username> <password> gwevents <device_id> [datetime]
 *  # Return SmartConnect platform's dictionary, useful for digging into JSON returned data
 *      APC-ScrapConnect.php <username> <password> dict
 *  # Search for device with provided serialnumber or IP and return a basic subset of properties
 *     Designed for easy integration with Zabbix discovery rules and LLD macro
 *      APC-ScrapConnect.php <username> <password> discovery <device_sn> [device_ip]
 *
 * Output:
 *  JSON string with "Data" and "Error" properties.
 *   "Data" contains actual data retrieved from APC platform
 *   "Error" is set to null in case of success
 *
 * Note: Ensure you have php-curl installed and enabled on your system before running the script.
 *
 * [Copyright 2023 lestoilfante](https://github.com/lestoilfante)
 *
 * Credits:
 *  apc-smartconnect-py made by Anders Birkenes for enlightening login process
 *  on https://github.com/datagutten/apc-smartconnect-py
 */
error_reporting(0);
if($argc < 4){
    exit(ApcScrapConnect::SetOutput(null, 'Invalid parameter provided'));
}
try {
    switch(strtolower($argv[3])){
        case 'list':
            $Apc = new ApcScrapConnect($argv[1], $argv[2]);
            exit($Apc->GetGetawaysBasics());
            break;
        case 'discovery':
            if(isset($argv[4]) && !empty($argv[4])) {
                $inputSanitized = preg_replace('/[^a-zA-Z0-9-_]/', '', $argv[4]);
                $Apc = new ApcScrapConnect($argv[1], $argv[2],$inputSanitized);
                exit($Apc->GetawayZabbixDiscovery($inputSanitized));
            }
            elseif(isset($argv[5]) && !empty($argv[5])) {
                if(filter_var($argv[5], FILTER_VALIDATE_IP) === false)
                    exit(ApcScrapConnect::SetOutput(null, 'Invalid IP provided'));
                $Apc = new ApcScrapConnect($argv[1], $argv[2], $argv[5]);
                exit($Apc->GetawayZabbixDiscovery($argv[5]));
            }
            break;
        case 'events':
            $Apc = new ApcScrapConnect($argv[1], $argv[2]);
            if(isset($argv[4]))
                exit($Apc->GetEvents($argv[4]));
            else
                exit($Apc->GetEvents());
            break;
        case 'gwinfo':
            if (isset($argv[4]) && CheckValidId($argv[4])) {
                $Apc = new ApcScrapConnect($argv[1], $argv[2], $argv[4]);
                exit($Apc->GetGateway($argv[4]));
            }
            break;
        case 'gwdetails':
            if (isset($argv[4]) && CheckValidId($argv[4])) {
                $Apc = new ApcScrapConnect($argv[1], $argv[2], $argv[4]);
                exit($Apc->GetGatewayDetails($argv[4]));
            }
            break;
        case 'gwevents':
            if (isset($argv[4]) && CheckValidId($argv[4])) {
                $Apc = new ApcScrapConnect($argv[1], $argv[2], $argv[4]);
                if(isset($argv[5]))
                    exit($Apc->GetGatewayEvents($argv[4], $argv[5]));
                else
                    exit($Apc->GetGatewayEvents($argv[4]));
            }
            break;
        case 'dict':
            $Apc = new ApcScrapConnect($argv[1], $argv[2]);
            exit($Apc->GetDictionaries());
            break;
        default:
            exit(ApcScrapConnect::SetOutput(null, 'Invalid function'));
            break;
    }
}
catch (Exception $e) {
    exit(ApcScrapConnect::SetOutput(null, 'Ooops something went very wrong'));
}


function CheckValidId($gwId){
    if(!ctype_alnum($gwId) || strlen($gwId) < 10 || strlen($gwId) > 15)
        exit(ApcScrapConnect::SetOutput(null, 'Invalid gateway id provided'));
    else
        return true;
}

class ApcScrapConnect
{
    const BASE_DOMAIN = 'https://smartconnect.apc.com';
    const INIT_AUTH_URI = self::BASE_DOMAIN . '/auth/login';
    const API_URI = self::BASE_DOMAIN . '/api/v1';
    const GW_URI = self::API_URI . '/gateways';
    const DICT_URI = self::API_URI . '/dictionaries/en';

    const COOKIE_FILE = 'APC-ScrapConnectCookieJar';
    
    private $username;
    private $password;
    private $session;
    private $httpBaseLocation;

    public function __construct($user, $pass, $gwId = null)
    {
        $this->username = $user;
        $this->password = $pass;
        // Build a unique cookie tightened to caller/user/device
        $cookieFile = self::COOKIE_FILE . posix_getuid() . $user;
        switch($gwId){
            //
            case null:
                $cookieFile = $cookieFile;
                break;
            // GatewayID
            default:
                $cookieFile = $cookieFile . $gwId;
                break;
        }
        $tmpFolder = sys_get_temp_dir();
        $cookieFileUnique = $tmpFolder . '/' . hash('md5', $cookieFile) . '.apcsc';

        $this->session = curl_init();
        curl_setopt_array($this->session, array(
            CURLOPT_COOKIEFILE => $cookieFileUnique,
            CURLOPT_COOKIEJAR => $cookieFileUnique,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => 'gzip, deflate, br',
            CURLOPT_HTTPHEADER => array(
                'Accept-Language: nb-NO,nb;q=0.9,no;q=0.8,nn;q=0.7,en-US;q=0.6,en;q=0.5,da;q=0.4,und;q=0.3',
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36'
            ),
        ));
    }

    public function __destruct()
    {
        curl_close($this->session);
    }

    public function Login() {
        try {
            // disable redirect
            curl_setopt($this->session, CURLOPT_FOLLOWLOCATION, false);
            // GET to initial url (should return a 302 redirect to some https://secureidentity.schneider-electric.com dynamic url)
            curl_setopt($this->session, CURLOPT_URL, self::INIT_AUTH_URI);
            $response = curl_exec($this->session);
            $location = curl_getinfo($this->session, CURLINFO_REDIRECT_URL);
            if (substr($location, 0, 4) !== 'http') {
                exit(ApcScrapConnect::SetOutput(null, 'Invalid redirect'));
            }
            // GET to redirect location and parse response body where javascript code sets document.cookie and a relative path document.location
            $httpBaseLocation = $this->Get_HttpBaseUrl($location);
            curl_setopt($this->session, CURLOPT_URL, $location);
            $response = curl_exec($this->session);
            $this->Set_JS_Cookies($response, $this->session, $httpBaseLocation);
            $auth_url_location = $httpBaseLocation . $this->Get_JS_Redirect($response);

            // GET to custom auth_url_location (following a 302 redirect) then parse response
            curl_setopt($this->session, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($this->session, CURLOPT_URL, $auth_url_location);
            $response = curl_exec($this->session);
            $jid_step1 = $this->Get_jid($response, 1);
            $jid_step2 = $this->Get_jid($response, 2);
            $sf_keys1 = $this->Get_Salesforce_Keys($response);
            $formAuthUrl = $httpBaseLocation . $this->Get_FormAuth_Url($response);

            // POST to login url, step #1
            $login_payload1 = $this->Build_Login_Payload($this->username, $jid_step1, $sf_keys1);
            curl_setopt($this->session, CURLOPT_FOLLOWLOCATION, false);
            curl_setopt($this->session, CURLOPT_URL, $formAuthUrl);
            curl_setopt($this->session, CURLOPT_POSTFIELDS, $login_payload1);
            curl_setopt($this->session, CURLOPT_POST, true);
            $response = curl_exec($this->session);
            $sf_keys2 = $this->Get_Salesforce_Keys($response);
            // POST to login url, step #2
            $login_payload2 = $this->Build_Login_Payload($this->password, $jid_step2, $sf_keys2);
            curl_setopt($this->session, CURLOPT_URL, $formAuthUrl);
            curl_setopt($this->session, CURLOPT_POSTFIELDS, $login_payload2);
            curl_setopt($this->session, CURLOPT_POST, true);
            $response = curl_exec($this->session);

            // GET to location in meta tag and parse JS location.replace
            $frontDoorUrl = $this->Get_MetaLocation($response);
            curl_setopt($this->session, CURLOPT_POST, false);
            //curl_setopt($this->session, CURLOPT_POSTFIELDS, NULL);
            curl_setopt($this->session, CURLOPT_URL, $frontDoorUrl);
            $response = curl_exec($this->session);
            $redirUrl = $this->Get_JS_Redirect($response);
            // GETs following JS redirect chain
            curl_setopt($this->session, CURLOPT_URL, $redirUrl); //apex
            $response = curl_exec($this->session);
            $redirUrl = $this->Get_JS_Redirect($response, $httpBaseLocation);
            curl_setopt($this->session, CURLOPT_URL, $redirUrl); //setup
            $response = curl_exec($this->session);
            $redirUrl = $this->Get_JS_Redirect($response);
            curl_setopt($this->session, CURLOPT_URL, $redirUrl); //check
            $response = curl_exec($this->session);
            if(curl_getinfo($this->session, CURLINFO_HTTP_CODE) === 302){
                return true;
            }
        }
        catch (Exception $e) {
            return false;
        }
        return false;
    }

    private function Set_JS_Cookies($page, $session, $baseLocation) {
        $domain = str_replace(array('http://', 'https://'), '', $baseLocation);
        if (preg_match_all('/document\.cookie = [\'|"](.*?)[\'|"];/', $page, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $cookie_line = 'Set-Cookie: ' . $match[1]. '; domain=' . $domain;
                curl_setopt($session, CURLOPT_COOKIELIST, $cookie_line);
            }
        }
    }

    private function Get_JS_Redirect($page, $baseUrl = null) {
        $out = null;
        if (preg_match('/window\.location = ["|\'](.*?)["|\']/', $page, $matches)) {
            $out = $matches[1];
        }
        elseif (preg_match('/window\.location\.replace\([\'|"](.*?)[\'|"]\)/', $page, $matches)) {
            if (substr($matches[1], 0, 4) === 'http'){
                $out = $matches[1];
            }
            else{
                $out = $baseUrl . $matches[1];
            }
        } 
        return $out;
    }

    private function Get_HttpBaseUrl($url) {
        $out = null;
        if (preg_match('/^(https:\/\/.+?)\//', $url, $matches)) {
            $out = $matches[1];
        }
        return $out;
    }

    private function Get_jid($page, $step) {
        if (preg_match('/dicvLogin' . $step . 'Act.*Submit\([\'|"](j_id0:j_id[0-9]+).+?similarityGroupingId.+?(j_id0:j_id\d+:j_id\d+)[\'|"]/', $page, $matches)) {
            return array($matches[1], $matches[2]);
        }
        return null;
    }

    private function Get_Salesforce_Keys($page) {
        if (preg_match_all('/name="(com\.salesforce\.visualforce\..*?)"\s+value="(.*?)"/', $page, $matches, PREG_SET_ORDER)) {
            $keys = array();
            foreach ($matches as $match) {
                $keys[$match[1]] = $match[2];
            }
            return $keys;
        }
        return null;
    }

    private function Get_FormAuth_Url($page) {
        if (preg_match('/<form.*?action=[\'|"](\/.*?)[\'|"]/', $page, $matches)) {
            $out = $matches[1];
            return $out;
        }
        return null;
    }

    private function Build_Login_Payload($credentialParam, $jid, $sf_keys) {
        $data = array(
            'AJAXREQUEST' => '_viewRoot',
            $jid[0] => $jid[0],
            $jid[1] => $jid[1],
            'usrname' => $credentialParam,
            '' => ''
        );
        $payloadEncoded = http_build_query(array_merge($data, $sf_keys));
        return $payloadEncoded;
    }

    private function Get_MetaLocation($page) {
        if (preg_match('/<meta name=.Location.*?content=["|\'](.+?)["|\']/', $page, $matches)) {
            $out = $matches[1];
            return $out;
        }
        return null;
    }

    private function Get($uri) {
        curl_setopt($this->session, CURLOPT_URL, $uri);
        $response = curl_exec($this->session);
        if(curl_getinfo($this->session, CURLINFO_HTTP_CODE) === 401){
            if($this->Login() === true){
                curl_setopt($this->session, CURLOPT_URL, $uri);
                return $this->SetOutput(curl_exec($this->session));
            }
            else{
                return($this->SetOutput(null, 'SmartConnect login failed'));
            }
        }
        return $this->SetOutput($response);
    }

    public function GetGateways() {
        return $this->get(self::GW_URI);
    }

    public function GetGateway($gateway_id) {
        return $this->get(self::GW_URI .'/'. $gateway_id);
    }

    public function GetGatewayDetails($gateway_id, $sub = null) {
        if($sub === null)
            return $this->get(self::GW_URI .'/'. $gateway_id . '?collection=input,output,battery,network,main_outlet,switched_outlets');
        else
            return $this->get(self::GW_URI .'/'. $gateway_id . '?collection=' . $sub);
    }

    public function GetDictionaries() {
        return $this->get(self::DICT_URI);
    }

    public function GetEvents($startDate = null) {
        // Regular expression pattern for ISO 8601 date-time format (2023-07-20T22:00:00.000Z)
        $iso8601Pattern = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/';
        if($startDate === null ){
            $date = new DateTime('now', new DateTimeZone('UTC'));
            $startDate = $date->sub(new DateInterval('PT1H'));
        }
        elseif(!preg_match($iso8601Pattern, $startDate)){
            return($this->SetOutput(null, 'Invalid start date provided'));
        }
        return $this->get(self::GW_URI .'/'. 'events/all?from=' . $startDate);
    }

    public function GetGatewayEvents($gateway_id, $startDate = null) {
        $evts = json_decode($this->GetEvents($startDate), true);
        if($evts['Error'] === null && isset($evts['Data'])){
            $filteredData = array_filter($evts['Data'], function($entry) use ($gateway_id) {
                    return isset($entry['deviceId']) && $entry['deviceId'] === $gateway_id;
                });
            return $this->SetOutput(json_encode($filteredData), null, true);
        }
        else
            return($this->SetOutput(null, 'Something went wrong retrieving device data (' . $evts['Error'] . ')'));
    }

    public function GetGatewaysId()
    {
        $gws = json_decode($this->GetGateways());
        if($gws->Error === null && isset($gws->Data->gateways)){
            $ids = array_map(function($obj) {
                    return $obj->deviceId;
                }, $gws->Data->gateways);
            return $this->SetOutput(json_encode($ids));
        }
        return($this->SetOutput(null, 'Something went wrong retrieving device data (' . $gws->Error . ')'));
    }

    public function GetGetawaysBasics(){
        $gws = json_decode($this->GetGateways(), true);
        if ($gws['Error'] === null && isset($gws['Data']['gateways']) && is_array($gws['Data']['gateways'])) {
            $gwsPropertiesSubset = array();
            foreach ($gws['Data']['gateways'] as $gateway) {
                $gwdetail = json_decode($this->GetGatewayDetails($gateway['deviceId'], 'network'), true);
                if ($gwdetail['Error'] === null && isset($gwdetail['Data']['network']['interface']['ipAddress'])) {
                    $subset = array(
                        'model' => $gateway['model'],
                        'serialNumber' => $gateway['serialNumber'],
                        'name' => $gateway['name'],
                        'ipAddress' => $gwdetail['Data']['network']['interface']['ipAddress'],
                        'deviceId' => $gateway['deviceId']
                        );
                    $gwsPropertiesSubset[] = $subset;
                }
                else
                    return($this->SetOutput(null, 'Something went wrong retrieving device data ('  . $gwdetail['Error'] . ')'));
            }
            $result = array('gateways' => $gwsPropertiesSubset);
            return $this->SetOutput(json_encode($result));
        }
        else
            return($this->SetOutput(null, 'Something went wrong retrieving device data (' . $gws['Error'] . ')'));
    }

    public function GetawayZabbixDiscovery($sn_or_ip){
        $id = null;
        $sn = null;
        $gws = json_decode($this->GetGateways(), true);
        if ($gws['Error'] === null && isset($gws['Data']['gateways']) && is_array($gws['Data']['gateways'])) {
            $gwsPropertiesSubset = array();
            // SN Discovery
            if (filter_var($sn_or_ip, FILTER_VALIDATE_IP) === false) {
                foreach ($gws['Data']['gateways'] as $gateway) {
                    if(isset($gateway['serialNumber']) && $gateway['serialNumber'] === $sn_or_ip) {
                        $id = $gateway['deviceId'];
                        $sn = $gateway['serialNumber'];
                        break;
                    }
                }
            }
            // IP Discovery
            else {
                foreach ($gws['Data']['gateways'] as $gateway) {
                    $gwdetail = json_decode($this->GetGatewayDetails($gateway['deviceId'], 'network'), true);
                    if ($gwdetail['Error'] === null && isset($gwdetail['Data']['network']['interface']['ipAddress'])) {
                        if ($gwdetail['Data']['network']['interface']['ipAddress'] === $sn_or_ip) {
                            $id = $gateway['deviceId'];
                            $sn = $gateway['serialNumber'];
                            break;
                        }
                     }
                     else
                        return($this->SetOutput(null, 'Something went wrong retrieving device data ('  . $gwdetail['Error'] . ')'));
                }
            }
            if(!isset($id))
                return($this->SetOutput(null, 'No device found with data provided'));
            $_dictionary = json_decode($this->GetDictionaries(), true);
            $dictionary = ($_dictionary['Error'] === null && isset($_dictionary['Data'])) ? $_dictionary['Data'] : null;
            if(!isset($dictionary))
                return($this->SetOutput(null, 'Something went wrong retrieving platform dictionary'));
            $evts = array();
            foreach ($dictionary as $key => $event) {
                if(isset($event["event"]["name"]) && !empty($event["event"]["name"]) && isset($event["severity"]) && !empty($event["severity"])) {
                    $evts[] = array(
                        "K" => $key,
                        "D" => trim(preg_replace('/\{\{.*?\}\}/', '', $event["event"]["name"])),
                        "S" => $event["severity"],
                        );
                }
            }
            $discovery = array(
                        "{#SN}" => $sn,
                        "{#ID}" => $id,
                        "{#EVTS}" => json_encode($evts),
                        );            
            return $this->SetOutput(json_encode(array($discovery)));
        }
        else
            return($this->SetOutput(null, 'Something went wrong retrieving device data (' . $gws['Error'] . ')'));
    }

    public static function SetOutput($data, $error = null, $allowNoData = false){
        $d = json_decode($data);
        $out = array(
            'Data' => $d,
            'Error' => $error,
        );
        if ($error === null && $d === null && $allowNoData === false)
            $out['Error'] = 'Invalid data';
        return json_encode($out);
    }
}

?>