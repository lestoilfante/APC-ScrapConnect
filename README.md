# APC-ScrapConnect

APC-ScrapConnect is an utility script made to interact with APC SmartConnect cloud platform.
Since APC doesn't provide (yet?!) an API this program runs through platform's **SUPEREVIL** login
process and retrieve available devices data.
Session cookies are reused whenever possible but kept unique for each device.

## Usage
 #### Return a basic subset of properties for each device registered on platform
     APC-ScrapConnect.php <username> <password> list
 #### Return log events since datetime(ISO8601 UTC format) for all devices, defaults to last hour
     APC-ScrapConnect.php <username> <password> events [datetime]
 #### Return generic info for supplied device_id
     APC-ScrapConnect.php <username> <password> gwinfo <device_id>
 #### Return detailed status for supplied device_id
     APC-ScrapConnect.php <username> <password> gwdetails <device_id>
 #### Return log events since datetime(ISO8601 UTC format) for supplied device_id, defaults to last hour
     APC-ScrapConnect.php <username> <password> gwevents <device_id> [datetime]
 #### Return SmartConnect platform's dictionary, useful for digging into JSON returned data
     APC-ScrapConnect.php <username> <password> dict
 #### Search for device with provided serialnumber or IP and return a basic subset of properties
    Designed for easy integration with Zabbix discovery rules and LLD macro
     APC-ScrapConnect.php <username> <password> discovery <device_sn> [device_ip]

## Output
 JSON string with "Data" and "Error" properties.
  "Data" contains actual data retrieved from APC platform
  "Error" is set to null in case of success

### Note
 Ensure you have php-curl installed and enabled on your system before running the script.

## License & Copyright

[Copyright 2023 lestoilfante](https://github.com/lestoilfante)

GNU General Public License version 3 (GPLv3)

## Credits:
 apc-smartconnect-py made by [Anders Birkenes](https://github.com/datagutten/) for enlightening the login process
