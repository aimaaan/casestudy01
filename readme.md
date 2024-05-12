# Case Study

## Group Name

seeker

## Group Members

1. Ahmad Arif Aiman bin Ahmad Fauzi (2113419)
2. N
3. Z

## Assigned Tasks

1. Ahmad Arif Aiman bin Ahmad Fauzi (2113419)
    - Identify, evaluate and prevent of:
      - Information Gathering, Port scanning for open port  
      - Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)
      - Hash Disclosure
      - CSRF (Cross-Site Request Forgery)
      - Secured Cookies

2. Z ()
    - Identify, evaluate and prevent of:
      - csp
      - JS Library
      - HTTPS implementation (TLS/SSL)

3. N ()
    - Identify, evaluate and prevent of:
      - Cookie Poisoning
      - Potential XSS
      - Information Disclosure

## Table of Contents

1. [Description](#desc)
2. [Objectives](#obj)
3. [Observation Results](#obsv)
    1. [Information Gathering, Port scanning for open port](#port)
    2. [Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)](#serv)
    3. [Hash Disclosure](#hash)
    4. [CSRF](#csrf)
    5. [Secured Cookies](#sec)
    6. [CSP](#csp)
    7. [JS Library](#jsl)
    8. [HTTPS implementation (TLS/SSL)](#https)
    9. [Cookie Poisoning](#coo)
    10. [Potential XSS](#pot)
    11. [Information Disclosure](#inf)

## <a name="desc"/> Description

Our assigned web application is the Selangor Football Club official website. In this case study, our group will look into the vulnerabilities of the web application by scanning the website using OWASP ZAP using both the automated scan and manual explore.
We will mainly be focusing on automated scan due to the large amount of webpages the site has. <br>

The alerts observed are listed on the table of contents and we will also identify the level of risk for each alert and additional information on the classification of threats (CWE or CVE).

## <a name="obj"/> Objectives

The objectives of the case study are to identify, evaluate, and mitigate vulnerabilities on the Selangor FC official website. The specific goals are outlined as follows:
- Identify Vulnerabilities: Discover security vulnerabilities that could be exploited by attackers. These include, but are not limited to, SQL injection, cross-site scripting (XSS), broken authentication,          security misconfigurations, and exposure of sensitive data.
- Evaluate Vulnerabilities: Assess the risk associated with each identified vulnerability, considering both the potential impact and the likelihood of exploitation. This evaluation helps prioritize the             vulnerabilities that require urgent attention.
- Prevent Vulnerabilities: For each identified vulnerability, provide detailed recommendations on how to remediate or mitigate the risks. This includes both immediate fixes and longer-term strategies to enhance    the overall security posture of the website.

## <a name="obsv"/>Observation Results
### <a name="port"/>a. Information Gathering, Port scanning for open port
Information gathering through the external network using OSINT (Open-Source Intelligence) to identify and analyse data that can be seen on the internet.

| # | URL                     | Open Ports                        |
|---|-------------------------|-----------------------------------|
| 1 | https://selangorfc.com/ | Shodan Ext: 443                   |
|   |                         | Nmap: 80, 443                     |
|   |                         | OWASP Zap: 25, 80, 110, 563, 587, |
|   |                         | 465, 119, 143, 443                |

- Shodan extension:  https://selangorfc.com <br>
  ![shodan scan ](https://github.com/aimaaan/casestudy01/assets/99475237/ec66b7d0-ec5a-4f11-b3dc-cb3de8eb66b9)

- Wappalyzer Extension: https://selangorfc.com/ <br>
![wappalyzer scan](https://github.com/aimaaan/casestudy01/assets/99475237/feab017f-ba08-499b-ab2b-392ad23f6612)
Wappalyzer extension shows the web application technology stack used.

- Nmap scan: https://selangorfc.com/ <br>
  ![nmap scan details](https://github.com/aimaaan/casestudy01/assets/99475237/c720c622-aaca-48b1-a180-aebedd81461b)

- OWASP Zap scan: https://selangorfc.com/ <br>
![zap open port scanning](https://github.com/aimaaan/casestudy01/assets/99475237/919b03cd-052a-48c9-a14b-4d17dc9a0448)


### <a name="serv"/>b. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)

#### Identify:
- Old Asp.Net Version in Use <br>
![image](https://github.com/aimaaan/casestudy01/assets/99475237/0bd0246d-41fc-434d-88cd-e8eae5d25ac5)
  - CWE ID: 642 - External Control of Critical State Data
  - Risk level: Low
  - Confidence level: Medium
- Cross-Domain JavaScript Source File Inclusion <br>
![1 1](https://github.com/aimaaan/casestudy01/assets/99475237/83e87e10-eb3d-41e0-a1a7-ca710f0f8a68)
    - After scanning it shows 7987 result. however, after deep inspection the result are mostly Server-Side Scripting used is JavaScript as shown by the script source .js extension are from selangorFC domain and        googletagmanager in which they use it for google analytics.
    - CWE ID: 829 - Inclusion of Functionality from Untrusted Control Sphere
    - Risk level: Low
    - Confidence level: Medium

#### Evaluate:
- Old Asp.Net:
   - The web application server use uses ASP.NET version 1.0 or 1.1
   - Shows in the server header in URL: https://selangorfc.com/en/news/3349/Match%20Preview%20LS18%20%7C%20Selangor%20FC%20vs%20Sabah%20FC%20%7C%20Prepared%20and%20Motivated%20for%20Battle
- Cross-Domain:
   - The page includes one or more script files from a third-party domain.

#### Prevent:
- Old Asp.Net:
   - Ensure the engaged framework is still supported by Microsoft.
- Cross-Domain:
   - Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.

Observed examples of these exploits can be seen on their cwe mitre webpage accordingly.
References:
- https://cwe.mitre.org/data/definitions/642.html
- https://cwe.mitre.org/data/definitions/829.html


  
