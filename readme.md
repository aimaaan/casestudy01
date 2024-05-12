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
2. [Observation Results](#obsv)
    a. [Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)](#serv)
    2. [Hash Disclosure](#hash)
    3. [CSRF](#csrf)
    4. [Secured Cookies](#sec)
    5. [CSP](#csp)
    6. [JS Library](#jsl)
    7. [HTTPS implementation (TLS/SSL)](#https)
    8. [Cookie Poisoning](#coo)
    9. [Potential XSS](#pot)
    10. [Information Disclosure](#inf)

## <a name="desc"/> Description

Our assigned web application is the Selangor Football Club official website. In this case study, our group will look into the vulnerabilities of the web application by scanning the website using OWASP ZAP using both the automated scan and manual explore.
We will mainly be focusing on automated scan due to the large amount of webpages the site has. <br>

The alerts observed are listed on the table of contents and we will also identify the level of risk for each alert and additional information on the classification of threats (CWE or CVE).

## <a name="obsv"/>Observation Results
### <a name="serv"/>a. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)

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


  
