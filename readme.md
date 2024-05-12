# Case Study

## Group Name

seeker

## Group Members

1. Ahmad Arif Aiman bin Ahmad Fauzi (2113419)
2. Muhammad Nasrullah Bin Mat Radzi (2013677)
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

3. Muhammad Nasrullah Bin Mat Radzi (2013677)
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

### <a name="hash"/> b. Hash Disclosure
#### Identify:
- No alerts, i.e. no vulnerability detected by the automated scan. There is also no risk level and cwe assigned on ZAP's alert page.

#### Evaluate:
- N/a for this website. The definition of it is a hash that was disclosed/leaked by the web server.

#### Prevent:
- N/a for this website. Otherwise, ensure that hashes that are used to protect credentials or other resources are not leaked by the web server or database. There is typically no requirement for password hashes to be accessible to the web browser.

### <a name="csrf"/>c. CSRF
#### Identify:
- Absence of Anti-CSRF Tokens <br>
![3](https://github.com/aimaaan/casestudy01/assets/99475237/ae5589cc-5577-48ad-917e-32f2b2fa6d0f)
    - Eg. of absence: <br>
    ![3 1](https://github.com/aimaaan/casestudy01/assets/99475237/5db0928b-ebcf-4316-bd9c-d975937cf4f3)
    - CWE ID: 352 - Cross-Site Request Forgery (CSRF)
    - Risk level: Medium
    - Confidence level: Low

#### Evaluate:
Based on  examination of HTML submission forms present on the website, it was discovered that no Anti-CSRF tokens were present.
Anti CSRF tokens are (pseudo) random parameters used to protect against Cross Site Request Forgery (CSRF) attacks. However they also make a penetration testers job harder, especially if the tokens are regenerated every time a form is requested.

CSRF attacks are effective in a number of situations, including:
    * The victim has an active session on the target site.
    * The victim is authenticated via HTTP auth on the target site.
No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token] was found in the following HTML form: [Form 1: "__EVENTARGUMENT" "__EVENTTARGET" "__EVENTVALIDATION" "__VIEWSTATE" "__VIEWSTATEGENERATOR" ].

#### Prevent:
- Phase: Architecture and Design
   - Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
     For example, use anti-CSRF packages such as the OWASP CSRFGuard.
   - Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).
     Note that this can be bypassed using XSS.

- Phase: Implementation
   - Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.
   - Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy         reasons.

- Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.
- Note that this can be bypassed using XSS.
- Use the ESAPI Session Management control. This control includes a component for CSRF.
- Do not use the GET method for any request that triggers a state change.
References:
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/352.html

### <a name="sec"/> d. Secured Cookies
#### Identify:
- Identified as Cookie without the same attribute <br>
![4](https://github.com/aimaaan/casestudy01/assets/99475237/ce9050ac-a0ff-4ab3-b307-88bb3f0b5013)
- CWE ID: 1275 - Sensitive Cookie with Improper SameSite Attribute
- Risk level: Low
- Confidence level: Medium

#### Evaluate:
- A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective countermeasure to cross-site request forgery, cross-site script inclusion, and timing attacks.

#### Prevent:
- Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.

References:
- https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site

### <a name="coo"/>g. Cookie Poisoning
#### Identify:
- No alert was found by OWASP ZAP. Thus, no risk level and CWE ID.
#### Evaluate:
- Not available on this website. But, from https://www.zaproxy.org/docs/alerts/10029/, this check examines user input in query string parameters and POST data to see where cookie parameters may be altered. This is known as a cookie poisoning attack, and it may be exploited when an attacker can change the cookie in various ways. While this may not be exploitable in some instances, enabling URL parameters to set cookie values is usually seen as a problem.
#### Prevent:
- Not available on this website. If not, the solution for this alert is not to enable the user to modify cookie names and values. If query string parameters must be placed in cookie values, ensure that semicolons are not used as name/value pair delimiters.

### <a name="pot"/>h. Potential XSS
<ins>Automated scan:</ins>
#### Identify:
- Identified as User Controllable HTML Element Attribute.
- The risk level is Informational.
- Classified as CWE ID:20
- The page involved is at URL: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
#### Evaluate:
- Alert type is Passive
- This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled.
- This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.
- Alert tags
    - OWASP_2021_A03
    - OWASP_2017_A01
- The number of XSS-based attacks is practically infinite, but they frequently involve sending sensitive information to the attacker, such as cookies or other session data, rerouting the victim to their web content, or abusing the user's computer while impersonating the vulnerable website.

#### Prevent:
- Validate all input and sanitize output before writing to any HTML attributes.

<ins>Manual Explore:</ins>
1. In manual exploration, I scanned it using the AJAX spider scanner and found some of other risks that are different from the automated scan:
   ![xss_ME](https://github.com/aimaaan/casestudy01/assets/106076684/c2e25486-1bba-46d6-868e-057804ebd1fd)
- Above is the Alerts for the potential XSS where its shows the User Controllable HTML Element Attribute (Potential XSS) (852).
  
### <a name="inf"/>i. Information Disclosure
<ins>Automated scan:</ins>
  
#### Identify:
- Risk level: Informational
- CWE ID:200 
- The page involved is at URL: 
https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InformationDisclosureSuspiciousCommentsScanRule.java

#### Evaluate:
- Information might be sensitive to different parties, each of which may have their own expectations for whether the information should be protected. These parties include:
    - the product's users
    - people or organizations whose information is created or used by the product, even if they are not direct product users
    - the product's administrators, including the admins of the system(s) and/or networks on which the product operates the developer
 - It is common practice to describe any loss of confidentiality as an "information exposure," but this can lead to overuse of CWE-200 in CWE mapping. From the CWE perspective, loss of confidentiality is a technical impact that can arise from dozens of different weaknesses, such as insecure file permissions or out-of-bounds read. CWE-200 and its lower-level descendants are intended to cover the mistakes that occur in behaviors that explicitly manage, store, transfer, or cleanse sensitive information.
#### Prevent:
- Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

<ins>Manual Explore:</ins>
1. In manual exploration, I scanned it using the AJAX spider scanner and found some of other risks that are different from the automated scan:
   
![ID_ME](https://github.com/aimaaan/casestudy01/assets/106076684/2ade5938-f292-48e8-b4d8-bd3a5d9fc5fc)
- Above is the alerts that I found in the website https://selangorfc.com/ where its shows alerts on Information disclosure - suspicious comments (164).

![potential_sensisitive](https://github.com/aimaaan/casestudy01/assets/106076684/40d42954-ae14-4799-9f37-23f0c5527bbd)
- Above is another alert that I found but the risk level is LOW and the alerts show Big redirect detected (potential sensitive informatil leak (50). 

