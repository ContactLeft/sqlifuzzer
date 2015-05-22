![http://securitytheatre.files.wordpress.com/2012/01/sqlifuzzer.png](http://securitytheatre.files.wordpress.com/2012/01/sqlifuzzer.png)

sqlifuzzer is a command line scanner that seeks to identify SQL injection vulnerabilities. It parses Burp logs to create a list of fuzzable requests... then fuzzes them.

# What is sqlifuzzer? #

It's a wrapper for curl written in bash. It's also a tool that can be used to remotely identify SQL (and XPath) injection vulnerabilities. It does this by sending a range of injection payloads and examining the responses for signs of 'injectability'. If a parameter appears to be vulnerable, sqlifuzzer sends exploit payloads to extract data.

Like almost all web app scanners, sqlifuzzer includes OR 1=1 payloads; this means that there is a significant risk of data destruction, Denial of Service, and/or other undesirable implications for any host (or intermediary device) scanned using sqlifuzzer. sqlifuzzer is beta; don't use it in an environment that matters to you or anyone else. Do not use sqlifuzzer to scan hosts without the owner's permission.

# Features #
  * Payloads/tests for numeric, string, error and time-based SQL injection
  * Support for MSSQL, MYSQL and Oracle DBMS's
  * A range of filter evasion options:
    * case variation, nesting, double URL encoding, comments for spaces, 'like' for 'equals' operator, intermediary characters, null and CRLF prefixes, HTTP method swapping (GETs become POSTs / POSTs become GETs)
  * ORDER BY and UNION SELECT tests on vulnerable parameters to:
    * enumerate select query column numbers
    * identify data-type string columns in select queries
    * extract database schema and configuration information
  * Conditional tests to extract DBMS info when data extraction via UNION SELECT fails (i.e. no string type columns)
  * Time delay based tests to extract DBMS info when data extraction via conditional methods fails (i.e. fully blind scenarios)
  * Boolean response-based XPath injection testing and data extraction
  * Support for automated detection and testing of parameters in POST URIs and multipart forms
  * Scan 'state' maintenance:
    * Halt a scan at any time - scan progress is saved and you can easily resume a scan from the URL where you stopped
    * Specify a specific request number to resume a scan from
  * Optional exclusion of a customizable list of parameters from scanning scope
  * Tracking of parameters scanned and avoidance of re-scanning scanned parameters
  * HTML format output with:
    * links/buttons to send Proof of Concept SQL injection requests
    * links to response difference files and to extracted data

# What do I need to use sqlifuzzer? #

sqlifuzzer is built and tested on [BackTrack](http://www.backtrack-linux.org/). On all other platforms Your Mileage May Vary; you will need a an OS that can support bash (`*`nix, cygwin (not tested), etc), curl must be installed and in your path, and 'replace' (which is missing from Ubuntu) must also be installed in in your path. Until I implement web spider functionality, sqlifuzzer is dependent upon [burp proxy](http://portswigger.net) to create log files (not burp state files) which sqlifuzzer uses to build its internal list of fuzz requests. The free version of burp can be used to create these log files. Within Burp go to options > misc and check the proxy requests tick box; browse the target site, populate your log, then pass it to sqlifuzzer.

# How does sqlifuzzer work? #

sqlifuzzer receives a burp log (which you must create for it) that specifies a bunch of HTTP requests. Requests in the burp log look like this:

```
======================================================
3:09:54 PM  http://192.168.182.136:80
======================================================
POST /orangehrm/menu.php?TEST=1111 HTTP/1.1
Host: 192.168.182.136
Accept: */*
Accept-Language: en
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)
Connection: close
Referer: http://192.168.182.136/orangehrm/index.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Cookie: PHPSESSID=bf7u0ad95cbubpcvdjda2bqro3; Loggedin=True; EliteNinja=False

module=Home&action=UnifiedSearch&search_form=false&tabnumber=1
======================================================
```

sqlifuzzer converts these into it's own format; a list of all the requests like this:

```
GET /orangehrm/menu.php?TEST=1111
POST /orangehrm/menu.php?TEST=1111??module=Home&action=UnifiedSearch&search_form=false&tabnumber=1
GET /orangehrm/index.php?module=Contacts&action=index&return_module=Contacts&return_action=DetailView&&print=true
GET /orangehrm/index.php?module=Home&menu_no=0&menu_no_top=home&submenutop=home1 
```

Next, sqlifuzzer looks at what payload types have been specified, and concatenates the relevant files to create a payload list. The list of requests and the payload list are then passed into the main scanning loop. The loop sends a 'clean' reference request (by calling out to curl), then, for the first line in the request list, the loop selects the first parameter and replaces this with the first payload and sends the fuzzed request (again via curl). The two responses are then compared; specifically, the response length and the duration of the responses are compared, the response HTTP status codes are examined, and the responses are searched for some common error strings. If anything 'juicy' is found, URL and payload information is logged to an output file and printed to the screen. The loop iterates through all payloads before moving on to the next parameter, and so on for each request.

# Why was sqlifuzzer created? #

Ever wanted to hit every dynamic parameter of a web app with a single quote? That's how sqlifuzzer started out. At first, it just compared the response lengths. Then I added the ability to iterate over a list of payloads. Then came POST requests, URL encoding, time delay diffing, searching for common error messages, logging, sessions, the ability to define parameters NOT to scan, method swapping, null byte prefixes, POST URIs, DBMS fingerprinting, data extraction, conditional testing, filter evasion options, boolean response-based XPath injection detection and data extraction and support for multipart forms.

# Thanks #

People I stole/learned from:

  * The curl team - http://curl.haxx.se/
  * Brian Holyfield - I stole a load of ideas from a tool written by Brian
  * Adam Muntner - I stole the common errors file and some payloads from [fuzzdb](http://code.google.com/p/fuzzdb/)
  * [PortSwigger](http://portswigger.net/burp/proxy.html) - Creator of Burp Suite
  * The authors of SQL Injection Attacks and Defense - I have stolen/learned a great deal from this book
  * I also nicked some stuff from [SQL Injection Pocket Reference](https://docs.google.com/Doc?docid=0AZNlBave77hiZGNjanptbV84Z25yaHJmMjk)
  * A number of filter evasion modes are based on [sqlmap](http://sqlmap.sourceforge.net/)'s tamper scripts
  * XPath injection tests were inspired by [XPath Blind Explorer](http://code.google.com/p/xpath-blind-explorer/) and [XMLmao](https://github.com/SpiderLabs/XMLmao)


# Also... #

If you like sqlifuzzer, check out:

[The Manipulator](http://code.google.com/p/the-manipulator/)

[MIMeGusta](http://code.google.com/p/mimegusta/)