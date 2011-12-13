#!/bin/bash
# ./sqli-fuzzer30.sh

#############global variables##############

#default delay duration to use for timedelay testing: 
timedelay="20"

#delay threshold in seconds. When running a time delay scan, this can be set to tune out false positives. This should be higher than 'normal' request times to prevent false positives, but lower than the timedelay value:
timedelaythreshhold="1" 

# set the search term to a non-null value to prevent a match on an blank value:
ErrorString="foo123rewerwer435345345345"

#remove any residual files left lying about: 
rm cleanscannerinputlist.txt 2>/dev/null
rm 0 2>/dev/null
rm dump 2>/dev/null
rm dumpfile 2>/dev/null
rm search.txt 2>/dev/null
rm scannerinputlist.txt 2>/dev/null
rm 1scannerinputlist.txt 2>/dev/null
rm search.txt 2>/dev/null
rm dumpfile 2>/dev/null
rm dump 2>/dev/null
rm 2scannerinputlist.txt 2>/dev/null
rm dump.txt.txt 2>/dev/null

#initialise some of the logic flags to false:
n=false
s=false
q=false
m=false
e=false
h=false
x=false
u=false
curlproxy=""
P=false
b=false
C=false
f=false
o=false
D=false

#################command switch parser section#########################

while getopts l:c:t:nsqehx:d:bu:P:v:L:M:Q:I:T:C:rWS:ABjYfoD: namer; do
    case $namer in 
    l)  #path to burp log to parse
        burplog=$OPTARG
        ;;
    D)  #back end dbms
	D=true
        dbms=$OPTARG
        ;;
    o)  #OVERRIDE NON TESTING OF LOGIN
	o=true
        ;;
    c)  #cookie to add to requests
        cookie=$OPTARG
        ;;
    t)  #target hostname/ip
        uhostname=$OPTARG
        ;;    
    T)  #url to test a connection to
        T=true
	testurl=$OPTARG
        ;;
    n)  #use numeric injection payloads
        n=true
        ;;
    f)  #fulsh out the session file
        f=true
        ;;
    s)  #use string injection payloads
        s=true
        ;;
    q)  #use quote injection payloads 
        q=true
        ;;
    r)  #use encoded quote injection payloads 
        r=true
        ;;
    e)  #use SQL time delay injection payloads 
        e=true
        ;;
    b)  #use OS command injection delay payloads
        b=true
        ;;     
    h)  #help!
        h=true
        ;;
    x) # time delay duration
        x=true
	timedelay=$OPTARG
        ;;
    d) # default error string used to ID a default error page
        d=true
	ErrorString=$OPTARG
        ;;
    j) # default error string used to ID a default error page
        j=true
	 ;;
    A) # null mode
        A=true
        ;;  
    B) # CRLF mode
        B=true
        ;;  
    v) # set a curl proxy
        v=true
	curlproxy=$OPTARG
        ;;
    P) # parse the log and create an input file
        P=true
	parseOutputFile=$OPTARG
        ;;    
    I) # Use an input file file, not a burp log
        I=true
	inputFile=$OPTARG
        ;;    
    L) # Session cookie liveness check GET URL
        L=true
	canaryRequest=$OPTARG
        ;;
    M) # Session cookie liveness check search string
        M=true
	canaryRequestSearchString=$OPTARG
        ;;
    Q) # Session cookie liveness check search string
        Q=true
	resumeline=$OPTARG
        ;;    
    C) # Custom payload list
        C=true
	custompayloadlist=$OPTARG
        ;;
    W) # Method swapping mode
        W=true
        ;;
    S) # parameters to skip
        S=true
	parameterstoskip=$OPTARG
        ;;
    Y) # parameters to skip
        Y=true
	;;
    esac
done

# help mode activated
if [ true = "$h" ] || ["$1" == ""] 2>/dev/null ; then
	echo "sqlifuzzer.sh - A wrapper for curl written in bash :-)"
	echo "Written by Toby Clarke"
	echo "Influenced by code written by Brian Holyfield"
	echo "Common errors strings taken from Adam Muntner's fuzzdb regex/errors.txt"
	echo ""
	echo "Required arguments:"
	echo "  -t <host> Target hostname or IP address. No trailing slash."
	echo "AND one of:"
	echo "  -l <burplog> Path to the burp log file that will be parsed for requests. NOT a burp state file, but a log created in Burp > options > logging"
	echo "  -I <input file to use> Parse an input file, not a burp log. Input files can be created using the -P switch"
	echo "OR just:" 
	echo "  -T <test URL> Test mode: define a test URL to attempt a connection to. Also may require -c <cookie> to connect"
	echo "OR:"
	echo "  -P <input file to create> Parse mode: create an input file from a burp log. This can subsequently be scanned using the -I option. Also requires -l <burplog> to parse"	
	echo "AND one or more of the following payload types:"
	echo "  -s String injection"
	echo "  -n Numeric injection"
	echo "  -q Quote injection"	
	echo "  -r Quote injection with various encodings"	
	echo "  -e SQL delay injection"
        echo "  -b OS Command injection"
        echo "  -C <path to payload list text file> Use a custom payload list. Where the character 'X' is included in a payload, it may be replaced with a time delay value."
        echo "  -Y XSS injection (very basic!)"
	echo "Optional arguments:"
	echo "   Payload modifiers:"
	echo "  -A Prepend payloads with %00"
	echo "  -B Prepend payloads with %0d%0a"
	echo "  -W HTTP Method Swapping mode: GET requests are converted to POSTs and vice-versa. These new requests are tested IN ADDITION to the original."
	echo "Various extra options:"	
	echo "  -D <mssql, oracle, mysql> Specify a back end DBMS if known. Reduces the number of payloads. Options are currently mssql, oracle or mysql"
	echo "  -x <delay in seconds> Time delay for SQL and command injection - if not provided, this will default to $timedelay seconds"
	echo "  -c <cookie> Add cookies. Enclose in single quotes: -c 'foo=bar'. Multiple cookies must be defined without spaces: -c 'foo=bar;sna=fu'"
	echo "  -d <default error string> Define a detection string (inside double quotes) to identify a default error page"
	echo "  -v <http://proxy:port> Define a proxy. Currently, I crash burp. Dont know why."
	echo "  -L <URL of session liveness check page> Conduct an access check on a given page to determine the session cookie is valid"	
        echo "  -M <Search string> String to search for in session liveness check page. Replace spaces with periods: 'Welcome user Bob' should be 'Welcome.user.Bob'"
        echo "  -Q <Request number> Resume a halted scan at a given request number"        
	echo "  -T <Test URL> Test mode: define a test URL to attempt a connection to. Also may require -c <cookie> to connect"
	echo "  -S <file containing parameters to skip, each parameter on a seperate line> Define one or many parameters NOT to scan"
	echo "  -o Override the typical behaviour of excluding any requests which include the following phrases: logoff, logout, exit, signout, delete, signoff"
	echo "Some examples:"
	echo "A string, numeric and time-based SQL injection scan based on a burp log"
	echo "  $0 -t http://www.foo.bar -l example-burp.log -sne"
	echo "Using Parse mode to create an input file from a burp log file:"
	echo "  $0 -l example-burp.log -P example-burp.input"
	echo "A scan based on an input file, injecting encoded quote payloads with a leading null character and using method swapping:"
	echo "  $0 -t http://192.168.2.21 -I example-burp.input -rAW"
	echo "Runtime hints: CNTRL+Z to stop scanning, re-run with the same values to resume an incomplete scan"
	exit
fi

#no burplog or input file specified:
if [[ "$burplog" == "" && "$inputFile" == "" && "$testurl" == "" ]] ; then
	echo "I need a burplog or an input file to parse." >&2
	echo "-l <burplog> or -I <input file>">&2
	exit
fi

#no hostname provided:
if [[ "$uhostname" == "" && "$burplog" == "" && "$testurl" == "" ]]; then
	echo "I need a hostname (no trailing slash)." >&2
	echo "-t <host>">&2
	exit
fi

#if we are not creating an input file from a burp log (-P), and no payloads have been specified, ask for a payload:
if [[ true != "$P" && true != "$T" && true != "$Y" && true != "$s" && true != "$n" && true != "$q" && true != "$e" && true != "$b" && true != "$C" && true != "$r" && true != "$j" ]]; then
	echo "I need a payload type" >&2
	echo "-s, -n, -q, -r, -e, -b, -Y, -C" >&2
	exit
fi

# this fixes weird behaviour if no cookie value is given by setting a stupid cookie
if [[ "$cookie" == "" ]]; then
	echo "Cookie not provided. Setting cookie to foo=bar" >&2
	cookie="foo=bar"
fi

safefilename=`echo $uhostname-$(date)| replace " " "-" | replace "//" "" | replace ":" "."`
safehostname=`echo $uhostname | replace " " "-" | replace "//" "" | replace ":" "."`

#unless we are using an .input file, the safelogname should be the $burplog path value
if [[ true != "$I" ]]; then
	safelogname=`echo $burplog | replace " " "" | replace "/" "SLASH" | replace ":" "." | replace '\' ''`
else
	safelogname=`echo $inputFile | replace " " "" | replace "/" "SLASH" | replace ":" "." | replace '\' ''`
fi


#################burplog parser section#########################

########BURPLOG PARSING SECTION############

#if the user hasn't provided an input file, or a test URL, they must have provided a burp log to parse: 
if [[ true != "$I" && true != "$T" ]] ; then
	rm 1scannerinputlist.txt 2>/dev/null
	rm scannerinputlist.txt 2>/dev/null
	
	burplines=`wc -l $burplog | cut -d " " -f 1`
	echo "Parsing burp log $burplog with $burplines lines"  
		
	########BURPLOG ANALYSIS SECTION############

	N=0
	lineflag=0
	fileflag=0
	captureflag=0
	#the below get re-used later on in the code - dont change them
	#for some reason it seemed easier to define these and then match against the definition
	equalcheck="======================================================"
	get="GET "
	get2="GET"
	post="POST "
	post2="POST" 
	question="\?"
	colon=":"
	equals="="
	#initialise some variables:
	postflag=0
	postdataflag=0
	postURIflag=0
	
	# this next block of code is a 'for' loop over the list of entries in the $burplog txt file.
	# its purpose is to translate a burp log into .input format, which is a list of lines like this:
	# GET /foobar.php?sna=fu 
	# i use a 'while | read' instead of a 'for' because this can handle lines with spaces in. if 
	# you use a 'for' loop in bash it treats spaces as delimiters by default - 'while | read' is 
	# one way to get bash to treat each line as a whole regardless of spaces
	cat $burplog | while read LINE ; do 
		if [ $lineflag == 2 ]; then
			#two =========== lines gone past: this is the trigger to start capturing data"
			captureflag=1
			counter=$((counter+1))
		fi
	
		if [ $lineflag == 3 ]; then
			#three =========== lines gone past: this is the trigger to stop capturing data"
			captureflag=0		
			#reset the flag that counts the number of ============= lines that have passed by:
			lineflag=0
		fi
		if [ $captureflag == 1 ]; then
		# we are capturing burp log info:
		# first question: is it a POST or GET request?
			if [[ $LINE =~ $get && $LINE =~ $question ]]; then
				# GET detected the next line takes a line like:"
				# GET /foobar.asp?snafu=yep HTTP/1.1
				# and outputs:
				# GET /foobar.asp?snafu=yep				
				getline=`echo "$LINE" | cut -d " " -f 1,2`
				echo $getline >> 1scannerinputlist.txt
			fi
			#this code includes support for POST URI parameters:
			if [[ $LINE =~ $post && $LINE =~ $question ]]; then
				# POST with URI parameters detected. Store in the 'outer' variable, a line such as:"
				# /foobar.asp?snafu=yep				
				outer=`echo "$LINE" | cut -d " " -f 2`;
				postflag=1;
				postURIflag=1;
								
			fi
			if [[ $LINE =~ $post && !($LINE =~ $question) ]]; then
				# 'Normal' POST detected:
				# as before with the URI POST, we chop off the 'POST ' and 'HTTP/1.1' feilds either 
				# side of the URI, to store in the 'outer' variable something like:
				# /foobar.asp
				outer=`echo "$LINE" | cut -d " " -f 2`;
				# raise the postflag: we are hunting for the postdata now:
				postflag=1;
			fi
			if [ $postflag == 1 ]; then
				#this is my lame postdata matching condition:
				#the post data has an "=" and DOESENT have a ":" (keeps the headers away from the door...)
				if [[ $LINE =~ $equals && !($LINE =~ $colon) && !($LINE =~ $question) ]]; then
 					if [ $postURIflag == 1 ]; then
						echo "POST" $outer"??"$LINE  >> 1scannerinputlist.txt
						# In the case of a POST with URI parameters, POST body parameters are preceded with ??, like this:
						# POST /foobar.aspx?URIparam=1??bodyparam=2
						postURIflag=0
					else
						echo "POST" $outer"?"$LINE  >> 1scannerinputlist.txt
						# In the case of a 'normal' POST request, POST body parameters are preceded with ?, like this:
						# POST /foobar.aspx?bodyparam=2
						
					fi
				#reset the post flag in preparation for parsing the next request:
				postflag=0;
				fi
			fi
		fi
		
		#echo "Line $N = $LINE"
		if [[ $LINE =~ $equalcheck ]]; then
			# this flag tracks long lines of '=' characters. burp logs use three of these lines to capture a single request:
			# ======================================================
			# 1:50:18 PM  http://192.168.182.136:80
			# ======================================================
			# POST /dvwa/vulnerabilities/exec/ HTTP/1.1
			# Host: 192.168.182.136
			# Referer: http://192.168.182.136/dvwa/vulnerabilities/exec/
			# Cookie: security=high; PHPSESSID=67pq8ivtjaj485sbvck5fs8c87; acopendivids=phpbb2,redmine; acgroupswithpersist=nada
			# Content-Length: 20
			#	
			# ip=qwe&submit=submit
			# ======================================================
			lineflag=$((lineflag+1))
		fi
		N=$((N+1))
	done

 	#cat $burplog | grep -v ".png" | grep -v ".jpg" | grep -v ".css" | grep -v ".flv" | grep -v ".bmp"| grep -v ".gif"| grep -v ".js" > cleanburplist.txt
	#grep -i "\(logoff\|logout\|exit\|signout\|delete\|login\|signoff\)"
	rm 2scannerinputlist.txt 2>/dev/null

	# if Method swapping has been specified, add a GET for each POST and vice-versa:
	# btw, if a POST request is normal (i.e. no URI params), then the body params are preceded by a single '?'
	# however, if a POST request has URI parameters, then these are preceded by a '?', while the POST body params are preceded by '??'
	if [ true = "$W" ] ; then
		cat 1scannerinputlist.txt | while read i;
			do methodical=`echo $i | cut -d " " -f 1`;
			if [[ "$methodical" =~ "POST" ]]; then
				echo GET `echo $i | cut -d " " -f2 | replace '??' '&'` >> 2scannerinputlist.txt; 
				echo POST `echo $i | cut -d " " -f2` >> 2scannerinputlist.txt;
			else
				echo GET `echo $i | cut -d " " -f2` >> 2scannerinputlist.txt; 
				echo POST `echo $i | cut -d " " -f2` >> 2scannerinputlist.txt;
				#the above line causes GET params to be passed as POST body params, otherwide they'd be treated as POST URI params	
			fi
		done
	else 
		cp 1scannerinputlist.txt 2scannerinputlist.txt	
	fi

#cat 2scannerinputlist.txt
#exit
	#sort uniq the list and also clean out log entries that you dont want to be scanning:
	cat 2scannerinputlist.txt | grep -v "\(\.png\|\.jpg\|\.css\|\.bmp\|\.gif\)" | sort | uniq > 3scannerinputlist.txt

	#need some code to double up the post reqs with params:
	#this is to support scanning of POST URIs
	#where a POST is found, first time it'll scan the POST URIs, next time it'll scan the POST data params. (or the other way round.. i cant remember)
	#hence we need duplicates of POST requests that have POST URIs.
	#this has to be done after the | sort | uniq
	cat 3scannerinputlist.txt | while read LINE; do
		echo $LINE >> scannerinputlist.txt
		if [[ $LINE =~ $post && $LINE =~ $question$question ]]; then
			echo $LINE >> scannerinputlist.txt
		fi
	done
			
	#as 1scannerinputlist.txt (and its friends) is accumulative by nature, it must be cleared down 
	rm 1scannerinputlist.txt 2>/dev/null	
	rm 2scannerinputlist.txt 2>/dev/null	
	rm 3scannerinputlist.txt 2>/dev/null
fi

#URL connection testing routine:
if [ true = "$T" ] ; then
	echo "Testing connection to $testurl" 
	testresult=`curl $testurl -v -o testoutput.html --cookie $cookie $curlproxy -w %{http_code}:%{size_download}`
	testresultstatus=`echo $testresult | cut -d ":" -f 1`
	testresultlength=`echo $testresult | cut -d ":" -f 2`
	echo "The status code was "$testresultstatus 
	echo "The response length was "$testresultlength
	echo "The output has been saved as testoutput.html" 
	exit 
fi

#An input file has been specified:
if [ true = "$I" ] ; then
	rm scannerinputlist.txt 2>/dev/null
	echo "Parsing input file" $I
	cat $inputFile | while read quack; do
		echo $quack >> scannerinputlist.txt;
	done
	echo "Parsed input file $inputFile" 
fi


#as both the below lists are accumulative ny nature, they must first be cleared down before they are used:
rm cleanscannerinputlist.txt 2>/dev/null
rm exceptionlist.txt 2>/dev/null

if [ false = "$o" ] ; then
	#identify any risky request URLs
	cat scannerinputlist.txt | while read quack; do
		textsearch=`echo $quack | grep -i "\(update\|logoff\|login\|logout\|exit\|signout\|delete\|signoff\|password\)"`
		if [[ "$textsearch" != "" ]] ; then
			echo $quack >> exceptionlist.txt				
		else
			echo $quack >> cleanscannerinputlist.txt
		fi
	done
else
	cp scannerinputlist.txt cleanscannerinputlist.txt;
fi

if [ true = "$P" ] ; then
	cat scannerinputlist.txt | while read quack; do
		echo $quack >> $parseOutputFile;
	done
	echo "Input file $parseOutputFile created"
	echo "The following potentially risky URLs (if any) were removed: " >> urltested.txt;
	cat exceptionlist.txt >> urltested.txt;
	echo "	*	*	*	*	*	*" >> urltested.txt;
	echo "The following URLs were added: " >> urltested.txt
	cat cleanscannerinputlist.txt >> urltested.txt
	cat urltested.txt
	rm urltested.txt 2>/dev/null	
	exit
fi

rm scannerinputlist.txt 2>/dev/null

entries=`wc -l cleanscannerinputlist.txt | cut -d " " -f 1`

echo "Scan list created with $entries entries" 

#echo "debugGOT  HERE"
#exit

exceptions=`cat exceptionlist.txt 2>/dev/null`
if [[ "$exceptions" != "" ]] ; then
	echo "The following potentially risky URLs will be excluded from scanning. Run the scan again using the -o option to include them."
	cat exceptionlist.txt 2>/dev/null 
	echo -n "Enter y to continue or n to quit: "
	read keyinput
		if [[ "$keyinput" == "n" ]] ; then
		exit;
	fi
fi

rm exceptionlist.txt 2>/dev/null

#######Prep the param list section########

#the output of this section will be a list of payloads called payloads.txt

#clear down the payloads.txt list incase it has entries left in it
rm payloads.txt 2>/dev/null

##this section concatenates payload list files based on user input###

if [ true = "$s" ] ; then
	if [ true = "$D" ] ; then	
		cat ./payloads/stringpayloads.$dbms.txt | while read quack; do
			echo $quack >> payloads.txt;
		done
	else
		cat ./payloads/stringpayloads.txt | while read quack; do
			echo $quack >> payloads.txt;
		done
	fi
fi

if [ true = "$n" ] ; then
	cat ./payloads/numericpayloads.txt | while read quack; do
		echo $quack >> payloads.txt;
	done
fi	

if [ true = "$e" ] ; then
	if [ true = "$D" ] ; then	
		cat ./payloads/timedelaypayloads.$dbms.txt | while read quack; do
			echo $quack | replace "X" $timedelay >> payloads.txt;
		done
	else
		cat ./payloads/timedelaypayloads.txt | while read quack; do
			echo $quack | replace "X" $timedelay >> payloads.txt;
		done
	fi
fi

if [ true = "$b" ] ; then
	cat ./payloads/commandpayloads.txt | while read quack; do		
		echo $quack | replace "X" $timedelay >> payloads.txt;
	done
fi

if [ true = "$q" ] ; then
	cat ./payloads/quotepayloads.txt | while read quack; do
		echo $quack >> payloads.txt;
	done
fi

if [ true = "$j" ] ; then
	cat ./payloads/all_attacks.txt | while read quack; do
		echo $quack >> payloads.txt;
	done
fi

if [ true = "$r" ] ; then
	cat ./payloads/encodedquotepayloads.txt | while read quack; do
		echo $quack >> payloads.txt;
	done
fi

if [ true = "$Y" ] ; then 
	cat ./payloads/xsspayloads.txt | while read quack; do
		echo $quack >> payloads.txt;
	done
fi

# this code scans through a custom payload list and replaces 'X' with the $timedelay value:
# this allows users to specifiy their own timedelay sqli payloads:
if [ true = "$C" ] ; then
	cat $custompayloadlist | while read quack; do
		echo $quack | replace "X" $timedelay >> payloads.txt;
	done
fi

#flatten this down just in case theres an old version lying about:
rm nullpayloads.txt 2>/dev/null;

# this code prepends each payload with a %00, sometimes useful for filter evasion:
if [ true = "$A" ] ; then
	cat payloads.txt | while read quack; do
		echo "%00"$quack >> nullpayloads.txt;
	done
	cat nullpayloads.txt > payloads.txt;
	rm nullpayloads.txt 2>/dev/null;
fi

# this code prepends each payload with a %0d%0a, sometimes useful for filter evasion:
if [ true = "$B" ] ; then
	cat payloads.txt | while read quack; do
		echo "%0d%0a"$quack >> nullpayloads.txt;
	done
	cat nullpayloads.txt > payloads.txt;
	rm nullpayloads.txt 2>/dev/null;
fi

totalpayloads=`wc -l payloads.txt | cut -d " " -f 1`
echo "Payload list created with $totalpayloads entries" 


### session file checking / creation code ###
# the idea here is that the user should be comfy killing and resuming a scan.
# this is facilitated by saving the scan progress (specifically the request 
# or "URL number" last scanned) in a session file and then checking for the 
# presence of this file whenever a scan is launched
echo "Checking for session file."

if [ true = "$f" ] ; then
	rm ./session/$safehostname.$safelogname.session.txt 2>/dev/null
fi

session=''
session=`cat ./session/$safehostname.$safelogname.session.txt 2>/dev/null`
if [[ "$session" != "" ]]; then
	echo "Session file found at ./session/$safehostname.$safelogname.session.txt" 
	echo "Do you want to resume from the last URL scanned: ($session)?"
	echo -n "Enter y at the prompt to resume from URL $session or n to start from the first URL: "
	read choice
	if [[ "$choice" == "y" ]]; then
		echo "Resuming scan from URL $session"		
		resumeline=$session
		Q=true
	else 
		echo "Starting from the first URL"
		resumeline=0
	fi
else echo "Session file not found. Creating ./session/$safehostname.$safelogname.session.txt and starting from the first URL"
fi

#this IF statement creates list of params to skip based on a user-supplied list, or using the default list.
rm ./parameters_to_skip.txt 2>/dev/null
if [ true = "$S" ] ; then					
	cat $parameterstoskip | while read quack; do
		echo $quack >> parameters_to_skip.txt;
	done
else 
	cat ./payloads/default_parameters_to_skip.txt | while read quack; do
		echo $quack >> parameters_to_skip.txt;
	done
fi

#########################################
echo "" >> outputheader.txt
echo "" >> outputheader.txt
echo "		**********************" > outputheader.txt
echo "		***  TEST RESULTS  ***" > outputheader.txt
echo "		**********************" > outputheader.txt
echo "" >> outputheader.txt
echo "" >> outputheader.txt

echo "Test Details" >> outputheader.txt
echo "Output file: ./output/$safefilename$safelogname.txt" >> outputheader.txt
echo "Log file used: ./session/$safehostname.$safelogname.session.txt" >> outputheader.txt
echo "Host scanned: $uhostname" >> outputheader.txt
echo "Time of scan: $(date)" >> outputheader.txt

#################scanner section#########################
K=0
####### scanning loop #############

#this line makes sure we have specified a payload type
if [[ true = "$n" || true = "$s" || true = "$e" || true = "$b" || true = "$q" || true = "$r" || true = "$Y" || true = "$C" ]] ; then

echo "Scan commenced"
### new scanning engine ###
##BEGINING OF PER-URL LOOP:
firstPOSTURIURL=0
# the firstPOSTURIURL flag handles situats where POST requests have URI parmeters and has three states: 
# 0 no postURI params, 
# 1 postURI param detected, fuzz the postURI params, send the post data params as a static string
# 2 postURI param detected, fuzz the post data params, send the postURI params as a static string

cat cleanscannerinputlist.txt | while read i; do
	#if [[ $LINE =~ $equals && !($LINE =~ $colon) && !($LINE =~ $question) ]]; then
	if [[ $i =~ $question$question && $i =~ $post ]] ; then
		#increment the firstPOSTURIURL flag: 
		firstPOSTURIURL=$((firstPOSTURIURL+1)); 
	fi
	
	K=$((K+1)); #this is a request counter
	sentnormalrequestflag="FALSE";
	continueflag=0;
	if [ true = "$L" ] ; then
		# session liveness check was requested
		checkpage=`curl $canaryRequest -o dump.txt --cookie $cookie $curlproxy`;
		cat dump.txt 2>/dev/null | egrep -o $canaryRequestSearchString > search.txt;
		search=`cat search.txt`;
		if [[ $search != "" ]]
			then echo "Session is valid";
		else	
			echo "Halting as session is invalid. Resume at request number "$K;
			break;
		fi
	fi
	# resume routine to allow users to resume a scan from a given request number
	if [ true = "$Q" ] ; then
		if (($K<$resumeline))
			then echo "Skipping request number "$K;
			continue 3;
		fi
	fi
	method=`echo $i | cut -d " " -f 1`;
	#echo "debug i "$i;
	#echo "debug firstPOSTURIURL $firstPOSTURIURL";
	
	#work out what the page value is. for a firstPOSTURIURL value of 2, set the page to be the page AND the postURI params
	#for everything else, the page is the page... 
	if [ $firstPOSTURIURL == 2 ] ; then 
		page=`echo $i | cut -d " " -f 2 | cut -d "?" -f 1,2`;
	else
		page=`echo $i | cut -d " " -f 2 | cut -d "?" -f 1`;
	fi
	#echo "debug page "$page;	
	
	#now work out the params that will be fuzzed in this loop iteration
	if (($firstPOSTURIURL>0)) ; then
		if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
			params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`;
			static=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`;
		fi
		if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
			params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`;
			static=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`;
		fi
	else #we are dealing with a simple GET request
		params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`;
	fi
	
	#echo "debug params "$params;	
			
	stringofparams=`echo $params | tr "&" " "`;

	#echo "debug string of params "$stringofparams;
	paramsarray=($stringofparams);
	#echo "debug paramsarray "${paramsarray[*]};
	output='';
	arraylength=${#paramsarray[*]};
	((arraylengthminusone=$arraylength-1));
	#echo "debug arraylengthminusone " $arraylengthminusone
	#this flag will track which param we are fuzzing (lets initialise it down to 0): 	
	paramflag=0;
	#sleep 0.5;
	##BEGINING OF PER-PARAMETER LOOP
	for paramstring in ${paramsarray[*]}; do
		#this line is where we include the payload path string:
		#here we are going to feed in our newly compiled payload list:
		((payloadcounter=0));		
		##BEGINING OF PER-PAYLOAD LOOP
		cat payloads.txt | while read payload; do
			#payloadcounter is not used for logic, it just presents the user with the payload number			
			payloadcounter=$((payloadcounter+1))
			#echo "debug payload counter: $payloadcounter"
			# the output buffer will hold the final string of params including the injected param and the normal ones
			# lets clear it down at the begining of the loop:
			output='';
			# for each parameter in a given URL we need to create a request where one of the parameters has 
			# a payload injected but all the others are 'normal'. A normal request like this:
			# http://www.foobar.com/foo.aspx?a=1&b=2&c=3
			# ... should be fuzzed like this:
			# http://www.foobar.com/foo.aspx?a=PAYLOAD&b=2&c=3
			# http://www.foobar.com/foo.aspx?a=1&b=PAYLOAD&c=3
			# http://www.foobar.com/foo.aspx?a=1&b=2&c=PAYLOAD
			# so, we need an inner loop that will, for each parameter in the URL
			# create a request with one injected parameter.
			# we will use the paramflag variable to determine which param is to be injected.
			# y will be the innerloop iterator. where y=paramflag, we will inject our payload.
			# note that while y increments for each loop iteration, paramflag does not 
			for (( y = 0; y <= $arraylengthminusone; y += 1 )); do
				#echo "debug payload "$payload;	
				#echo "debug y="$y;
				#echo "debug paramflag="$paramflag;
				# below is the url encoding scheme which is applied to payloads - its not perfect, but works most of the time 
				if (( $y == $paramflag )) 
					then encodedpayload=`echo $payload | replace " " "%20" | replace "." "%2e" | replace "<" "%3c" | replace ">" "%3e" | replace "?" "%3f" | replace "+" "%2b" | replace "*" "%2a" | replace ";" "%3b" | replace ":" "%3a" | replace "(" "%28"| replace ")" "%29" | replace "," "%2c"`;
					#inject the payload into this parameter:
					output=$output`echo ${paramsarray[$y]} | cut -d "=" -f1`"="$encodedpayload;
					#echo "output after payload injection $output";
					#echo "debug paramsarray at y " ${paramsarray[$y]};
					paramtotest=`echo ${paramsarray[$y]} | cut -d "=" -f1`;
					#echo "debug paramtotest: "$paramtotest;
					#check to see if the current parameter should be skipped:
					for paramcheck in `cat parameters_to_skip.txt`; do
						if [[ "$paramcheck" == "$paramtotest" ]]; then
							continueflag=1;
							break;
						fi
					done
					#echo "continueflag1="$continueflag;
					#echo "debug output " $output;					
				else 
					#we are not injecting this parameter, so print it out as normal:
					output=$output${paramsarray[$y]};
				fi
				#this line works out if we need to append an & to the parameter value:
				if (($y == $arraylengthminusone))
					then foobar="foobar";
					#no need to add a '&' suffix to $output as no more params left to add...
				else 
					output=$output"&"; 
				fi
				#if we are testing the last parameter, we have a full list of params ready to go to the scanner:				
				if (($y == $arraylengthminusone))
					###IMPORTANT: this instruction MUST BE HERE!!!:
					then asd=1; 
					r=$uhostname$page"?"$output;
					#echo $r;
					i=$uhostname$page"?"$params;
					#echo $i;					
					# this is where we stop dicking about with URLs and hand them off to CURL
					#but first we need to know if this is a POST or a GET
											
					#echo "method is: "$method;
					#echo "continueflag2="$continueflag;
					if (( $continueflag == 1 )); then
						echo "Skipping param $paramtotest as instructed";
						continueflag=0;
						continue;
					fi										

					#sleep 1;
					if [[ $method != "POST" ]]; then #we're doing a get - simples					
						#echo "debug y="$y;						
						#echo "debug paramflag="$paramflag;
						# IDEA: put an if 'sentnormalrequestflag' here so you only send one good request per URL instead of one per parameter
						if [[ $sentnormalrequestflag != "TRUE" ]]; then
							# send a 'normal' request						
							and1eq1=`curl $i -o dump --cookie $cookie $curlproxy -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`; 
							sentnormalrequestflag="TRUE";								
							echo "Testing URL $K of $entries GET $i";
						fi
						# send an 'evil' request
						echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload";
						and1eq2=`curl $r -o dumpfile --cookie $cookie $curlproxy -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`;
						#echo "EVIL GET " $r; 
					else	# we're doing a POST - not so simple...
						#echo "debug y="$y;
						#echo "debug paramflag="$paramflag;
						if [[ $sentnormalrequestflag != "TRUE" ]]; then
							# send a 'normal' POST request
							if (($firstPOSTURIURL>0)) ; then
								if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
									and1eq1=`curl -d "$static" $uhostname$page"?"$params -o dump --cookie $cookie $curlproxy -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`;
									sentnormalrequestflag="TRUE";
									echo "Testing URL $K of $entries POST $uhostname$page?$params??$static"; 	
								fi
								if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
									and1eq1=`curl -d "$params" $uhostname$page -o dump --cookie $cookie $curlproxy -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`;
									sentnormalrequestflag="TRUE";
									echo "Testing URL $K of $entries POST $uhostname$page??$params"; 
								fi
							else #just a normal POST:
								and1eq1=`curl -d "$params" $uhostname$page -o dump --cookie $cookie $curlproxy -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`;
								sentnormalrequestflag="TRUE";
								echo "Testing URL $K of $entries POST $uhostname$page?$params"; 		
							fi						
						fi
						# send an 'evil' POST request
						if (($firstPOSTURIURL>0)) ; then
							if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
								and1eq2=`curl -d "$static" $uhostname$page"?"$output -o dumpfile --cookie $cookie $curlproxy -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`;
								echo "$method URL $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"; 	
							fi
							if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
								and1eq2=`curl -d "$output" $uhostname$page -o dumpfile --cookie $cookie $curlproxy -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`;
								echo "$method URL $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"; 
							fi
						else #just a normal POST:
							echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload";
							and1eq2=`curl -d "$output" $uhostname$page -o dumpfile --cookie $cookie $curlproxy -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`;
							#echo "EVIL POST " $uhostname$page"?"$output;
						
						fi
					fi
					#echo "DEBUG "$method $i;
					#echo "DEBUG "$method $r;
					#check the response code and alert the user if its not 200:
					reponseStatusCode=`echo $and1eq2 | cut -d ":" -f 1`;
					if [[ "$reponseStatusCode" != "200" && "$reponseStatusCode" != "404" ]]
						then echo "ALERT: Status code "$reponseStatusCode" reposnse";
					fi 
					#beginning of response parsing section
					#xss testing IF statement
					if [ true = "$Y" ] ; then
						cat ./dumpfile | grep -i -o "$payload" > search.txt;
						search=`cat search.txt`;
						if [[ $search != "" ]] ; then
							if [[ $method != "POST" ]] ; then  #we're doing a get - simples
								echo "[XSS: $paramtotest] $method URL: $uhostname$page"?"$output" >> ./output/$safefilename$safelogname.txt;
								echo "[XSS: $paramtotest] $method URL: $uhostname$page"?"$output";
							else
								if (($firstPOSTURIURL>0)) ; then
									if [ $firstPOSTURIURL == 1 ] ; then
										echo "[XSS: $paramtotest] $method URL: $uhostname$page"?"$static"??"$output" >> ./output/$safefilename$safelogname.txt;
									else
										echo "[XSS: $paramtotest] $method URL: $uhostname$page"??"$output" >> ./output/$safefilename$safelogname.txt;
									fi
								fi
							fi							
						fi
					fi	
					#this code scans responses for common error strings:			
					cat ./payloads/errors-two-words.txt | while read z; do 
						cat ./dumpfile | egrep -i -o $z > search.txt;
						search=`cat search.txt`;
						if [[ $search != "" ]] ; then 
							if [[ $method != "POST" ]]; then #we're doing a get - simples
								echo "[ERROR: $z] $method URL: $uhostname$page"?"$output" >> ./output/$safefilename$safelogname.txt;
								echo "[ERROR: $z] $method URL: $uhostname$page"?"$output";
							else
								if (($firstPOSTURIURL>0)) ; then
									if [ $firstPOSTURIURL == 1 ] ; then
										echo "[ERROR: $z] $method URL: $uhostname$page"?"$static"??"$output" >> ./output/$safefilename$safelogname.txt;
										echo "[ERROR: $z] $method URL: $uhostname$page"?"$static"??"$output";
									else
										echo "[ERROR: $z] $method URL: $uhostname$page"??"$output" >> ./output/$safefilename$safelogname.txt;
										echo "[ERROR: $z] $method URL: $uhostname$page"??"$output";
									fi
								fi
							fi		
						fi
					done
					#end of code that scans for common error strings
					
					#new response length logic goes in here:
					#echo "DEBUG: payload: $payload"
					if [[ "$payload" =~ "345=345" || "$payload" =~ "345'='345" || "$payload" =~ "dfth=dfth" ]]
						then SQLequallength=`echo $and1eq2 | cut -d ":" -f 2`;
						#echo "debug: SQLequallength "$SQLequallength
					fi

					if [[ "$payload" =~ "345=456" || "$payload" =~ "345'='456" || "$payload" =~ "dfth=fghj" ]]
						then SQLunequallength=`echo $and1eq2 | cut -d ":" -f 2`;
						#echo "debug: SQLequallength "$SQLunequallength
					fi

					if [[ "$SQLequallength" != "" && "$SQLunequallength" != "" ]]
						then ((answer=$SQLequallength-$SQLunequallength))
						SQLequallength="";
						SQLunequallength="";
						if [ $answer -gt 4 ] || [ $answer -lt -4 ] ; then
							if [[ $method != "POST" ]]; then #we're doing a get - simples 
								echo "[LENGTH-DIFF $answer] $method URL: $uhostname$page"?"$output" >> ./output/$safefilename$safelogname.txt;
								echo "[LENGTH-DIFF $answer] $method URL: $uhostname$page"?"$output" ;
							else
								if (($firstPOSTURIURL>0)) ; then
									if [ $firstPOSTURIURL == 1 ] ; then
										echo "[LENGTH-DIFF $answer] $method URL: $uhostname$page"?"$static"??"$output" >> ./output/$safefilename$safelogname.txt;
										echo "[LENGTH-DIFF $answer] $method URL: $uhostname$page"?"$static"??"$output";
									else
										echo "[LENGTH-DIFF $answer] $method URL: $uhostname$page"??"$output" >> ./output/$safefilename$safelogname.txt;
										echo "[LENGTH-DIFF $answer] $method URL: $uhostname$page"??"$output";
									fi
								fi
							fi
						fi
					fi
			
					#this searches through the response looking for a provided error string:
					cat ./dumpfile | egrep -o "$ErrorString" > search.txt;
					search=`grep "$ErrorString" search.txt`;
					if [[ $search == "$ErrorString" ]]
						then echo "Application error page - skipping "$r >> ./output/$safefilename$safelogname.txt;
					elif [[ $search != "$ErrorString" ]]
					#continue only if the default error page has not been found run the scan...
						# the new result format is 404:4040
						# separate out the http status code from the results:
						then and1eq2status=`echo $and1eq2 | cut -d ":" -f 1`;
						((status=$and1eq2status));
						if (($status == "500")) 
							then echo "[STATUS-CODE: $status] $method URL: $uhostname$page"?"$output" >> ./output/$safefilename$safelogname.status.txt; 								#echo "[STATUS-CODE: $status] $method URL: $uhostname$page"?"$output" ;
						fi
						if (($status == "302")) 
							then echo "[STATUS-CODE: $status] $method URL: $uhostname$page"?"$output" >> ./output/$safefilename$safelogname.status.txt;
							###echo "[STATUS-CODE: $status] $method URL: $uhostname$page"?"$output" ;
						fi
						# if you get a 404 status, dont bother diffing the response lengths
						if (($status == "404"))
							then arbitrary="ierfherfuu"; 
						fi
						#put time diff scan here
						and1eq1time=`echo $and1eq1 | cut -d ":" -f 3`;
						and1eq2time=`echo $and1eq2 | cut -d ":" -f 3`;
						#one problem was that the time is returned in ms
						#the substr below returns the result in s 

						injected_time=`expr substr $and1eq2time 1 1`;
						normalreq_time=`expr substr $and1eq1time 1 1`;
						((time_diff=injected_time-normalreq_time));

						
						#the below two lines are from the original absolute time diff:
						#answer=`expr substr $and1eq2time 1 1`;
						#if (( $answer >= $timedelaythreshhold ))
						if (( $injected_time > $normalreq_time )) ; then
							if [[ $method != "POST" ]] ; then #we're doing a get - simples
								echo "[TIME-DELAY-"$time_diff"SEC] $method URL: $uhostname$page"?"$output" >> ./output/$safefilename$safelogname.txt; 
								echo "[TIME-DELAY-"$time_diff"SEC] $method URL: $uhostname$page"?"$output" ;
							else
								if (($firstPOSTURIURL>0)) ; then
									if [ $firstPOSTURIURL == 1 ] ; then
										echo "[TIME-DELAY-"$time_diff"SEC] $method URL: $uhostname$page"?"$static"??"$output" >> ./output/$safefilename$safelogname.txt;
										echo "[TIME-DELAY-"$time_diff"SEC] $method URL: $uhostname$page"?"$static"??"$output";
									else
										echo "[TIME-DELAY-"$time_diff"SEC] $method URL: $uhostname$page"??"$output" >> ./output/$safefilename$safelogname.txt;
										echo "[TIME-DELAY-"$time_diff"SEC] $method URL: $uhostname$page"??"$output";
									fi
								fi
							fi
						fi
					fi
					#gotta clear down the output buffer:					
					output='';
				fi						
			done 
		##END OF PER-PAYLOAD LOOP:		
		done
	((paramflag=$paramflag+1));
	##END OF PER-PARAMETER LOOP:
	done
##END OF PER-URL LOOP:
if [ $firstPOSTURIURL == 2 ] ; then
	firstPOSTURIURL=0
fi
#write the URL number into the session file:
echo $((K+1)) > ./session/$safehostname.$safelogname.session.txt
done
fi

#need to do this at the end to clean up:
#need to update this

rm ./parameters_to_skip.txt 2>/dev/null
rm scannerinputlist.txt 2>/dev/null
rm cleanscannerinputlist.txt 2>/dev/null
rm 0 2>/dev/null
rm dump 2>/dev/null
rm dumpfile 2>/dev/null
rm 1scannerinputlist.txt 2>/dev/null
rm search.txt 2>/dev/null
rm dumpfile 2>/dev/null
rm dump 2>/dev/null
rm payloads.txt 2>/dev/null

#if you get here, youve finished scanning so write nothing into the session file to clear it down:
echo "" > ./session/$safehostname.session.txt

cat outputheader.txt 2>/dev/null
cat ./output/$safefilename$safelogname.txt 2>/dev/null | sort | uniq
cat ./output/$safefilename$safelogname.status.txt 2>/dev/null | sort | uniq
#cat urltested.txt 2>/dev/null







