#!/bin/bash

if [[ "$1" == "" ]] ; then
	echo "$0 <input sqlifuzzer log.txt file>"
	echo "Compiles HTML reports from sqlifuzzer log.txt files"
	exit
fi

echo "" > $1.html

echo "<html>" >> $1.html
echo "<head>" >> $1.html
echo "<title>sqlifuzzer results page</title>" >> $1.html
echo "<body>" >> $1.html
echo "<H3>sqlifuzzer test results</H3>" >> $1.html
#echo "Output file: ./output/$safefilename$safelogname.txt" >> $1.html
#echo "<br>" >> $1.html
#echo "Session file: ./session/$safehostname.$safelogname.session.txt" >> $1.html
#echo "<br>" >> $1.html
#echo "Host scanned: $uhostname" >> $1.html
#echo "<br>" >> $1.html
#echo "Time of scan: $(date)" >> $1.html
#echo "<br>" >> $1.html
echo "------------------------------------------------------------------" >> $1.html
echo "<br>" >> $1.html

echo "Reading in $1"
echo "Compiling report to create $1.html"

cat $1 | while read aLINE ; do
	echo -n "."
	message=`echo $aLINE|cut -d "]" -f1|cut -d "[" -f2`
	fullrequest=`echo $aLINE|cut -d "]" -f2`
	method=`echo $fullrequest | cut -d " " -f1`
	request=`echo $fullrequest | cut -d " " -f3`

	protocol=`echo $request | cut -d "/" -f1`
	host=`echo $request | cut -d "/" -f3`
	params=`echo $request | cut -d "/" -f4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30`
	page=`echo $params | cut -d "?" -f1`

	#echo "fullrequest: $fullrequest"
	#echo "message $message";
	#echo "method $method";
	#echo "request $request";
	#echo "protocol $protocol"
	#echo "host $host"
	#echo "params: $params"

	if [[ "$method" == "POST" ]] ; then
		if [[ $request =~ "??" ]] ; then 
			postdataparams=`echo $params | cut -d "?" -f4`
			postURIparams=`echo $params | cut -d "?" -f2`
			#echo "postURIparams $postURIparams"
			#echo "postdataparams $postdataparams"

		else
			postdataparams=`echo $params | cut -d "?" -f2`			
			#echo "postdataparams $postdataparams"
		fi
		postdataparamslist=`echo "$postdataparams"| replace "&" " "`
	fi

	echo "$message" >> $1.html
	echo "<br>" >> $1.html
	echo "<br>" >> $1.html
	if [[ "$method" == "GET" ]]  ; then 
		echo "$method /$params" >> $1.html
		echo "<br>" >> $1.html	
		echo "Host: $host" >> $1.html
		echo "<br>" >> $1.html
		echo "<br>" >> $1.html
		echo "<a href="$request">Submit Query</a>" >> $1.html
		echo "<br>" >> $1.html
	else
		if [[ $request =~ "??" ]] ; then 
			echo "$method /$page?$postURIparams" >> $1.html
			echo "<br>" >> $1.html
			echo "Host: $host" >> $1.html
			echo "<br>" >> $1.html
			echo "<br>" >> $1.html
			echo "$postdataparams" >> $1.html
			echo "<br>" >> $1.html			
			echo "<br>" >> $1.html
			echo "<form action="$protocol//$host/$page?$postURIparams" method="POST">" >> $1.html
			for param in `echo $postdataparamslist` ; do
				paramname=`echo $param | cut -d "=" -f 1`
				paramval=`echo $param | cut -d "=" -f 2`
				echo -n "<Input type="hidden" name=\""$paramname"\" value=\""$paramval"\"> " >> $1.html
				#echo "<br>" >> $1.html
			done
			echo "<input type="submit"> " >> $1.html
			echo "</form> " >> $1.html

		else
			echo "$method /$page" >> $1.html
			echo "<br>" >> $1.html
			echo "Host: $host" >> $1.html
			echo "<br>" >> $1.html
			echo "<br>" >> $1.html
			echo "$postdataparams" >> $1.html
			echo "<br>" >> $1.html
			echo "<br>" >> $1.html
			#echo "$postdataparams"
			#echo "$postdataparamslist"
			echo "<form action="$protocol//$host/$page" method="POST">" >> $1.html
			for param in `echo $postdataparamslist` ; do
				paramname=`echo $param | cut -d "=" -f 1`
				paramval=`echo $param | cut -d "=" -f 2`
				#decparam=`echo $paramval | replace "%20" " "`
				echo -n "<Input type="hidden" name=\""$paramname"\" value=\""$paramval"\"> " >> $1.html
				#echo "<br>" >> $1.html
			done
			echo "<input type="submit"> " >> $1.html
			echo "</form> " >> $1.html
		fi
	fi
	echo "------------------------------------------------------------------" >> $1.html
	echo "<br>" >> $1.html
done 
echo "</body>" >> $1.html
echo "</html>" >> $1.html 
echo ""
echo "Done. HTML report written to $1.html"
