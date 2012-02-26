#!/bin/bash

input=$1
if [[ "$input" == "" ]] ; then
	echo "ultracoder.sh \"<string to encode/decode>\"" 
	exit
fi 

#stringlength=${#input}
#((stringlengthminus1=$stringlength-1))
#fre=${input:0:1}
#echo "string length is $stringlength and first letter is $fre"
#echo $input | awk '{printf(" %3d %2x %c %i %o %u %X %f %e %E %g %G %c %s\n", $1, $1, $1, $1, $1, $1, $1, $1, $1, $1, $1, $1, $1, $1)}'

echo "You entered: $input"

echo "Comma-separated decimal to characters:"
i=0
#input=$1
outbuf=''
stringofdecimals=`echo $1 | tr ',' ' '`

for i in $stringofdecimals; do
	outbuf=$outbuf`echo $i | awk '{printf("%c", $1)}'`
done 
echo "$outbuf"

echo "URL encoding:"
i=0
#input=$1
outbuf=''
stringlength=${#input}
((stringlengthminus1=$stringlength-1))
while ((i<$stringlength)) ; do 
	char=`echo "${input:i:1}"`
	outbuf=$outbuf`echo -n "%"`
	outbuf=$outbuf`printf "%02x" "'$char'"`
	((i++))
done 
echo "$outbuf"

echo "URL decoding:"
i=0
#input=$outbuf
outbuf=''
stringlength=${#input}
while ((i<$stringlength)) ; do 
	char=`echo "${input:i:1}"`
	if [[ "$char" == "%" ]] ; then	
		char1=`echo "${input:(i+1):1}"`		
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
		char2=`echo "${input:(i+2):1}"`
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
		((one=$char1*16)) 2>/dev/null
		((two=$char2+$one)) 2>/dev/null
		outbuf=$outbuf`echo $two | awk '{printf("%c", $1)}'`
	fi
	((i=$i+3))
done 
echo "$outbuf"

#input=$1
echo "URI unicode:"
i=0
outbuf=''
stringlength=${#input}
((stringlengthminus1=$stringlength-1))
while ((i<$stringlength)) ; do 
	char=`echo "${input:i:1}"`
	val=`printf "%02x" "'$char'"`
	vallength=${#val}
	if [[ "$vallength" == "2" ]] ; then
		outbuf=$outbuf`echo -n "%u00"`
	else
		outbuf=$outbuf`echo -n "%u"`
	fi
	outbuf=$outbuf`echo -n $val`
	((i++))
done 
echo "$outbuf"

echo "URI unicode decoding:"
i=0
#input="$outbuf"
outbuf=''
stringlength=${#input}
while ((i<$stringlength)) ; do 
	char=`echo "${input:i:1}"`
	if [[ "$char" == "%" ]] ; then	
		char1=`echo "${input:(i+4):1}"`		
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
		char2=`echo "${input:(i+5):1}"`
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
 		((one=$char1*16)) 2>/dev/null
		((two=$char2+$one)) 2>/dev/null
		outbuf=$outbuf`echo $two | awk '{printf("%c", $1)}'`
	fi
	((i=$i+3))
done 
echo "$outbuf"

input=$1
echo "utf-8:"
i=0
outbuf=''
stringlength=${#input}
((stringlengthminus1=$stringlength-1))
while ((i<$stringlength)) ; do 
	char=`echo "${input:i:1}"`
	val=`printf "%02x" "'$char'"`
	vallength=${#val}
	if [[ "$vallength" == "2" ]] ; then
		outbuf=$outbuf`echo -n "\\u00"`
	else
		outbuf=$outbuf`echo -n "\\u"`
	fi
	outbuf=$outbuf`echo -n $val`
	((i++))
done 
echo "$outbuf"

echo "utf-8 decoding:"
i=0
#input=$outbuf
outbuf=''
stringlength=${#input}
while ((i<$stringlength)) ; do 
	char=`echo "${input:i:1}"`
	if [[ "$char" == "\\" ]] ; then	
		char1=`echo "${input:(i+4):1}"`		
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
		char2=`echo "${input:(i+5):1}"`
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
		((one=$char1*16)) 2>/dev/null
		((two=$char2+$one)) 2>/dev/null
		outbuf=$outbuf`echo $two | awk '{printf("%c", $1)}'`
	fi
	((i=$i+3))
done 
echo "$outbuf"

input=$1
echo "hex encoding"
i=0
outbuf=''
stringlength=${#input}
((stringlengthminus1=$stringlength-1))
while ((i<$stringlength)) ; do 
	char=`echo "${input:i:1}"`
	val=`printf "%02x" "'$char'"`
	vallength=${#val}
	outbuf=$outbuf`echo -n $val`
	((i++))
done 
echo "$outbuf"

echo "hex decoding:"
i=0
#input="$outbuf"
outbuf=''
stringlength=${#input}
while ((i<$stringlength)) ; do 
		char1=`echo "${input:(i):1}"`		
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
		char2=`echo "${input:(i+1):1}"`
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
		((one=$char1*16)) 2>/dev/null
		((two=$char2+$one)) 2>/dev/null
		outbuf=$outbuf`echo $two | awk '{printf("%c", $1)}'`
	((i=$i+2))
done 
echo "$outbuf"	

echo "asdasd"
input=$1
#1' declare @werui varchar(100) select @werui=0x77616974666f722064656c61792027303a303a323027 exec(@werui)--
echo "MSSQL declare/exec/hex encoding:"
i=0
outbuf=''
stringlength=${#input}
((stringlengthminus1=$stringlength-1))
while ((i<$stringlength)) ; do 
	char=`echo "${input:i:1}"`
	val=`printf "%02x" "'$char'"`
	vallength=${#val}
	outbuf=$outbuf`echo -n $val`
	((i++))
done 
outbuf="declare @werui varchar(100) select @werui=0x$outbuf exec(@werui)"
echo "$outbuf"

input=$1
echo "MSSQL char:"
i=0
outbuf=''
stringlength=${#input}
((stringlengthminus1=$stringlength-1))
while ((i<$stringlength)) ; do 
	char=`echo "${input:i:1}"`
	outbuf=$outbuf`echo -n "char(0x"`	
	outbuf=$outbuf`printf "%x" "'$char'"`
	if [[ "$i" -lt "$stringlengthminus1" ]] ; then
		outbuf=$outbuf`echo -n ")+"`
	fi
	if [[ "$i" == "$stringlengthminus1" ]] ; then
		outbuf=$outbuf`echo -n ")"`
	fi
	((i++))
done 
echo "$outbuf"


#chr(55)||chr(56)||chr(57)||chr(56)||chr(55)||chr(57)
input=$1
echo "Oracle chr:"
i=0
outbuf=''
stringlength=${#input}
((stringlengthminus1=$stringlength-1))
while ((i<$stringlength)) ; do 
	char=`echo "${input:i:1}"`
	outbuf=$outbuf`echo -n "chr("`	
	outbuf=$outbuf`printf "%x" "'$char'"`
	if [[ "$i" -lt "$stringlengthminus1" ]] ; then
		outbuf=$outbuf`echo -n ")||"`
	fi
	if [[ "$i" == "$stringlengthminus1" ]] ; then
		outbuf=$outbuf`echo -n ")"`
	fi
	((i++))
done 
echo "$outbuf"
