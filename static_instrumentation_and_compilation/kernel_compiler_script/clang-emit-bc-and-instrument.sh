#!/bin/bash

CLANG=${CLANG:-clang}-13
OFILE=`echo $* | sed -e 's/^.* \(.*\.o\) .*$/\1/'`
PYSCRIPT1="/home/rooter/llvm_suff/callgraph/python-c-instrumenter.py"
PYSCRIPT2="/home/rooter/llvm_suff/callgraph/python-llvm-instrumenter.py"
BCFILE=`echo $OFILE | sed -e 's/o$/llbc/'`

python3 $PYSCRIPT1 "`pwd`" "$@"

if [ $? == 0 ];
then
	>&2 echo "if taken for:" $OFILE
	$CLANG -fcommon -Xclang -load -Xclang /home/rooter/llvm_suff/llvm-13.0.0.src/llvm-build-release/lib/CallAndDerefParser.so -flegacy-pass-manager "$@"
else
	>&2 echo "else taken for:" $OFILE
	$CLANG "$@"
fi
