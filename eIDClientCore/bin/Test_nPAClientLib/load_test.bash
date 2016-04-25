#!/bin/bash

usage() {
	echo "Need at least two parameters."
	echo
	echo "Usage: $0 number_of_threads command [arguments of command]"
	echo
	echo "Example usage: $0 20 bin/Start_Testcase --testcase=AutentApp --card-reader=\"Virtual PCD 00 00\""
	exit 1
}

if [ $# -lt 2 ]
then
	usage
fi

NUM_THREADS=$1

if ! [[ $NUM_THREADS =~ ^[1-9][0-9]*$ ]] ; then
	echo "First argument \"$NUM_THREADS\" has to be a positive integer."
	usage
fi

shift
#"$@" now only contains: "command" ["argument of command"] ...

#Waits for all PIDs in an array
wait_for_pids() {
	declare -a PIDs=("${!1}")
	for i in "${PIDs[@]}"
	do
		wait "$i"
	done
}

# Add a prefix to each line of stdin.
add_prefix() {
    local line
    while read line; do printf '%s%s\n' "$1" "$line"; done
}

# Prepend prefix
start_with_prefix() {
	PREFIX=$1
	shift
	#"$@" now only contains: "command" ["argument of command"] ...

	# Create FIFOs for the command's stdout and stderr.
	stdout=$(mktemp /tmp/eID_DOS.$$.stdout.XXXXXXXX -u)
	stderr=$(mktemp /tmp/eID_DOS.$$.stderr.XXXXXXXX -u)
	mkfifo "$stdout" "$stderr"

	#Save PIDs to wait for them later
	PIDs=()
	
	# Read from the FIFOs in the background, adding the desired prefixes.
	add_prefix ${PREFIX}'_O:' < "$stdout" >&1 &
	PIDs+=($!)
	add_prefix ${PREFIX}'_E:' < "$stderr" >&2 &
	PIDs+=($!)

	# Now execute the command, sending its stdout and stderr to the FIFOs.
	"$@" 1> "$stdout" 2> "$stderr" &
	PIDs+=($!)
	
	#It is important to wait for the add_prefix calls, because otherwise
	#we return before they wrote everything to the command line. They will
	#then continue to write to the command line (until they wrote 
	#everything). It will look like the program hangs.
	wait_for_pids PIDs[@]

	rm $stdout
	rm $stderr
}

(
	PIDs=()

	for i in $(seq -f "%0${#NUM_THREADS}g" 1 $NUM_THREADS);
	do
		start_with_prefix "$i" "$@" &
		PIDs+=($!)
	done

	wait_for_pids PIDs[@]
)
