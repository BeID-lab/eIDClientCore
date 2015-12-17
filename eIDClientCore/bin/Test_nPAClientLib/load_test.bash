#!/bin/bash

usage() {
	echo "Need exactly two parameters."
	echo "Usage: $0 \"command\" number_of_threads"
	echo "Example usage: $0 \"bin/Start_Testcase --testcase=AutentApp --cancel-after-paos\" 20"
	exit 1
}

if [ $# -ne 2 ]
then
	usage
fi

CMD=$1
NUM_THREADS=$2

if [[ "$NUM_THREADS" -le 0 ]] 2>/dev/null; then
	echo "Second argument has to be a positive integer."
	usage
fi

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
	CMD=$1
	PREFIX=$2
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
	$CMD 1> "$stdout" 2> "$stderr" &
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
		start_with_prefix "$CMD" "$i" &
		PIDs+=($!)
	done

	wait_for_pids PIDs[@]
)
