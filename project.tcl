# Create a Simulator
set ns [new Simulator]

# Create a Trace file
set tracefile [open project.tr w]
$ns trace-all $tracefile

# NAM file creation
set namfile [open project.nam w]
$ns namtrace-all $namfile

# Finish Proc
proc finish {} {
    global ns tracefile namfile
    $ns flush-trace
    close $tracefile
    close $namfile
    exec nam project.nam &
    exit 0
}

$ns color 1 black
$ns color 2 green
$ns color 3 blue
$ns color 4 red

#### Implementations

## **** Stable Connection ****
## Communication without attack or Encryption
set stable0 [$ns node]
set stable1 [$ns node]

$stable0 color green
$stable0 label "Stable Node 0"
$stable1 color green
$stable1 label "Stable Node 1"

# Connection
$ns duplex-link $stable0 $stable1 5Mb 2ms DropTail

# Agent Creation
set udp [new Agent/UDP]
$ns attach-agent $stable0 $udp
$udp set fid_ 1

set null [new Agent/Null]
$ns attach-agent $stable1 $null

$ns connect $udp $null

# Creation of Application
set cbrStable [new Application/Traffic/CBR]
$cbrStable attach-agent $udp

# Start Traffic
$ns at 0.1 "$ns trace-annotate {Starting Stable Communication...}"
$ns at 0.1 "$cbrStable start"
$ns at 0.6 "$cbrStable stop"
$ns at 0.6 "$ns trace-annotate {Stable Communication Stopped...}"



## **** Attacked Connection ****
## Connection with a DOS Attack

set server1 [$ns node]
set server2 [$ns node]
set client1 [$ns node]
set client2 [$ns node]
set attacker [$ns node]

$server1 color orange
$server1 label "server 1"
$server2 color orange
$server2 label "server 2"
$client1 color blue
$client1 label "client 1"
$client2 color blue
$client2 label "client 2"
$attacker color red
$attacker label "attacker"

# Connection
$ns duplex-link $client1 $server1 12Mb 100ms DropTail
$ns duplex-link $client2 $server1 12Mb 100ms DropTail
$ns duplex-link $attacker $server1 12Mb 100ms DropTail
$ns duplex-link $server1 $server2 6Mb 200ms DropTail
$ns queue-limit $server1 $server2 20

# set qmonitor [$ns monitor-queue $server1 $server2 [open qm.out w] ];
# [$ns link $server1 $server2] queue-sample-timeout;

# Agents
set udp1 [new Agent/UDP]
$ns attach-agent $client1 $udp1
$udp1 set fid_ 3

set udp2 [new Agent/UDP]
$ns attach-agent $client2 $udp2
$udp2 set fid_ 3  

set udp3 [new Agent/UDP]
$ns attach-agent $attacker $udp3 
$udp3 set fid_ 4

set null [new Agent/Null]
$ns attach-agent $server2 $null

$ns connect $udp1 $null
$ns connect $udp2 $null
$ns connect $udp3 $null

# Application
set cbr1 [new Application/Traffic/CBR]
$cbr1 attach-agent $udp1
$cbr1 set packet_size_ 7000
$cbr1 set rate_ 0.4Mb
$cbr1 set random_ false
$cbr1 set interval_ 0.08

set cbr2 [new Application/Traffic/CBR]
$cbr2 attach-agent $udp2
$cbr2 set packet_size_ 4000
$cbr2 set rate_ 0.6Mb
$cbr2 set random_ false
$cbr2 set interval_ 0.05

set cbr3 [new Application/Traffic/CBR]
$cbr3 attach-agent $udp3
$cbr3 set packet_size_ 24000
$cbr3 set rate_ 0.3Mb
$cbr3 set random_ false
$cbr3 set interval_ 0.02

# Start Traffic
$ns at 0.8 "$ns trace-annotate {Attack Simulation Starting...}"
$ns at 0.8 "$ns trace-annotate {___Clients start communication with the server...}"
$ns at 0.8 "$cbr1 start"
$ns at 0.8 "$cbr2 start"
$ns at 1.2 "$ns trace-annotate {___Attacker starts the attack...}"
$ns at 1.2 "$cbr3 start"
$ns at 1.6 "$cbr1 stop"
$ns at 1.6 "$cbr2 stop"
$ns at 1.6 "$cbr3 stop"
$ns at 1.8 "$ns trace-annotate {Attack Simulation Stopped...}"


## **** Encrypted Connection ****
## Communication with Encryption

# Procedure to Encrypt
proc encrypt {s {n 3}} {
    set r {}
    binary scan $s c* d
    foreach {c} $d {
        append r [format %c [expr {
                        (($c ^ 0x40) & 0x5F) < 27 ? 
                        (((($c ^ 0x40) & 0x5F) + $n - 1) % 26 + 1) | ($c & 0xe0)
                        : $c
                    }]]
    }
    return $r
}

# Procedure to Decrypt
proc decrypt {s {n 3}} {
    set n [expr {abs($n - 26)}]
     return [encrypt $s $n]
}

# UDP Agent procedure to Process Recieved Data
Agent/UDP instproc process_data {size data} {
    global ns
    $self instvar node_
    $ns trace-annotate "Message received by [$node_ node-addr] :  {$data}"
    set dec_message [decrypt $data]
    $ns trace-annotate "Decoded Message recieved by [$node_ node-addr]: {$dec_message}"
}

# Procedure to send Data
proc send_message {node agent message} {
    global ns
    $ns trace-annotate "Message to be sent by [$node node-addr] : {$message}"
    set enc_message [encrypt $message]
    $ns trace-annotate "Encoded Message sent by [$node node-addr] : {$enc_message}"
    eval {$agent} send 999 {$enc_message}
}

set node0 [$ns node]
set node1 [$ns node]

$node0 color violet
$node0 label "encrypted node 1"
$node1 color violet
$node1 label "encrypted node 2"

# Connection
$ns duplex-link $node0 $node1 0.7Mb 100ms DropTail

# Agent Creation
set enc_udp0 [new Agent/UDP]
$ns attach-agent $node0 $enc_udp0
$enc_udp0 set fid_ 0

set enc_udp1 [new Agent/UDP]
$ns attach-agent $node1 $enc_udp1
$enc_udp1 set fid_ 1

$ns connect $enc_udp0 $enc_udp1

# Start Traffic
$ns at 2.1 "$ns trace-annotate {Starting Encrypted Communication...}"
$ns at 2.1 "send_message $node0 $enc_udp0 {Send me the password}"
$ns at 2.3 "send_message $node1 $enc_udp1 {Password is ThIsisInFosEcuRiTy}"
$ns at 2.5 "$ns trace-annotate {Encrypted Communication Stopped...}"


$ns at 2.8 "finish"
$ns run