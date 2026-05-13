#!/usr/bin/perl
use strict;
use warnings;
use JSON;
use File::Basename;

my $initcommand = 'pfctl -sr -v';  # Change this to any safe shell command

my $dirname = dirname(__FILE__);
my $gwfile = "$dirname/system.json";
my $json_text = do {
    open(my $fh, "<:encoding(UTF-8)", $gwfile)
        or die "Could not open $gwfile: $!";
    local $/; # Enable 'slurp' mode to read the whole file at once
    <$fh>;
};

my $gwdata = decode_json($json_text);

my $data = {};
my $nextok = 0;
my $ip = "";
my $iface = "";
my $direction = "";
my @record = [];
my $subid = "";
my $skip = 0;
sub initData {
    open(my $fh, '-|', $initcommand) or die "Failed to execute '$initcommand': $!";
    while (my $line = <$fh>) {
        chomp($line);  # Remove trailing newline
        @record = split /\s+/, $line;
        if($line =~ /subid/){
            if($record[1] =~ /in/){
                $ip = $record[7];
                $iface = $record[4];
                $direction = $record[1];
                $subid =  $record[-1];
                $data->{"ids"}->{$record[16]}->{"addr"} = $record[7];
                $data->{"ids"}->{$record[16]}->{"out"} = 0;
                $data->{"ids"}->{$record[16]}->{"in"} = 0;
                $data->{"ids"}->{$record[16]}->{"dropout"} = 0;
                $data->{"ids"}->{$record[16]}->{"gateway"} = $gwdata->{"gateways"}->{$record[-1]};
                $data->{"ifaces"}->{$record[4]}->{"out"} = 0;
                $data->{"ifaces"}->{$record[4]}->{"in"} = 0;
                $data->{"gateways"}->{$record[-1]}->{"name"} = $gwdata->{"gateways"}->{$record[-1]};
                $data->{"gateways"}->{$record[-1]}->{"count"} += 1;
                $data->{"gateways"}->{$record[-1]}->{"iface"} = $gwdata->{"ifaces"}->{$gwdata->{"gateways"}->{$record[-1]}};
            } elsif ($record[1] =~ /out/) {
                $data->{"ifaces"}->{$record[4]}->{"out"} = 0;
                $data->{"ifaces"}->{$record[4]}->{"in"} = 0;
            }
        }
    }

    # Close the filehandle and check for errors
    close($fh)
        or warn "Error closing pipe: $!";
}

sub setCpuStats {
    my $cmd = "sysctl | grep degC | head -1";
    open(my $fh, '-|', $cmd) or die "Failed to execute '$cmd': $!";
    while (my $line = <$fh>) {
        chomp($line);  # Remove trailing newline
        @record = split /\=/, $line;
        $data->{"cpu"}->{"temperature"} = $record[1];
    }
    close($fh) or warn "Error closing pipe: $!";

    my $cmd = "iostat";
    open(my $fh, '-|', $cmd) or die "Failed to execute '$cmd': $!";
    while (my $line = <$fh>) {
        chomp($line);  # Remove trailing newline
        @record = split /\s+/, $line;
        $data->{"cpu"}->{"idle"} = $record[-1];
    }
    close($fh) or warn "Error closing pipe: $!";
}

initData();
setCpuStats();

sub setBytes {
    my $subid = shift;
    my $dl = shift;
    my $cmd = "pfctl -sq -v | grep -A1 \" $subid\"";
    my $record = [];
    open(my $fh, '-|', $cmd) or die "Failed to execute '$cmd': $!";
    my $out = 0;
    my $in = 0;
    my $gw = $data->{"ids"}->{$subid}->{"gateway"};
    my $inbytes = 0;
    my $outbytes = 0;
    while (my $line = <$fh>) {
        chomp($line);  # Remove trailing newline
        @record = split /\s+/, $line;
        if ($line =~ /$subid+lan/){
            $out = 1;
            next;
        }
        if ($line =~ /$subid$gw/){
            $in = 1;
            next;
        }
        if ($out == 1){
            if($dl > 0){
                $outbytes = ($record[5] - $record[10]) - $data->{"ids"}->{$subid}->{"out"};
                $outbytes = $outbytes/$dl;
                $data->{"ids"}->{$subid}->{"out"} = ($outbytes)*8;
            } else {
                $data->{"ids"}->{$subid}->{"dropout"} = 0+$record[10];
                $data->{"ids"}->{$subid}->{"out"} = $record[5] - $record[10];
            }
            $out = 0;
            $in = 0;
            next;
        }
        if ($in == 1){
            if($dl > 0){
                $inbytes = ($record[5] - $record[10]) - $data->{"ids"}->{$subid}->{"in"};
                $inbytes = $inbytes/$dl;
                $data->{"ids"}->{$subid}->{"in"} = ($inbytes)*8;
            } else {
                $data->{"ids"}->{$subid}->{"in"} = $record[5] - $record[10];
            }
            $in = 0;
            $in = 0;
            next;
        }
    }
    close($fh) or warn "Error closing pipe: $!";
}

my $time_start = time();
foreach my $key (keys %{$data->{"ids"}}) {
    setBytes($key, 0);
}
sleep(1);
my $time_end = time();
foreach my $key (keys %{$data->{"ids"}}) {
    setBytes($key, $time_end - $time_start);
}
my $json_datatext = encode_json($data);
print $json_datatext;