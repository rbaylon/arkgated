#!/usr/bin/perl
use strict;
use warnings;
use JSON;

my $initcommand = 'pfctl -sr -v';  # Change this to any safe shell command

my $gwfile = "gateways.json";
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
initData();

sub setBytes {
    my $subid = shift;
    my $dl = shift;
    my $cmd = "pfctl -sq -v | grep -A1 \" $subid\"";
    my $record = [];
    open(my $fh, '-|', $cmd) or die "Failed to execute '$cmd': $!";
    my $out = 0;
    my $in = 0;
    my $gw = $data->{"ids"}->{$subid}->{"gateway"};
    while (my $line = <$fh>) {
        chomp($line);  # Remove trailing newline
        @record = split /\s+/, $line;
        if ($line =~ /$subid/ && $line =~ /\s+lan/){
            $out = 1;
            next;
        }
        if ($line =~ /$subid/ && $line =~ /\s+$gw\s+/){
            $in = 1;
            next;
        }
        if ($out == 1){
            if($dl == 1){
                $data->{"ids"}->{$subid}->{"out"} = ($record[5] - $data->{"ids"}->{$subid}->{"out"})*8;
            } else {
                $data->{"ids"}->{$subid}->{"dropout"} = 0+$record[10];
                $data->{"ids"}->{$subid}->{"out"} = 0+$record[5];
            }
            $out = 0;
            $in = 0;
            next;
        }
        if ($in == 1){
            if($dl == 1){
                $data->{"ids"}->{$subid}->{"in"} = ($record[5] - $data->{"ids"}->{$subid}->{"in"})*8;
            } else {
                $data->{"ids"}->{$subid}->{"in"} = 0+$record[5];
            }
            $in = 0;
            $in = 0;
            next;
        }
    }
    close($fh) or warn "Error closing pipe: $!";
}

foreach my $key (keys %{$data->{"ids"}}) {
    setBytes($key, 0);
}
sleep(1);
foreach my $key (keys %{$data->{"ids"}}) {
    setBytes($key, 1);
}
my $json_datatext = encode_json($data);
print $json_datatext;