#!/usr/bin/perl
use strict;
use warnings;
use JSON;

my $data = {};
my $key = $ARGV[0];
my $internalInterface = $ARGV[1];
sub initData {
    my $s = shift;
    $data->{$s}->{"in"} = 0;
    $data->{$s}->{"out"} = 0;
    $data->{$s}->{"dropout"} = 0;
}

initData($key);

sub setBytes {
    my $subid = shift;
    my $dl = shift;
    my $cmd = "pfctl -sq -v | grep -A1 \" $subid\"";
    my @record = [];
    open(my $fh, '-|', $cmd) or die "Failed to execute '$cmd': $!";
    my $out = 0;
    my $in = 0;
    my $inbytes = 0;
    my $outbytes = 0;
    while (my $line = <$fh>) {
        chomp($line);  # Remove trailing newline
        @record = split /\s+/, $line;
        if ($line =~ /$subid/){
            if ($line =~ /$internalInterface\s+/) {
                $out = 1;
                next;
            } else {
                $in = 1;
                next;                
            }
        }
        if ($out == 1){
            if($dl > 0){
                $outbytes = ($record[5] - $record[10]) - $data->{$subid}->{"out"};
                $outbytes = $outbytes/$dl;
                $data->{$subid}->{"out"} = ($outbytes)*8;
            } else {
                $data->{$subid}->{"dropout"} = 0+$record[10];
                $data->{$subid}->{"out"} = $record[5] - $record[10];
            }
            $out = 0;
            $in = 0;
            next;
        }
        if ($in == 1){
            if($dl > 0){
                $inbytes = ($record[5] - $record[10]) - $data->{$subid}->{"in"};
                $inbytes = $inbytes/$dl;
                $data->{$subid}->{"in"} = ($inbytes)*8;
            } else {
                $data->{$subid}->{"in"} = $record[5] - $record[10];
            }
            $in = 0;
            $out = 0;
            next;
        }
    }
    close($fh) or warn "Error closing pipe: $!";
}

my $time_start = time();
setBytes($key, 0);
sleep(1);
my $time_end = time();
setBytes($key, $time_end - $time_start);
my $json_datatext = encode_json($data);
print $json_datatext;