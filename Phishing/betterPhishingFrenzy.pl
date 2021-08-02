#!/usr/bin/perl

use HTTP::BrowserDetect;

=pod

# written ~ Nov-Dec 2016
phishing frenzy when you go on the reports page doesn't give you an option to download a file which has the full info:
UID, email, TS, UA. etc .. because it's crap :)
so you have to do the following.

go to the reports page and download the apache raw log file, and supply the filename to the script
this is needed as it will:
get the UID from the link, and for each uid will store in a hash the timestamp of the request, the IP, and UA

then, the part that sucks (this is needed to match UID and email):
go to the report page with burp intercepting the requests and look at a request like this (you can also inspect the DOM and paste the full HTML but its quicket to parse the JSON from phishing frenzy than the formatted HTML)
https://host/reports/victims_list/<ID>
In the response, copy the whole thing and paste it in a txt file, and pass it as the second argument of the script
so script.pl www-campaign-41-access.log fullinfo.txt
at the end it will print stuff like this:

[email victim no#] EMAIL clicked X times from the following locations:
	[1] TIME: 30/Nov/2016:13:50:02 +1100 - FROM: 139.x.x.x - DEVICE: Win7
	[2] TIME: 30/Nov/2016:13:48:25 +1100 - FROM: 139.x.x.x - DEVICE: Win7
	[3] TIME: 30/Nov/2016:18:55:32 +1100 - FROM: 110.x.x.x - DEVICE: iOS
	[4] TIME: 30/Nov/2016:13:51:33 +1100 - FROM: 139.x.x.x - DEVICE: Win7
	[5] TIME: 30/Nov/2016:18:56:18 +1100 - FROM: 110.x.x.x - DEVICE: iOS
	[6] TIME: 30/Nov/2016:13:48:41 +1100 - FROM: 139.x.x.x - DEVICE: Win7


[email victim no#] EMAIL clicked X times from the following locations:
	[1] TIME: 30/Nov/2016:12:35:21 +1100 - FROM: 139.x.x.x - DEVICE: Win7
	[2] TIME: 30/Nov/2016:12:37:13 +1100 - FROM: 139.x.x.x - DEVICE: Win7


## Stats 2:

1 people clicked 15 times on the link
5 people clicked 11 times on the link
4 people clicked 10 times on the link
2 people clicked 9 times on the link
etc etc ..

## Stats 3:

2122 (79.535%) clicks from Win7
369 (13.831%) clicks from iOS
79 (2.961%) clicks from Mac OS X
44 (1.649%) clicks from Win10.0
etc etc ..

=cut



my %data = {};
my %clicks = ();
my %oss = ();
my %victims = ();

my $access_logs = $ARGV[0];
my $frenzy_stuff = $ARGV[1];
my $total_clicks = 0;

if ((!$access_logs)||(!$frenzy_stuff)) {
	print "\nUsagez:\n\tdie.pl access_log frenzy_stuff\n\tTo understand more just read the comments at the beginning of the script\n\nbyez by Italy\nSmoke and drive fast\n";
	exit;
}


open(R,'<',$frenzy_stuff);
while(my $b = <R>) {
	while ($b =~ /\["([^"]+)","([^"]+)","Yes","Yes","Yes"/g) {
		$victims{$1} = $2;
	}
}

open (F, '<', $access_logs);
while (my $a = <F>) {
	if ($a =~ /^([0-9.]+)\s-\s-\s\[([^\]]+)\]\s"[^\s]+\s\/\?uid=([a-zA-Z0-9]+)\s[^"]+"[^"]+"[^"]+"[^"]+"([^"]+)"/) {
		my $ip = $1;
		my $ts = $2;
		my $uid = $3;
		my $ua = $4;

		if (!exists $victims{$uid}) {
			next;
		}

		$data{$uid}{$ts} = $ip."_".$ua;

		my $uap = HTTP::BrowserDetect->new($ua);
		my $os = $uap->os_string();

		if (!exists $oss{$os}) {
			$oss{$os} = 1;
		}
		else {
			$oss{$os} = $oss{$os} +1;
		}

		$total_clicks++;
	}
}

my $cccc = 0;
my $not = 0;

print "\n## Stats 1:\n\n";

while ( my ($key, $value) = each(%data) ) {
	
	my $count = keys %{$data{$key}};
	my $vem = $victims{$key};

	if (!exists $victims{$key}) {
		next;
	}
	$cccc++;


	my $t = 'times';
	if ($count <= 1) {
		$t = 'time';
	}

	print "[$cccc] $vem clicked $count $t from the following locations:\n";

	if (!exists $clicks{$count}) {
		$clicks{$count} = 1;
	}
	else {
		$clicks{$count} = $clicks{$count} +1;
	}	

	my $ccc = 0;
	while ( my ($keyy, $valuee) = each(%$value) ) {
		$ccc++;
		$valuee =~ /([0-9.]+)_(.+)/;
		my $ip = $1;
		my $r = $2;
		my $uap = HTTP::BrowserDetect->new($r);
		my $os = $uap->os_string();
		print "\t[$ccc] TIME: $keyy - FROM: $ip - DEVICE: $os\n";
	}
	print "\n\n";
}

print "## Stats 2:\n\n";
my $ccccc = 0;
foreach (sort { $b <=> $a } keys(%clicks) ) {
	$ccccc = $ccccc + $clicks{$_};
	my $t = 'times';
	if ($_ <= 1) {
		$t = 'time';
	}

	print $clicks{$_}." people clicked $_ $t on the link\n";
}

# print "Tot users scraped from access_logs : $cccc ; users now $ccccc\n";

print "\n\n## Stats 3:\n\n";

foreach (sort { $oss{$b} <=> $oss{$a} } keys(%oss) ) {
    my $perc = ($oss{$_} / $total_clicks)*100;
    my $rounded = sprintf "%.3f", $perc;
	print $oss{$_}." ($rounded%) clicks from $_\n";
}

print "\n\nHasta la vista!\n\n";