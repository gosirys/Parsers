#!/usr/bin/perl

# Gio has the biggest cazzo in the solar system.
# Gio is a big cazzo, thassit

# stores in a hash the systems (IPs) with web open ports. also stores the port and the protocol
# then opens the file with all hostnames. foreach of these, gets their ip. if this ip is inside
# the hash of the systems, means that that host as open ports. gets which ports and protocols,
# and builds the URL.

# Coded sometime in 2016??



$nmap_input_file = $ARGV[0];
$hostnames_input_file = $ARGV[1];
$hosts_supplied = 1;


if ($nmap_input_file =~ /^(.+)\.xml$/) {
    $output_file = time."_".$1.".OUT.txt";
    if (!open INPUT_F_NMAP, '<', $nmap_input_file) {
        print "[-] The nmap input file provided could not be opened !\n    $!\n\n";
        exit(0);
    }
}
else {
    print "[-] The nmap input file must be a NMAP XML file.\n\n";
    exit(0);
}

if (length($hostnames_input_file) > 1) {
    if (!open INPUT_F_HOSTS, '<', $hostnames_input_file) {
        print "[-] The hostnames input file provided could not be opened !\n    $!\n\n";
        exit(0);
    }
}
else {
    $hosts_supplied = 0;
}


my %data = {};
my @urls;

open(OUT, '>', $output_file);


my $input_file_content = '';
while (my $a = <INPUT_F_NMAP>) {
    $a =~ s/\n//g;
    if ($a =~ /<host /) {
        $c++;
        $a =~ s/<host /\n\n<host /;
    }
    if ($a =~ /<\/host>/) {
        $a =~ s/<\/host>/<\/host>\n\n/;
    }
    $input_file_content .= $a;
}

my %hostnames = ();
if ($hosts_supplied == 1) {
	while (my $a = <INPUT_F_HOSTS>) {
	    $a =~ s/\n//g;
	    if (!(exists($hostnames{$a}))) {
	    	$hostnames{$a} = '';
	    }
	}
}





&analyze_xml($input_file_content);

if ($hosts_supplied == 1) {
	&compare_with_hostnames;
}


print "\n\nDONE: check: ".$output_file."\n\n";
close(OUT);
close(INPUT_F_NMAP);
close(INPUT_F_HOSTS);

sub analyze_xml() {
	my $input_file_content = $_[0];

	while ($input_file_content =~ /<host ([^\n]+)<\/host>/g) {
		
		my $content = $1;

		my($ip,$host,$port_content,$status,$count);
		if ($content =~ /<address addr="([^"]+)"/) {
			$ip = $1;
		}
		my $port_stram = '';
		      
		if ($content =~ /<ports>(.+)<\/ports>/g) {      
			$port_content = $1;                       
			
			if ($port_content =~ /<port /) {
				$port_content =~ s/<port /\n\n<port /g;
			}
			if ($port_content =~ /<\/port>/) {
				$port_content =~ s/<\/port>/<\/port>\n\n/g;
			}

			$open_ports = 0;
			while ($port_content =~ /<port ([^\n]+)<\/port>/g) {
				my @protocols = ();
				my $sport_cont = $1;
				my($Pprotocol,$Pport,$Pport_status,$Pservice_name,$ssl) = '';
				
			    if ($sport_cont =~ /portid="([^"]+)"><state state="([^"]+)"/) {
			    	($Pport,$Pport_status) = ($1,$2);
			  	}
			  	if ($Pport_status !~ /open/) {
			  		next;
			  	}

			  	if ($sport_cont =~ /<service name="([^"]+)"/) {
			    	$Pservice_name = $1;
			    }

			  	if ($sport_cont =~ /tunnel="ssl"/) {
			    	$ssl = 1;
			    }


			  	#print "$ip - $Pport - $Pservice_name\n";
			  	if ($Pservice_name =~ /^https$/) {
			  		if ($ssl != 1) {
			  			@protocols = qw(http https);
			  		}
			  		else {
			  			@protocols = qw(https);
			  		}
			  	}
			  	elsif (($Pservice_name =~ /^http$/)||($Pservice_name =~ /^http-proxy$/)) {
			  		if ($ssl == 1) {
			  			@protocols = qw(http https);
			  		}
			  		else {
			  			@protocols = qw(http);
			  		}
			  	}
			  	foreach my $ii(@protocols) {
			  		print "\t\t$ip - $Pport - $ii\n";
			  		# $data{$ip} = $Pport.'#'.$Pservice_name;
			  		$data{$ip}{$Pport} = $ii;
			  		if ($hosts_supplied == 0) {
			  			my $url = $ii.'://'.$ip.':'.$Pport.'/';
						print "\t".$url."\n";
						print OUT $url."\n";
						push(@urls,$url);
			
			  		}
			  	}

			}
		}

	}


}


sub compare_with_hostnames {

	# while (my($key, $value) = each(%data)) {
	# 	print "$key\n";
	# 	while (my($keyy, $valuee) = each(%$value)) {
	# 		print "\t$keyy - $valuee\n";
	# 	}
	# }

	foreach my $key (keys %hostnames) {
		print "Host: $key - IP: ";
		my $ip;
		if ($key =~ /^[0-9\.]+$/) {
			$ip = $key;
		}
		else {
			$ip = conv_host2ip($key);
			# 
		}
		print "$ip ..\n";
		if ($ip =~ /^[0-9\.]+$/) {
			if (exists $data{$ip}) {
				# print "IP: $ip\n";
				my $ref = $data{$ip};
				while (my($port, $protocol) = each(%$ref)) {
					print "\tk: $port\n\t$protocol\n\n";
					my $url = $protocol.'://'.$key.':'.$port.'/';
					my $url2 = $protocol.'://'.$ip.':'.$port.'/';
					print "\t".$url."\n\t".$url2."\n";
					print OUT $url."\n".$url2."\n";
					push(@urls,$url);
				}
				# my $url = $protocol.'://'.$ip.':'.$port.'/';
				# print "\t".$url."\n";
				# print OUT $url."\n";
				# push(@urls,$url);
			}
		}
	}

}

sub conv_host2ip() {
	my $h = $_[0];
	my(@octets,$raw_addr,$host_name);
	@octets = ();
	$raw_addr = (gethostbyname($h))[4];
    @octets = unpack("C4", $raw_addr);
    $host_name = join(".", @octets);
	return($host_name);
}

# EOF*off