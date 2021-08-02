#!/usr/bin/perl

# Parses Nmap XML output and creates a Mindmap with important info such as:
# IPs, hostnames, Open Services and ports, software versions, etc..
# Coded sometime in Nov 2011


@brute_forces = ('ftp','ssh','telnet','pop3','rdp','ms-sql','mysql');
@ftps = ();
@sshs = ();
@telnets = ();
@pop3s = ();
@rdps = ();
@mssqls = ();
@mysqls = ();
@softwares_services = ();

my $input_file = $ARGV[0];
my $output_file = $ARGV[1];


open FILE, '<', $input_file or die "lol\n";

open FILE2, '>', $output_file or die "lolz\n";


my $head = '<?xml version="1.0" ?><map version="0.7.1"><node FOLDED="false" ID="'.create_random_id().'" TEXT="NMAP RESULTS">'."\n";
my $foot = "</node></map>\n";
	


my $input_file_content = '';
while (my $a = <FILE>) {
	$a =~ s/\n//g;
	if ($a =~ /<host /) {
		$a =~ s/<host /\n\n<host /;
	}
	if ($a =~ /<\/host>/) {
		$a =~ s/<\/host>/<\/host>\n\n/;
	}
	$input_file_content .= $a;
}

#print $input_file_content."\n";

#exit;

print FILE2 $head;
#exit;

while ($input_file_content =~ /<host ([^\n]+)<\/host>/g) {
	my $content = $1;

	my($ip,$host,$port,$software,$version,$extras,$port_content,$status,$count,@extras);
	if ($content =~ /<address addr="([^"]+)"/) {
		$ip = $1;###
	}
	if ($content =~ /<hostname name="([^"]+)"/) {
		$host = $1;###
	}
	
	if ((length($host) > 1)&&(length($ip) > 0)) {
		print FILE2 '<node FOLDED="false" ID="'.create_random_id().'" POSITION="right" TEXT="'.$ip.'&#xA;'.$host.'"><node FOLDED="true" ID="'.create_random_id().'" TEXT="Ports">'."\n";
	}
	else {
		if (length($ip) > 0) {
			print FILE2 '<node FOLDED="false" ID="'.create_random_id().'" POSITION="right" TEXT="'.$ip.'"><node FOLDED="true" ID="'.create_random_id().'" TEXT="Ports">'."\n";
		}
	}
	       
	while ($content =~ /<ports>(.+)<\/ports>/g) {      
		$port_content = $1;                       
		
		if ($port_content =~ /<extraports state="([^"]+)" count="([0-9]*)"/) {
			($status,$count) = ($1,$2);###
		}
		
		if ($port_content =~ /<port /) {
			$port_content =~ s/<port /\n\n<port /g;
		}
		if ($port_content =~ /<\/port>/) {
			$port_content =~ s/<\/port>/<\/port>\n\n/g;
		}
		
		
		
		while ($port_content =~ /<port ([^\n]+)<\/port>/g) {
			my $sport_cont = $1;
			splice(@extras,0);
			my($Pprotocol,$Pport,$Pport_status,$Preason,$Pservice_name,$Pproduct,$Pversion,$Phostname,$Pextrainfo,$PProduct);
			
			if ($sport_cont =~ /protocol="([^"]+)" portid="([^"]+)"><state state="([^"]+)" reason="([^"]+)"/) {
				($Pprotocol,$Pport,$Pport_status,$Preason) = ($1,$2,$3,$4);###
			}
			push(@extras,$Pport_status.' ('.$Preason.')');	
			if ($sport_cont =~ /<service name="([^"]+)"/) {
				$Pservice_name = $1;###
				
				if (in_array($Pservice_name,@brute_forces) == 1) {
					
					if ($Pservice_name eq 'ftp') {
						push(@ftps,$ip.":".$Pport);
					}
					elsif ($Pservice_name eq 'ssh') {
						push(@sshs,$ip.":".$Pport);
					}
					elsif ($Pservice_name eq 'telnet') {
						push(@telnets,$ip.":".$Pport);
					}
					elsif ($Pservice_name eq 'pop3') {
						push(@pop3s,$ip.":".$Pport);
					}
					elsif ($Pservice_name eq 'rdp') {
						push(@rdps,$ip.":".$Pport);
					}
					elsif ($Pservice_name eq 'ms-sql') {
						push(@mssqls,$ip.":".$Pport);
					}
					elsif ($Pservice_name eq 'mysql') {
						push(@mysqls,$ip.":".$Pport);
					}
				}
				
			}
			if ($sport_cont =~ /product="([^"]+)"/) {
				$Pproduct = $1;###
			}
			if ($sport_cont =~ /version="([^"]+)"/) {
				$Pversion = $1;###
			}
			
			if (length($Pproduct) > 1) {
				$PProduct = $Pproduct.' '.$Pversion;
				push(@extras,$PProduct);
			}
			
			if ($sport_cont =~ /hostname="([^"]+)"/) {
				$Phostname = $1;###
				push(@extras,$Phostname);
			}
			if ($sport_cont =~ /extrainfo="([^"]+)"/) {
				$Pextrainfo = $1;###
				push(@extras,$Pextrainfo);
			}
			while ($sport_cont =~ /<script id="([^"]+)" output="([^"]+)"\/>/g) {
				my $Pscripts = $1." : ".$2;
				#print $Pscripts."\n";
				push(@extras,$Pscripts);	
			}
			
			if (length($PProduct) > 0) {
				if (length($Pextrainfo) > 0) {
					push(@softwares,"|-|".$ip.":".$Pport."|-|".$PProduct." ".$Pextrainfo);
				}
				else {
					push(@softwares,"|-|".$ip.":".$Pport."|-|".$PProduct);
				}
			}
			
			
			
			
			print FILE2 '<node ID="'.create_random_id().'" TEXT="'.$Pport.'/'.$Pprotocol.' '.$Pservice_name.'">'."\n";
			
			foreach my $e(@extras) {
				print FILE2 '<node ID="'.create_random_id().'" TEXT="'.$e.'"/>'."\n";
			}
			
			print FILE2 '</node>'."\n";
			
		}
		
		if ((length($status) > 0)&&(length($count) > 0)) {
			print FILE2 '<node ID="'.create_random_id().'" TEXT="Extraports State:'.$count.' ports are '.$status.'"/>'."\n";
		}
		
	}
	print FILE2 "</node>\n";
	
	
	
	
	if ($content =~ /<osmatch name=/) {
		print FILE2 '<node FOLDED="true" ID="'.create_random_id().'" TEXT="Misc">'."\n";
		print FILE2 '<node FOLDED="true" ID="'.create_random_id().'" TEXT="OS Guess">'."\n";
		while ($content =~ /<osmatch name="([^"]+)" accuracy="([^"]+)"/g) {  
			print FILE2 '<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$1.' ('.$2.'%)"/>'."\n";
		}
		print FILE2 '</node></node>';
	}
	
	print FILE2 "</node>\n";
}
	
print FILE2 $foot;	
	
	
sub create_random_id {
	my @chars_length = ('8','4','4','4','12');
	my @chars = ('A'..'Z','0'..'9');
	my $tot_str;
	foreach my $l(@chars_length) {
		my $rstr;
		foreach (1..$l) {
			$rstr .= $chars[rand @chars];
		}
		$tot_str .= $rstr."-";
	}
	$tot_str =~ s/-$//;
	
	my $r = in_array($tot_str,@randoms_id);
	if ($r == 1) {
		create_random_id();
	}
	else {
		push(@randoms_id,$tot_str);
	}
	return($tot_str);
}

sub in_array() {
    my($l,@arr) = @_;
    my $found = 0;
    foreach my $e(@arr) {
        if ($found == 0) {
            if ($e eq $l) {
                $found = 1;
            }
        }
    }
    return $found;
}