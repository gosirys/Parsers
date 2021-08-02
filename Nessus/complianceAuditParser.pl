#!/usr/bin/perl

# by ME
# Parses Nessus Compliances reports (CIS benchmarks etc) and creates an HTML report with nice tables, summary stats, ready to copy and paste in MS Word
# Useful for Vulnerability Assessments/PCI compliance to get Nessus Findings into a Word document

use Data::Dumper;
use Sort::Versions;
use HTML::Entities;

open(F, '<', $ARGV[0]);

my %policies_failed = ();
my %policies_passed = ();

my $content = '';
while (my $a = <F>) {
	$content .= $a;
}



$content =~ s/<ReportHost name/\n\n\n\n<ReportHost name/g;
@hosts_content = split /\n\n\n\n/, $content;

my $host_content = '';		
	
foreach my $bits(@hosts_content) {
	# print $bits."\n\n\n";
	my $ip = '';
	my @item_contents = ();

	if ($bits =~ /ReportHost name="([^"]+)/) {
		$ip = $1;
	}

	my $thost_content = $bits;
	

	$thost_content =~ s/<ReportItem/\n\n\n\n<ReportItem/g;
	@item_contents = split /\n\n\n\n/, $thost_content;

	

	foreach my $bit(@item_contents) {
		#title
		# print "\n\n==========\n";
		
		my($policy_number,$policy_name,$policy_info,$policy_see_also,$policy_ref,$policy_expected_value,$policy_actual_value,$policy_result) = '';
	
		if ($bit =~ /<cm:compliance-check-name>([^<]+)<\/cm:compliance-check-name>/) {
			$policy_name = $1;
			if ($policy_name =~ /^([^\s]+)/) {
				$policy_number = $1;
			}
			# print "#$policy_number - name: $policy_name\n";
		}
	
		#info
		if ($bit =~ /<cm:compliance-info>([^<]+)<\/cm:compliance-info>/) {
			$policy_info = $1;
			# print "info: $policy_info\n";
		}
		
		#ref
		if ($bit =~ /<cm:compliance-see-also>([^<]+)<\/cm:compliance-see-also>/) {
			$policy_see_also = $1;
			# print "see also: $policy_see_also\n";
		}
		
		if ($bit =~ /<cm:compliance-reference>([^<]+)<\/cm:compliance-reference>/) {
			$policy_ref = $1;
			# print "ref: $policy_ref\n";
		}
		
		#expected value
		if ($bit =~ /<cm:compliance-policy-value>([^<]+)<\/cm:compliance-policy-value>/) {
			$policy_expected_value = $1;
			$policy_expected_value =~ s/\\\\//g;
			# print "exp value: $policy_expected_value\n";
		}
		
		#actual value
		if ($bit =~ /<cm:compliance-actual-value>([^<]+)<\/cm:compliance-actual-value>/){
			$policy_actual_value = $1;
			$policy_actual_value =~ s/\\\\//g;
			# print "actual value: $policy_actual_value\n";
		}
		
		#status
		if ($bit =~ /<cm:compliance-result>([^<]+)<\/cm:compliance-result>/) {
			$policy_result = $1;
			# print "status: $policy_result\n";
		}
	
		# my($policy_name,$policy_info,$policy_see_also,$policy_ref,$policy_expected_value,$policy_actual_value,$policy_result) = '';
	
	
		if ($policy_result eq 'FAILED') {
			if (!exists $policies_failed{$policy_number}) {
				$policies_failed{$policy_number}{'name'} = $policy_name;
				$policies_failed{$policy_number}{'info'} = $policy_info;
				$policies_failed{$policy_number}{'see_also'} = $policy_see_also;
				$policies_failed{$policy_number}{'ref'} = $policy_ref;
				$policies_failed{$policy_number}{'expected_value'} = $policy_expected_value;
		
			}
			$policies_failed{$policy_number}{'system_specific_result'}{$ip} = decode_entities($policy_actual_value);
			# else {
			# 	$policies{$policy_name}{'services'} .= ', '.$service;
			# }
		}
		elsif ($policy_result eq 'PASSED') {
			if (!exists $policies_passed{$policy_number}) {
				$policies_passed{$policy_number}{'name'} = $policy_name;
				$policies_passed{$policy_number}{'info'} = $policy_info;
				$policies_passed{$policy_number}{'see_also'} = $policy_see_also;
				$policies_passed{$policy_number}{'ref'} = $policy_ref;
				$policies_passed{$policy_number}{'expected_value'} = $policy_expected_value;
			}

			$policies_passed{$policy_number}{'system_specific_result'}{$ip} = $policy_actual_value;	
		}
	
	}
}


# print "\n\n\n\n\n\n";
# print Dumper(\%policies_failed);

# exit;
my $css_style = '<style type="text/css">

table {
	padding: 0;
	border: 0;
	border-spacing: 0px;
	border-collapse:collapse;
}

tr {
	padding: 0;
	border: 0;
	border-spacing: 0px;
}

td {
	border-width: 1px 1px 1px 1px;
	border-style: solid;
	border-color: black;
	border-spacing: 0px;
	padding: 0px;
}

.header {
	background-color: #808080;
	color: white;
}

</style>';

my $html = '<html><head><title>dfdffdf</title>'.$css_style.'</head><body><table style="border:1px solid black;border-collapse:collapse;"><tr class="header">
<td>Policy</td>
<td>Info</td>';
# <td>Ref</td>
# <td>See also</td>
$html .= '<td>Expected Value</td>
<td>Actual Value</td></tr>';


# print Dumper(\%policies_failed);
# exit;



my @l = sort versioncmp keys %policies_failed;

# print $_."\n" for @l;
# exit;



foreach my $keyy(@l) {

# while ( my ($keyy, $valuee) = each(%policies_failed) ) {
	# while ( my ($keyyy, $valueer) = each(%$valuee) ) {
		$html .= '<tr>';
		# if (ref($valueer) eq "HASH") {
		# 	print "mmmm\n";
		# 	while ( my ($z, $c) = each(%$valueer) ) {
		# 		print "\t___z: $z\n\t___c: $c\n";
		# 	}
		# }
		# else {
			my $name = $policies_failed{$keyy}{'name'};
			my $info = $policies_failed{$keyy}{'info'};
			my $ref = $policies_failed{$keyy}{'ref'};
			my $see_also = $policies_failed{$keyy}{'see_also'};
			my $expected_value = $policies_failed{$keyy}{'expected_value'};
			print "\n\n\nname: $name\ninfo: $info\nref: $ref\nsee also: $see_also\nexpected value: $expected_value\n";

			$html .= '<td>'.$name.'</td><td>'.$info.'</td>';
			# <td>'.$ref.'</td><td>'.$see_also.'</td>
			$html .= '<td>'.$expected_value.'</td>';
			if (ref($policies_failed{$keyy}{'system_specific_result'}) eq "HASH") {
				$html .= '<td>';
				while ( my ($z, $c) = each($policies_failed{$keyy}{'system_specific_result'}) ) {
					# z: is the IP
					# $html .= ''.$z.': '.$c.'';
					$html .= $c;
					print "\t___z: $z\n\t___c: $c\n";
				}
				$html .= '</td>';			
			}

			# print "keyyy: $keyyy\nvalueer: $valueer\n\n";

		# }
		$html .= '</tr>';
		# if ($keyyy eq 'system_specific_result') {
		# 	print "aa\n";

		# 	while ( my ($z, $c) = each(%$keyyy) ) {
		# 		print "\t___z: $z\n\t___c: $c\n";
		# 	}

		# 	# while ( my ($keyyyy, $valueerr) = each(%policies_failed{$keyy}{'system_specific_result'}) ) {
		# 	# 	print "\t\t_________ $valueerr\n";
		# 	# }
		# }

	# }
	# print "=========\n";
}
$html .= '</table></body></html>';
open(OUT, '>', 'testhtml1.html');
print OUT $html;
close(OUT);
`open testhtml1.html`;

