#!/usr/bin/perl

# 30/07/2015
# This script parses google search pages and creates email addresses for a given company.
# by me

# there shouldn't be FP, or at least very few ... go ahead SPAMMING.

# Go to google, go in the settings. disable instant results and select 100 results per page. now disable JS
# in the browser. Then start searching: site:linkedin.com intext:company name
# then open the HTML source, copy it and paste it in a file. do that for every google page (4 pages is more than enough).
# then, save this file on your computer, and put its name in the variable $filename. 
# also put the email syntax and email domain.

use Switch;
use Data::Dumper;
use LWP::UserAgent;
use HTTP::Cookies;
use Parallel::ForkManager;
use HTML::Entities;

my $company = "google";

my @company = ("google inc");

my $email_syntax = "1";
my $email_domain = $ARGV[0];
my $debug = 1;
my $filename = $ARGV[1];

=begin Email syntax
1  - firstname.lastname
2  - lastname.firstname
3  - firstname_lastname
4  - lastname_firstname
5  - f.lastname
6  - l.firstname
7  - f_lastname
8  - l_firstname
9  - firstname.l
10  - lastname.f
11 - firstname_l
12  - lastname_f
13  - f.l
14  - l.f
15  - f_l
16  - l_f
17  - lastname
18 - firstname
19 - firstnamelastname
20 - lastnamefirstname
21 - flastanme
22 - lfirstname
23 - firstnamel
24 - lastnamef
=cut


open(A, '<', $filename);
$res = '';
while ($a = <A>) {
	$res .= $a;
}
close(A);

# $res =~ s/<li class="g">/<li class="g">\n/g;
# @res_splitted = split /class="g">\n/, $res;

my %people = ();


# $res =~ s/<h3 class="r">/\n<h3 class="r">/g;
# @res_splitted = split /\n<h3 class="r">/, $res;


# my $pm = Parallel::ForkManager->new(30);

# my $fname = 'responses_'.$email_domain.'.txt';

# open(F,'>', $fname);

# my @ress = ();

# foreach my $a(@res_splitted) {
# 	# print $a."\n\n\n";
# 	my $cc = 0;
# 	while ($a =~ /<a href="\/url\?q=([^&]+)/g) {

		
# 		my $match = 0;
# 		my $linkedinLink = $1;

# 		print "req: $linkedinLink\n";
# 		if (($linkedinLink =~ /\/jobs\/view\//)||($linkedinLink =~ /\/company\//)) {
# 			print "\sSkipping ..\n";
# 			next;
# 		}
# 		my $pid = $pm->start and next;
# 		my $res = req($linkedinLink);
# 		print F $res;

# 		$pm->finish;
# 	}
# }
# $pm->wait_all_children;
# close(F);

my $tres = '';
my $tres2 = '';
open(F,'<', $fname);
while (my $a = <F>) {
	$tres .= $a;
	$tres2 .= $a;
}
close(F);

		# print "res: $res\n\n";


$tres =~ s/<!DOCTYPE html>/\n<!DOCTYPE html>/g;
@res_splitted2 = split /\n<!DOCTYPE html>/, $tres;

$res =~ s/<div class="g">/\n<div class="g">/g;
@res_splittedz = split /\n<div class="g">/, $res;

foreach my $sres(@res_splitted2z) {
	while ($sres =~ /data-section="headline">([^<]+)<\/p>/g) {
		my $position = decode_entities($1);
		my $match = 0;
		
		print "pos: $position\n";

		foreach my $c(@company) {
			if ($position =~ /$c/i) {
				$match = 1;
			}
			if ($match == 1) {
				if ($sres =~ /<h1 id="name" class="fn">([^<]+)<\/h1>/) {
					my $fname = $1;
					print "fname: $fname\n\n";
					add($fname);
				}
			}			
		}

	}
	while ($sres =~ /headline-container" data-li-template="headline"><div id="headline" class="editable-item"><p class="title" dir="ltr">([^<]+)<\/p>/g) {
		my $position = decode_entities($1);
		my $match = 0;
		
		print "pos: $position\n";

		foreach my $c(@company) {
			if ($position =~ /$c/i) {
				$match = 1;
			}
			if ($match == 1) {
				if ($sres =~ /<span class="full-name" dir="auto">([^<]+)<\/span>/) {
					my $fname = $1;
					print "fname: $fname\n\n";
					add($fname);
				}
			}			
		}

	}		

}




foreach my $a(@res_splittedz) {
	$a =~ s/\n//g;
	# print $a."\n\n";
	$fname = '';
	$title = '';

	if ($a =~ /h3 class="r"><a href="[^"]+">([a-zA-Z\s\(\)]+)\| LinkedIn/) {
		$fname = $1;
	}
	
	print "fname: $fname\n\n";
	
	if (length($fname) < 2) {
		next;
	}

	my $match = 0;
	if ($a =~/class="f slp">([^<]+)</) {
		my $r = $1;
		print "r: $r\n\n";
		if ($r =~ /$company/) {
			print "\t\tR: $fname\n";
			$match = 1;
			add($fname);
			next;
		}
	}

	if (($a =~ /<span class="st">(.+)<\/span>/i)&&($match == 0)) {
		print "\n\n\n".$1."\n\n\n";
		my $t = $1;
		print "t: $t\n\n";
		if ($t =~ /current[^;]+$company/i) {
			print "YES: $fname\n\t\t$t\n\n";
			# print "\t\tT: $fname\n";
			add($fname);
		}

		else {
			if ($t =~ /$company/) {
				if ($t =~ /present/) {
					print "YES: $fname\n\t\t$t\n\n";
					# print "\t\tT: $fname\n";
					add($fname);
				}
				else {
					print "\t\tT<: $fname\n";
					#print "NO: $fname\n\t\t$t\n\n";
					add($fname);
				}				
			}
		}
	}
}

if ($debug == 1) {
	print "Debug info, for you:\n\n".Dumper(\%people)."\n\n";
}
print "\nEmails:\n\n";

my $c = 0;
my $tot = keys(%people);
foreach my $name (sort keys %people) {
	$c++;
	my $sp;
	if (length($tot) == 1) {
		$sp = ' ';
	}
	elsif (length($tot) == 2) {
		$sp = ' ';
		if ($c < 10) {
			$sp = '  ';
		}

	}
	elsif (length($tot) == 3) {
		$sp = ' ';
		if (length($c) == 1) {
			$sp = '   ';
		}
		elsif (length($c) == 2) {
			$sp = '  ';
		}
	}
	print "[".$c."]".$sp.$people{$name}{'email'}."\n";
}

sub add() {
	my $fullname = $_[0];
	# print "## $fullname\n";
	if (!exists $people{$fullname}) {
		# print "## $fullname\n";

		if (length($email_syntax) > 0) {
			if ($email_syntax =~ /[0-9]+/) {
				my @pieces = ();
				while ($fullname =~ /([^\s]+)/g) {
					push(@pieces,$1);
				}
		
				my $lpieces = scalar(@pieces);
				if (($lpieces == 2)||(($lpieces == 3)&&($pieces[2] =~ /\(/))) {

					my $tfname = lc($pieces[0]);
					my $tlname = lc($pieces[1]);
					$tfname =~ s/(\w+)/\u$1/g;
					$tlname =~ s/(\w+)/\u$1/g;

					$people{$fullname}{'fname'} = $tfname;
					$people{$fullname}{'lname'} = $tlname;
					# some dushz have Firstname Lastname (Something no idea nickname?)
				}
				else {
					# if someone has a name like: mark paul john the third - wtf, no idea how would that fit so skip it.				
					return;
				}

				switch ($email_syntax) {
					case 1  { $people{$fullname}{'email'} = $people{$fullname}{'fname'}.".".$people{$fullname}{'lname'}."\@".$email_domain; }
					case 2  { $people{$fullname}{'email'} = $people{$fullname}{'lname'}.".".$people{$fullname}{'fname'}."\@".$email_domain; }
					case 3  { $people{$fullname}{'email'} = $people{$fullname}{'fname'}."_".$people{$fullname}{'lname'}."\@".$email_domain; }
					case 4  { $people{$fullname}{'email'} = $people{$fullname}{'lname'}."_".$people{$fullname}{'fname'}."\@".$email_domain; }
					case 5  { $people{$fullname}{'email'} = substr($people{$fullname}{'fname'}, 0, 1).".".$people{$fullname}{'lname'}."\@".$email_domain; }
					case 6  { $people{$fullname}{'email'} = substr($people{$fullname}{'lname'}, 0, 1).".".$people{$fullname}{'fname'}."\@".$email_domain; }
					case 7  { $people{$fullname}{'email'} = substr($people{$fullname}{'fname'}, 0, 1)."_".$people{$fullname}{'lname'}."\@".$email_domain; }
					case 8  { $people{$fullname}{'email'} = substr($people{$fullname}{'lname'}, 0, 1)."_".$people{$fullname}{'fname'}."\@".$email_domain; }
					case 9  { $people{$fullname}{'email'} = $people{$fullname}{'fname'}.".".substr($people{$fullname}{'lname'}, 0, 1)."\@".$email_domain; }
					case 10 { $people{$fullname}{'email'} = $people{$fullname}{'lname'}.".".substr($people{$fullname}{'fname'}, 0, 1)."\@".$email_domain; }
					case 11 { $people{$fullname}{'email'} = $people{$fullname}{'fname'}."_".substr($people{$fullname}{'lname'}, 0, 1)."\@".$email_domain; }
					case 12 { $people{$fullname}{'email'} = $people{$fullname}{'lname'}."_".substr($people{$fullname}{'fname'}, 0, 1)."\@".$email_domain; }
					case 13 { $people{$fullname}{'email'} = substr($people{$fullname}{'fname'}, 0, 1).".".substr($people{$fullname}{'lname'}, 0, 1)."\@".$email_domain; }
					case 14 { $people{$fullname}{'email'} = substr($people{$fullname}{'lname'}, 0, 1).".".substr($people{$fullname}{'fname'}, 0, 1)."\@".$email_domain; }
					case 15 { $people{$fullname}{'email'} = substr($people{$fullname}{'fname'}, 0, 1)."_".substr($people{$fullname}{'lname'}, 0, 1)."\@".$email_domain; }
					case 16 { $people{$fullname}{'email'} = substr($people{$fullname}{'lname'}, 0, 1)."_".substr($people{$fullname}{'fname'}, 0, 1)."\@".$email_domain; }
					case 17 { $people{$fullname}{'email'} = $people{$fullname}{'lname'}."\@".$email_domain; }
					case 18 { $people{$fullname}{'email'} = $people{$fullname}{'fname'}."\@".$email_domain; }
					case 19 { $people{$fullname}{'email'} = $people{$fullname}{'fname'}.$people{$fullname}{'lname'}."\@".$email_domain; }
					case 20 { $people{$fullname}{'email'} = $people{$fullname}{'lname'}.$people{$fullname}{'fname'}."\@".$email_domain; }
					case 21 { $people{$fullname}{'email'} = substr($people{$fullname}{'fname'}, 0, 1).$people{$fullname}{'lname'}."\@".$email_domain; }
					case 22 { $people{$fullname}{'email'} = $people{$fullname}{'fname'}.".".$people{$fullname}{'lname'}."\@".$email_domain; }
					case 23 { $people{$fullname}{'email'} = $people{$fullname}{'fname'}.substr($people{$fullname}{'lname'}, 0, 1)."\@".$email_domain; }
					case 24 { $people{$fullname}{'email'} = $people{$fullname}{'lname'}.substr($people{$fullname}{'fname'}, 0, 1)."\@".$email_domain; }

				}

			}

		}

	}
}


sub req() {
	my $url = $_[0];


	my $ua  = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 },);

	$ua->default_header('Accept-Encoding' => 'gzip, deflate, sdch, br');
	$ua->agent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36');

	# $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

		$ENV{PERL_NET_HTTPS_SSL_SOCKET_CLASS} = "Net::SSL";
		$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
		$ENV{HTTPS_PROXY} = "http://127.0.0.1:8080";

	my $response = $ua->get($url);
	if ($response->is_success) {
		$res = $response->content;
		# print $res;
		return($res);
	}
	else {
		return();
	}
}

# EOF
