#!/usr/bin/perl

# Parses Hashcat output and, based on a provided list of users with Domain Admin privileges
# tells you the passwords of DAs that were cracked

open(C, '<', $ARGV[0]) or die($!); ## file with list of DA one per line
open(F, '<', $ARGV[1]) or die($!); ## file from hashcat with --user and--show

my @das = ();
while (my $a = <C>) {
	my $da = $a;
	$da =~ s/\s+$//;
	push(@das,$da);

}

my $da_total = scalar(@das);
my %hashes = {};
my @cc = ();

while (my $a = <F>) {
	# print $a."\n";
	if ($a =~ /^([^\\]+)\\([^:]+):[^:]+:(.+)$/) {
		my $domain = $1;
		my $user = $2;
		my $pwd = $3;
		# print "$user\t$pwd\n";
		foreach my $da(@das) {
			# print "Comparing $user with DA $da\n";
			if ($da eq $user) {
				push(@cc,$pwd);
			}
		}
	}
	
}
my $cracked_total = scalar(@cc);

print "\n\nPasswords of DAs cracked:\n";
foreach my $u(@cc) {
	print $u."\n";
}
