#!/usr/bin/perl

# Out of all users whose passwords were cracked, based on a provided list of users with Domain Admin privileges
# tells you how many DA's passwords were cracked

open(C, '<', $ARGV[0]) or die($!); ## file with list of DA one per line
open(F, '<', $ARGV[1]) or die($!); ## file with list of users whose pwd were cracked

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
	my $user = $a;
	$user =~ s/\s+$//;
	foreach my $da(@das) {
		# print "Comparing $user with DA $da\n";
		if ($da eq $user) {
			push(@cc,$user);
		}
	}
	
}
my $cracked_total = scalar(@cc);

print "\n\nDomain Admins whose passwords were cracked: $cracked_total/$da_total\n";
foreach my $u(@cc) {
	print $u."\n";
}












