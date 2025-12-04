#!/usr/bin/perl

# Script  : E-Mail eXtractor
# Author  : Osirys
# Contact : osirys[at]live[dot]it
# Thx: StAkeR
# *Use it under a *nix box
# THIS IS THE PUBLIC RELEASE
# In the private release, you can scan all kind of emails that you want, on a lot of different engines.

use IO::Socket::INET;
use HTTP::Request;
use LWP::UserAgent;
use HTTP::Request::Common;

print q{
-------------------------------------
 [> E-Mail eXtractor
 [> PUBLIC RELEASE
 [> Coded by Osirys
 [> Contact: osirys[at]live[dot]it
-------------------------------------
};

my $mode = $ARGV[0];
$gtest = ("www.google.com/search?q=hi&hl=en&start=10&sa=N");

CASES : {
            &usage(), last CASES if (!$ARGV[0]);
            &bash(), last CASES if ($mode =~ /bash-mode/);
            &usage(), last CASES if (($mode =~ /irc-mode/)&&(!$ARGV[1])|(!$ARGV[2])|(!$ARGV[3])|(!$ARGV[4]));
            &irc_mode($ARGV[1],$ARGV[2],$ARGV[3],$ARGV[4]), last CASES if (($mode =~ /irc-mode/)&&(($ARGV[1])||($ARGV[2])||($ARGV[3])||($ARGV[4])));
            &help(), last CASES if ($mode =~ /help/);
        }

sub help() {
    print q{
                          --- HELP ---
If you have a direct command line on the server where you are launching
the script, like you are in with a bash shell, you can just use the
bash mode. Unless, if you can't have a direct command line, launch it
in irc-mode, so you will command the script under Irc.

This is the public release. In the private release you can scan all
kind of emails, on a lot of different engines.

Thank you using E-Mail eXtractor

By Osirys

};
    &usage();
}

sub usage() {
    print "\nUsage:\n";
    print " [1] perl $0 bash-mode - FOR A SHELL USE\n";
    print " [2] perl $0 irc-mode server port nick chan - FOR IRC USE\n";
    print " [+] perl $0 help - FOR HELP\n";
    print "[©] Coded by Osirys\n\n";
    exit(1);
}

sub bash() {
    print "\n[+] Cheeking if my ip is banned by Google..\n";
    $re = query($gtest);
    $re =~ /Google Home/ || die "[-] Sorry, Test not passed, got banned by Google, try again later\n";
    print "[+] Test passed. Google Status: Ready\n";
    print "[+] Insert now the email domain to find\n";
    print "[*] Domains allowed: hotmail ~ msn ~ gmail ~ libero ~ yahoo ~ virgilio ~live ~ alice\n";
    $domain = <STDIN>;
    chomp($domain);
    $domain =~ /hotmail|msn|gmail|libero|yahoo|virgilio|live|alice/ || die "[-] Error, or domain not allowed\n"; 
    print "[+] Ok, searching \@$domain emails on Google ..\n";
    &find($domain,"bash-mode");
    print "[+] Done\n";
}

sub irc_mode() {
    my ($ircd, $port, $nick, $chan) = @_;
    if (fork() == 0) {
        &irc($ircd, $port, $nick, $chan);
    }
    else {
        exit(0);
    }
}

sub irc() {
    my ($ircd, $port, $nick, $chan) = @_;
    $chan =~ s/(.+?)/\#$1/;
    print "\n[+] Connecting on:\nServer/Port: $ircd:$port\nNick: $nick\nChannel: $chan\n# Coded by Osirys\n\n";
    $c0n = IO::Socket::INET->new(PeerAddr => "$ircd",PeerPort => "$port",Proto => "tcp") || die "[-] Can not connect on $ircd!\n";
    $c0n->autoflush(1);
    print $c0n "NICK $nick\n";
    print $c0n "USER eMailer 8 *  : Osirys\n";
    print $c0n "JOIN $chan\n";
    wr($chan,"15,1/_ E-Mail eXtractor Public Release Launched !!");
    wr($chan,"11,1© Coded by Osirys");
    while ($line = <$c0n>) {

        if ($line =~ /^PING \:(.*)/) {
            print $c0n "PONG :$1";
        }

        if ($line =~ /PRIVMSG $chan :!help/) {
            wr($chan,"15,1-= E-Mail eXtractor Public Release =-");
            wr($chan,"11,1© Coded by Osirys");
            wr($chan,"9,1!help 4,1>7,1 For Help");
            wr($chan,"9,1!domain 4,1>7,1 Get the domains avaible");
            wr($chan,"9,1!start domain 4,1>7,1 Start the scann on the domain choosed");
            wr($chan,"9,1!killme 4,1>7,1 Kill the Bot");
        }

        if ($line =~ /PRIVMSG $chan :!killme/) {
            wr($chan,"4,1Bye Bye!!");
            print $c0n "QUIT";
            exec("pkill perl");
        }

        if ($line =~ /PRIVMSG $chan :!domain/) {
            wr($chan,"15,1[*] Domain allowed: hotmail, msn, gmail, libero, yahoo, virgilio, live, alice");
        }

        if (($line =~ /PRIVMSG $chan :!start\s+(.*)/)&&(fork() == 0)) {
            my $mail = $1;
            wr($chan,"15,1[+] Cheeking if my ip is banned by Google..");
            $re = query($gtest);
            if ($re =~ /Google Home/) {
                wr($chan,"9,1[+] Test passed. Google Status: Ready");
                if ($mail =~ /hotmail|msn|gmail|libero|yahoo|virgilio|live|alice/) {
                    wr($chan,"15,1[+] E-Mail eXtractor started, emails: 9,1\@$mail");
                    &find($mail,"irc-mode");
                    wr($chan,"4,1[-] E-Mail eXtractor finished, emails: 9,1\@$mail");
                }
                else {
                    wr($chan,"4,1[-] Error, or domain not allowed");
                }
            }
            else {
                wr($chan,"4,1[-] Sorry, Test not passed, got banned by Google, try again later");
            }
        }
    }
}



sub find() {
    my @domain  = ("at","com.au","com.br","ca","ch","de","dk","es","fr","it","co.jp","com.mx","co.uk");
    my @langs   = ("de","en","br","en","de","de","dk","es","fr","it","jp","es","en");
    my @country = ("AT","AU","BR","CA","CH","DE","DK","ES","FR","IT","JP","MX","UK");
    my $mail = $_[0];
    my $mode = $_[1];
    my @forks;
    my $count = 0;
    my $dd = 0;
    my $l = 0;
    my $c = 0;
    foreach my $d(@domain) {
        if ($count % 1 == 0) {
            foreach my $f(@forks){
                waitpid($f,0);
            }
        }
        $forks[$count] = fork();
        if ($forks[$count] == 0) {
            for ($i=0;$i<=1000;$i+=100) {
                my $gsup = ("www.google.".$d."/search?q=\@".$mail.".".$d."&num=100&hl=".$langs[$l]."&cr=country".$country[$c]."&as_qdr=all&start=".$i."&sa=N");
                my $re = query($gsup);
                while ($re =~ m/([\w\-\+\.]+)\@<em>$mail<\/em>\.<em>$d<\/em>/g) {
                    my $user = $1;
                    push(@tot, $user);
                }
            }
            @unique = unique(@tot);
            @ord = sort(@unique);
            my $nickname = "$mail.".$d;
            if ($mode =~ /bash-mode/) {
                open($file, ">>", "$mail."."$d.txt");
                foreach my $u(@ord) {
                    print $file "$u"."@"."$mail."."$d\n";
                }
                print "[*]Found ".scalar(@ord)." \@".$mail.".".$d." emails. Cheek in: $mail.$d.txt\n";
            }
            elsif ($mode =~ /irc-mode/) {
                &paste($nickname,@ord);
            }
            exit(0);
        }
        $l++;
        $c++;
        $count++;
        $dd++;
    }
    foreach my $f(@forks){
        waitpid($f,0);
    }
}

sub paste() {
    my $name = $_[0];
    my @tot = @_[1];
    my $cont = join("\n",@tot);
    my $p_ua;
    my $p_request;
    $p_ua = LWP::UserAgent->new(
                                agent   => "StAkeR ~ Paste",
                                timeout => "0"
                               );
    $p_request = $p_ua->post("http://nopaste.biz",
                              [
                                insert       => "1",
                                name         => "$name EMails",
                                beschreibung => "$name Emails, powered by Osirys",
                                code         => $cont
                              ]
                            );
    if ($p_request->is_success) {
        if ($p_request->content =~ /URL=(.+?)\">/) {
            my $link = $1;
            wr($chan,"9,1[!]$name Emails Link4,1 =>11,1 $link");
        }
    }
}

sub unique {
    my @unique = ();
    my %seen = ();
    foreach my $s(@_) {
        $s =~ s/\/+/\//g;
        next if $seen{$s}++;
        push(@unique,$s);
    }
    return @unique;
}

sub query() {
    my $url = $_[0];
    my $host  = $url;
    my $query = $url;
    $host  =~ s/([-a-zA-Z0-9\.]+)\/.*/$1/;
    $query =~ s/$host//;
    eval {
        my $sock = IO::Socket::INET->new(PeerAddr => "$host",PeerPort => "80",Proto => "tcp") || return;
        print $sock "GET $query HTTP/1.0\r\nHost: $host\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        my @r = <$sock>;
        $page = "@r";
        close($sock);
    };
    return $page;
}

sub wr() {
    my $chan = $_[0];
    my $cont = $_[1];
    print $c0n "PRIVMSG $chan :$cont\n";
}

# Coded by Osirys