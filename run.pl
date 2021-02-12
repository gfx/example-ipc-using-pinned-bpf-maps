#!/usr/bin/perl
use strict;
use warnings;

exec "sudo", $^X, $0 if $< != 0;

my $main_pid = fork();
die $! unless defined $main_pid;

if ($main_pid == 0) {
  exec("./main") or die $!;
}

exec("./tracer", $main_pid) or die "cannot run tracer: $!";
