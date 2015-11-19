=head1 NAME

Linux::Netfilter::Conntrack - Read or manipulate the Linux conntrack tables

=head1 SYNOPSIS

List all the connections in the conntrack table:

  use Linux::Netfilter::Conntrack qw(:constants);
  
  my $cth = Linux::Netfilter::Conntrack::Handle->new(NFNL_SUBSYS_CTNETLINK, 0);
  
  $cth->ct_callback_register(NFCT_T_ALL, sub
  {
	  my ($type, $conn) = @_;
	  
	  print "$conn\n";
	  
	  return NFCT_CB_CONTINUE;
  });
  
  $cth->query(NFCT_Q_DUMP, AF_INET);

Wait for conntrack events and print them as they occur:

  use Linux::Netfilter::Conntrack qw(:constants);
  
  my $cth = Linux::Netfilter::Conntrack::Handle->new(NFNL_SUBSYS_CTNETLINK, NFCT_ALL_CT_GROUPS);
  
  $cth->ct_callback_register(NFCT_T_ALL, sub
  {
	  my ($type, $conn) = @_;
	  
	  print $conn->snprintf($type, NFCT_O_DEFAULT, 0), "\n";
	  
	  return NFCT_CB_CONTINUE;
  });
  
  $cth->catch();

=head1 DESCRIPTION

This module wraps the C<libnetfilter_conntrack> library...

L<Linux::Netfilter::Conntrack::Handle> wraps the C<nfct_handle> structure and
associated functions, providing netlink access to the conntrack tables.

L<Linux::Netfilter::Conntrack::Connection> wraps the C<nf_conntrack> structure
which represents a single entry in the connection table.

=head1 CONSTANTS

The C<libnetfilter_conntrack> constants may be imported from this library
individually or using the C<:constants> import tag.

=cut

use strict;
use warnings;

package Linux::Netfilter::Conntrack;

use Exporter qw(import);

use Linux::Netfilter::Conntrack::Connection;
use Linux::Netfilter::Conntrack::Constants;
use Linux::Netfilter::Conntrack::Handle;

our @EXPORT_OK;
our %EXPORT_TAGS = (
	constants => [ @EXPORT_OK ],
);

our $VERSION = "0.01";

=head1 AUTHOR

Daniel Collins E<lt>daniel.collins@smoothwall.netE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2015 L<Smoothwall Ltd.|http://www.smoothwall.com/>

This library is free software; you may redistribute it and/or modify it under
the same terms as Perl itself.

=cut

1;
