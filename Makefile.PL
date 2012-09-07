use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Dancer::Plugin::Auth::Extensible',
    AUTHOR              => q{David Precious <davidp@preshweb.co.uk>},
    VERSION_FROM        => 'lib/Dancer/Plugin/Auth/Extensible.pm',
    ABSTRACT_FROM       => 'lib/Dancer/Plugin/Auth/Extensible.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'Dancer'     => 1.3100,
        'Dancer::Plugin::Database' => 1.82,
        'Crypt::SaltedHash' => 0,
        
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Dancer-Plugin-Auth-Extensible-*' },
);
