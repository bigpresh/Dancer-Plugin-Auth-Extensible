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
        'Mock::Quick' => 0,
        'Dancer'     => 1.3100,
        'Crypt::SaltedHash' => 0,
        'YAML'       => 0, # for config files (TODO: make optional?)
        
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Dancer-Plugin-Auth-Extensible-*' },
    META_MERGE => {
        resources => {
            repository => 'https://github.com/bigpresh/Dancer-Plugin-Auth-Extensible',
            bugtracker => 'https://github.com/bigpresh/Dancer-Plugin-Auth-Extensible/issues',
            homepage   => 'https://github.com/bigpresh/Dancer-Plugin-Auth-Extensible/',
        },
    },

);
