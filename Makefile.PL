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
    EXE_FILES           => [ 'bin/generate-crypted-password' ],
    PREREQ_PM => {
        'Test::More' => 0,
        'Mock::Quick' => 0,
        'Dancer'     => 1.3118,
        'Crypt::SaltedHash' => 0,
        'YAML'       => 0, # for config files (TODO: make optional?)
        
    },
    MIN_PERL_VERSION    => 5.006001,
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Dancer-Plugin-Auth-Extensible-*' },
    META_MERGE => {
        "meta-spec" => { version => 2 },
        resources => {
            repository => 'https://github.com/bigpresh/Dancer-Plugin-Auth-Extensible',
            bugtracker => 'https://github.com/bigpresh/Dancer-Plugin-Auth-Extensible/issues',
            homepage   => 'https://github.com/bigpresh/Dancer-Plugin-Auth-Extensible/',
        },
        prereqs => {
            runtime => {
                recommends => {
                    'Authen::Simple::PAM'      => 0,
                    'Dancer::Plugin::Database' => 0,
                    'Unix::Passwd::File'       => 0,
                }
            }
        }
    },

);
