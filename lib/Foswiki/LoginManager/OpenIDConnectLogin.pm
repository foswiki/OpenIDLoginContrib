# Module of Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# Copyright (C) 2016 by Pascal Schuppli pascal.schuppli@gbsl.ch
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version. For
# more details read LICENSE in the root of this distribution.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
package Foswiki::LoginManager::OpenIDConnectLogin;

=begin TML

---+ Foswiki::LoginManager::OpenIDConnectLogin

This provides an external authentication system, namely
OpenID Connect. 

=cut

use strict;
use warnings;
use Foswiki;
use Foswiki::LoginManager::TemplateLogin ();
use Foswiki::Sandbox ();

use LWP::UserAgent;
use JSON;

use Foswiki::Contrib::OpenIDLoginContrib::OpenIDConnect qw(endpoint_discovery get_auth_endpoint get_supported_scopes exchange_code_for_id_token random_bytes);

@Foswiki::LoginManager::OpenIDConnectLogin::ISA = qw( Foswiki::LoginManager::TemplateLogin );

=begin TML

---++ ClassMethod new($session)

Construct the <nop> object

=cut

sub new {
  my ($class, $session) = @_;
  my $this = bless($class->SUPER::new($session), $class);
  undef $this->{state};
  undef $this->{endpoints};
  undef $this->{client_id};
  undef $this->{client_secret};
  undef $this->{issuer};
  undef $this->{redirect_uri};
  undef $this->{loginname_attr};
  undef $this->{wikiname_attrs};
  return $this;
}

sub loadProviderData {
    my $this = shift;
    my $provider = shift;
    # TODO: We should cache this. On sites with heavy traffic, this adds needless delays, especially since
    # we need to load it twice for each login
    my $discovery_uri = $Foswiki::cfg{'Extensions'}{'OpenID'}{$provider}{'DiscoveryURL'};
    $this->{endpoints} = endpoint_discovery($discovery_uri);
    $this->{client_id} = $Foswiki::cfg{'Extensions'}{'OpenID'}{$provider}{'ClientID'};
    $this->{client_secret} = $Foswiki::cfg{'Extensions'}{'OpenID'}{$provider}{'ClientSecret'};
    $this->{issuer} = $Foswiki::cfg{'Extensions'}{'OpenID'}{$provider}{'IssuerRegex'};
    $this->{redirect_uri} = $Foswiki::cfg{'Extensions'}{'OpenID'}{$provider}{'RedirectURL'};
    $this->{loginname_attr} = $Foswiki::cfg{'Extensions'}{'OpenID'}{$provider}{'LoginnameAttribute'};
    $this->{wikiname_attrs} = $Foswiki::cfg{'Extensions'}{'OpenID'}{$provider}{'WikiNameAttributes'};   
}


sub serializedState {
    my $this = shift;
    if (!defined($this->{state})) {
	my $nonce = random_bytes(12);
	$this->{state} = Foswiki::Contrib::OpenIDLoginContrib::OpenIDConnect::encode($nonce);
	chomp $this->{state};
    }
    return $this->{state};
}

sub extractEmail {
    my $this = shift;
    my $id_token = shift;
    return $id_token->{'email'} if exists $id_token->{'email'};
    # TODO: Check whether this field contains something that looks like an E-Mail address (it does
    # on the only MS Azure tenant I have access to)
    return $id_token->{'upn'} if exists $id_token->{'upn'};
    return undef;
}

sub extractLoginname {
    my $this = shift;
    my $id_token = shift;
    my $login_attr = $this->{'loginname_attr'};
    my $login = $id_token->{$login_attr};
    # SMELL: This is here to make valid login names out of MS Azure AD subject values. Probably shouldn't be
    # done here, and this explicitly.
    $login =~ s/-/_/g;
    return $login;
}

sub urlencode_hash {
    my ($this, $session, $hash) = @_;
    my @query = ();
    foreach my $key (keys %$hash) {
	push(@query, $key . "=" . Foswiki::urlEncode($hash->{$key}));
    }
    return join("&", @query);
}

sub build_auth_request {
    my $this = shift;
    my $session = shift;
    my $origin = shift;

    my $endpoint = get_auth_endpoint($this->{endpoints});
    my %supported_scopes = map { $_ => 1 } @{get_supported_scopes($this->{endpoints}) };
    my $scopes = "openid";
    $scopes .= " email" if exists($supported_scopes{"email"});
    $scopes .= " profile" if exists($supported_scopes{"profile"});
    
    my $params = {
	client_id => $this->{client_id},
	response_type => "code",
	scope => $scopes,
	redirect_uri => $this->{redirect_uri},
	state => $this->serializedState($origin)
    };
    my $query = $this->urlencode_hash($session, $params);
    return $endpoint . "?" . $query;
}

sub buildWikiName {
    my $this = shift;
    my $idtoken = shift;
    my $attributes = $this->{'wikiname_attrs'};
    my $wikiname = '';
    foreach my $attr (split(/\s*,\s*/, $attributes)) {
	$wikiname .= $idtoken->{$attr}
    }
    # some minimal normalization
    $wikiname = s/\s+//g;
    return $wikiname;
}

sub registerUser {
    my $this = shift;
    my $session = shift;
    my $id_token = shift;

    my $loginname = undef;
    # TODO : This is way too simple. Fix it (duplicates, special characters etc)
    my $wikiname = $this->buildWikiName($id_token);
    
    if ($Foswiki::cfg{Register}{AllowLoginName}) {
	$loginname = $this->extractLoginname($id_token);
    }
    else {
	$loginname = $wikiname;
    }
    
    # Now we try to find/create a permanent mapping between loginname and username
    my $cuid = $session->{users}->getCanonicalUserID($loginname);
    if (!defined($cuid)) {
	my $email = $this->extractEmail($id_token);
	if (defined $email) {
	    my $users = $session->{'users'}->findUserByEmail($email);
	    if (scalar @$users == 1) {
		# we've identified this user by his e-mail address. Now add
		# the login name to the mapping		
		$cuid = $users->[0];
		my $wikiname = $session->{'users'}->getWikiName($cuid);
		$session->{'users'}->addUser($loginname, $wikiname, undef, $email);
		$session->logger->log({
		    level    => 'info',
		    action   => 'login',
		    extra    => "UPDATED $cuid ($wikiname $email) - "
				      });
	    }
	    else {
		# we don't know this user. Add a new mapping for him.
		$cuid = $session->{'users'}->addUser($loginname, $wikiname, undef, [$email]);
		$session->logger->log({
		    level    => 'info',
		    action   => 'login',
		    extra    => "REGISTERED $cuid ($wikiname $email) - "
				      });
	    }
	}
    }
    return $cuid;
}

sub redirectToProvider {
    my $this = shift;
    my $provider = shift;
    my $query = shift;
    my $session = shift;

    my $origin = $query->param('foswiki_origin');
    # Avoid accidental passthrough
    $query->delete( 'foswiki_origin', 'provider' );
    
    $this->loadProviderData($provider);
    
    my $request_uri = $this->build_auth_request($session, $origin);
    my $response = $session->{response};
    
    my $stored_state = $this->serializedState();
    Foswiki::Func::setSessionValue('openid_state', $stored_state);
    Foswiki::Func::setSessionValue('openid_provider', $provider);
    Foswiki::Func::setSessionValue('openid_origin', $origin);
    
    $response->redirect($request_uri);
}

sub oauthCallback {
    my $this = shift;
    my $code = shift;
    my $state = shift;
    my $query = shift;
    my $session = shift;

    $query->delete('code', 'state');
    
    $state = Foswiki::urlDecode($state);
    $code = Foswiki::urlDecode($code);

    my $stored_state = Foswiki::Func::getSessionValue('openid_state');
    my $provider = Foswiki::Func::getSessionValue('openid_provider');
    my $origin = Foswiki::Func::getSessionValue('openid_origin');
    Foswiki::Func::clearSessionValue('openid_state');
    Foswiki::Func::clearSessionValue('openid_provider');
    Foswiki::Func::clearSessionValue('openid_origin');
    die "OpenIDLoginContrib detected state mismatch ('$stored_state' vs '$state') - attack in progress?" unless ($stored_state eq $state);
    $this->{state} = $state;

    $this->loadProviderData($provider);
    
    my $id_token = exchange_code_for_id_token($this->{'endpoints'},
	$this->{'client_id'},
	$this->{'client_secret'},
 	$this->{'issuer'},
	$this->{'redirect_uri'},
	$code);

    my ( $origurl, $origmethod, $origaction ) = Foswiki::LoginManager::TemplateLogin::_unpackRequest($origin);
    my $topic = $session->{topicName};
    my $web = $session->{webName};    
    
    my $loginName = $this->extractLoginname($id_token);
    my $hrReadable = $id_token->{'given_name'} . $id_token->{'family_name'};
    $this->userLoggedIn($loginName);
    $session->logger->log({
	    level    => 'info',
	    action   => 'login',
	    webTopic => $web . '.' . $topic,
	    extra    => "AUTHENTICATION SUCCESS - $loginName ($hrReadable) - "
			  });

    my $cuid = $this->registerUser($session, $id_token);
    
    if ( !$origurl || $origurl eq $query->url() ) {
	$origurl = $session->getScriptUrl( 0, 'view', $web, $topic );
    } 
    else {
	# Unpack params encoded in the origurl and restore them
	# to the query. If they were left in the query string they
	# would be lost if we redirect with passthrough.
	# First extract the params, ignoring any trailing fragment.
	if ( $origurl =~ s/\?([^#]*)// ) {
	    foreach my $pair ( split( /[&;]/, $1 ) ) {
		if ( $pair =~ m/(.*?)=(.*)/ ) {
		    # SMELL: Removed TAINT on $2 because couldn't figure out where it was defined
		    $query->param( $1, $2 );
		}
	    }
	}
	
	# Restore the action too
	$query->action($origaction) if $origaction;
    }
    
    # Restore the method used on origUrl so if it was a GET, we
    # get another GET.
    $query->method($origmethod);
    $session->redirect( $origurl, 1 );
    return;
}

sub displayLoginTemplate {
    my $this = shift;
    my $query = shift;
    my $session = shift;

    my $users = $session->{users};
    my $loginTemplate = "openidlogin";
    # SMELL: This is ugly; should be done in a template, but the only way I can see
    # to do this in a template without introducing a large amount of code that will
    # break when templates change is to add a new skin, just for the login page.
    Foswiki::Func::addToZone('head', 'OPEN_ID_LOGIN', '<link rel="stylesheet" type="text/css" href="%PUBURL%/System/OpenIDLoginContrib/openidlogin.css" media="all" />');
    my $tmpl = $session->templates->readTemplate($loginTemplate);

    my $banner = $session->templates->expandTemplate('LOG_IN_BANNER');
    my $note   = '';
    my $topic  = $session->{topicName};
    my $web    = $session->{webName};


    # Truncate the path_info at the first quote
    my $path_info = $query->path_info();
    if ( $path_info =~ m/['"]/g ) {
        $path_info = substr( $path_info, 0, ( ( pos $path_info ) - 1 ) );
    }

    # Set session preferences that will be expanded when the login
    # template is instantiated
    $session->{prefs}->setSessionPreferences(
        FOSWIKI_ORIGIN => Foswiki::entityEncode(
            #_packRequest( $origurl, $origmethod, $origaction )
	    Foswiki::LoginManager::TemplateLogin::_packRequest( undef, undef, undef )
        ),

        # Path to be used in the login form action.
        # Could have used %ENV{PATH_INFO} (after extending {AccessibleENV})
        # but decided against it as the path_info might have been rewritten
        # from the original env var.
        PATH_INFO =>
          Foswiki::urlEncode( Foswiki::LoginManager::TemplateLogin::NFC( Foswiki::decode_utf8($path_info) ) ),
        BANNER => $banner,
        NOTE   => $note,
	ERROR => undef
        #ERROR  => $error
    );
    
    my $topicObject = Foswiki::Meta->new( $session, $web, $topic );
    $tmpl = $topicObject->expandMacros($tmpl);
    $tmpl = $topicObject->renderTML($tmpl);
    $tmpl =~ s/<nop>//g;
    $session->writeCompletePage($tmpl);
}


sub login {
    my ( $this, $query, $session ) = @_;

    my $provider = $query->param('provider');
    my $state = $query->param('state');
    my $code = $query->param('code');
    my $password = $query->param('password');
    
    # The login method now acts as a switchboard. When the provider
    # parameter is provided, we do an oauth redirect to the given
    # provider. When we get state and code parameters, we're running
    # the callback handler. If we don't get any parameters, we
    # display the login template to allow the user to pick a provider.
    # The 'native' provider value is there for graceful degradation
    # - it provides a way to access the original behaviour of the
    # TemplateLogin.
    
    if ((defined $provider) && ($provider ne 'native')) {
	$this->redirectToProvider($provider, $query, $session);
	return;
    }
    elsif ($state && $code) {
	$this->oauthCallback($code, $state, $query, $session);
    }
    elsif ($password || ((defined $provider) && ($provider eq 'native'))) {
	# if we get a password or a request for the native login 
	# provider, we redirect to the original TemplateLogin
	$this->SUPER::login($query, $session);
    }
    else {
	$this->displayLoginTemplate($query, $session);
    }
}
   

sub login2 {
    my ( $this, $query, $session ) = @_;
    my $users = $session->{users};

    my $origin = $query->param('foswiki_origin');
    my ( $origurl, $origmethod, $origaction ) = Foswiki::LoginManager::TemplateLogin::_unpackRequest($origin);
    
    my $loginName = $query->param('username');
    my $loginPass = $query->param('password');
    my $remember  = $query->param('remember');

    # Eat these so there's no risk of accidental passthrough
    $query->delete( 'foswiki_origin', 'username', 'password' );

    # UserMappings can over-ride where the login template is defined
    my $loginTemplate = $users->loginTemplateName();    #defaults to login.tmpl
    my $tmpl = $session->templates->readTemplate($loginTemplate);

    my $banner = $session->templates->expandTemplate('LOG_IN_BANNER');
    my $note   = '';
    my $topic  = $session->{topicName};
    my $web    = $session->{webName};

    # CAUTION:  LoginManager::userLoggedIn() will delete and recreate
    # the CGI Session.
    # Do not make a local copy of $this->{_cgisession}, or it will point
    # to a deleted session once the user has been logged in.

    $this->{_cgisession}->param( 'REMEMBER', $remember )
      if $this->{_cgisession};
    if (   $this->{_cgisession}
        && $this->{_cgisession}->param('AUTHUSER')
        && $loginName
        && $loginName ne $this->{_cgisession}->param('AUTHUSER') )
    {
        $banner = $session->templates->expandTemplate('LOGGED_IN_BANNER');
        $note   = $session->templates->expandTemplate('NEW_USER_NOTE');
    }

    my $error = '';

    if ($loginName) {
        my $validation = $users->checkPassword( $loginName, $loginPass );
        $error = $users->passwordError($loginName);

        if ($validation) {

            # SUCCESS our user is authenticated. Note that we may already
            # have been logged in by the userLoggedIn call in loadSession,
            # because the username-password URL params are the same as
            # the params passed to this script, and they will be used
            # in loadSession if no other user info is available.
            $this->userLoggedIn($loginName);
            $session->logger->log(
                {
                    level    => 'info',
                    action   => 'login',
                    webTopic => $web . '.' . $topic,
                    extra    => "AUTHENTICATION SUCCESS - $loginName - "
                }
            );

            # remove the sudo param - its only to tell TemplateLogin
            # that we're using BaseMapper..
            $query->delete('sudo');

            $this->{_cgisession}->param( 'VALIDATION', $validation )
              if $this->{_cgisession};
            if ( !$origurl || $origurl eq $query->url() ) {
                $origurl = $session->getScriptUrl( 0, 'view', $web, $topic );
            }
            else {

                # Unpack params encoded in the origurl and restore them
                # to the query. If they were left in the query string they
                # would be lost if we redirect with passthrough.
                # First extract the params, ignoring any trailing fragment.
                if ( $origurl =~ s/\?([^#]*)// ) {
                    foreach my $pair ( split( /[&;]/, $1 ) ) {
                        if ( $pair =~ m/(.*?)=(.*)/ ) {
                            $query->param( $1, TAINT($2) );
                        }
                    }
                }

                # Restore the action too
                $query->action($origaction) if $origaction;
            }

            # Restore the method used on origUrl so if it was a GET, we
            # get another GET.
            $query->method($origmethod);
            $session->redirect( $origurl, 1 );
            return;
        }
        else {

            # Tasks:Item1029  After much discussion, the 403 code is not
            # used for authentication failures. RFC states: "Authorization
            # will not help and the request SHOULD NOT be repeated" which
            # is not the situation here.
            $session->{response}->status(200);
            $session->logger->log(
                {
                    level    => 'info',
                    action   => 'login',
                    webTopic => $web . '.' . $topic,
                    extra    => "AUTHENTICATION FAILURE - $loginName - ",
                }
            );
            $banner = $session->templates->expandTemplate('UNRECOGNISED_USER');
        }
    }
    else {

        # If the loginName is unset, then the request was likely a perfectly
        # valid GET call to http://foswiki/bin/login
        # 4xx cannot be a correct status, as we want the user to retry the
        # same URL with a different login/password
        $session->{response}->status(200);
    }

    # Remove the validation_key from the *passed through* params. It isn't
    # required, because the form will have a new validation key, and
    # giving the parameter twice will confuse the strikeone Javascript.
    $session->{request}->delete('validation_key');

    # set the usernamestep value so it can be re-displayed if we are here due
    # to a failed authentication attempt.
    $query->param( -name => 'usernamestep', -value => $loginName );

    # TODO: add JavaScript password encryption in the template
    $origurl ||= '';

    # Truncate the path_info at the first quote
    my $path_info = $query->path_info();
    if ( $path_info =~ m/['"]/g ) {
        $path_info = substr( $path_info, 0, ( ( pos $path_info ) - 1 ) );
    }

    # Set session preferences that will be expanded when the login
    # template is instantiated
    $session->{prefs}->setSessionPreferences(
        FOSWIKI_ORIGIN => Foswiki::entityEncode(
            _packRequest( $origurl, $origmethod, $origaction )
        ),

        # Path to be used in the login form action.
        # Could have used %ENV{PATH_INFO} (after extending {AccessibleENV})
        # but decided against it as the path_info might have been rewritten
        # from the original env var.
        PATH_INFO =>
          Foswiki::urlEncode( NFC( Foswiki::decode_utf8($path_info) ) ),
        BANNER => $banner,
        NOTE   => $note,
        ERROR  => $error
    );

    my $topicObject = Foswiki::Meta->new( $session, $web, $topic );
    $tmpl = $topicObject->expandMacros($tmpl);
    $tmpl = $topicObject->renderTML($tmpl);
    $tmpl =~ s/<nop>//g;
    $session->writeCompletePage($tmpl);
}

1;
__END__
Module of Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2008-2015 Foswiki Contributors. All Rights Reserved.
Foswiki Contributors are listed in the AUTHORS file in the root
of this distribution. NOTE: Please extend that file, not this notice.

Additional copyrights apply to some or all of the code in this
file as follows:

Copyright (C) 2005-2006 TWiki Contributors. All Rights Reserved.
Copyright (C) 2005 Greg Abbas, twiki@abbas.org

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.

