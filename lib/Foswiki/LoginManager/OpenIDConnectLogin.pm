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

This provides a LoginManager which can authenticate using 
OpenID Connect, while still providing access to the underlying
TemplateLogin manager.

=cut

use strict;
use warnings;
use Foswiki;
use Foswiki::LoginManager::TemplateLogin ();
use Foswiki::Sandbox ();

use Foswiki::Contrib::OpenIDLoginContrib::OpenIDConnect qw(endpoint_discovery build_auth_request exchange_code_for_id_token random_bytes);
use JSON;

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

=pod
---++ ObjectMethod loadProviderData($provider) 
Given a provider key which must reference a key in the Foswiki configuration 
under Extensions->OpenID, loads relevant provider information into object
properties.
=cut 
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
    $this->{loginname_attr} = $Foswiki::cfg{'Extensions'}{'OpenID'}{$provider}{'LoginnameAttribute'} || $Foswiki::cfg{'Extensions'}{'OpenID'}{'LoginnameAttribute'};
    $this->{wikiname_attrs} = $Foswiki::cfg{'Extensions'}{'OpenID'}{$provider}{'WikiNameAttributes'} || $Foswiki::cfg{'Extensions'}{'OpenID'}{'WikiNameAttributes'};
}


sub getAndClearSessionValue {
    my $this = shift;
    my $key = shift;
    my $value = Foswiki::Func::getSessionValue($key);    
    Foswiki::Func::clearSessionValue($key);
    return $value;
}


=pod
---++ ObjectMethod serializedState() -> $encoded_state
This returns the url-encoded state, which currently only consists of a 
random nonce value. If no state exists, a random value is generated.
=cut
sub serializedState {
    my $this = shift;
    if (!defined($this->{state})) {
	my $nonce = random_bytes(12);
	$this->{state} = Foswiki::Contrib::OpenIDLoginContrib::OpenIDConnect::encode($nonce);
	chomp $this->{state};
    }
    return $this->{state};
}

=pod
---++ ObjectMethod extractEmail($id_token) -> $email
Given a id token, tries to find an e-mail claim and returns
it. Currently this is rather dumb; it should be made more intelligent.
=cut
sub extractEmail {
    my $this = shift;
    my $id_token = shift;
    return $id_token->{'email'} if exists $id_token->{'email'};
    # TODO: Check whether this field contains something that looks like an E-Mail address (it does
    # on the only MS Azure tenant I have access to)
    return $id_token->{'upn'} if exists $id_token->{'upn'};
    return undef;
}

=pod
---++ ObjectMethod extractLoginname($id_token) -> $loginname
This extracts a Foswiki loginname from a id token. Which claim
is used as the login name ultimately depends on the attribute configured
in Foswiki::cfg.
=cut
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

=pod
---++ ObjectMethod buildWikiName(id_token) => $wikiname
Given a id token, builds a wikiname from it. Which claims are used to
build the wikiname ultimately depends on the Foswiki::cfg settings.

If the wikiname that's built ends in ...Group or is contained in 
the list of forbidden WikiNames, WikiGuest (or rather, the configured
default WikiName) is returned instead.
=cut
sub buildWikiName {
    my $this = shift;
    my $idtoken = shift;
    my $attributes = $this->{'wikiname_attrs'};
    my $wikiname = '';
    foreach my $attr (split(/\s*,\s*/, $attributes)) {
	$wikiname .= $idtoken->{$attr}
    }
    # some minimal normalization
    $wikiname =~ s/\s+//g;

    if ($wikiname =~ m/Group$/) {
	return $Foswiki::cfg{DefaultUserWikiName};
    }
    
    # Forbidden wikinames get mapped to WikiGuest too
    my @forbidden = split(/\s+,\s+/, $Foswiki::cfg{Extensions}{OpenID}{ForbiddenWikinames});
    for my $bignono (@forbidden) {
	if ($wikiname eq $bignono) {
	    return $Foswiki::cfg{DefaultUserWikiName};
	}
    }
    return $wikiname;
}

=pod
---++ ObjectMethod matchWikiUser($wikiname, $email) => $wikiname
This checks whether the e-mail address stored in a WikiName topic's
form field matches the $email argument. If it does, then the name
of the topic (e.g. the $wikiname) is returned. If it doesn't, 
undef is returned.

The wikiname is also returned when the WikiName topic doesn't exist
or pre-assigning wikinames is disabled in the configuration. 
=cut   
sub matchWikiUser {
    my $this = shift;
    my $wikiname = shift;
    my $email = shift;

    my $web = $Foswiki::cfg{'UsersWebName'} || 'Main';
    
    # If the Wiki User Topic doesn't exist, there is no forseeable conflict,
    # so we return the candidate wikiname unchanged. We also return immediately
    # if User Form Matching is disabled.
    if (!Foswiki::Func::topicExists($web, $wikiname) || !$Foswiki::cfg{Extensions}{OpenID}{UserFormMatch}) {
	return $wikiname;
    }
    
    # otherwise, we see if the e-mail address matches the one in the user topic.
    # if so, we pronounce a match.
    my $fieldname = $Foswiki::cfg{Extensions}{OpenID}{UserFormMatchField} || 'Email';
    my $options = {
	type => 'query',
	web => $web,
    };

    my $matches = Foswiki::Func::query("fields[name='$fieldname'].value=~'^\\s*$email\\s*\$'", ["$web.$wikiname"], $options);
    while ($matches->hasNext) {
	my $found = $matches->next;
	my ($dummy, $wikiname) = Foswiki::Func::normalizeWebTopicName('', $found);
	return $wikiname;
    }
    # No match. This means we shouldn't give out the candidate $wikiname.
    return undef;
}

=pod
---++ ObjectMethod _isAlreadyMapped($session, $loginname, $email, $wikiname) => $boolean

This is an internal helper function which tries to determine whether a given loginname
is already mapped to a wikiname or not.

Unfortunately, there doesn't seem to be a "right" way to determine this while staying
inside the constraints of the public API. 
=cut
sub _isAlreadyMapped {
    my $this = shift;
    my $session = shift;
    my $loginname = shift;
    my $wikiname = shift;

    # Currently, there doesn't seem to be a universal way to check
    # whether a mapping between login name and username is already
    # in place.
    my $is_mapped = 0;    
    if ($Foswiki::cfg{Register}{AllowLoginName}) {
	my $aWikiname = Foswiki::Func::userToWikiName($loginname, 1);
	$is_mapped = $aWikiname ne $loginname;
	return $is_mapped;
    } else {
	# It's important to return 0 here so that if mapping is turned
	# off, on-the-spot pre-assignment checking is initiated by mapUser.
	# If this returned 1, we'd never do any checking.
	return 0;
    }
}
   
=pod
---++ ObjectMethod mapUser($session, id_token) => $cuid

This handles the mapping of a loginname as extracted from an id token 
to a WikiName. We don't keep a mapping ourselves; we simply instruct
the configured UserMapper to create one if it doesn't exist yet. If
the UserMapper doesn't create a permanent mapping, we'll go through 
the same motions again when the user authenticates the next time.

Much of the code here is concerned with trying to make sure that
WikiNames which were pre-assigned aren't used in a mapping by
mistake before the actual user authenticates and claims the WikiName.
We also handle duplicate names by increasing a counter to generate
WikiName2, WikiName3, WikiName4 etc.
=cut
sub mapUser {
    my $this = shift;
    my $session = shift;
    my $id_token = shift;

    my $loginname = undef;
    my $candidate = $this->buildWikiName($id_token);
    
    if ($Foswiki::cfg{Register}{AllowLoginName}) {
	$loginname = $this->extractLoginname($id_token);
    }
    # SMELL: Turning off AllowLoginName for Open ID is a really bad idea. Should
    # we complain, or add a warning to the log?
    else {
	$loginname = $candidate;
    }
    my $email = lc($this->extractEmail($id_token));
    
    if (!$this->_isAlreadyMapped($session, $loginname, $candidate)) {
	my $wikiname = undef;
	my $orig_candidate = $candidate;
	my $counter = 1;
	# Find an acceptable wikiname. We simply add an increasing number if a name is taken already
	while (!defined($wikiname)) {
	    my $users = $session->{users}->findUserByWikiName($candidate);
	    if (scalar @$users == 0) {
		$wikiname = $this->matchWikiUser($candidate, $email);
		Foswiki::Func::writeDebug("OpenIDLoginContrib: matchWikiUser for $candidate produces $wikiname");
		if (defined $wikiname) {
		    my $cuid = $session->{'users'}->addUser($loginname, $wikiname, undef, [$email]);
		    Foswiki::Func::writeDebug("OpenIDLoginContrib: Mapped user $cuid ($email) to $wikiname");
		    return $cuid;
		}
	    }
	    $counter = $counter + 1;
	    $candidate = $orig_candidate . $counter;
	}
    } else {
	# Mapping exists already, so return the canonical user id
	my $cuid = $session->{users}->getCanonicalUserID($loginname);
	Foswiki::Func::writeDebug("OpenIDLoginContrib: Use preexisting mapping for $loginname");
	return $cuid;
    }
}

=pod
---++ ObjectMethod redirectToProvider($provider, $query, $session)

This is called directly by login() and is responsible for building
the redirect url to the Open ID provider. It generates the redirect
and sends it back to the user agent.
=cut
sub redirectToProvider {
    my $this = shift;
    my $provider = shift;
    my $query = shift;
    my $session = shift;
    
    my $origin = $query->param('foswiki_origin');
    # Avoid accidental passthrough
    $query->delete( 'foswiki_origin', 'provider');

    my $topic = $session->{topicName};
    my $web = $session->{webName};
        
    $this->loadProviderData($provider);
    
    my $request_uri = build_auth_request($this->{endpoints},
					 $this->{client_id}, 
					 $this->{redirect_uri}, 
					 $this->serializedState());
    my $response = $session->{response};

    Foswiki::Func::setSessionValue('openid_state', $this->serializedState());
    Foswiki::Func::setSessionValue('openid_provider', $provider);
    Foswiki::Func::setSessionValue('openid_origin', $origin);
    Foswiki::Func::setSessionValue('openid_web', $web);
    Foswiki::Func::setSessionValue('openid_topic', $topic);
    # We should also store the nonce value, but right now we simply ignore it
    
    $response->redirect($request_uri);
}

=pod
---++ ObjectMethod oauthCallback($code, $state, $query, $session)

This is called directly by login() when login() detects a successful
callback from the Open ID provider. When we get here, we have an
authorization code and state and can now exchange it for an id token.
=cut
sub oauthCallback {
    my $this = shift;
    my $code = shift;
    my $state = shift;
    my $query = shift;
    my $session = shift;

    $query->delete('code', 'state');
    
    $state = Foswiki::urlDecode($state);
    $code = Foswiki::urlDecode($code);

    my $stored_state = $this->getAndClearSessionValue('openid_state');
    my $provider = $this->getAndClearSessionValue('openid_provider');
    my $origin = $this->getAndClearSessionValue('openid_origin');
    my $web = $this->getAndClearSessionValue('openid_web');
    my $topic = $this->getAndClearSessionValue('openid_topic');

    if ($stored_state ne $state) {
	Foswiki::Func::writeDebug("OpenIDLoginContrib: Detected state mismatch ('$stored_state' vs '$state') - attack in progress?");
	throw Foswiki::OopsException( 'oopsattention', def => 'generic',
				  params => [ "We encountered a protocol error. We can't sign you in at this time."  ] );    
    }
    
    $this->{state} = $state;

    $this->loadProviderData($provider);
    
    my $id_token = exchange_code_for_id_token($this->{'endpoints'},
	$this->{'client_id'},
	$this->{'client_secret'},
 	$this->{'issuer'},
	$this->{'redirect_uri'},
	$code);
    Foswiki::Func::writeDebug("OpenIDLoginContrib: ID Token: " . JSON::encode_json($id_token));
    
    my $cuid = $this->mapUser($session, $id_token);
    # SMELL: This isn't part of the public API! But Foswiki::Func doesn't provide login name lookup and
    # wikiname lookup doesn't work yet at that stage (yields the loginname, ironically...)
    my $wikiname = $session->{users}->getWikiName($cuid);
    my $loginName = $session->{users}->getLoginName($cuid);
       
    $this->userLoggedIn($loginName);
    $session->logger->log({
	    level    => 'info',
	    action   => 'login',
	    webTopic => $web . '.' . $topic,
	    extra    => "AUTHENTICATION SUCCESS - $loginName ($wikiname) - "
			  });
    
    my ( $origurl, $origmethod, $origaction ) = Foswiki::LoginManager::TemplateLogin::_unpackRequest($origin);
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

=pod
---++ ObjectMethod displayLoginTemplate($query, $session) 

Called by login() when it doesn't know what else to do. This
displays the openid login template, which is currently hardcoded,
so it can't be overwritten or reconfigured by a UserMapper.

Fair amounts of code are copied from the TemplateLogin login()
method. Code readability would profit from refactoring TemplateLogin
a bit...
=cut
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

sub displayError {
    my $this = shift;
    my $query = shift;
    my $session = shift;


    throw Foswiki::OopsException( 'oopsattention', def => 'generic',
				  params => [ "something horrible happened"  ] );
}

=pod
---++ ObjectMethod login($query, $session) 
The login method now acts as a switchboard. There are basically
two different uses of the login method.

First, it is used by the user agent to get a login page. We
detect this case by looking for the absence of all parameters
or for a provider=native parameter. The native provider is used
to display the original TemplateLogin page; in that case, this 
login() method simply hands the query and session on to it's parent.

Second, it is used as a callback url by an Open ID provider. We
detect this case by looking for state, code or error parameters.

There is one more case: When the provider parameter
is provided, we do an oauth redirect to the given provider. 
=cut    
sub login {
    my ( $this, $query, $session ) = @_;

    my $provider = $query->param('provider');
    my $state = $query->param('state');
    my $code = $query->param('code');
    my $password = $query->param('password');
    my $error = $query->param('error');
    
    
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
    elsif (defined($error)) {
	$this->displayError($query, $session);
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

