use Crypt::Random;
use Crypt::JWT;
use LWP::UserAgent;
use MIME::Base64;
use JSON;

use strict;
use warnings;

package Foswiki::Contrib::OpenIDLoginContrib::OpenIDConnect;
use Exporter 'import';
our @EXPORT_OK = qw(endpoint_discovery get_token_endpoint build_auth_request exchange_code_for_id_token random_bytes);

sub endpoint_discovery {
    my $discovery_uri = shift;
    my $ua = LWP::UserAgent->new;
    my $response = $ua->get($discovery_uri);
    if (!$response->is_success) {
	Foswiki::Func::writeDebug("OpenIDLoginContrib: Could not retrieve Open ID endpoint configuration at '$discovery_uri':");
	Foswiki::Func::writeDebug("OpenIDLoginContrib: response status=" . $response->message . " content=" . $response->decoded_content);
        throw_error("We encountered a protocol error while trying to fetch your Open ID provider configuration.");
    }
    return JSON::decode_json($response->decoded_content);
}

sub get_auth_endpoint {
    my $endpoints = shift;
    return $endpoints->{'authorization_endpoint'};
}

sub get_token_endpoint {
    my $endpoints = shift;
    return $endpoints->{'token_endpoint'};
}

sub get_supported_scopes {
    my $endpoints = shift;
    return $endpoints->{'scopes_supported'};
}   

sub retrieve_public_keys {
    my $discovery = shift;
    my $keydiscovery = $discovery->{'jwks_uri'};
    my $ua = LWP::UserAgent->new;
    my $response = $ua->get($keydiscovery);
    if (!$response->is_success) {
	Foswiki::Func::writeDebug("OpenIDLoginContrib: Could not retrieve public keys from $keydiscovery:");
	Foswiki::Func::writeDebug("OpenIDLoginContrib: response status=" . $response->message . " content=" . $response->decoded_content);
        throw_error("We encountered a protocol error while trying to fetch your Open ID provider's signing keys.");
    }    
    my $keys = JSON::decode_json($response->decoded_content)->{'keys'};
    return $keys;
}

sub build_auth_request {
    my $discovery = shift;
    my $client_id = shift;
    my $redirect_uri = shift;
    my $state = shift;
        
    my $endpoint = get_auth_endpoint($discovery);
    my %supported_scopes = map { $_ => 1 } @{get_supported_scopes($discovery) };
    my $scopes = "openid";
    $scopes .= " email" if exists($supported_scopes{"email"});
    $scopes .= " profile" if exists($supported_scopes{"profile"});
    
    my $params = {
	client_id => $client_id,
	response_type => "code",
	scope => $scopes,
	redirect_uri => $redirect_uri,
	state => $state,
	nonce => $state
    };
    my $query = urlencode_hash($params);
    return $endpoint . "?" . $query;
}

sub exchange_code_for_id_token {
    my $endpoints = shift;
    my $client_id = shift;
    my $client_secret = shift;
    my $issuer = shift;
    my $redirect_uri = shift;
    my $code = shift;

    my $params = {
	client_id => $client_id,
	client_secret => $client_secret,
	redirect_uri => $redirect_uri,
	code => $code,
	grant_type => "authorization_code"
    };
    
    my $ua = LWP::UserAgent->new;
    my $response = $ua->post(get_token_endpoint($endpoints), $params);
    if ($response->is_success) {
	# we get a bearer token consisting of access token, refresh token, id token, 
	# but we're currently only interested in the id token
	my $id_token = extract_id_token($response->decoded_content);
	# TODO: We should probably cache the keys for performance reasons!
	my $keys = retrieve_public_keys($endpoints);
	my $data = verify_id_token($id_token, $keys, $client_id, $issuer);
	return $data;
    } else {
	Foswiki::Func::writeDebug("OpenIDLoginContrib: Protocol error! Couldn't exchange auth code for token.");
	Foswiki::Func::writeDebug("OpenIDLoginContrib: code='$code', response msg=" . $response->message . " content=" . $response->decoded_content);

	throw_error("We encountered a protocol error while trying to redeem an authorization code with your Open ID provider.");
    }
}

sub throw_error {
    my $message = shift;
    $message .= " We can't sign you in at this time. If this problem persists, please contact your IT administrator.";
    throw Foswiki::OopsException('oopsattention', def => 'generic', params => [ $message ]);
}
    

sub extract_id_token {
    my $bearer_token_data = JSON::decode_json(shift);
    return $bearer_token_data->{'id_token'};
}

sub verify_id_token {
    my $id_token = shift;
    my $keys = shift;
    my $audience = shift;
    my $issuer = shift;
    
    my @parts = split(/\./, $id_token);
    if (scalar @parts != 3) {
	Foswiki::Func::writeDebug("OpenIDLoginContrib: JWT ID token verification failed: wrong number of segments");
	throw_error("We received a badly formatted answer from your Open ID provider.");
    }
    
    my $header = JSON::decode_json(MIME::Base64::decode($parts[0]));
    my $kid = $header->{'kid'};
    my $data = '';

    # This looks through all the public keys we got via the discovery document to find the one
    # that was used to sign the id token.
    foreach my $key (@$keys) {
	if ($key->{'kid'} eq $kid) {
	    eval {
		$data = Crypt::JWT::decode_jwt(token=>$id_token, key=>$key);
	    };
	    if ($@) {
		Foswiki::Func::writeDebug("OpenIDLoginContrib: JWT ID token verification failed: " . $@);
		throw_error("We couldn't verify the validity of the claims we received from your Open ID provider.");
	    };
	    if ($audience ne $data->{'aud'}) {
		Foswiki::Func::writeDebug("OpenIDLoginContrib: JWT ID token verification failed: wrong audience");
		throw_error("We couldn't verify the validity of the claims we received from your Open ID provider.");
	    }
	    if ($data->{'iss'} !~ /$issuer/) {
		Foswiki::Func::writeDebug("OpenIDLoginContrib: JWT ID token verification failed: wrong issuer (" . $data->{'iss'} . ")");
		throw_error("We couldn't verify the validity of the claims we received from your Open ID provider.");
	    }
	    return $data;
	}
    }

    # TODO: This may happen if we cache the keys for long periods (hours) instead of fetching them whenever 
    # we need them. In that case, we could recover by explicitely fetching them and retrying to verify.
    Foswiki::Func::writeDebug("OpenIDLoginContrib: JWT ID token verification failed: unknown signing key");
    throw_error("We couldn't verify the validity of the claims we received from your Open ID provider.");    
}    

sub random_bytes {
    my $size = shift;
    my $s = "";
    for (my $i=0; $i < $size; $i++) {
	my $r = Crypt::Random::makerandom(Size=>8, Strength=>0, Uniform=>1);
	$s = $s . chr($r);
    }
    return $s;
}

sub encode {
    my $arg = shift;
    return MIME::Base64::encode($arg);
}

sub decode {
    my $arg = shift;
    return MIME::Base64::decode($arg);
}

sub urlencode_hash {
    my $hash = shift;
    my @query = ();
    foreach my $key (keys %$hash) {
	push(@query, $key . "=" . Foswiki::urlEncode($hash->{$key}));
    }
    return join("&", @query);
}


1;
