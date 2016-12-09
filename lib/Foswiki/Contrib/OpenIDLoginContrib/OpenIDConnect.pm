use Crypt::Random;
use Crypt::JWT;
use LWP::UserAgent;
use MIME::Base64;
use JSON;

package Foswiki::Contrib::OpenIDLoginContrib::OpenIDConnect;
use Exporter 'import';
@EXPORT_OK = qw(endpoint_discovery get_auth_endpoint get_token_endpoint get_supported_scopes exchange_code_for_id_token random_bytes);

sub endpoint_discovery {
    my $discovery_uri = shift;
    my $ua = LWP::UserAgent->new;
    my $response = $ua->get($discovery_uri);
    die "Could not retrieve Open ID endpoint configuration at $discovery_uri" if !$response->is_success;
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
    die "Could not retrieve public keys" if !$response->is_success;    
    my $keys = JSON::decode_json($response->decoded_content)->{'keys'};
    return $keys;
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
	# doesn't seem to do anything ???
	#Foswiki::logger->log("debug", $response->code, $response->message);
	die "Couldn't exchange code for a bearer token: " . $response->message . "\n";
    }
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
    die "JWT ID token verification failed: wrong number of segments" unless scalar @parts == 3;

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
		die "JWT ID token verification failed: " . $@;
	    };
	    die "JWT ID token verification failed: wrong audience" unless $audience eq $data->{'aud'};
	    die "JWT ID token verification failed: wrong issuer (" . $data->{'iss'} . ")" unless $data->{'iss'} =~ /$issuer/;
	    return $data;
	}
    }
    # TODO: This may happen if we cache the keys for long periods (hours) instead of fetching them whenever 
    # we need them. In that case, we could recover by explicitely fetching them and retrying to verify.
    die "JWT ID token verification failed: unknown signing key";
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

1;
