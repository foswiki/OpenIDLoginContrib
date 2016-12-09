# ---+ Security and Authentication
# ---++ Open ID
# ---+++ Provider Details
# **URL LABEL="OpenID Connect Configuration URL"**
# An URL that points to the OpenID Connect discovery document.
# It should end in /.well-known/openid-configuration.
$Foswiki::cfg{Extensions}{OpenID}{Default}{DiscoveryURL} = '';
# **URL LABEL="Redirect/OAuth Callback URL"**
# The callback URL that the OpenID provider redirects to. This
# must be an URL pointing at the Foswiki login script.
$Foswiki::cfg{Extensions}{OpenID}{Default}{RedirectURL} = '';
# **STRING LABEL="Client ID"**
# The client id should be provided to you by your Open ID Provider
$Foswiki::cfg{Extensions}{OpenID}{Default}{ClientID} = '';
# **STRING LABEL="Client Secret"**
# The client secret should be provided to you by your Open ID Provider
$Foswiki::cfg{Extensions}{OpenID}{Default}{ClientSecret} = '';
# **REGEX LABEL="Issuer Regex Match" CHECK="undefok emptyok"**
# OpenID works with ID tokens issued by an identity provider. This regex lets
# you specify which identity providers you trust. If you leave this empty, the
# issuer value from the discovery document will be used. However, some providers,
# such as Microsoft Azure AD, host multiple tenants, all of them will have their
# own issuer identities. The discovery document can't list all of them, so in
# such a case you must provide a regex to manually match the correct issuer string.
# Look at the 'issuer' key in the discovery document of your Open ID Provider for 
# the format to expect.
$Foswiki::cfg{Extensions}{OpenID}{Default}{IssuerRegex} = '';
# ---+++ Users
# **STRING LABEL="WikiName Attributes"**
# Comma-separated ID token attributes which should make up the wiki name. The default
# should give good results.
$Foswiki::cfg{Extensions}{OpenID}{Default}{WikiNameAttributes} = 'given_name,family_name';
# **STRING LABEL="Loginname Attribute"**
# The ID Token attribute which will serves as a Loginname. The default is the subject
# identifier. Don't change this if you don't know what you're doing.
$Foswiki::cfg{Extensions}{OpenID}{Default}{LoginnameAttribute} = 'sub';

1;
