# ---+ Security and Authentication
# ---++ Open ID
# ---+++ Provider Details
# **URL LABEL="OpenID Connect Configuration URL"**
# An URL that points to the OpenID Connect discovery document.
# It usually ends in .well-known/openid-configuration.
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
# OpenID works with id tokens issued by an identity provider. This REGEX lets
# you specify which identity providers you trust. If you leave this empty, the
# issuer value from the discovery document will be used. However, some providers,
# such as Microsoft Azure AD, issue id tokens with issuer values that depend on the
# tenant. In that case, you must provide a regex which matches the issuer value.
# Look at the 'iss' key in the discovery document of your Open ID Provider for the
# exact format.
$Foswiki::cfg{Extensions}{OpenID}{Default}{IssuerRegex} = '';
# ---+++ Users
# **STRING LABEL="WikiName Attributes"**
# Comma-separated ID Token attributes which should make up the wiki name. The default
# should give good results.
$Foswiki::cfg{Extensions}{OpenID}{Default}{WikiNameAttributes} = 'given_name,family_name';
# **STRING LABEL="Loginname Attribute"**
# The ID Token attribute which will serves as a Loginname. The default is the subject
# identifier. Don't change this if you don't know what you're doing.
$Foswiki::cfg{Extensions}{OpenID}{Default}{LoginnameAttribute} = 'sub';

1;
