# ---+ Security and Authentication
# ---++ Open ID
# Configure Open ID Login here. Remember to select the OpenIDConnectLogin login manager under the Login tab to enable it. You're also strongly urged to enable 'AllowLoginName' (found under the Registration tab).
# ---+++ Provider Details
# Set up your first Open ID provider here. You can configure additional providers directly in LocalSite.cfg.
# **URL LABEL="OpenID Connect Configuration URL"**
# An URL that points to the OpenID Connect discovery document.
# It usually ends in /.well-known/openid-configuration.
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
# ID tokens only validate if their issuer claims match this regex.
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
# Configure how ID tokens are mapped onto the Foswiki loginname/WikiName infrastructure.
# **STRING LABEL="WikiName Claims"**
# Comma-separated ID token claims which should make up the WikiName.
# The default should give good results, but depending on the provider, you might want
# to experiment with other claims, such as the 'name' claim.
$Foswiki::cfg{Extensions}{OpenID}{WikiNameAttributes} = 'given_name,family_name';

# **STRING LABEL="Loginname Attribute"**
# The ID token attribute which will serves as a Loginname.
# The default is the subject identifier. Don't change this if you don't know what
# you're doing.
$Foswiki::cfg{Extensions}{OpenID}{LoginnameAttribute} = 'sub';

# **BOOLEAN LABEL="Reserve WikiNames"**
# Enable this to pre-assign WikiNames to specific people.
# You can make sure that a WikiName will be assigned to a specific user by
# creating a User topic (with the given WikiName) and populating it's EMail
# form field value with the e-mail address of the user. When a user which
# would ordinarily be mapped to the given WikiName authenticates, the e-mail
# claim in his ID token is checked against the form field value and if they
# don't match, the WikiName isn't given out to the user.
# (Don't rely solely on this for security! It isn't foolproof, as not
# every identity provider verifies control over e-mail addresses)
$Foswiki::cfg{Extensions}{OpenID}{UserFormMatch} = 0;

# **STRING LABEL="Form field to match"**
# Specifies the form field to use for E-Mail address matching.
# By default, if reserving of WikiNames is enabled, the form field to
# match is the 'EMail' field. If this field has a different name in
# your form, you can provide the name here.
$Foswiki::cfg{Extensions}{OpenID}{UserFormMatchField} = 'Email';

# **STRING LABEL="Forbidden Wikinames"**
# A comma-separated list of WikiNames that should never be given out by this LoginManager.
# If a user authenticates whose ID token would produce one of the WikiNames on this list, the
# user's WikiName will be 'WikiGuest'. 
# WikiNames ending in ...Group are automatically rejected, so you don't need to list them here.
$Foswiki::cfg{Extensions}{OpenID}{ForbiddenWikinames} = 'AdminUser,ProjectContributor,RegistrationAgent';

1;
