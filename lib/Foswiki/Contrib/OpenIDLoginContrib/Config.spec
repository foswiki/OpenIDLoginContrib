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

# **NUMBER LABEL="Enable UserForm matching"**
# You have no control over the people who will register via public Open ID providers.
# If you want to reserve WikiNames for specific people, you can pre-register them by
# creating a user topic with the given WikiName and pre-populating the E-Mail form field
# of the UserForm field with the person's address. Enabling UserTopic matching will compare
# the E-Mail returned in the ID Token with the one in the UserTopic and not give out the
# WikiName if they don't match. (Don't rely on this for security! It isn't foolproof, as not
# every identity provider verifies control over E-Mail addresses)
$Foswiki::cfg{Extensions}{OpenID}{UserFormMatch} = 0;

# **STRING LABEL="The form field to match in the user topic"**
# By default, if UserForm matching is enabled, the form field to match is the EMail field.
# If you've renamed this field, you can specify it's new name here.
$Foswiki::cfg{Extensions}{OpenID}{UserFormMatchField} = 'Email';

# **STRING LABEL="Forbidden Wikinames"**
# A comma-separated list of WikiNames that should never be given out by this LoginManager.
# WikiNames are constructed from ID Token contents. These can be partly controlled by people
# of malicious intent. If someone were to name a Google Account Admin User, he'd get assigned
# an 'AdminUser' wikiname, which probably wouldn't be a good thing, all things considered.
$Foswiki::cfg{Extensions}{OpenID}{ForbiddenWikinames} = 'AdminUser,ProjectContributor,RegistrationAgent';

1;
