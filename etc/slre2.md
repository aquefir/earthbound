# New API design

I have been authoring a rewrite of the Super Light Regular Expressions
library in the interim when fatigued. Here we frame the new API and
discuss its implementation strategy in detail.

In contrast to more heavyweight APIs, SLRE2 continues the API design of
the original SLRE library: there is no &lsquo;compiled&rsquo; regular
expression object. This approach was chosen for two reasons:

1. keeping with the simplicity of the previous API and character of the
   library
2. allowing for a very fast and lazy byte-oriented scanner
