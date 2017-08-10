"""
Salmon takes the policy that email it receives is most likely complete garbage
using bizarre pre-Unicode formats that are irrelevant and unnecessary in today's
modern world.  These emails must be cleansed of their unholy stench of
randomness and turned into something nice and clean that a regular Python
programmer can work with:  unicode.

That's the receiving end, but on the sending end Salmon wants to make the world
better by not increasing the suffering.  To that end, Salmon will canonicalize
all email it sends to be ascii or utf-8 (whichever is simpler and works to
encode the data).  When you get an email from Salmon, it is a pristine easily
parseable clean unit of goodness you can count on.

To accomplish these tasks, Salmon goes back to basics and assert a few simple
rules on each email it receives:

1) NO ENCODING IS TRUSTED, NO LANGUAGE IS SACRED, ALL ARE SUSPECT.
2) Python wants Unicode, it will get Unicode.
3) Any email that CANNOT become Unicode, CANNOT be processed by Salmon or
   Python.
4) Email addresses are ESSENTIAL to Salmon's routing and security, and therefore
   will be canonicalized and properly encoded.
5) Salmon will therefore try to "upgrade" all email it receives to Unicode
   internally, and cleaning all email addresses.
6) It does this by decoding all codecs, and if the codec LIES, then it will
   attempt to statistically detect the codec using chardet.
7) If it can't detect the codec, and the codec lies, then the email is bad.
8) All text bodies and attachments are then converted to Python unicode in the
   same way as the headers.
9) All other attachments are converted to raw strings as-is.

Once Salmon has done this, your Python handler can now assume that all
MailRequest objects are happily unicode enabled and ready to go.  The rule is:

    IF IT CANNOT BE UNICODE, THEN PYTHON CANNOT WORK WITH IT.

On the outgoing end (when you send a MailResponse), Salmon tries to create the
email it wants to receive by canonicalizing it:

1) All email will be encoded in the simplest cleanest way possible without
losing information.
2) All headers are converted to 'ascii', and if that doesn't work, then 'utf-8'.
3) All text/* attachments and bodies are converted to ascii, and if that doesn't
work, 'utf-8'.
4) All other attachments are left alone.
5) All email addresses are normalized and encoded if they have not been already.

The end result is an email that has the highest probability of not containing
any obfuscation techniques, hidden characters, bad characters, improper
formatting, invalid non-characterset headers, or any of the other billions of
things email clients do to the world.  The output rule of Salmon is:

    ALL EMAIL IS ASCII FIRST, THEN UTF-8, AND IF CANNOT BE EITHER THOSE IT WILL
    NOT BE SENT.

Following these simple rules, this module does the work of converting email
to the canonical format and sending the canonical format.  The code is
probably the most complex part of Salmon since the job it does is difficult.

Test results show that Salmon can safely canonicalize most email from any
culture (not just English) to the canonical form, and that if it can't then the
email is not formatted right and/or spam.

If you find an instance where this is not the case, then submit it to the
project as a test case.
"""

from email import encoders
from email.charset import Charset
from email.mime.base import MIMEBase
from email.message import Message
from email.utils import parseaddr
import email
import re
import string
import sys

import chardet

DEFAULT_ENCODING = "utf-8"
DEFAULT_ERROR_HANDLING = "strict"
CONTENT_ENCODING_KEYS = set(['Content-Type', 'Content-Transfer-Encoding',
                             'Content-Disposition', 'Mime-Version'])
CONTENT_ENCODING_REMOVED_PARAMS = ['boundary']

REGEX_OPTS = re.IGNORECASE | re.MULTILINE
ENCODING_REGEX = re.compile(r"\=\?([a-z0-9\-]+?)\?([bq])\?", REGEX_OPTS)
ENCODING_END_REGEX = re.compile(r"\?=", REGEX_OPTS)
INDENT_REGEX = re.compile(r"\n\s+")

VALUE_IS_EMAIL_ADDRESS = lambda v: '@' in v
ADDRESS_HEADERS_WHITELIST = ['From', 'To', 'Delivered-To', 'Cc', 'Bcc']


class EncodingError(Exception):
    """Thrown when there is an encoding error."""
    pass


class ContentEncoding(object):
    """
    Wrapper various content encoding headers

    The value of each key is returned as a tuple of a string and a dict of
    params. Note that changes to the params dict won't be reflected in the
    underlying MailBase unless the tuple is reassigned:

    >>> value = mail.content_encoding["Content-Type"]
    >>> print value
    ('text/html', {'charset': 'us-ascii'})
    >>> value[1]['charset'] = 'utf-8'
    >>> print mail["Content-Type"]  # unchanged
    ('text/html', {'charset': 'us-ascii'})
    >>> mail.content_encoding["Content-Type"] = value
    >>> print mail["Content-Type"]
    ('text/html', {'charset': 'utf-8'})

    Will raise EncodingError if you try to access a header that isn't in
    CONTENT_ENCODING_KEYS
    """
    def __init__(self, base):
        self.base = base
        self.defaults = {
            "Content-Transfer-Encoding": ("7bit", {}),
        }

    def get(self, key, default=None):
        if key not in CONTENT_ENCODING_KEYS:
            raise EncodingError("EncodingError: %s is not in CONTENT_ENCODING_KEYS" % key)

        value, params = parse_parameter_header(self.base.mime_part, key)
        value = value.lower() if value else value
        return (value, params)

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        if key not in CONTENT_ENCODING_KEYS:
            raise EncodingError("EncodingError: %s is not in CONTENT_ENCODING_KEYS" % key)

        # remove any other content header before adding our own
        del self.base.mime_part[key]
        self.base.mime_part.add_header(key, value[0], **value[1])

    def __delitem__(self, key):
        if key not in CONTENT_ENCODING_KEYS:
            raise EncodingError("EncodingError: %s is not in CONTENT_ENCODING_KEYS" % key)

        del self.base.mime_part[key]

    def __len__(self):
        return len(CONTENT_ENCODING_KEYS)

    def __contains__(self, key):
        return key in CONTENT_ENCODING_KEYS

    def keys(self):
        return CONTENT_ENCODING_KEYS


class MailBase(object):
    """
    MailBase is used as the basis of artemis.mail and contains the basics of
    encoding an email.  You actually can do all your email processing with this
    class, but it's more raw.
    """
    def __init__(self, mime_part_or_headers=None, parent=None):
        self.parts = []
        self.parent = parent
        self.content_encoding = ContentEncoding(self)

        if isinstance(mime_part_or_headers, Message):
            self.mime_part = mime_part_or_headers
        else:
            self.mime_part = Message()
            if mime_part_or_headers is not None and len(mime_part_or_headers) > 0:
                for key, value in mime_part_or_headers:
                    self.mime_part[key] = value

    def __getitem__(self, key):
        header = self.mime_part.get(normalize_header(key))
        return header_from_mime_encoding(header)

    def __len__(self):
        return len(self.mime_part)

    def __iter__(self):
        for k in self.mime_part.keys():
            yield k

    def __contains__(self, key):
        return normalize_header(key) in self.mime_part

    def __setitem__(self, key, value):
        try:
            del self.mime_part[normalize_header(key)]
        except KeyError:
            pass

        self.mime_part[normalize_header(key)] = value

    def __delitem__(self, key):
        del self.mime_part[normalize_header(key)]

    def __nonzero__(self):
        return self.body != None or len(self.mime_part) > 0 or len(self.parts) > 0

    def keys(self):
        """Returns header keys."""
        return self.mime_part.keys()

    def append_header(self, key, value):
        """Like __set_item__, but won't replace header values"""
        self.mime_part[normalize_header(key)] = value

    @property
    def body(self):
        body = self.mime_part.get_payload(decode=True)
        if body:
            # decode the payload according to the charset given if it's text
            ctype, params = self.content_encoding['Content-Type']

            if not ctype:
                charset = 'ascii'
                body = attempt_decoding(charset, body)
            elif ctype.startswith("text/"):
                charset = params.get('charset', 'ascii')
                body = attempt_decoding(charset, body)
            else:
                # it's a binary codec of some kind, so just decode and leave it
                # alone for now
                pass
        return body

    @body.setter
    def body(self, value):
        ctype, params = self.content_encoding['Content-Type']
        self.mime_part.set_payload(value, params.get("charset", None))


    def attach_file(self, filename, data, ctype, disposition):
        """
        A file attachment is a raw attachment with a disposition that
        indicates the file name.
        """
        assert filename, "You can't attach a file without a filename."
        assert ctype.lower() == ctype, "Hey, don't be an ass.  Use a lowercase content type."

        part = MailBase(parent=self)
        part.body = data
        part.content_encoding['Content-Type'] = (ctype, {'name': filename})
        part.content_encoding['Content-Disposition'] = (disposition,
                                                        {'filename': filename})
        self.parts.append(part)


    def attach_text(self, data, ctype):
        """
        This attaches a simpler text encoded part, which doesn't have a
        filename.
        """
        assert ctype.lower() == ctype, "Hey, don't be an ass.  Use a lowercase content type."

        part = MailBase(parent=self)
        part.body = data
        part.content_encoding['Content-Type'] = (ctype, {})
        self.parts.append(part)

    def walk(self):
        for p in self.parts:
            yield p
            for x in p.walk():
                yield x


class MIMEPart(Message):
    """
    A reimplementation of nearly everything in email.mime to be more useful
    for actually attaching things.  Rather than one class for every type of
    thing you'd encode, there's just this one, and it figures out how to
    encode what you ask it.
    """
    def __init__(self, type_, **params):
        self.mimetype = type_

        # classes from email.* are all old-style :(
        Message.__init__(self)

        self.add_header('Content-Type', type_, **params)

    def add_text(self, content, charset=None):
        # this is text, so encode it in canonical form
        charset = charset or 'ascii'
        try:
            encoded = content.encode(charset)
        except UnicodeError:
            encoded = content.encode('utf-8')
            charset = 'utf-8'

        self.set_payload(encoded, charset=charset)

    def extract_payload(self, mail):
        if mail.body == None:
            return  # only None, '' is still ok

        ctype, ctype_params = mail.content_encoding['Content-Type']
        cdisp, cdisp_params = mail.content_encoding['Content-Disposition']

        assert ctype, "Extract payload requires that mail.content_encoding have a valid Content-Type."

        if ctype.startswith("text/"):
            self.add_text(mail.body, charset=ctype_params.get('charset'))
        else:
            if cdisp:
                # replicate the content-disposition settings
                self.add_header('Content-Disposition', cdisp, **cdisp_params)

            self.set_payload(mail.body)
            encoders.encode_base64(self)

    def __repr__(self):
        return "<MIMEPart '%s': %r, %r, multipart=%r>" % (self.mimetype, self['Content-Type'],
                                              self['Content-Disposition'],
                                                            self.is_multipart())

def from_message(message, parent=None):
    """
    Given a MIMEBase or similar Python email API message object, this
    will canonicalize it and give you back a pristine MailBase.
    If it can't then it raises a EncodingError.
    """
    mail = MailBase(message, parent)

    if message.is_multipart():
        # recursively go through each subpart and decode in the same way
        for msg in message.get_payload():
            if msg != message:  # skip the multipart message itself
                mail.parts.append(from_message(msg, mail))

    return mail


def to_message(mail):
    """
    Given a MailBase message, this will construct a MIMEPart
    that is canonicalized for use with the Python email API.

    N.B. this changes the original email.message.Message
    """
    ctype, params = mail.content_encoding['Content-Type']
    if not ctype:
        if mail.parts:
            ctype = 'multipart/mixed'
        else:
            ctype = 'text/plain'
    else:
        if mail.parts:
            assert ctype.startswith("multipart") or ctype.startswith("message"), "Content type should be multipart or message, not %r" % ctype

    # adjust the content type according to what it should be now
    mail.content_encoding['Content-Type'] = (ctype, params)

    try:
        out = MIMEPart(ctype, **params)
    except TypeError, exc:
        raise EncodingError("Content-Type malformed, not allowed: %r; %r (Python ERROR: %s" %
                            (ctype, params, exc.message))

    for k in mail.keys():
        if k in ADDRESS_HEADERS_WHITELIST:
            value = header_to_mime_encoding(mail[k])
        else:
            value = header_to_mime_encoding(mail[k], not_email=True)

        if k.lower() in [key.lower() for key in CONTENT_ENCODING_KEYS]:
            del out[k]
            out[k] = value
        else:
            out[k.encode('ascii')] = value

    out.extract_payload(mail)

    # make sure payload respects cte
    cte, cte_params = mail.content_encoding['Content-Transfer-Encoding']
    if cte == "quoted-printable":
        encoders.encode_quopri(out)
    elif cte == "base64":
        encoders.encode_base64(out)

    # go through the children
    for part in mail.parts:
        out.attach(to_message(part))

    return out


def to_string(mail, envelope_header=False):
    """Returns a canonicalized email string you can use to send or store
    somewhere."""
    msg = to_message(mail).as_string(envelope_header)
    assert "From nobody" not in msg
    return msg


def from_string(data):
    """Takes a string, and tries to clean it up into a clean MailBase."""
    return from_message(email.message_from_string(data))


def to_file(mail, fileobj):
    """Writes a canonicalized message to the given file."""
    fileobj.write(to_string(mail))

def from_file(fileobj):
    """Reads an email and cleans it up to make a MailBase."""
    return from_message(email.message_from_file(fileobj))


def normalize_header(header):
    return string.capwords(header.lower(), '-')


def parse_parameter_header(message, header):
    params = message.get_params(header=header)
    if params:
        value = params.pop(0)[0]
        params_dict = dict(params)

        for key in CONTENT_ENCODING_REMOVED_PARAMS:
            if key in params_dict: del params_dict[key]

        return value, params_dict
    else:
        return None, {}


def properly_encode_header(value, encoder, not_email):
    """
    The only thing special (weird) about this function is that it tries
    to do a fast check to see if the header value has an email address in
    it.  Since random headers could have an email address, and email addresses
    have weird special formatting rules, we have to check for it.

    Normally this works fine, but in Librelist, we need to "obfuscate" email
    addresses by changing the '@' to '-AT-'.  This is where
    VALUE_IS_EMAIL_ADDRESS exists.  It's a simple lambda returning True/False
    to check if a header value has an email address.  If you need to make this
    check different, then change this.
    """
    try:
        return value.encode("ascii")
    except UnicodeEncodeError:
        if not_email is False and VALUE_IS_EMAIL_ADDRESS(value):
            # this could have an email address, make sure we don't screw it up
            name, address = parseaddr(value)
            return '"%s" <%s>' % (encoder.header_encode(name.encode("utf-8")), address)

        return encoder.header_encode(value.encode("utf-8"))


def header_to_mime_encoding(value, not_email=False):
    if not value: return ""

    encoder = Charset(DEFAULT_ENCODING)
    if type(value) == list:
        return "; ".join(properly_encode_header(v, encoder, not_email) for v in value)
    else:
        return properly_encode_header(value, encoder, not_email)


def header_from_mime_encoding(header):
    if header is None:
        return header
    elif type(header) == list:
        return [properly_decode_header(h) for h in header]
    else:
        return properly_decode_header(header)


def guess_encoding_and_decode(original, data, errors=DEFAULT_ERROR_HANDLING):
    try:
        charset = chardet.detect(str(data))

        if not charset['encoding']:
            raise EncodingError("Header claimed %r charset, but detection found none.  Decoding failed." % original)

        return data.decode(charset["encoding"], errors)
    except UnicodeError, exc:
        raise EncodingError("Header lied and claimed %r charset, guessing said "
                            "%r charset, neither worked so this is a bad email: "
                            "%s." % (original, charset, exc))


def attempt_decoding(charset, dec):
    try:
        if isinstance(dec, unicode):
            # it's already unicode so just return it
            return dec
        else:
            return dec.decode(charset)
    except UnicodeError:
        # looks like the charset lies, try to detect it
        return guess_encoding_and_decode(charset, dec)
    except LookupError:
        # they gave a crap encoding
        return guess_encoding_and_decode(charset, dec)


def apply_charset_to_header(charset, encoding, data):
    if encoding == 'b' or encoding == 'B':
        dec = email.base64mime.decode(data.encode('ascii'))
    elif encoding == 'q' or encoding == 'Q':
        dec = email.quoprimime.header_decode(data.encode('ascii'))
    else:
        raise EncodingError("Invalid header encoding %r should be 'Q' or 'B'." % encoding)

    return attempt_decoding(charset, dec)




def _match(data, pattern, pos):
    found = pattern.search(data, pos)
    if found:
        # contract: returns data before the match, and the match groups
        left = data[pos:found.start()]
        return left, found.groups(), found.end()
    else:
        left = data[pos:]
        return left, None, -1



def _tokenize(data, next):
    enc_data = None

    left, enc_header, next = _match(data, ENCODING_REGEX, next)

    if next != -1:
        enc_data, _, next = _match(data, ENCODING_END_REGEX, next)

    return left, enc_header, enc_data, next


def _scan(data):
    next = 0
    continued = False
    while next != -1:
        left, enc_header, enc_data, next = _tokenize(data, next)

        if next != -1 and INDENT_REGEX.match(data, next):
            continued = True
        else:
            continued = False

        yield left, enc_header, enc_data, continued


def _parse_charset_header(data):
    scanner = _scan(data)
    oddness = None

    try:
        while True:
            if not oddness:
                left, enc_header, enc_data, continued = scanner.next()
            else:
                left, enc_header, enc_data, continued = oddness
                oddness = None

            while continued:
                l, eh, ed, continued = scanner.next()

                if not eh:
                    assert not ed, "Parsing error, give Zed this: %r" % data
                    oddness = (" " + l.lstrip(), eh, ed, continued)
                elif eh[0] == enc_header[0] and eh[1] == enc_header[1]:
                    enc_data += ed
                else:
                    # odd case, it's continued but not from the same base64
                    # need to stack this for the next loop, and drop the \n\s+
                    oddness = ('', eh, ed, continued)
                    break

            if left:
                yield attempt_decoding('ascii', left)

            if enc_header:
                yield apply_charset_to_header(enc_header[0], enc_header[1], enc_data)

    except StopIteration:
        pass


def properly_decode_header(header):
    return u"".join(_parse_charset_header(header))


