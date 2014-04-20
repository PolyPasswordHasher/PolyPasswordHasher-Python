import os
import pickle
import hashlib

# For thresholdless password support...
from Crypto.Cipher import AES

from .shamirsecret import PY3
try:
    from .fastshamirsecret import ShamirSecret
except ImportError:
    from .shamirsecret import ShamirSecret


class PolyPassHash(object):
    """
    This is a PolyHash object that has special routines for passwords
    """
    # this is keyed by user name.  Each value is a list of dicts (really a
    # struct) where each dict contains the salt, sharenumber, and
    # passhash (saltedhash XOR shamirsecretshare).
    accountdict = None

    # This contains the shamirsecret object for this data store
    shamirsecretobj = None

    # Is the secret value known?   In other words, is it safe to use the
    # passwordfile
    knownsecret = False

    # length of the salt in bytes
    saltsize = 16

    # hashing algorithm
    hasher = hashlib.sha256

    # serialization object supporting dump/load methods
    serializer = pickle

    # number of bytes of data used for partial verification...
    partialbytes = 0

    # thresholdless support.   This could be random (and unknown) in the default
    # algorithm
    thresholdlesskey = None

    # number of used shares.   While I could duplicate shares for normal users,
    # I don't do so in this implementation.   This duplication would allow
    # co-analysis of password hashes
    nextavailableshare = None

    def __init__(self, threshold, passwordfile=None, partialbytes=0):

        self.threshold = threshold

        self.accountdict = {}

        self.partialbytes = partialbytes

        self.nextavailableshare = 1

        # creating a new password file
        if passwordfile is None:
            # generate a 256 bit key for AES.   I need 256 bits anyways
            # since I'll be XORing by the
            # output of SHA256, I want it to be 256 bits (or 32 bytes) long
            self.thresholdlesskey = os.urandom(32)
            # protect this key.
            self.shamirsecretobj = ShamirSecret(threshold,
                                                self.thresholdlesskey)
            # I've generated it now, so it is safe to use!
            self.knownsecret = True
            return

        # Okay, they have asked me to load in a password file!
        self.shamirsecretobj = ShamirSecret(threshold)
        self.knownsecret = False
        self.thresholdlesskey = None

        # just want to deserialize this data.  Should do better validation
        self.accountdict = self.serializer.load(open(passwordfile, 'rb'))

        assert isinstance(self.accountdict, dict)

        # compute which share number is the largest used...
        for username in self.accountdict:
            # look at each share
            for share in self.accountdict[username]:
                self.nextavailableshare = max(self.nextavailableshare,
                                              share['sharenumber'])

        # ...then use the one after when I need a new one.
        self.nextavailableshare += 1

    def create_account(self, username, password, shares):
        """
        Creates a new account.
        Raises a ValueError if given bad data or if the system isn't initialized
        """
        shares = int(shares)
        if PY3:
            password = bytes(password, encoding='utf8')

        if not self.knownsecret:
            raise ValueError("Password File is not unlocked!")

        if username in self.accountdict:
            raise ValueError("Username exists already!")

        # Were I to add support for changing passwords, etc. this code would be
        # moved to an internal helper.

        if shares > 255 or shares < 0:
            raise ValueError("Invalid number of shares: {0}".format(shares))

        # Note this is just an implementation limitation.   I could do all sorts
        # of things to get around this (like just use a bigger field).
        if shares + self.nextavailableshare > 255:
            raise ValueError("Would exceed maximum number of shares: {}".format(shares))

        # for each share, we will add the appropriate dictionary.
        self.accountdict[username] = []

        if shares == 0:
            thisentry = {}
            thisentry['sharenumber'] = 0
            # get a random salt, salt the password and store the salted hash
            thisentry['salt'] = os.urandom(self.saltsize)
            saltedpasswordhash = self.hasher(thisentry['salt'] + password).digest()
            # Encrypt the salted secure hash.   The salt should make all entries
            # unique when encrypted.
            thisentry['passhash'] = AES.new(self.thresholdlesskey).encrypt(saltedpasswordhash)
            # technically, I'm supposed to remove some of the prefix here, but why
            # bother?

            # append the partial verification data...
            thisentry['passhash'] += saltedpasswordhash[len(saltedpasswordhash) - self.partialbytes:]
            thisentry['passhash'] = bytes(thisentry['passhash'])

            self.accountdict[username].append(thisentry)
            # and exit (don't increment the share count!)
            return thisentry

        for sharenumber in range(self.nextavailableshare, self.nextavailableshare + shares):
            thisentry = {}
            thisentry['sharenumber'] = sharenumber
            # take the bytearray part of this
            shamirsecretdata = self.shamirsecretobj.compute_share(sharenumber)[1]
            thisentry['salt'] = os.urandom(self.saltsize)
            saltedpasswordhash = self.hasher(thisentry['salt'] + password).digest()
            # XOR the two and keep this.   This effectively hides the hash unless
            # threshold hashes can be simultaneously decoded
            thisentry['passhash'] = do_bytearray_xor(saltedpasswordhash, shamirsecretdata)
            # append the partial verification data...
            thisentry['passhash'] += saltedpasswordhash[len(saltedpasswordhash) - self.partialbytes:]
            thisentry['passhash'] = bytes(thisentry['passhash'])

            self.accountdict[username].append(thisentry)

        # increment the share counter.
        self.nextavailableshare += shares
        return self.accountdict[username]

    def is_valid_login(self, username, password):
        if PY3:
            password = bytes(password, encoding='utf8')

        if not self.knownsecret and self.partialbytes == 0:
            raise ValueError("Password File is not unlocked and partial verification is disabled!")

        if username not in self.accountdict:
            raise ValueError("Unknown user {0!r}".format(username))

        # I'll check every share.   I probably could just check the first in almost
        # every case, but this shouldn't be a problem since only admins have
        # multiple shares.   Since these accounts are the most valuable (for what
        # they can access in the overall system), let's be thorough.

        for entry in self.accountdict[username]:

            saltedpasswordhash = self.hasher(entry['salt'] + password).digest()

            # If not unlocked, partial verification needs to be done here!
            if not self.knownsecret:
                saltedcheck = saltedpasswordhash[len(saltedpasswordhash) - self.partialbytes:]
                entrycheck = entry['passhash'][len(entry['passhash']) - self.partialbytes:]
                return saltedcheck == entrycheck

            # XOR to remove the salted hash from the password
            sharedata = do_bytearray_xor(saltedpasswordhash,
                                         entry['passhash'][:len(entry['passhash']) - self.partialbytes])

            # If a thresholdless account...
            if entry['sharenumber'] == 0:
                # return true if the password encrypts the same way...
                cryptcheck = AES.new(self.thresholdlesskey).encrypt(saltedpasswordhash)
                entrycheck = entry['passhash'][:len(entry['passhash']) - self.partialbytes]
                return cryptcheck == entrycheck

            # now we should have a shamir share (if all is well.)
            share = entry['sharenumber'], sharedata

            # If a normal share, return T/F depending on if this share is valid.
            return self.shamirsecretobj.is_valid_share(share)

    def write_password_data(self, passwordfile):
        """ Persist the password data to disk."""
        if self.threshold >= self.nextavailableshare:
            raise ValueError("Would write undecodable password file.   Must have more shares before writing.")

        # Need more error checking in a real implementation
        with open(passwordfile, 'wb') as outfile:
            self.serializer.dump(self.accountdict, outfile)

    def unlock_password_data(self, logindata):
        """Pass this a list of username, password tuples like: [('admin',
           'correct horse'), ('root','battery staple'), ('bob','puppy')]) and
           it will use this to access the password file if possible."""

        if self.knownsecret:
            raise ValueError("Password File is already unlocked!")
        # Okay, I need to find the shares first and then see if I can recover the
        # secret using this.

        sharelist = []

        for (username, password) in logindata:
            if PY3:
                password = bytes(password, encoding='utf8')
            if username not in self.accountdict:
                raise ValueError("Unknown user '{0}'".format(username))

            for entry in self.accountdict[username]:

                # ignore thresholdless account entries...
                if entry['sharenumber'] == 0:
                    continue

                thissaltedpasswordhash = self.hasher(entry['salt'] + password).digest()
                thisshare = (entry['sharenumber'], do_bytearray_xor(thissaltedpasswordhash,
                                                                    entry['passhash'][:len(entry['passhash']) - self.partialbytes]))

                sharelist.append(thisshare)

        # This will raise a ValueError if a share is incorrect or there are other
        # issues (like not enough shares).
        self.shamirsecretobj.recover_secretdata(sharelist)
        self.thresholdlesskey = self.shamirsecretobj.secretdata
        # it worked!
        self.knownsecret = True


#### Private helper...
def do_bytearray_xor(a, b):
    a = bytearray(a)
    b = bytearray(b)

    # should always be true in our case...
    if len(a) != len(b):
        print((len(a), len(b), a, b))
    assert len(a) == len(b)
    result = bytearray()

    for pos in range(len(a)):
        result.append(a[pos] ^ b[pos])

    return result
