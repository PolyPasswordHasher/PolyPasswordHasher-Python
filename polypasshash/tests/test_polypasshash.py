from polypasshash import PolyPassHash

THRESHOLD = 10
PASSWORDFILE = 'securepasswords'


def test_1_decode():
    # require knowledge of 10 shares to decode others.   Create a blank, new
    # password file...
    pph = PolyPassHash(threshold=THRESHOLD, passwordfile=None)

    # create three admins so that any two have the appropriate threshold
    pph.create_account('admin', 'correct horse', THRESHOLD / 2)
    pph.create_account('root', 'battery staple', THRESHOLD / 2)
    pph.create_account('superuser', 'purple monkey dishwasher', THRESHOLD / 2)

    # make some normal user accounts...
    pph.create_account('alice', 'kitten', 1)
    pph.create_account('bob', 'puppy', 1)
    pph.create_account('charlie', 'velociraptor', 1)
    pph.create_account('dennis', 'menace', 0)
    pph.create_account('eve', 'iamevil', 0)

    # try some logins and make sure we see what we expect...
    assert pph.is_valid_login('alice', 'kitten')
    assert pph.is_valid_login('admin', 'correct horse')
    assert not pph.is_valid_login('alice', 'nyancat!')
    assert pph.is_valid_login('dennis', 'menace')
    assert not pph.is_valid_login('dennis', 'password')

    # persist the password file to disk
    pph.write_password_data(PASSWORDFILE)


def test_2_file():

    # let's load it back in
    pph = PolyPassHash(threshold=THRESHOLD, passwordfile=PASSWORDFILE)

    # The password information is essentially useless alone.   You cannot know
    # if a password is valid without threshold or more other passwords!!!
    try:
        pph.is_valid_login('alice', 'kitten')
    except ValueError:
        pass
    else:
        print("Can't get here!   It's still locked!!!")

    # with a threshold (or more) of correct passwords, it decodes and is usable.
    pph.unlock_password_data([
        ('admin', 'correct horse'),
        ('root', 'battery staple'),
        ('bob', 'puppy'),
        ('dennis', 'menace')
    ])

    # now, I can do the usual operations with it...
    assert pph.is_valid_login('alice', 'kitten')

    pph.create_account('moe', 'tadpole', 1)
    pph.create_account('larry', 'fish', 0)

    ##### TEST PARTIAL VERIFICATION

    # require knowledge of 10 shares to decode others.   Create a blank, new
    # password file...
    pph = PolyPassHash(threshold=THRESHOLD, passwordfile=None, partialbytes=2)

    # create three admins so that any two have the appropriate threshold
    pph.create_account('admin', 'correct horse', THRESHOLD / 2)
    pph.create_account('root', 'battery staple', THRESHOLD / 2)
    pph.create_account('superuser', 'purple monkey dishwasher', THRESHOLD / 2)

    # make some normal user accounts...
    pph.create_account('alice', 'kitten', 1)
    pph.create_account('bob', 'puppy', 1)
    pph.create_account('charlie', 'velociraptor', 1)
    pph.create_account('dennis', 'menace', 0)
    pph.create_account('eve', 'iamevil', 0)

    # try some logins and make sure we see what we expect...
    assert pph.is_valid_login('alice', 'kitten')
    assert pph.is_valid_login('admin', 'correct horse')
    assert not pph.is_valid_login('alice', 'nyancat!')
    assert pph.is_valid_login('dennis', 'menace')
    assert not pph.is_valid_login('dennis', 'password')

    # persist the password file to disk
    pph.write_password_data(PASSWORDFILE)


def test_3_partial():
    # let's load it back in
    pph = PolyPassHash(threshold=THRESHOLD, passwordfile='securepasswords', partialbytes=2)

    # The password threshold info should be useful now...
    try:
        assert pph.is_valid_login('alice', 'kitten')
        assert pph.is_valid_login('admin', 'correct horse')
        assert not pph.is_valid_login('alice', 'nyancat!')
    except ValueError:
        print("Partial verification but it is still locked!!!")

    try:
        pph.create_account('moe', 'tadpole', 1)
    except ValueError:
        # Should be locked...
        pass
    else:
        print("Partial verification does not allow account creation!")

    # with a threshold (or more) of correct passwords, it decodes and is usable.
    pph.unlock_password_data([
        ('admin', 'correct horse'),
        ('root', 'battery staple'),
        ('bob', 'puppy'),
        ('dennis', 'menace')
    ])

    # now, I can do the usual operations with it...
    assert pph.is_valid_login('alice', 'kitten')

    # including create accounts...
    pph.create_account('moe', 'tadpole', 1)
    pph.create_account('larry', 'fish', 0)
