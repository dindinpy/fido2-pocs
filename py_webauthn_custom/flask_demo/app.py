import os
import sys

from flask import Flask
from flask import flash
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask_login import LoginManager
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user

import util
import pprint

from db import db
from context import webauthn
from models import User

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(
    os.path.join(os.path.dirname(os.path.abspath(__name__)), 'webauthn.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
sk = os.environ.get('FLASK_SECRET_KEY')
app.secret_key = sk if sk else os.urandom(40)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

# RP_ID = '127.0.0.1'
# ORIGIN = 'http://127.0.0.1:5000'
RP_ID = 'localhost'
ORIGIN = 'http://localhost:5000'
RP_NAME = 'webauthn demo localhost'

# Trust anchors (trusted attestation roots) should be
# placed in TRUST_ANCHOR_DIR.
TRUST_ANCHOR_DIR = 'trusted_attestation_roots'


@login_manager.user_loader
def load_user(user_id):
    try:
        int(user_id)
    except ValueError:
        return None

    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/webauthn_begin_activate', methods=['POST'])
def webauthn_begin_activate():
    print("[ENTER] begin registration")
    import pdb;pdb.set_trace()
    # MakeCredentialOptions
    username = request.form.get('register_username')
    display_name = request.form.get('register_display_name')

    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Invalid username.'}), 401)
    if not util.validate_display_name(display_name):
        return make_response(jsonify({'fail': 'Invalid display name.'}), 401)

    if User.query.filter_by(username=username).first():
        return make_response(jsonify({'fail': 'User already exists.'}), 401)

    #clear session variables prior to starting a new registration
    session.pop('register_ukey', None)
    session.pop('register_username', None)
    session.pop('register_display_name', None)
    session.pop('challenge', None)

    session['register_username'] = username
    session['register_display_name'] = display_name

    challenge = util.generate_challenge(32)
    print("[INFO] registration challenge ", challenge)
    ukey = util.generate_ukey()

    # We strip the saved challenge of padding, so that we can do a byte
    # comparison on the URL-safe-without-padding challenge we get back
    # from the browser.
    # We will still pass the padded version down to the browser so that the JS
    # can decode the challenge into binary without too much trouble.
    session['challenge'] = challenge.rstrip('=')
    print("[INFO] challenge.rstrip('=') ", session['challenge'])
    session['register_ukey'] = ukey

    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge, RP_NAME, RP_ID, ukey, username, display_name,
        'https://example.com')
    
    js =  make_credential_options.registration_dict
    pprint.pprint(js)
    print("[EXIT] begin registration\n")
    return jsonify(js)


@app.route('/webauthn_begin_assertion', methods=['POST'])
def webauthn_begin_assertion():
    
    username = request.form.get('login_username')
    print("[ENTER] begin authentcation for user ", username)
    import pdb;pdb.set_trace()
    if not util.validate_username(username):
        print("[ERROR] Invalid username.")
        return make_response(jsonify({'fail': 'Invalid username.'}), 401)

    user = User.query.filter_by(username=username).first()

    if not user:
        print("[ERROR] User does not exist.")
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)
    if not user.credential_id:
        print("[ERROR] Unknown credential ID.")
        return make_response(jsonify({'fail': 'Unknown credential ID.'}), 401)

    session.pop('challenge', None)

    challenge = util.generate_challenge(32, True)
    print("[INFO] authentication challenge ", challenge)
    # print("[INFO] challenge type ", type(challenge))

    # We strip the padding from the challenge stored in the session
    # for the reasons outlined in the comment in webauthn_begin_activate.
    session['challenge'] = challenge.rstrip('=')

    webauthn_user = webauthn.WebAuthnUser(
        user.ukey, user.username, user.display_name, user.icon_url,
        user.credential_id, user.pub_key, user.sign_count, user.rp_id)

    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
        webauthn_user, challenge)

    
    ad = webauthn_assertion_options.assertion_dict
    pprint.pprint(ad)
    print("[EXIT] begin authentcation\n")
    return jsonify(ad)


@app.route('/verify_credential_info', methods=['POST'])
def verify_credential_info():
    print("[ENTER] Registration complete")
    challenge = session['challenge']
    username = session['register_username']
    display_name = session['register_display_name']
    ukey = session['register_ukey']
    # import pdb;pdb.set_trace()
    registration_response = request.form
    import pdb;pdb.set_trace()
    trust_anchor_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
    trusted_attestation_cert_required = True
    self_attestation_permitted = True
    none_attestation_permitted = True

    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        RP_ID,
        ORIGIN,
        registration_response,
        challenge,
        trust_anchor_dir,
        trusted_attestation_cert_required,
        self_attestation_permitted,
        none_attestation_permitted,
        uv_required=False)  # User Verification

    try:
        webauthn_credential = webauthn_registration_response.verify()
    except Exception as e:
        return jsonify({'fail': 'Registration failed. Error: {}'.format(e)})

    # Step 17.
    #
    # Check that the credentialId is not yet registered to any other user.
    # If registration is requested for a credential that is already registered
    # to a different user, the Relying Party SHOULD fail this registration
    # ceremony, or it MAY decide to accept the registration, e.g. while deleting
    # the older registration.
    credential_id_exists = User.query.filter_by(
        credential_id=webauthn_credential.credential_id).first()
    if credential_id_exists:
        return make_response(
            jsonify({
                'fail': 'Credential ID already exists.'
            }), 401)

    existing_user = User.query.filter_by(username=username).first()
    if not existing_user:
        if sys.version_info >= (3, 0):
            webauthn_credential.credential_id = str(
                webauthn_credential.credential_id, "utf-8")
            webauthn_credential.public_key = str(
                webauthn_credential.public_key, "utf-8")
        user = User(
            ukey=ukey,
            username=username,
            display_name=display_name,
            pub_key=webauthn_credential.public_key,
            credential_id=webauthn_credential.credential_id,
            sign_count=webauthn_credential.sign_count,
            rp_id=RP_ID,
            icon_url='https://example.com')
        db.session.add(user)
        db.session.commit()
    else:
        return make_response(jsonify({'fail': 'User already exists.'}), 401)

    msg = 'Successfully registered as ' + username
    print("[INFO] ", msg)
    flash(msg)
    print("[EXIT] complete Registration\n")
    return jsonify({'success': 'User successfully registered.'})


@app.route('/verify_assertion', methods=['POST'])
def verify_assertion():
    print("[ENTER] complete authentcation")
    # import pdb;pdb.set_trace()
    challenge = session.get('challenge')
    assertion_response = request.form
    import pdb;pdb.set_trace()
    credential_id = assertion_response.get('id')
    print("assertion_response ", assertion_response)

    user = User.query.filter_by(credential_id=credential_id).first()
    if not user:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)

    webauthn_user = webauthn.WebAuthnUser(
        user.ukey, user.username, user.display_name, user.icon_url,
        user.credential_id, user.pub_key, user.sign_count, user.rp_id)

    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user,
        assertion_response,
        challenge,
        ORIGIN,
        uv_required=False)  # User Verification

    try:
        sign_count = webauthn_assertion_response.verify()
    except Exception as e:
        print("[ERROR] ", e)
        return jsonify({'fail': 'Assertion failed. Error: {}'.format(e)})

    # Update counter.
    user.sign_count = sign_count
    db.session.add(user)
    db.session.commit()

    login_user(user)
    msg = 'Successfully authenticated as '  + user.username + \
            '\n\tCredential Id: ' + credential_id
    print(msg)
    print("[EXIT] complete authentcation\n")
    return jsonify({
        'success':
        'Successfully authenticated as {}'.format(user.username)
    })


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    # app.run(host='0.0.0.0', ssl_context='adhoc', debug=True)
    app.run(debug=True)