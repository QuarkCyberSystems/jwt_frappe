import random

import frappe
import jwt
from frappe import _
from frappe.auth import LoginManager
from frappe.utils import cint, get_url, get_datetime
from frappe.utils.password import check_password, passlibctx, update_password


def get_linked_user(id_type, id):
	"""
	Returns the user associated with the details
	:param id_type: either 'mobile' or 'email'
	:param id: the email/mobile
	"""
	if id_type not in ("mobile", "sms", "email"):
		frappe.throw(f"Invalid id_type: {id_type}")

	if id_type in ("mobile", "sms"):
		id_type = "mobaile_no"

	return frappe.db.get_value("User", {id_type: id})





@frappe.whitelist(allow_guest=True)
def get_token(user, pwd, expires_in=3600, expire_on=None, device=None):
	"""
	Get the JWT Token
	:param user: The user in ctx
	:param pwd: Pwd to auth
	:param expires_in: number of seconds till expiry
	:param expire_on: yyyy-mm-dd HH:mm:ss to specify the expiry (deprecated)
	:param device: The device in ctx
	"""
	if not frappe.db.exists("User", user):
		raise frappe.ValidationError(_("Invalide User"))

	from frappe.sessions import clear_sessions
	login = LoginManager()
	login.check_if_enabled(user)
	if not check_password(user, pwd):
		login.fail('Incorrect password', user=user)
	login.login_as(user)
	login.resume = False
	login.run_trigger('on_session_creation')
	_expires_in = 3600
	if cint(expires_in):
		_expires_in = cint(expires_in)
	elif expire_on:
		_expires_in = (get_datetime(expire_on) - get_datetime()).total_seconds()


	token = get_bearer_token(
		user=user,
		expires_in=_expires_in
	)
	frappe.local.response["token"] = token["access_token"]
	frappe.local.response.update(token)


def get_oath_client():
	client = frappe.db.get_value("OAuth Client", {})
	if not client:
		# Make one auto
		client = frappe.get_doc(frappe._dict(
				doctype="OAuth Client",
				app_name="default",
				scopes="all openid",
				redirect_urls=get_url(),
				default_redirect_uri=get_url(),
				grant_type="Implicit",
				response_type="Token"
		))
		client.insert(ignore_permissions=True)
	else:
		client = frappe.get_doc("OAuth Client", client)

	return client


import hashlib
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from oauthlib.oauth2.rfc6749.tokens import random_token_generator
import frappe.oauth

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,  # You can adjust the number of iterations for your needs
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data, key):
    cipher_text = jwt.encode(data, key, algorithm='HS256')
    return cipher_text

def get_bearer_token(user, expires_in=3600):
    client = get_oath_client()

    # Generate random tokens
    access_token = random_token_generator(None)
    refresh_token = random_token_generator(None)

    # Create a dictionary with token information
    token_info = {
        'access_token': access_token,
        'expires_in': expires_in,
        'token_type': 'Bearer',
        'scopes': client.scopes,
        'refresh_token': refresh_token
    }

    # Save the token information in the database
    bearer_token = frappe.new_doc("OAuth Bearer Token")
    bearer_token.client = client.name
    bearer_token.scopes = token_info['scopes']
    bearer_token.access_token = token_info['access_token']
    bearer_token.refresh_token = token_info['refresh_token']
    bearer_token.expires_in = token_info['expires_in'] or 3600
    bearer_token.user = user
    bearer_token.save(ignore_permissions=True)
    frappe.db.commit()

    # Encrypt the token info
    salt = "random_salt"  # You should use a random and unique salt for each token
    encryption_key = derive_key("your_secret_password", salt)
    encrypted_token = encrypt_data(token_info, encryption_key)

    # You may want to return the salt along with the encrypted token
    return {
        'encrypted_token': encrypted_token,
        'salt': salt
    }


# def get_bearer_token(user, expires_in=3600):
# 	import hashlib
# 	import jwt
# 	import frappe.oauth
# 	from oauthlib.oauth2.rfc6749.tokens import random_token_generator, OAuth2Token

# 	client = get_oath_client()
# 	token = frappe._dict({
# 			'access_token': random_token_generator(None),
# 			'expires_in': expires_in,
# 			'token_type': 'Bearer',
# 			'scopes': client.scopes,
# 			'refresh_token': random_token_generator(None)
# 	})
# 	bearer_token = frappe.new_doc("OAuth Bearer Token")
# 	bearer_token.client = client.name
# 	bearer_token.scopes = token['scopes']
# 	bearer_token.access_token = token['access_token']
# 	bearer_token.refresh_token = token.get('refresh_token')
# 	bearer_token.expires_in = token['expires_in'] or 3600
# 	bearer_token.user = user
# 	bearer_token.save(ignore_permissions=True)
# 	frappe.db.commit()

# 	# ID Token
# 	id_token_header = {
# 			"typ": "jwt",
# 			"alg": "HS256"
# 	}
# 	id_token = {
# 			"aud": "token_client",
# 			"exp": int((frappe.db.get_value("OAuth Bearer Token", token.access_token, "expiration_time") - frappe.utils.datetime.datetime(1970, 1, 1)).total_seconds()),
# 			"sub": frappe.db.get_value("User Social Login", {"parent": bearer_token.user, "provider": "frappe"}, "userid"),
# 			"iss": "frappe_server_url",
# 			"at_hash": frappe.oauth.calculate_at_hash(token.access_token, hashlib.sha256)
# 	}
# 	id_token_encoded = jwt.encode(
# 			id_token, "client_secret", algorithm='HS256', headers=id_token_header)
# 	id_token_encoded = frappe.safe_decode(id_token_encoded)
# 	token.id_token = id_token_encoded
# 	frappe.flags.jwt = id_token_encoded
	
# 	return token


@frappe.whitelist()
def get_jwt_token():
	"""
	Get jwt token for the active user
	"""
	return get_bearer_token(
			user=frappe.session.user, expires_in=86400
	)["access_token"]
 

 
@frappe.whitelist()
def nor_dev():
	import requests
	import json

	url = "http://frappejwt.quarkcyber.systems/api/resource/User"

	payload = json.dumps({
		"email": "mmmn@gmail.com",
		"first_name": "mnnnii"
	})
	headers = {
		'Authorization': 'token c6135ae101891c2:441ec4a643223eb',
		'Accept': 'application/json',
		'Content-Type': 'application/json',
		'Cookie': 'full_name=Guest; sid=Guest; system_user=no; user_id=Guest; user_image='
	}

	response = requests.request("POST", url, headers=headers, data=payload)

	print(response.text)
 
 
@frappe.whitelist()
def jwt_dev():
	import requests
	import json

	url = "http://frappejwt.quarkcyber.systems/api/resource/User"

	payload = json.dumps({
		"email": "mmmvvn@gmail.com",
		"first_name": "mnnniill"
	})

	jwt_token = "7nYx5qQkTfBMI0UNpuleGEWvQcMiRR"

	headers = {
			'Authorization': f'Bearer {jwt_token}',
			'Accept': 'application/json',
			'Content-Type': 'application/json',
			'Cookie': 'full_name=Guest; sid=Guest; system_user=no; user_id=Guest; user_image='
	}

	response = requests.request("POST", url, headers=headers, data=payload)

	print(response.text)
