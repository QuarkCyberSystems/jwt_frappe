import frappe
import base64


def encript_payload(self, event):
    a = {
        "oaid": 7602,
        "oa_name": "dsf"
        }
    data_str = str(a)

    encoded_data = base64.b64encode(data_str.encode()).decode()
    print(encoded_data)