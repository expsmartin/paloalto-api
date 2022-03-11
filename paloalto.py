import requests, json, xmltodict

requests.packages.urllib3.disable_warnings()

class PaloAlto(object):
    def __init__(self,username,password,hostname):
        self.username = username
        self.password = password
        self.hostname = hostname

        self.api = {"xmlurl": "", "resturl": "", "key": ""}
    
    def get_api_key(self):
        self.api["xmlurl"] = f'https://{self.hostname}/api/'
        self.api["resturl"] = f'https://{self.hostname}/restapi/v10.0/'
        api_key_query = {'type': 'keygen', 'user': self.username, 'password': self.password}
        try:
            response = requests.get(self.api["xmlurl"], verify=False, params=api_key_query)
            response_json = json.loads(json.dumps(xmltodict.parse(response.text)))
            self.api["key"] = response_json['response']['result']['key']
            results = {'result': True, 'message':'Succesffuly generated API key.', 'url': response.url, 'text': response.text, 'json': response_json}
            return results
        except:
            results = {'result': False, 'message': 'Failed to generate API key. Check credentials and/or hostname.'}
            return results
    
    def commit(self):
        api_params = {'key': self.api["key"],
                  'type': 'commit',
                  'cmd': '<commit><description>Adding Certificate for Global Protect</description></commit>'
        }
        response = requests.get(self.api["xmlurl"], verify=False, params=api_params)
        response_json = json.loads(json.dumps(xmltodict.parse(response.text)))

        if response_json['response']['@status'] == 'success':
            results = {'result': True, 'message':'Successfully committed configuration.', 'url': response.url, 'text': response.text, 'json': response_json}
            return results
        else:
            results = {'result': False, 'message':'API call successful, but failed to commit configuration.', 'url': response.url, 'text': response.text, 'json': response_json}
            return results

    def revert(self):
        api_params = {'key': self.api["key"],
                  'type': 'op',
                  'cmd': '<revert><config></config></revert>'
        }
        try:
            response = requests.get(self.api["xmlurl"], verify=False, params=api_params)
            response_json = json.loads(json.dumps(xmltodict.parse(response.text)))    

            if response_json['response']['@status'] == 'success':
                results = {'result': True, 'message':'Successfully reverted configuration.', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
            else:
                results = {'result': False, 'message':'API call successful, but failed to revert configuration.', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
        except:
            results = {'result': False, 'message':'Failed to Execute API call', 'url': response.url, 'text': response.text, 'json': None}
            return results

    def xml_api(self, type="config", action="set", xpath="", content=""):
        api_params = {'key': self.api["key"],
                  'type': type,
                  'action': action,
                  'xpath': xpath,
                  'element': content
        }
        try:
            response = requests.get(self.api["xmlurl"], verify=False, params=api_params)
            response_json = json.loads(json.dumps(xmltodict.parse(response.text)))
    
            if response_json['response']['@status'] == 'success':
                results = {'result': True, 'message':'Successfully executed XML API Call, returned Success.', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
            else:
                results = {'result': False, 'message':'Successfully executed XML API Call, returned Error', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
        except:
            results = {'result': False, 'message':'Failed to Execute API call', 'url': response.url, 'text': response.text, 'json': None}
            return results

    def rest_api(self, path, data, method="post"):
        headers = {"X-PAN-KEY": self.api["key"]}
        try:
            if method == "post":
                response = requests.post(f'{self.api["resturl"]}{path}', verify=False, headers=headers, data=data)
            elif method == "put":
                response = requests.put(f'{self.api["resturl"]}{path}', verify=False, headers=headers, data=data)
        
            response_json = json.loads(response.text)

            if response_json['@status'] == 'success':
                results = {'result': True, 'message':'Successfully executed REST API Call, returned Success.', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
            else:
                results = {'result': False, 'message':'Successfully executed REST API Call, returned Error', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
        except:
            results = {'result': False, 'message':'Failed to Execute API call', 'url': f'{self.api["resturl"]}{path}'}
            return results
    
    def import_saml_metadata(self,file):
        metadata_load_query = {'key': self.api["key"], 'type': 'import', 'category': 'idp-metadata',
                                   'profile-name': f'OneLogin', 'validate-idp-certificate': 'no'}
        metadata = {'file': file}
        try:    
            response = requests.post(f'{self.api["xmlurl"]}', verify=False, files=metadata, params=metadata_load_query)
            response_json = json.loads(json.dumps(xmltodict.parse(response.text)))
    
            if response_json['response']['@status'] == 'success':
                results = {'result': True, 'message':'Successfully executed XML API Call, returned Success.', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
            else:
                results = {'result': False, 'message':'Successfully executed XML API Call, returned Error', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
        except:
            results = {'result': False, 'message':'Failed to Execute API call', 'url': response.url, 'text': response.text, 'json': None}
            return results

    def import_certificate(self,file,name,passphrase):        
        try:
            file = {'file': file}
            certificate_load_query = {'key': self.api["key"], 'type': 'import', 'category': 'certificate',
                                        'certificate-name': name, 'format': 'pkcs12', 'passphrase': passphrase}
            response = requests.post(f'{self.api["xmlurl"]}', verify=False, files=file, params=certificate_load_query)
            response_json = json.loads(json.dumps(xmltodict.parse(response.text)))

            if response_json['response']['@status'] == 'success':
                results = {'result': True, 'message':'Successfully imported certificate via XML.', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
            else:
                results = {'result': False, 'message':'Successfully executed XML API Call but failed to import certificate', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
        except:
            results = {'result': False, 'message':'Failed to Execute API call', 'url': response.url, 'text': response.text, 'json': None}
            return results

    def import_gp_login_page(self,file):
        api_params = {'key': self.api["key"], 'type': 'import',
                                'category': 'global-protect-portal-custom-login-page'}
        login_page = {'file': file}
        try:
            response = requests.post(f'{self.api["xmlurl"]}', verify=False,files=login_page, params=api_params)
            response_json = json.loads(json.dumps(xmltodict.parse(response.text)))

            if response_json['response']['@status'] == 'success':
                results = {'result': True, 'message':'Successfully executed XML API Call, returned Success.', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
            else:
                results = {'result': False, 'message':'Successfully executed XML API Call, returned Error', 'url': response.url, 'text': response.text, 'json': response_json}
                return results
        except:
            results = {'result': False, 'message':'Failed to Execute API call', 'url': response.url, 'text': response.text, 'json': None}
            return results
