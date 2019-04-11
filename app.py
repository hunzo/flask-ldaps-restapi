from flask import Flask, render_template, request, jsonify
from AD_LDAPS import *

app = Flask(__name__)


@app.route('/')
def main():
    return 'AD API'


@app.route('/api/ad/auth', methods=['POST'])
def ad_auth():
    if request.method == 'POST':
        result = request.get_json('adserver')
        result = request.get_json('domain')
        result = request.get_json('username')
        result = request.get_json('password')

        authserver = result['adserver']
        domainname = result['domain']
        user = result['username']
        password = result['password']

        c = ActiveDirectoryLDAPs()
        try:
            r = c.ad_auth_ldap(authserver, domainname, user, password)
        except Exception as e:
            return jsonify({'error-message': str(e)})
        return jsonify(r)
    return 'AD Auth'


@app.route('/api/adstandard/searchinfo', methods=['POST'])
def get_adstarndard_attributes_info():

    # attributes_list = ['cn', 'description', 'Distinguishedname',
    #                    'samaccountname', 'userPrincipalName']

    attributes_list = ['CN', 'Distinguishedname', 'displayname', 'mail', 'department', 'samaccountname',
                       'objectCategory', 'company', 'givenName', 'logonCount',
                       'lastlogontimestamp', 'info', 'pwdlastset', 'accountexpires',
                       'userPrincipalName', 'memberof', 'title', 'objectclass', 'userAccountControl']

    if request.method == 'POST':
        results = request.get_json('adserver')
        results = request.get_json('searchbase')
        results = request.get_json('binduser')
        results = request.get_json('bindpassword')
        results = request.get_json('searchuser')

        adserver = results['adserver']
        searchbase = results['searchbase']
        binduser = results['binduser']
        bindpassword = results['bindpassword']
        searchuser = results['searchuser']

        try:
            c = ActiveDirectoryLDAPs()
            rs = c.search_adusers_information(
                adserver, searchbase, binduser, bindpassword, searchuser, attributes_list)
            # print(rs)
        except Exception as e:
            return jsonify({'error-message': str(e)})
        return jsonify(rs)


@app.route('/api/adnida/searchinfo', methods=['POST'])
def get_adnida_attributes_info():

    attributes_list = ['CN', 'Distinguishedname', 'displayname', 'mail', 'department', 'optionalemail', 'samaccountname',
                       'lastlogontimestamp', 'info', 'pwdlastset', 'accountexpires', 'objectCategory', 'userPrincipalName',
                       'extensionattribute1', 'extensionattribute2', 'extensionattribute3', 'extensionattribute4',
                       'extensionattribute5', 'extensionattribute6', 'extensionattribute7', 'extensionattribute8',
                       'extensionattribute9', 'extensionattribute10', 'extensionattribute11', 'extensionattribute12',
                       'extensionattribute13', 'extensionattribute14', 'extensionattribute15', 'memberof', 'title',
                       'objectclass', 'userAccountControl', 'logonCount', 'givenName']

    if request.method == 'POST':
        results = request.get_json('adserver')
        results = request.get_json('searchbase')
        results = request.get_json('binduser')
        results = request.get_json('bindpassword')
        results = request.get_json('searchuser')

        adserver = results['adserver']
        searchbase = results['searchbase']
        binduser = results['binduser']
        bindpassword = results['bindpassword']
        searchuser = results['searchuser']

        try:
            c = ActiveDirectoryLDAPs()
            rs = c.search_adusers_information(
                adserver, searchbase, binduser, bindpassword, searchuser, attributes_list)
            # print(rs)
        except Exception as e:
            return jsonify({'error-message': str(e)})
        return jsonify(rs)


@app.route('/api/ad/modifypassword', methods=['POST'])
def modify_ad_password():
    if request.method == 'POST':
        results = request.get_json('adserver')
        results = request.get_json('searchbase')
        results = request.get_json('binduser')
        results = request.get_json('bindpassword')
        results = request.get_json('usermodify')
        results = request.get_json('newpassword')

        adserver = results['adserver']
        searchbase = results['searchbase']
        binduser = results['binduser']
        bindpassword = results['bindpassword']
        usermodify = results['usermodify']
        newpassword = results['newpassword']

        conn_get_user_dn = ActiveDirectoryLDAPs()
        try:
            user_dn = conn_get_user_dn.get_ad_users_group_dn(
                adserver, searchbase, binduser, bindpassword, 'person', usermodify)

        except Exception as e:
            return jsonify({'error-message': str(e)})
        # print(user_dn)

        conn = ActiveDirectoryLDAPs()
        try:
            mod_result = conn.modify_ad_password(
                adserver, binduser, bindpassword, user_dn, newpassword)
        except Exception as e:
            return jsonify({'error-message': str(e)})

        return jsonify(mod_result)


@app.route('/api/ad/modifyattributes', methods=['POST'])
def modify_ad_attributes():
    if request.method == 'POST':
        results = request.get_json('adserver')
        results = request.get_json('searchbase')
        results = request.get_json('binduser')
        results = request.get_json('bindpassword')
        results = request.get_json('usermodify')
        results = request.get_json('attributename')
        results = request.get_json('attributevalue')

        adserver = results['adserver']
        searchbase = results['searchbase']
        binduser = results['binduser']
        bindpassword = results['bindpassword']
        usermodify = results['usermodify']
        attributename = results['attributename']
        attributevalue = results['attributevalue']

        conn_get_user_dn = ActiveDirectoryLDAPs()
        try:
            user_dn = conn_get_user_dn.get_ad_users_group_dn(
                adserver, searchbase, binduser, bindpassword, 'person', usermodify)
        except Exception as e:
            return jsonify({'error-message': str(e)})
        # print(user_dn)

        conn = ActiveDirectoryLDAPs()
        try:
            mod_result = conn.modify_ad_attributes(
                adserver, binduser, bindpassword, user_dn, attributename, attributevalue)
        except Exception as e:
            return jsonify({'error-message': str(e)})

        return jsonify(mod_result)


@app.route('/api/ad/getdn', methods=['POST'])
def get_group():
    if request.method == 'POST':
        result = request.get_json('adserver')
        result = request.get_json('searchbase')
        result = request.get_json('binduser')
        result = request.get_json('bindpassword')
        result = request.get_json('objclass')
        result = request.get_json('searchobj')

        adserver = result['adserver']
        searchbase = result['searchbase']
        binduser = result['binduser']
        bindpassword = result['bindpassword']
        objclass = result['objclass']
        searchobj = result['searchobj']

        conn = ActiveDirectoryLDAPs()

        try:
            rs = conn.get_ad_users_group_dn(
                adserver, searchbase, binduser, bindpassword, objclass, searchobj)
        except Exception as e:
            return jsonify({'error-message': str(e)})
    return jsonify({"result": rs})


@app.route('/api/ad/addusertogroup', methods=['POST'])
def add_member_to_group():
    if request.method == 'POST':
        result = request.get_json('adserver')
        result = request.get_json('searchbase')
        result = request.get_json('binduser')
        result = request.get_json('bindpassword')
        result = request.get_json('username')
        result = request.get_json('groupname')

        adserver = result['adserver']
        searchbase = result['searchbase']
        binduser = result['binduser']
        bindpassword = result['bindpassword']
        username = result['username']
        groupname = result['groupname']

        conn = ActiveDirectoryLDAPs()

        try:
            rs = conn.add_member_to_group(
                adserver, searchbase, binduser, bindpassword, username, groupname)
        except Exception as e:
            return jsonify({'error-message': str(e)})
    return jsonify({"result": rs})


@app.route('/api/ad/createuser', methods=['POST'])
def create_user():
    if request.method == 'POST':
        result = request.get_json('adserver')
        result = request.get_json('searchbase')
        result = request.get_json('domain')
        result = request.get_json('binduser')
        result = request.get_json('bindpassword')
        result = request.get_json('username')
        result = request.get_json('password')
        result = request.get_json('userdescription')

        adserver = result['adserver']
        searchbase = result['searchbase']
        domain = result['domain']
        binduser = result['binduser']
        bindpassword = result['bindpassword']
        username = result['username']
        password = result['password']
        userdescription = result['userdescription']

        conn = ActiveDirectoryLDAPs()

        try:
            rs = conn.create_user(adserver, searchbase, domain, binduser,
                                  bindpassword, username, password, userdescription)
        except Exception as e:
            return jsonify({'error-message': str(e)})
    return jsonify({"result": rs})


@app.route('/api/ad/creategroup', methods=['POST'])
def create_group():
    if request.method == 'POST':
        result = request.get_json('adserver')
        result = request.get_json('searchbase')
        result = request.get_json('domain')
        result = request.get_json('binduser')
        result = request.get_json('bindpassword')
        result = request.get_json('groupname')
        result = request.get_json('groupdescription')

        adserver = result['adserver']
        searchbase = result['searchbase']
        domain = result['domain']
        binduser = result['binduser']
        bindpassword = result['bindpassword']
        groupname = result['groupname']
        groupdescription = result['groupdescription']

        conn = ActiveDirectoryLDAPs()

        try:
            rs = conn.create_group(
                adserver, searchbase, domain, binduser, bindpassword, groupname, groupdescription)
        except Exception as e:
            return jsonify({'error-message': str(e)})

    return jsonify({"result": rs})


@app.route('/api/ad/search_dn', methods=['POST'])
def search_user_group_dn():
    if request.method == 'POST':
        result = request.get_json('adserver')
        result = request.get_json('searchbase')
        result = request.get_json('binduser')
        result = request.get_json('bindpassword')
        result = request.get_json('objclass')
        result = request.get_json('searchobj')

        adserver = result['adserver']
        searchbase = result['searchbase']
        binduser = result['binduser']
        bindpassword = result['bindpassword']
        objclass = result['objclass']
        searchobj = result['searchobj']

        conn = ActiveDirectoryLDAPs()
        try:
            rs = conn.search_ad_users_group_dn(
                adserver, searchbase, binduser, bindpassword, objclass, searchobj)
        except Exception as e:
            return jsonify({'error-message': str(e)})

        obj = []
        for i in rs:
            temp = {}
            temp['cn'] = i['cn']
            temp['DN'] = i['Distinguishedname']
            obj.append(temp)
    return jsonify({'result': obj})


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True, port=5000)
