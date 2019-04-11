from ldap3 import Server, Connection, ALL_ATTRIBUTES, ALL, SUBTREE, MODIFY_REPLACE, Tls
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUsersInGroups
import json
import ssl
import time


class ActiveDirectoryLDAPs:
    def test_ad_class(self):
        return 'Connect Active Directory With LDAPs'

    def ad_auth_ldap(self, AD_SERVER, DOMAIN, USER_NAME, USER_PASSWORD):
        s = Server(AD_SERVER, get_info=ALL)
        user_dn = USER_NAME + '@' + DOMAIN
        # print(user_dn)
        c = Connection(s, user=user_dn, password=USER_PASSWORD)
        if not c.bind():
            print('error in bind : {}', c.result)
        # print(c.entries)
        c.unbind()
        r = c.result
        return r

    def search_adusers_information(self, AD_SERVER, SEARCH_BASE, BIND_USENAME, BIND_PASSWORD, SEARCH_USERS, ATTRIBUTES_LIST):
        tls_config = Tls(validate=ssl.CERT_NONE)
        filters = '(&(objectclass=person)(cn=' + SEARCH_USERS + '))'
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tls_config, get_info=ALL)

        # print(AD_SERVER, SEARCH_BASE, BIND_USENAME,
        #       BIND_PASSWORD, SEARCH_USERS, ATTRIBUTES_LIST)

        try:
            conn = Connection(server, BIND_USENAME, BIND_PASSWORD)
            conn.start_tls()

            if not conn.bind():
                return 'Bind ERROR {}'.format(conn.result)

            conn.search(SEARCH_BASE, filters,
                        attributes=ATTRIBUTES_LIST, paged_size=5,
                        paged_cookie=5, search_scope=SUBTREE)
            rs_respone = conn.response

        except Exception as e:
            return 'ERROR from get_ad_info()--->{}'.format(e)

        conn.unbind()

        user_info_list = []
        for ex in rs_respone:
            user_data = {}
            for i in ATTRIBUTES_LIST:
                user_data[i] = ex['attributes'][i]
            user_info_list.append(user_data)

        return user_info_list

    def modify_ad_password(self, AD_SERVER, BIND_USENAME, BIND_PASSWORD, USER_DN, NEW_PASSWORD):

        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tls_config, get_info=ALL)

        # print(AD_SERVER, BIND_USENAME,
        #       BIND_PASSWORD, USER_DN, NEW_PASSWORD)

        try:
            conn = Connection(server, BIND_USENAME, BIND_PASSWORD)
            conn.start_tls()
            if not conn.bind():
                return 'Bind ERROR {}'.format(conn.result)

            conn.extend.microsoft.modify_password(USER_DN, NEW_PASSWORD)
            rs_mod = conn.result

        except Exception as e:
            return 'ERROR from modify_ad_password()--->{}'.format(e)

        conn.unbind()

        # return 'Operation Modify Password Result : {}'.format(rs_mod)
        return (rs_mod)

    def modify_ad_attributes(self, AD_SERVER, BIND_USENAME, BIND_PASSWORD, USER_DN, ATTRIBUTE_NAME, NEW_VALUE):

        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tls_config, get_info=ALL)

        # print(AD_SERVER, BIND_USENAME, BIND_PASSWORD,
        #       USER_DN, ATTRIBUTE_NAME, NEW_VALUE)

        try:
            conn = Connection(server, BIND_USENAME, BIND_PASSWORD)
            conn.start_tls()
            if not conn.bind():
                return 'Bind ERROR {}'.format(conn.result)
            conn.modify(USER_DN, {ATTRIBUTE_NAME: [
                        (MODIFY_REPLACE, [NEW_VALUE])]})
            rs_mod = conn.result

        except Exception as e:
            return 'ERROR from modify_ad_attributes()--->{}'.format(e)

        conn.unbind()
        return 'Operation Modify Attributes Result : {}'.format(rs_mod)

    def get_user_dn(self, AD_SERVER, SEARCH_BASE, BIND_USERNAME, BIND_PASSWORD, SEARCH_USERS):

        FILTERS = '(&(objectclass=person)(cn=' + SEARCH_USERS + '))'

        tlsconfig = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tlsconfig, get_info=ALL)

        # print(AD_SERVER, BIND_USENAME, BIND_PASSWORD, SEARCH_USERS)

        if str(SEARCH_USERS).find('*') != -1:
            return 'NO Allows ******* Input'
        else:
            try:
                conn = Connection(server, BIND_USERNAME, BIND_PASSWORD)
                conn.start_tls()
                if not conn.bind():
                    return 'Bind ERROR {}'.format(conn.result)
                conn.search(SEARCH_BASE, FILTERS)
                entry = conn.entries[0].entry_to_json()
            except Exception as e:
                return 'SEARCH_ERROR : {}'.format(e)

        conn.unbind()
        user_dn = json.loads(entry)
        return user_dn['dn']

    def get_ad_users_group_dn(self, AD_SERVER, SEARCH_BASE, BIND_USERNAME, BIND_PASSWORD, SERCH_TYPE, SEARCH_OBJ):

        FILTERS = '(&(objectclass=' + SERCH_TYPE + ')(cn=' + SEARCH_OBJ + '))'

        tlsconfig = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tlsconfig, get_info=ALL)

        # print(AD_SERVER, BIND_USENAME, BIND_PASSWORD, SEARCH_OBJ)

        if str(SEARCH_OBJ).find('*') != -1:
            return 'NO Allows ******* Input'
        else:
            try:
                conn = Connection(server, BIND_USERNAME, BIND_PASSWORD)
                conn.start_tls()
                if not conn.bind():
                    return 'Bind ERROR {}'.format(conn.result)
                conn.search(SEARCH_BASE, FILTERS)
                entry = conn.entries[0].entry_to_json()
            except Exception as e:
                return 'SEARCH_ERROR : {}'.format(e)

        conn.unbind()
        group_dn = json.loads(entry)
        return group_dn['dn']

    def search_ad_users_group_dn(self, AD_SERVER, SEARCH_BASE, BIND_USERNAME, BIND_PASSWORD, SERCH_TYPE, SEARCH_OBJ):

        FILTERS = '(&(objectclass=' + SERCH_TYPE + ')(cn=' + SEARCH_OBJ + '))'

        tlsconfig = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tlsconfig, get_info=ALL)

        # print(AD_SERVER, BIND_USENAME, BIND_PASSWORD, SEARCH_OBJ)

        try:
            conn = Connection(server, BIND_USERNAME, BIND_PASSWORD)
            conn.start_tls()
            if not conn.bind():
                return 'Bind ERROR {}'.format(conn.result)
            conn.search(SEARCH_BASE, FILTERS, search_scope=SUBTREE, attributes=[
                        'cn', 'Distinguishedname', 'userprincipalname'])
            entry = conn.response
        except Exception as e:
            return 'SEARCH_ERROR : {}'.format(e)

        conn.unbind()
        # print(entry)

        obj_dn = []
        for i in entry:
            obj_dn.append(i['attributes'])

        print(obj_dn)

        return obj_dn

    def add_member_to_group(self, AD_SERVER, SEARCH_BASE, BIND_USERNAME, BIND_PASSWORD, MEMBER_NAME, GROUP_NAME):
        tlsconfig = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tlsconfig, get_info=ALL)

        # print(AD_SERVER, BIND_USENAME, BIND_PASSWORD, SEARCH_OBJ)
        try:
            conn = Connection(server, BIND_USERNAME, BIND_PASSWORD)
            conn.start_tls()
            if not conn.bind():
                return 'Bind ERROR {}'.format(conn.result)
            group_dn = self.get_ad_users_group_dn(
                AD_SERVER, SEARCH_BASE, BIND_USERNAME, BIND_PASSWORD, 'group', GROUP_NAME)
            user_dn = self.get_ad_users_group_dn(
                AD_SERVER, SEARCH_BASE, BIND_USERNAME, BIND_PASSWORD, 'person', MEMBER_NAME)

            rs = addUsersInGroups(conn, user_dn, group_dn)
            print(rs, group_dn, user_dn)

        except Exception as e:
            return 'SEARCH_ERROR : {}'.format(e)

        conn.unbind()

        return 'ADD USER : ' + user_dn + ' --- to --- > GROUP : ' + group_dn + " Completed"

    def create_user(self, AD_SERVER, OU_BASE, DOMAIN, BIND_USERNAME, BIND_PASSWORD, NEW_USER, NEW_USER_PASWORD, DESCRIPTION):

        tlsconfig = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tlsconfig, get_info=ALL)

        print(AD_SERVER, OU_BASE, DOMAIN, BIND_USERNAME, BIND_PASSWORD, NEW_USER)

        try:
            conn = Connection(server, BIND_USERNAME, BIND_PASSWORD)
            conn.start_tls()
            if not conn.bind():
                return 'Bind ERROR {}'.format(conn.result)

            temp_user_dn = 'cn=' + NEW_USER + ',' + OU_BASE
            print(temp_user_dn)

            conn.add(temp_user_dn, 'user', {'givenName': NEW_USER, 'description': 'Create Time : ' + time.ctime(), 'company': DESCRIPTION,
                                            'samaccountname': NEW_USER, 'userPrincipalName': NEW_USER + '@' + DOMAIN})
            if conn.result['result'] != 0:
                conn.unbind
                return conn.result
            print(conn.result)

            conn.extend.microsoft.modify_password(
                temp_user_dn, NEW_USER_PASWORD)
            if conn.result['result'] != 0:
                conn.delete(temp_user_dn)
                conn.unbind
                return conn.result
            print(conn.result)

            conn.modify(temp_user_dn, {'userAccountControl': [
                        (MODIFY_REPLACE, ['512'])]})

        except Exception as e:
            return 'Create User Error : {}'.format(e)

        conn.unbind()
        return conn.result

    def create_group(self, AD_SERVER, OU_BASE, DOMAIN, BIND_USERNAME, BIND_PASSWORD, NEW_GROUP, DESCRIPTION):

        tlsconfig = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tlsconfig, get_info=ALL)

        print(AD_SERVER, OU_BASE, DOMAIN, BIND_USERNAME,
              BIND_PASSWORD, NEW_GROUP, DESCRIPTION)

        try:
            conn = Connection(server, BIND_USERNAME, BIND_PASSWORD)
            conn.start_tls()
            if not conn.bind():
                return 'Bind ERROR {}'.format(conn.result)

            temp_group_dn = 'cn=' + NEW_GROUP + ',' + OU_BASE
            print(temp_group_dn)

            conn.add(temp_group_dn, 'group', {'description': DESCRIPTION})

            if conn.result['result'] != 0:
                conn.unbind()
                return conn.result
            print(conn.result)

        except Exception as e:
            return 'Create Group Error : {}'.format(e)

        conn.unbind()
        return conn.result
