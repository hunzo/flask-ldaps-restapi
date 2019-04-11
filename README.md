# "# flask-ldaps-restapi" 

### '/api/ad/auth', methods=['POST']
* 'adserver'
* 'domain'
* 'username'
* 'password'

### '/api/adstandard/searchinfo', methods=['POST']
* 'adserver'
* 'searchbase'
* 'binduser'
* 'bindpassword'
* 'searchuser'

### '/api/adnida/searchinfo', methods=['POST']
* 'adserver'
* 'searchbase'
* 'binduser'
* 'bindpassword'
* 'searchuser'

### '/api/ad/modifypassword', methods=['POST']
* 'adserver'
* 'searchbase'
* 'binduser'
* 'bindpassword'
* 'usermodify'
* 'newpassword'

### '/api/ad/modifyattributes', methods=['POST']
* 'adserver'
* 'searchbase'
* 'binduser'
* 'bindpassword'
* 'usermodify'
* 'attributename'
* 'attributevalue'

### '/api/ad/getdn', methods=['POST']
* 'adserver'
* 'searchbase'
* 'binduser'
* 'bindpassword'
* 'objclass'
* 'searchobj'

### '/api/ad/addusertogroup', methods=['POST']
* 'adserver'
* 'searchbase'
* 'binduser'
* 'bindpassword'
* 'username'
* 'groupname'

### '/api/ad/createuser', methods=['POST']
* 'adserver'
* 'searchbase'
* 'domain'
* 'binduser'
* 'bindpassword'
* 'username'
* 'password'
* 'userdescription'

### '/api/ad/creategroup', methods=['POST']
* 'adserver'
* 'searchbase'
* 'domain'
* 'binduser'
* 'bindpassword'
* 'groupname'
* 'groupdescription'

### '/api/ad/search_dn', methods=['POST']
* 'adserver'
* 'searchbase'
* 'binduser'
* 'bindpassword'
* 'objclass'
* 'searchobj'
