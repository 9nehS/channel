from xml.dom.minidom import Document
from uuid import uuid1, uuid4

ACCOUNTS_NUM = 50
DOMAIN_NAME = '10.117.60.173'
START_ACCOUNT_ID = 1001337
# To be added before execution
PASSWORD = ''
#REMOTE_HOST = '210.103.120.26'
REMOTE_HOST = 'im.jumin.com'
REMOTE_PORT = '5222'


def encode_password(password, key):
    result = ''
    if len(key) == 0:
        return password

    #unicode_key = unicode(key)
    #print unicode_key
    i = 0
    for char in password:
        #str_hex = '%04x' % (int(unicode(char), 16) ^ int(unicode_key[i], 16))
        str_hex = '%04x' % (ord(char) ^ ord(key[i]))
        result += str_hex
        i += 1
        if i >= len(key):
            i = 0
    return result

def create_accounts_to_xml(filename):
    uuid_list = []
    account_tag_list = []
    jid_list = []
    resource_list = []
    accounts_name_list = []
    doc = Document()
    accounts_root = doc.createElement("accounts")
    accounts_root.setAttribute("version", "0.16.571.630 (28-01-2017)")
    accounts_root.setAttribute("xmlns", "http://psi-im.org/options")
    accounts_list = doc.createElement("accounts")
    accounts_root.appendChild(accounts_list)
    doc.appendChild(accounts_root)

    # Create order list with items for all the accounts
    order = doc.createElement("order")
    order.setAttribute("type", "QStringList")
    for i in range(0, ACCOUNTS_NUM):
        uuid_list.append(uuid1())
        item = doc.createElement("item")
        item.appendChild(doc.createTextNode("{" + str(uuid_list[i]) + "}"))
        order.appendChild(item)
    accounts_root.appendChild(order)

    # Initialize account_tag_list, resource_list, and jid_list
    account_id = START_ACCOUNT_ID
    for i in range(0, ACCOUNTS_NUM):
        account_tag_list.append('a' + str(i))
        resource_list.append('Psi_' + account_tag_list[i])
        jid_list.append(str(account_id) + '@' + DOMAIN_NAME)
        accounts_name_list.append('channel_test_' + account_tag_list[i])
        account_id += 1
    print account_tag_list
    print resource_list
    print jid_list
    print accounts_name_list

    # Create the accounts tree
    for i in range(0, ACCOUNTS_NUM):
        # account = doc.createElement("a0")
        account = doc.createElement(account_tag_list[i])
        accounts_list.appendChild(account)

        tls = doc.createElement("tls")
        account.appendChild(tls)
        scram = doc.createElement("scram")
        account.appendChild(scram)
        custom_auth = doc.createElement("custom-auth")
        account.appendChild(custom_auth)
        proxy_id = doc.createElement("proxy-id")
        proxy_id.setAttribute("type", "QString")
        proxy_id.appendChild(doc.createTextNode(""))
        account.appendChild(proxy_id)
        keep_alive = doc.createElement("keep-alive")
        keep_alive.setAttribute("type", "bool")
        keep_alive.appendChild(doc.createTextNode("true"))
        account.appendChild(keep_alive)
        require_mutual_auth = doc.createElement("require-mutual-auth")
        require_mutual_auth.setAttribute("type", "bool")
        require_mutual_auth.appendChild(doc.createTextNode("false"))
        account.appendChild(require_mutual_auth)
        last_with_priority = doc.createElement("last-with-priority")
        last_with_priority.setAttribute("type", "bool")
        last_with_priority.appendChild(doc.createTextNode("false"))
        account.appendChild(last_with_priority)
        port = doc.createElement("port")
        port.setAttribute("type", "int")
        # port.appendChild(doc.createTextNode("5222"))
        port.appendChild(doc.createTextNode(REMOTE_PORT))
        account.appendChild(port)
        ignore_ssl_warnings = doc.createElement("ignore-SSL-warnings")
        ignore_ssl_warnings.setAttribute("type", "bool")
        ignore_ssl_warnings.appendChild(doc.createTextNode("false"))
        account.appendChild(ignore_ssl_warnings)
        connect_after_sleep = doc.createElement("connect-after-sleep")
        connect_after_sleep.setAttribute("type", "bool")
        connect_after_sleep.appendChild(doc.createTextNode("false"))
        account.appendChild(connect_after_sleep)
        stun_username = doc.createElement("stun-username")
        stun_username.setAttribute("type", "QString")
        stun_username.appendChild(doc.createTextNode(""))
        account.appendChild(stun_username)
        compress = doc.createElement("compress")
        compress.setAttribute("type", "bool")
        compress.appendChild(doc.createTextNode("false"))
        account.appendChild(compress)
        muc_bookmarks = doc.createElement("muc-bookmarks")
        muc_bookmarks.setAttribute("type", "QStringList")
        account.appendChild(muc_bookmarks)
        stun_hosts = doc.createElement("stun-hosts")
        stun_hosts.setAttribute("type", "QStringList")
        account.appendChild(stun_hosts)
        enable_sm = doc.createElement("enable-sm")
        enable_sm.setAttribute("type", "bool")
        enable_sm.appendChild(doc.createTextNode("true"))
        account.appendChild(enable_sm)
        host = doc.createElement("host")
        host.setAttribute("type", "QString")
        # host.appendChild(doc.createTextNode("210.103.120.26"))
        host.appendChild(doc.createTextNode(REMOTE_HOST))
        account.appendChild(host)
        priority_depends_on_status = doc.createElement("priority-depends-on-status")
        priority_depends_on_status.setAttribute("type", "bool")
        priority_depends_on_status.appendChild(doc.createTextNode("true"))
        account.appendChild(priority_depends_on_status)
        pgp_secret_key_id = doc.createElement("pgp-secret-key-id")
        pgp_secret_key_id.setAttribute("type", "QString")
        pgp_secret_key_id.appendChild(doc.createTextNode(""))
        account.appendChild(pgp_secret_key_id)
        use_host = doc.createElement("use-host")
        use_host.setAttribute("type", "bool")
        use_host.appendChild(doc.createTextNode("true"))
        account.appendChild(use_host)
        auto = doc.createElement("auto")
        auto.setAttribute("type", "bool")
        auto.appendChild(doc.createTextNode("false"))
        account.appendChild(auto)
        ssl = doc.createElement("ssl")
        ssl.setAttribute("type", "QString")
        ssl.appendChild(doc.createTextNode("auto"))
        account.appendChild(ssl)
        automatic_resource = doc.createElement("automatic-resource")
        automatic_resource.setAttribute("type", "bool")
        automatic_resource.appendChild(doc.createTextNode("false"))
        account.appendChild(automatic_resource)
        last_status_message = doc.createElement("last-status-message")
        last_status_message.setAttribute("type", "QString")
        last_status_message.appendChild(doc.createTextNode(""))
        account.appendChild(last_status_message)
        password = doc.createElement("password")
        password.setAttribute("type", "QString")
        # password.appendChild(doc.createTextNode("00000002000300050007000e000f0078"))
        password.appendChild(doc.createTextNode(encode_password(PASSWORD, jid_list[i])))
        account.appendChild(password)
        security_level = doc.createElement("security-level")
        security_level.setAttribute("type", "int")
        security_level.appendChild(doc.createTextNode("0"))
        account.appendChild(security_level)
        id = doc.createElement("id")
        id.setAttribute("type", "QString")
        # id.appendChild(doc.createTextNode("{0786530c-bea0-460d-8f49-ac98777224df}"))
        id.appendChild(doc.createTextNode("{" + str(uuid_list[i]) + "}"))
        account.appendChild(id)
        ignore_global_actions = doc.createElement("ignore-global-actions")
        ignore_global_actions.setAttribute("type", "bool")
        ignore_global_actions.appendChild(doc.createTextNode("false"))
        account.appendChild(ignore_global_actions)
        jid = doc.createElement("jid")
        jid.setAttribute("type", "QString")
        # jid.appendChild(doc.createTextNode("1288100@10.117.60.173"))
        jid.appendChild(doc.createTextNode(jid_list[i]))
        account.appendChild(jid)
        reconn = doc.createElement("reconn")
        reconn.setAttribute("type", "bool")
        reconn.appendChild(doc.createTextNode("true"))
        account.appendChild(reconn)
        last_status = doc.createElement("last-status")
        last_status.setAttribute("type", "QString")
        last_status.appendChild(doc.createTextNode("online"))
        account.appendChild(last_status)
        enabled = doc.createElement("enabled")
        enabled.setAttribute("type", "bool")
        enabled.appendChild(doc.createTextNode("true"))
        account.appendChild(enabled)
        log = doc.createElement("log")
        log.setAttribute("type", "bool")
        log.appendChild(doc.createTextNode("true"))
        account.appendChild(log)
        legacy_ssl_probe = doc.createElement("legacy-ssl-probe")
        legacy_ssl_probe.setAttribute("type", "bool")
        legacy_ssl_probe.appendChild(doc.createTextNode("false"))
        account.appendChild(legacy_ssl_probe)
        stun_host = doc.createElement("stun-host")
        stun_host.setAttribute("type", "QString")
        stun_host.appendChild(doc.createTextNode("stun.jabber.ru:5249"))
        account.appendChild(stun_host)
        bytestreams_proxy = doc.createElement("bytestreams-proxy")
        bytestreams_proxy.setAttribute("type", "QString")
        bytestreams_proxy.appendChild(doc.createTextNode(""))
        account.appendChild(bytestreams_proxy)
        pgp_pass_phrase = doc.createElement("pgp-pass-phrase")
        pgp_pass_phrase.setAttribute("type", "QString")
        pgp_pass_phrase.appendChild(doc.createTextNode(""))
        account.appendChild(pgp_pass_phrase)
        priority = doc.createElement("priority")
        priority.setAttribute("type", "int")
        priority.appendChild(doc.createTextNode("55"))
        account.appendChild(priority)
        ibb_only = doc.createElement("ibb-only")
        ibb_only.setAttribute("type", "bool")
        ibb_only.appendChild(doc.createTextNode("false"))
        account.appendChild(ibb_only)
        resource = doc.createElement("resource")
        resource.setAttribute("type", "QString")
        # resource.appendChild(doc.createTextNode("Psi+_szhao_0001"))
        resource.appendChild(doc.createTextNode(resource_list[i]))
        account.appendChild(resource)
        allow_plain = doc.createElement("allow-plain")
        allow_plain.setAttribute("type", "QString")
        allow_plain.appendChild(doc.createTextNode("over encryped"))
        account.appendChild(allow_plain)
        always_visible_contacts = doc.createElement("always-visible-contacts")
        always_visible_contacts.setAttribute("type", "QStringList")
        account.appendChild(always_visible_contacts)
        name = doc.createElement("name")
        name.setAttribute("type", "QString")
        # name.appendChild(doc.createTextNode("10.117.60.173"))
        name.appendChild(doc.createTextNode(accounts_name_list[i]))
        account.appendChild(name)
        stun_password = doc.createElement("stun-password")
        stun_password.setAttribute("type", "QString")
        stun_password.appendChild(doc.createTextNode(""))
        account.appendChild(stun_password)
        auto_same_status = doc.createElement("auto-same-status")
        auto_same_status.setAttribute("type", "bool")
        auto_same_status.appendChild(doc.createTextNode("true"))
        account.appendChild(auto_same_status)

        # <tls>
        override_certificate = doc.createElement("override-certificate")
        override_certificate.setAttribute("type", "QByteArray")
        override_certificate.appendChild(doc.createTextNode(""))
        tls.appendChild(override_certificate)
        override_domain = doc.createElement("override-domain")
        override_domain.setAttribute("type", "QString")
        override_domain.appendChild(doc.createTextNode(""))
        tls.appendChild(override_domain)

        # <scram>
        salted_password = doc.createElement("salted-password")
        salted_password.setAttribute("type", "QString")
        salted_password.appendChild(doc.createTextNode(""))
        scram.appendChild(salted_password)
        store_salted_password = doc.createElement("store-salted-password")
        store_salted_password.setAttribute("type", "bool")
        store_salted_password.appendChild(doc.createTextNode("false"))
        scram.appendChild(store_salted_password)

        # <custom-auth>
        use = doc.createElement("use")
        use.setAttribute("type", "bool")
        use.appendChild(doc.createTextNode("false"))
        custom_auth.appendChild(use)
        authid = doc.createElement("authid")
        authid.setAttribute("type", "QString")
        authid.appendChild(doc.createTextNode(""))
        custom_auth.appendChild(authid)
        realm = doc.createElement("realm")
        realm.setAttribute("type", "QString")
        realm.appendChild(doc.createTextNode(""))
        custom_auth.appendChild(realm)

        # <stun_hosts>
        item_list = ['stun.jabber.ru:5249', 'stun.habahaba.im', 'stun.ekiga.net',
                     'provserver.televolution.net', 'stun1.voiceeclipse.net', 'stun.callwithus.com',
                     'stun.counterpath.net', 'stun.endigovoip.com', 'stun.ideasip.com',
                     'stun.internetcalls.com', 'stun.noc.ams-ix.net', 'stun.phonepower.com',
                     'stun.phoneserve.com', 'stun.rnktel.com', 'stun.softjoys.com', 'stun.sipgate.net',
                     'stun.sipgate.net:10000', 'stun.stunprotocol.org', 'stun.voipbuster.com',
                     'stun.voxgratia.org']
        for item_text in item_list:
            item = doc.createElement("item")
            item.appendChild(doc.createTextNode(item_text))
            stun_hosts.appendChild(item)

    with open(filename, 'w') as f:
        f.write(doc.toprettyxml(indent='\t', encoding='utf-8'))
    return

if __name__ == "__main__":
    create_accounts_to_xml("accounts.xml")
    # password = '888888'
    # key = '1001338@10.117.60.173'
    # new_password = encode_password(password, key)
    # print new_password