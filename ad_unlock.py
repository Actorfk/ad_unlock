from ldap3 import Server, Connection, NTLM, MODIFY_REPLACE, SUBTREE

LDAP_SERVER = '192.168.3.168'
ADMIN_USER = 'py\\administrator'
ADMIN_PASSWORD = 'Actor@123'
SEARCH_BASE = 'dc=py,dc=cc'



def unlock_by_username(username):
    print(f"[*] 正在尝试连接域控: {LDAP_SERVER} ...")

    try:
        server = Server(LDAP_SERVER, get_info=None)
        conn = Connection(server,
                          user=ADMIN_USER,
                          password=ADMIN_PASSWORD,
                          authentication=NTLM,
                          auto_bind=True)

        print(f"[*] 连接成功。正在搜索用户: {username} ...")

        search_filter = f'(sAMAccountName={username})'
        conn.search(search_base=SEARCH_BASE,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=['distinguishedName'])

        if not conn.entries:
            print(f"[!] 错误: 未找到用户 '{username}'。请检查拼写。")
            return False

        #获取 DN
        user_dn = conn.entries[0].distinguishedName.value
        print(f"[*] 找到用户 DN: {user_dn}")

        #执行解锁操作
        print(f"[*] 正在解锁...")
        conn.modify(user_dn,{'userAccountControl':[MODIFY_REPLACE,[66048]]})
        print(f"[*] 解锁成功")



    except Exception as e:
        print(f"[!] 系统错误: {str(e)}")
        return False

    finally:
        #关闭连接
        if 'conn' in locals() and conn.bound:
            conn.unbind()


if __name__ == '__main__':
    target_user = input("请输入要解锁的用户名 (sAMAccountName): ").strip()

    if target_user:
        unlock_by_username(target_user)
    else:
        print("用户名不能为空。")