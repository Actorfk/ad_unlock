import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
from ldap3 import Server, Connection, NTLM, MODIFY_REPLACE, SUBTREE


class ADUnlockerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AD 域账户解锁工具")
        self.root.geometry("600x500")

        # 设置默认配置值 (来自您的原始代码)
        self.default_server = ''
        self.default_user = ''
        self.default_pwd = ''
        self.default_base = ''

        self.create_widgets()

    def create_widgets(self):
        # ================= 配置区域 (LabelFrame) =================
        config_frame = tk.LabelFrame(self.root, text="服务器配置", padx=10, pady=10)
        config_frame.pack(fill="x", padx=10, pady=5)

        # Grid 布局配置
        # Row 0: Server
        tk.Label(config_frame, text="域控 IP/主机名:").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        self.entry_server = tk.Entry(config_frame, width=40)
        self.entry_server.insert(0, self.default_server)
        self.entry_server.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        # Row 1: Admin User
        tk.Label(config_frame, text="管理员账号:").grid(row=1, column=0, sticky="e", padx=5, pady=2)
        self.entry_admin = tk.Entry(config_frame, width=40)
        self.entry_admin.insert(0, self.default_user)
        self.entry_admin.grid(row=1, column=1, sticky="w", padx=5, pady=2)

        # Row 2: Password
        tk.Label(config_frame, text="管理员密码:").grid(row=2, column=0, sticky="e", padx=5, pady=2)
        self.entry_pwd = tk.Entry(config_frame, width=40, show="*")  # 密码显示为星号
        self.entry_pwd.insert(0, self.default_pwd)
        self.entry_pwd.grid(row=2, column=1, sticky="w", padx=5, pady=2)

        # Row 3: Search Base
        tk.Label(config_frame, text="搜索路径 (Base DN):").grid(row=3, column=0, sticky="e", padx=5, pady=2)
        self.entry_base = tk.Entry(config_frame, width=40)
        self.entry_base.insert(0, self.default_base)
        self.entry_base.grid(row=3, column=1, sticky="w", padx=5, pady=2)

        # ================= 操作区域 =================
        action_frame = tk.Frame(self.root, padx=10, pady=10)
        action_frame.pack(fill="x", padx=10)

        tk.Label(action_frame, text="目标用户名 (sAMAccountName):", font=("Arial", 10, "bold")).pack(side="left")
        self.entry_target_user = tk.Entry(action_frame, width=20, font=("Arial", 10))
        self.entry_target_user.pack(side="left", padx=10)
        self.entry_target_user.bind('<Return>', lambda event: self.start_unlock_thread())  # 回车键触发

        self.btn_unlock = tk.Button(action_frame, text="执行解锁", command=self.start_unlock_thread, bg="#4CAF50",
                                    fg="white", font=("Arial", 10, "bold"))
        self.btn_unlock.pack(side="left", padx=10)

        # ================= 日志区域 =================
        log_frame = tk.LabelFrame(self.root, text="运行日志", padx=10, pady=10)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True)


    def log(self, message):
        """向日志窗口添加信息"""
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)  # 自动滚动到底部
        self.log_text.config(state='disabled')

    def clear_log(self):
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')

    def toggle_inputs(self, enable):
        """锁定或解锁输入框，防止操作过程中修改配置"""
        state = 'normal' if enable else 'disabled'
        self.entry_server.config(state=state)
        self.entry_admin.config(state=state)
        self.entry_pwd.config(state=state)
        self.entry_base.config(state=state)
        self.btn_unlock.config(state=state)

    def start_unlock_thread(self):
        """启动子线程执行网络请求，防止界面卡死"""
        target_user = self.entry_target_user.get().strip()
        if not target_user:
            messagebox.showwarning("提示", "请输入要解锁的用户名！")
            return

        # 获取当前配置
        config = {
            'server': self.entry_server.get().strip(),
            'user': self.entry_admin.get().strip(),
            'pwd': self.entry_pwd.get().strip(),
            'base': self.entry_base.get().strip(),
            'target': target_user
        }

        self.toggle_inputs(False)  # 禁用按钮
        thread = threading.Thread(target=self.unlock_logic, args=(config,))
        thread.daemon = True
        thread.start()

    def unlock_logic(self, config):
        """实际的 LDAP 业务逻辑"""
        ldap_server = config['server']
        admin_user = config['user']
        admin_pwd = config['pwd']
        search_base = config['base']
        username = config['target']

        self.log("-" * 40)
        self.log(f"[*] 正在连接域控: {ldap_server} ...")

        conn = None
        try:
            # 建立连接
            server = Server(ldap_server, get_info=None)
            conn = Connection(server,
                              user=admin_user,
                              password=admin_pwd,
                              authentication=NTLM,
                              auto_bind=True)

            self.log(f"[*] 连接成功。正在搜索用户: {username} ...")

            search_filter = f'(sAMAccountName={username})'
            conn.search(search_base=search_base,
                        search_filter=search_filter,
                        search_scope=SUBTREE,
                        attributes=['distinguishedName', 'userAccountControl'])

            # 检查是否找到用户
            if not conn.entries:
                self.log(f"[!] 错误: 未找到用户 '{username}'。请检查拼写或 Base DN。")
            else:
                # 获取 DN
                user_dn = conn.entries[0].distinguishedName.value
                self.log(f"[*] 找到用户 DN: {user_dn}")

                # 执行解锁操作
                # 注意：根据您原本的代码，这里修改的是 userAccountControl 为 66048
                # 66048 = DONT_EXPIRE_PASSWORD (65536) + NORMAL_ACCOUNT (512)
                # 如果您只是想单纯解锁而不改变密码过期策略，通常建议修改 lockoutTime 为 0
                self.log(f"[*] 正在执行解锁操作...")

                # 方法 A：按照您提供的代码 (强制设置属性)
                conn.modify(user_dn, {'userAccountControl': [MODIFY_REPLACE, [66048]]})

                # 方法 B (备用建议)：仅清除锁定时间，影响更小
                # conn.modify(user_dn, {'lockoutTime': [MODIFY_REPLACE, [0]]})

                if conn.result['description'] == 'success':
                    self.log(f"[*] 解锁成功！用户 [{username}] 已恢复。")
                    messagebox.showinfo("成功", f"用户 {username} 解锁成功！")
                else:
                    self.log(f"[!] 操作结果: {conn.result['description']}")

        except Exception as e:
            self.log(f"[!] 系统错误: {str(e)}")
            messagebox.showerror("错误", f"发生错误: {str(e)}")

        finally:
            if conn and conn.bound:
                conn.unbind()

            # 恢复界面按钮状态 (需在主线程执行，Tkinter非线程安全，但在简单场景下直接调用通常可行，
            # 严谨做法是使用 after 或 queue，这里为了代码简洁直接调用)
            self.root.after(0, lambda: self.toggle_inputs(True))


if __name__ == '__main__':
    root = tk.Tk()
    app = ADUnlockerApp(root)
    root.mainloop()