import tkinter as tk
from tkinter import ttk
import requests
import json
from os import path
from base64 import b64encode, b64decode
from http.cookiejar import MozillaCookieJar
import webbrowser
from time import time, strftime, localtime
from re import compile, IGNORECASE
from traceback import print_exc

IP_REG = compile(r"当前 IP：([^ ]+)", IGNORECASE)
ccmtv_app_api_url = "https://www.ccmtv.cn//ccmtvtp/Home/CcmtvAppApi/index"
android_gp_api_url = "https://yun.ccmtv.cn//admin.php/AndroidGpApi/index"
signin_type_list_url = "https://yunsxs.ccmtv.cn/index.php/wx/SignIn/typeList"
signin_get_type_info_url = "https://yunsxs.ccmtv.cn/index.php/wx/SignIn/getMySignTypeInfo"
signin_sign_url = "https://yunsxs.ccmtv.cn/index.php/wx/SignIn/userMySignPost"
YOUKE_UID = "10008594"
NO_SEP = (',', ':')

win = tk.Tk()
win.title("签到工具")
win.resizable(0, 0)
pusername = ""
ppasswd = ""
puid = ""
username = tk.StringVar()
passwd = tk.StringVar()
uid = tk.StringVar()
sign_type = tk.StringVar()
signin_list = []
signin_data_list = []
checkinData = {}
lng = tk.StringVar()
lat = tk.StringVar()
address = tk.StringVar()
ip = tk.StringVar()
custom_ip = tk.BooleanVar()

ses = requests.Session()
ses.headers["User-agent"] = "CCMTV/5.3.2 (iPad; iOS 16.5.1; Scale/2.00)"
WEB_Headers = {
    "User-Agent": "Mozilla/5.0 (iPhone; CPU OS 16_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148;linlicccmtvapp",
    "X-Requested-With": "XMLHttpRequest"
}
jar = MozillaCookieJar("cookie.txt")
if path.exists("cookie.txt"):
    jar.load()
ses.cookies = jar


def gen_datacheck():
    data = {"password": ppasswd, "model": "iPad13,18", "systemversion": "16.5.1",
            "source": "iOS", "userAccount": pusername, "version": "5.3.2"}
    if puid != YOUKE_UID:
        data["sourceflag"] = "account_login"
    return b64encode(b64encode(json.dumps(data, separators=NO_SEP).encode())).decode()


def encode_data(d):
    return b64encode(b64encode(json.dumps(d, separators=NO_SEP).encode())).decode()


def decode_data(d: bytes):
    return json.loads(b64decode(b64decode(d)))


def saveconfig():
    with open("ccmtv.json", "w") as f:
        json.dump({"username": pusername, "passwd": ppasswd,
                   "uid": puid, "checkinData": checkinData}, f, ensure_ascii=False)


def loadconfig():
    global username, passwd, uid, pusername, ppasswd, puid, checkinData
    if path.exists("ccmtv.json"):
        with open("ccmtv.json", "r") as f:
            i = json.load(f)
            try:
                username.set(i["username"])
                passwd.set(i["passwd"])
                uid.set(i["uid"])
                pusername = i["username"]
                ppasswd = i["passwd"]
                puid = i["uid"]
                if "checkinData" in i:
                    checkinData = i["checkinData"]
                return
            except:
                pass
    username.set("游客")
    passwd.set("123456")
    uid.set(YOUKE_UID)
    pusername = "游客"
    ppasswd = "123456"
    puid = YOUKE_UID


def dologin():
    if username.get() == "" or passwd.get() == "":
        info.configure(text="用户名或密码不能为空")
        return ()
    d = {"act": "ulogin", "password": passwd.get(
    ), "userAccount": username.get(), "user_port": "1"}
    login = ses.post(ccmtv_app_api_url, {
                     "datacheck": gen_datacheck(), "data": encode_data(d)})
    if login.status_code == 200:
        re = decode_data(login.content)
        print(re)
        if re["code"] == "200" and re["data"]["status"] == "1":
            uid.set(re["data"]["data"]["uid"])
            global pusername
            global ppasswd
            global puid
            pusername = username.get()
            ppasswd = passwd.get()
            puid = uid.get()
            saveconfig()
            logsuccess()
    else:
        info.configure(text="登录失败")


def logsuccess():
    labelframe.configure(text="已登录")
    info.configure(text="登录成功")
    framelogin.grid_remove()
    framelogged.grid(column=0, row=0)


def openSystemURL():
    d = {"act": "getHomeFuncList", "uid": puid}
    re = ses.post(android_gp_api_url, {
                  "datacheck": gen_datacheck(), "data": encode_data(d)})
    if re.status_code == 200:
        r = decode_data(re.content)
        print(r)
        if r["code"] == "200" and r["data"]["status"] == "1":
            for s in r["data"]["data"]["all_system"]:
                if s['system_id'] == '7':
                    webbrowser.open_new_tab(s['ccmtvurl'])


def getSigninSystemURL():
    d = {"act": "getOneSystemFunclist",
         "system_id": "7", "title": "", "uid": puid}
    re = ses.post(android_gp_api_url, {
                  "datacheck": gen_datacheck(), "data": encode_data(d)})
    if re.status_code == 200:
        r = decode_data(re.content)
        print(r)
        if r["code"] == "200" and r["data"]["status"] == "1":
            for bs in r["data"]["data"]["oneSystemFunclist"]:
                for s in bs["children"]:
                    if s["fid"] == "1138":
                        return s['app_url']


def openSigninSystemURL():
    url = getSigninSystemURL()
    if url is not None:
        webbrowser.open_new_tab(url)


def getDate():
    now = time()
    n = localtime(now)
    return strftime("%Y-%m-%d", n)


def getSigninTypeList():
    re = ses.post(signin_type_list_url, {
                  "date": getDate()}, headers=WEB_Headers)
    r = re.json()
    print(r)
    if r['status'] == '1':
        return r['data']['group_list']
    else:
        raise ValueError(r['errorMessage'])


def initSigninTypeList():
    global signin_list
    signin_list = getSigninTypeList()
    li = [i['group_name'] for i in signin_list]
    signin_type_list = ttk.OptionMenu(
        frameCheckIn, sign_type, li[0], *li, command=lambda e: initSigninTypeData())
    signin_type_list.grid(column=1, row=0, sticky="W", padx=1, pady=10)
    initSigninTypeData()


def getSigninTypeData():
    d = {"date": getDate(), "group_name": sign_type.get()}
    re = ses.post(signin_get_type_info_url, d, headers=WEB_Headers)
    r = re.json()
    print(r)
    if r["status"] == "1":
        return r["data"]
    else:
        raise ValueError(r['errorMessage'])


def getIP():
    r = requests.get("https://myip.ipip.net/")
    if not r.ok:
        print(r.text)
        raise ValueError(f"{r.status_code} {r.reason}")
    ip = IP_REG.match(r.text)
    if ip is None:
        print(r.text)
        raise ValueError("Failed to extract IP.")
    return ip.group(1)


def checkin():
    if not lng.get() or not lat.get() or not address.get():
        info.configure(text="经度、维度和地址不能为空。")
        return
    cip = custom_ip.get()
    if cip and not ip.get():
        info.configure(text="IP地址不能为空")
        return
    else:
        try:
            ip.set(getIP())
        except Exception:
            info.configure(text="获取IP地址失败")
            print_exc()
            return
    checkinData[sign_type.get()] = {"lng": lng.get(), "lat": lat.get(
    ), "address": address.get(), "custom_ip": custom_ip.get(), "ip": ip.get()}
    saveconfig()
    d = {"group_name": sign_type.get(), "date": getDate(), "ip": ip.get(), "lng": lng.get(), "lat": lat.get(), "address": address.get(), "sign_port": "wx",
         "device[model]": "iPad13,18", "device[source]": "iOS", "device[systemversion]": "16.5.1", "device[version]": "V5.3.2", "config_id": "undefined", "config_key": "undefined", "content": ""}
    re = ses.post(signin_sign_url, d, headers=WEB_Headers)
    r = re.json()
    print(r)
    if r["status"] == "1":
        info.configure(text=f"签到成功。")
        initSigninTypeData()
    else:
        info.configure(text=f"签到失败：{r['errorMessage']}")


def initSigninTypeData():
    global signin_data_list
    signin_data_list = getSigninTypeData()
    f = ttk.LabelFrame(frameCheckIn, text=sign_type.get())
    f.grid(column=0, row=1, padx=10, pady=10, sticky="W", columnspan=2)
    i = 0
    for d in signin_data_list:
        btn_text = d['btn_text']
        state = '' if d['click'] == "1" else 'disabled'
        ttk.Button(f, text=btn_text, command=checkin, state=state).grid(
            column=0, row=i, padx=10, pady=10, sticky="W")
        ttk.Label(f, text=d["sign_in_time"]).grid(
            column=1, row=i, padx=10, pady=10, sticky="W")
        ttk.Label(f, text=d["user_sign_in_time"]).grid(
            column=2, row=i, padx=10, pady=10, sticky="W")
        i += 1
        ttk.Label(f, text=d["user_sign_in_address"]).grid(
            column=1, columnspan=2, row=i, padx=10, pady=10, sticky="W")
        i += 1
    st = sign_type.get()

    def set_default():
        lng.set("")
        lat.set("")
        address.set("")
        custom_ip.set(False)
        ip.set("")
    try:
        if st in checkinData:
            d = checkinData[st]
            lng.set(d["lng"])
            lat.set(d["lat"])
            address.set(d["address"])
            custom_ip.set(d["custom_ip"])
            ip.set(d["ip"])
        else:
            set_default()
    except:
        set_default()
    ttk.Label(f, text="经度：").grid(
        column=0, row=i, padx=10, pady=10, sticky="W")
    ttk.Spinbox(f, textvariable=lng, from_=-180, to=180, increment=0.000001).grid(
        column=1, columnspan=2, row=i, padx=10, pady=10, sticky="W")
    i += 1
    ttk.Label(f, text="维度：").grid(
        column=0, row=i, padx=10, pady=10, sticky="W")
    ttk.Spinbox(f, textvariable=lat, from_=-90, to=90, increment=0.000001).grid(
        column=1, columnspan=2, row=i, padx=10, pady=10, sticky="W")
    i += 1
    ttk.Label(f, text="地址：").grid(
        column=0, row=i, padx=10, pady=10, sticky="W")
    ttk.Entry(f, textvariable=address).grid(
        column=1, columnspan=2, row=i, padx=10, pady=10, sticky="W")
    i += 1
    ttk.Checkbutton(f, text="自定义IP：", variable=custom_ip).grid(
        column=0, row=i, padx=10, pady=10, sticky="W")
    ttk.Entry(f, textvariable=ip).grid(
        column=1, columnspan=2, row=i, padx=10, pady=10, sticky="W")


def openSigninPage():
    url = getSigninSystemURL()
    if url is None:
        return
    ses.get(url)
    initSigninTypeList()
    framelogged.grid_remove()
    frameCheckIn.grid(column=0, row=0)


def closeSigninPage():
    frameCheckIn.grid_remove()
    framelogged.grid(column=0, row=0)


def logout():
    global puid, pusername, ppasswd
    d = {"act": "exitVerification", "uid": puid}
    re = ses.post(ccmtv_app_api_url, {
                  "data": encode_data(d), "datacheck": gen_datacheck()})
    if re.status_code == 200:
        r = decode_data(re.content)
        print(r)
        if r["code"] == "200" and r["data"]["status"] == "1":
            info.configure(text="已注销")
            framelogged.grid_remove()
            framelogin.grid(column=0, row=0)
            labelframe.configure(text="未登录")
            puid = YOUKE_UID
            pusername = "游客"
            ppasswd = "123456"
            saveconfig()
        else:
            info.configure(text="注销失败")


frame1 = ttk.Frame(win)
frame1.grid(column=0, row=0, padx=5, pady=5)
labelframe = ttk.LabelFrame(frame1, text="未登录")
labelframe.grid(column=0, row=0)

framelogin = ttk.Frame(labelframe)
framelogged = ttk.Frame(labelframe)
frameCheckIn = ttk.Frame(labelframe)

ttk.Label(framelogin, text="用户名:", width=10).grid(
    column=0, row=0, sticky="W", padx=10, pady=5)
ttk.Label(framelogin, text="密 码:", width=10).grid(
    column=0, row=1, sticky="W", padx=10, pady=5)
ttk.Label(framelogin, text="UID:", width=10).grid(
    column=0, row=2, sticky="W", padx=10, pady=5)
ttk.Label(framelogin, textvariable=uid).grid(
    column=1, row=2, sticky="E", padx=10, pady=5)
ttk.Entry(framelogin, width=13, textvariable=username).grid(
    column=1, row=0, sticky="E", padx=10, pady=5)
ttk.Entry(framelogin, width=13, textvariable=passwd,
          show="*").grid(column=1, row=1, sticky="E", padx=10, pady=5)
ttk.Button(framelogin, text="登录", width=10, command=dologin).grid(
    column=1, row=3, sticky="E", padx=10, pady=5)

ttk.Button(framelogged, text="打开实习生管理系统（网页）", width=22, command=openSystemURL).grid(
    column=0, row=0, sticky="W", padx=2, pady=10)
ttk.Button(framelogged, text="打开签到页面（网页）", width=17, command=openSigninSystemURL).grid(
    column=1, row=0, sticky="W", padx=2, pady=10)
ttk.Button(framelogged, text="打开签到页面", width=12, command=openSigninPage).grid(
    column=0, row=1, sticky="W", padx=2, pady=10)
ttk.Button(framelogged, text="注销", width=4, command=logout).grid(
    column=0, row=2, sticky="W", padx=2, pady=10)

ttk.Button(frameCheckIn, text="返回", width=4, command=closeSigninPage).grid(
    column=0, row=0, sticky="W", padx=2, pady=10)

framelogin.grid(column=0, row=0)

frame2 = ttk.Frame(win)
frame2.grid(column=0, row=1, padx=5, pady=10)
infoframe = ttk.LabelFrame(frame2, text=" 状态 ")
infoframe.grid(column=0, row=0)
info = ttk.Label(infoframe, text="高效学习 快乐成长", width=27, anchor="center")
info.grid(column=0, row=0, padx=10, pady=5)
loadconfig()


if puid != YOUKE_UID:
    logsuccess()


def exitcallback():
    try:
        jar.save()
    finally:
        win.destroy()


win.protocol('WM_DELETE_WINDOW', exitcallback)


def run():
    win.mainloop()
