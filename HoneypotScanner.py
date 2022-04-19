#!/usr/bin/python3
# coding: utf-8
import subprocess
import re
from multiprocessing import Pool
import argparse
import threadpool
import uuid

parser = argparse.ArgumentParser(description="a honeypot detection program")
parser.add_argument('-f','--fileofiplist',type=str,default='iplist.txt',help='input your ipfile name(ex:-f iplist.txt)')
parser.add_argument('-t','--thread',type=int,default=5,help='thread numbers(ex:-t 10)')
args = parser.parse_args()

#加载文件
def loadfile(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    return content

#把txt里面的ip转换为list
def parseiplist(filename):
    content = loadfile(filename).split('\n')
    return content

#保存文件 
def savefile(target,filename,count):
    with open(filename, 'a', encoding='utf-8') as f:
        f.write("count:" + str(count) + "---"+target)
        f.write("\n")

#爬取ip 生成该ip所有请求domain
def generatefile(target,jsonfilename):
    cmd = ["./crawlergo", "-m","5","-c", "/home/kali/Desktop/chrome-linux/chrome", "-o", "json", "--custom-headers","{\"User-Agent\": \"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.0 Safari/537.36\"}","--output-json",jsonfilename,target]
    rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = rsp.communicate()
    # return jsonfilename

#处理文件
def work(target):
    jsonfilename = str(uuid.uuid4())[0:4] + '.json'
    # jsonfilename = 'xxx.json'
    generatefile(target,jsonfilename)
    resultfilename = "result.txt"
    biglist = loadfile("biglist.txt")
    testiplist = loadfile(jsonfilename)
    result1 = re.search('\"all_domain_list\"\:\[(.*?)\]',testiplist,re.S)
    a1 = result1.group(1).replace('"','').split(',')
    count = 0
    countcount = 0
    for i in a1:
        if i in biglist:
            count = count + 1
    if count > 0 and count < 20 :
        print("possible honeypot:%s"%target)
        print("confirm times:%s"%count)
        savefile(target,resultfilename,count)
    elif count >= 20:
        print("honeypot!!!:%s"%target)
        print("confirm times:%s"%count)
        savefile(target,resultfilename,count)
    else:
        print("nomal url:%s"%target)
        print("confirm times:%s"%count)
    

def main():
    #待检测的ip文件名
    # ipfilename = "iplist.txt"
    # jsonfilename = str(uuid.uuid4())[0:4] + '.json'   
    ipfilename = args.fileofiplist
    iplist = parseiplist(ipfilename)
    pool = threadpool.ThreadPool(args.thread)
    requests = threadpool.makeRequests(work, iplist)
    for i in requests:
        pool.putRequest(i)
    pool.wait()

if __name__ == '__main__':
    main()