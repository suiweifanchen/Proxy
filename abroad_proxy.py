# -*- coding: utf-8 -*-
"""
Created at: 2017/12/8 12:13

@Author: Qian
"""

import os
import re
import random
import pymysql
import requests
from my_modules import mysqlconn

file_path = os.path.dirname(__file__)


def get_https(url):
    ip_list = []
    host = url.split("/")[2]
    headers = {"Host": host,
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36", }

    # 获取页面信息
    page = requests.get(url, headers=headers)
    # 获取代理信息的部分
    string = "</thead><tbody>(.*?)</tbody>"
    pattern = re.compile(string)
    info_part = re.findall(pattern, page.text)[0]
    # 提取 ip, port, country, anonymity, https
    string = "<tr><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td>.*?<td>(.*?)</td>.*?<td class='hx'>(.*?)</td>.*?</tr>"
    pattern = re.compile(string)
    result_list = re.findall(pattern, info_part)

    # 选出elite proxy的代理
    for i in result_list:
        if i[3] == 'elite proxy':
            if i[4] == 'yes':
                # 下方元组含义   ip, port, https, error_num, state, insert_time
                ip_list.append({"ip": i[0], "port": i[1], "https": "yes",
                                "error_num": 0, "state": "unknown",
                                "latest_time": "localtime()"})
            else:
                ip_list.append({"ip": i[0], "port": i[1], "https": "no",
                                "error_num": 0, "state": "unknown",
                                "latest_time": "localtime()"})
        else:
            pass

    return ip_list


def certify_ip(proxies):
    """验证代理的有效性，无效或者超时10s，返回exception；如果成功，返回值1"""

    https_url = ["https://www.youtube.com/",
                 "https://www.facebook.com/",
                 "https://twitter.com/"]
    url = random.choice(https_url)
    try:
        page = requests.get(url, proxies=proxies, timeout=10)
    except Exception as e:
        return e
    else:
        if page.status_code == 200:
            return 1
        else:
            return Exception("Page Status Code is not 200")


def sql_string(sql_type, dict, table_name, primary_key=None):
    """生成数据库的sql语句，type有insert、update语句"""

    string = ["", ""]
    keys = []
    data = []
    for i in dict:
        keys.append(i)
        data.append(dict[i])

    # insert_sql_string
    string[0] = "insert into " + table_name + " (" + \
                str(keys).strip('[').strip(']').replace("'", "") + \
                ") values (" + \
                str(data).strip('[').strip(']') + ")"

    # update_sql_string
    if primary_key:
        string[1] = "update " + table_name + " set "
        j = 0
        for i in range(len(keys)):
            if keys[i] not in primary_key:
                if j:
                    string[1] += ", "
                string[1] += str(keys[i]) + "='" + str(data[i]) + "'"
                j = 1
        string[1] += " where "
        for i in range(len(primary_key)):
            if i:
                string[1] += " and "
            string[1] += str(primary_key[i]) + "='" + str(dict[primary_key[i]]) + "'"

    # 将sql语句最后做一些调整
    for i in range(len(string)):
        string[i] = string[i].replace("'curdate()'", "curdate()")
        string[i] = string[i].replace("'localtime()'", "localtime()")
        string[i] = string[i].replace("'NULL'", "NULL").encode('utf-8', 'ignore')

    if sql_type == "insert":
        return [string[0], ]
    elif sql_type == "update":
        return [string[1], ]
    elif sql_type == "all":
        return string
    else:
        raise Exception("Type Error")


def db_insert(conn, data, table):
    """将数据insert到数据库，data为dict型，table为string型"""

    cur = conn.cursor()
    sql = sql_string("insert", data, table)
    try:
        cur.execute(sql[0])
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e


def db_update(conn, data, key, table):
    """将数据update到数据库，data为dict型，key为list型，table(表名)为string型"""

    cur = conn.cursor()
    sql = sql_string("update", data, table, primary_key=key)
    try:
        cur.execute(sql[0])
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e


if __name__ == "__main__":
    # 删除之前的在运行的进程
    try:
        pid = os.getpid()
        cmd = "kill -9 `ps -aux | grep -v %i | grep python3 | grep abroad_proxy.py | awk '{print $2}'`" % pid
        os.system(cmd)
    except:
        pass

    import time

    # 获取 https://www.us-proxy.org/ , https://free-proxy-list.net/anonymous-proxy.html 最新代理
    url_list = ["https://www.us-proxy.org/", "https://free-proxy-list.net/anonymous-proxy.html"]
    ip_list = []
    for url in url_list:
        ip_list += get_https(url)
        time.sleep(10)
    conn = mysqlconn.mysqlconn()
    for i in ip_list:
        try:
            db_insert(conn, i, "ip_proxy")
        except pymysql.err.IntegrityError:
            db_update(conn, i, ["ip", "port"], "ip_proxy")
        except Exception as e:
            raise e

    # 从数据库中取出所有https代理，验证是否存活
    cur = conn.cursor()
    cur.execute("select * from ip_proxy where https='yes' and state<>'dead'")
    ip_list = cur.fetchall()
    for i in ip_list:
        proxies = {"https": "http://" + i[0] + ":" + i[1]}
        result = certify_ip(proxies)
        if result == 1:
            i = {"ip": i[0], "port": i[1], "https": i[2],
                 "error_num": 0, "state": "alive",
                 "latest_time": "localtime()"}
        elif i[3] + 1 > 5:
            i = {"ip": i[0], "port": i[1], "https": i[2],
                 "error_num": i[3] + 1, "state": "dead",
                 "latest_time": "localtime()"}
        else:
            i = {"ip": i[0], "port": i[1], "https": i[2],
                 "error_num": i[3] + 1, "state": "unknown",
                 "latest_time": "localtime()"}
        try:
            db_update(conn, i, ["ip", "port"], "ip_proxy")
        except Exception as e:
            raise e
    
    conn.close()
