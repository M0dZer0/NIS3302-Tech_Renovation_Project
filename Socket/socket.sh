#!/bin/bash

rm -f ./TCP/pri_key_file
rm -f ./TCP/pub_key_file
rm -f ./TCP/private_key.der
rm -f ./TCP/public_key.der
rm -f ./TCP/server_pub_key_file
rm -f ./TCP/client_pub_key_file

rm -f ./UDP/pri_key_file
rm -f ./UDP/pub_key_file
rm -f ./UDP/private_key.der
rm -f ./UDP/public_key.der
rm -f ./UDP/server_pub_key_file
rm -f ./UDP/client_pub_key_file

rm -f ./pri_key_file
rm -f ./pub_key_file
rm -f ./private_key.der
rm -f ./public_key.der
rm -f ./server_pub_key_file
rm -f ./client_pub_key_file
# 检查参数数量
if [ $# -ne 4 ]; then
  echo "参数数量不正确！"
  echo "用法: $0 <server/client> <TCP/UDP> <目标IP> <端口号>"
  exit 1
fi

# 获取用户传入的参数
target=$1
protocol=$2
ip=$3
port=$4

# 根据参数编译相应的文件
if [ "$protocol" = "TCP" ]; then
  if [ "$target" = "client" ]; then
    gcc  -pthread -o ./TCP/client ./TCP/client.c
    ./TCP/client $ip $port 
  elif [ "$target" = "server" ]; then
    gcc  -pthread -o ./TCP/server ./TCP/server.c
    ./TCP/server $port
  else
    echo "目标参数不正确！"
    exit 1
  fi
elif [ "$protocol" = "UDP" ]; then
  if [ "$target" = "client" ]; then
    gcc  -pthread -o ./UDP/client ./UDP/client.c
    ./UDP/client $ip $port
  elif [ "$target" = "server" ]; then
    gcc  -pthread -o ./UDP/server ./UDP/server.c
    ./UDP/server $port
  else
    echo "目标参数不正确！"
    exit 1
  fi
else
  echo "协议参数不正确！"
  exit 1
fi


