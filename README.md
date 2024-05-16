# openvpn

GitHub

brew install git  安装git

git init 初始化

git remote -v 显示远程信息

git remote add origin git@github.com:D-Lansen/openvpn.git 添加远程信息

git branch -M master 修改分支名称

git status
git add .
git commit -m 'xx'
git push


远程登录
ssh root@116.205.143.112
密码
.a123456

未登录状态下上传文件,文件夹
scp /Users/lichen/Desktop/openvpn-install/readme.txt ubuntu@43.143.199.116:/home/ubuntu/
scp -r /Users/lichen/Desktop/openvpn-install ubuntu@43.143.199.116:/home/ubuntu/

已登录状态下执行安装脚本
sudo su
bash /home/ubuntu/openvpn-install/openvpn-install.sh

116.205.143.112
1) UDP
1194
1) Current system resolvers
client

未登录状态文件下载本地
scp -r root@116.205.143.112: /home/client.ovpn /Users/lichen/Desktop/openvpn-install/


GitHub

brew install git  安装git

git init

git remote -v 显示远程信息
git remote add origin git@github.com:D-Lansen/openvpn.git 添加远程信息

git status
git branch -M master

git add .
git commit -m 'xx'
git pull
git push

git diff --cached



# easy-rsa
关键字:easy-rsa vars
/home/lichen/Desktop/github/openvpn/server/bin/easy-rsa/vars
set_var EASYRSA_REQ_COUNTRY     "US"
set_var EASYRSA_REQ_PROVINCE    "California"
set_var EASYRSA_REQ_CITY        "San Francisco"
set_var EASYRSA_REQ_ORG "Copyleft Certificate Co"
set_var EASYRSA_REQ_EMAIL       "me@example.net"
set_var EASYRSA_REQ_OU          "My Organizational Unit"






