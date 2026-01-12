### Jsoft_express_cabinet

 <img src="https://www.jsoftstudio.top/css/Jsoft_logo.png" width = "100" height = "100" alt="Jsoft_logo" align=center />

###### ©2024-2026 Jsoft Studio

------

<img src="https://img.shields.io/github/stars/kamcdev/Jsoft_express_cabinet.svg">

<img src="https://img.shields.io/badge/Python-3.13.7-blue">

<img src="https://img.shields.io/badge/交流QQ群-984242265-purple">

<img src="https://img.shields.io/badge/B站-J软件官方-light">

<img src="https://img.shields.io/badge/官网-www.jsoftstudio.top-yellow">

<img src="https://img.shields.io/badge/使用提示-生产环境建议使用venv虚拟环境-red">

------

目录
* [介绍](#介绍)
* [部署](#部署)
    * [克隆项目文件](#克隆)
    * [准备环境](#准备)
    * [启动项目](#启动)
* [结语](#结语)

<p id="介绍"></p>

------

# 介绍

这是一款使用flask开发的文件快递柜

支持文件存取，后台管理，功能限制，网站个性化

首次启动会要求设置后台密码
后台地址：/admin/login

成品演示：[文件快递柜](https://file.jsoftstudio.top/)

<p id="部署"></p>

------

# 部署

<p id="克隆"></p>

1.克隆项目文件

使用git工具命令

```
git clone https://github.com/kamcdev/Jsoft_express_cabinet.git
```

或

直接下载压缩包

<p id="准备"></p>

2.准备环境

安装Python3并在安装过程中启用环境变量

进入Jsoft_express_cabinet目录

使用命令

```
pip install -r requirements.txt
```

安装预设的依赖列表

<p id="启动"></p>

3.启动项目

使用命令

```
python app.py
```

启动flask项目后端

在浏览器输入[http://127.0.0.1:23478](http://127.0.0.1:23478)

进入前端页面

首次启动会要求设置管理员密码

密码将使用md5加密存储，若想使用更安全的加密，请自行修改app.py代码

随后会进入快递柜主页

接下来前往[http://127.0.0.1:23478/admin/login](http://127.0.0.1:23478/admin/login)

并输入管理员密码进入后台

进行项目配置

待配置和测试完毕后，即可开放运行

<p id="结语"></p>

------

# 结语

感谢您的体验与支持，希望您在体验便利的同时也可以贡献一份代码，为本项目的开源事业做出贡献！