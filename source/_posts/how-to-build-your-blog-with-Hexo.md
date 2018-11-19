---
title: 从零开始的建博客生活
date: 2018-11-19 09:28:48
tags:
---
## 写作缘由
大家吼哇，这是我的第一篇博客。周末的时候突然想起来，上一个博客挂了很久了，然后一直被其他事情占据了空闲时间，趁着这次有时间而且还记得，赶紧把博客重新建起来。之前在某个ctf后找writeup，某大佬的博客就是用Hexo+Yelee主题的，当时看了觉得很惊艳，所以这次博客就想尝试一下。Hexo是一个快速，简单的博客框架，采用Markdown来解析文章，而且搭建过程非常简单。这里记录一下搭建的过程
<!-- more -->
## 准备工作
首先，请确保安装了`node.js`、 `npm`以及`git`。具体安装命令取决于不同的发行版（包管理器），这里便不再赘述。
## 开始安装
接下来只需要一条命令即可安装Hexo
```
npm install -g hexo-cli
```
注意，此操作如果没有root权限的话需要`sudo`。这样，我们的Hexo就安装好了。接下来我们生成一个博客框架。在你想要放置博客全部文件的地方，使用命令
```
hexo init <folder>
cd <folder>
npm install
```
这样，一个demo就初始化好了
## 个性化配置
接下来我们来安装yelee主题。在你的博客目录下，使用命令
```
git clone https://github.com/MOxFIVE/hexo-theme-yelee.git themes/yelee
```
然后修改主目录下的_config.yml，找到`theme: XXXX` 这一行， 将其改为`theme: yelee`。然后我们到`themes/yelee/_config.yml`中，找到`on: true`这一行，把它的注释去掉，否则会出现主页没有内容的问题。接下在终端中，输入命令，
```
sudo hexo s -p 80
```
启动Hexo server，然后在浏览器中访问localhost，如果前面的操作没有问题，应该就会出现正常界面了。剩下的事情就是写作啦，具体如何操作请自行阅读[官方文档](https://hexo.io/zh-cn/docs)。
## 部署静态页面
动态加载实在是太慢了，我们需要更加快速的静态页面。首先通过命令
```
hexo g
```
来生成静态页面。生成完毕后可以选择通过Hexo的部署功能进行部署。配置好`_config.yml`文件中的`deploy`部分，我这里采用了git的部署方式，还有其他方式可供选择，这里不再一一列举。具体操作请自行查看文档。
服务器上只要启一个Apache即可，非常的方便快捷。
## 坑点
这里也记录一下搭建过程中遇到的坑点
* git submodule的坑，git是个好工具，submodule是个好思想，git submodule 是个灾难。
* 侧边栏社交图标不显示。解决办法: 下载一个图标放到`/themes/yelee/source/img`中，命名为`GitHub.png`注意大小写，然后在`/themes/yelee/source/css/_partial/customise/social-ico.styl`中删除.GitHub下面的4～6行相关内容，在上面的`img-logo`中增加一行`GitHub black 75`，具体参数自己琢磨吧，主要是上面提及的三处地方一定要名称一致。
* 主页空白不显示，具体解决方法在上文中已经提到了，这里不再赘述
