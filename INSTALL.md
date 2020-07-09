## 搭建 Spear-framework {docsify-ignore}

Spear-framework 基于 [docsify](https://docsify.js.org/) 进行构建。

## 本地预览

### docsify-cli

1. 推荐全局安装 `docsify-cli` 工具，可以方便地创建及在本地预览生成的文档。

```shell
npm i docsify-cli -g
```

2. git clone 项目


```shell
git clone github.com/0nise/spear-framework
```

3. 本地预览，通过运行 `docsify serve` 启动一个本地服务器，可以方便地实时预览效果。默认访问地址 <http://localhost:3000>

```shell
cd spear-framework
docsify serve .
```

!> 更多命令行工具用法，参考 [docsify-cli 文档](https://github.com/docsifyjs/docsify-cli)。

### python

如果你觉得上述过程太麻烦，并且电脑已经安装了 python，可通过以下方式进行本地预览：

python2.x

```shell
cd spear-framework && python -m SimpleHTTPServer 3000
```

python3.x

```shell
cd spear-framework && python -m http.server 3000
```

## 部署

和 GitBook 生成的文档一样，我们可以直接把文档网站部署到 GitHub Pages 或者 VPS 上。

### GitHub Pages

GitHub Pages 支持从三个地方读取文件

- docs/ 目录
- master 分支
- gh-pages 分支

可以将文档放在 `docs/` 目录下，在设置页面开启 `GitHub Pages` 功能并选择 `master branch /docs folder` 选项。

![](images/1.png)

!> 也可以将文档放在根目录下，然后选择 `master` 分支 作为文档目录。**需要在部署位置下放一个 `.nojekyll` 文件**。

### GitLab Pages

如果你正在部署你的主分支, 在 .gitlab-ci.yml 中包含以下脚本：

!> .public 的解决方法是这样的，cp 不会无限循环的将 public/ 复制到自身。

```YAML
pages:
  stage: deploy
  script:
  - mkdir .public
  - cp -r * .public
  - mv .public public
  artifacts:
    paths:
    - public
  only:
  - master
```

!> 你可以用 `- cp -r docs/. public` 替换脚本, 如果 `./docs` 是 `docsify` 子文件夹。

### [更多](https://docsify.js.org/#/zh-cn/deploy)