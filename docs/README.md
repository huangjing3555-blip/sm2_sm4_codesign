# 软硬协同的国密 SM2/SM4 动态密钥协商与全密态传输系统

本项目包含 Windows PC 客户端与香橙派 5 Plus (RK3588) 服务端，通过 TCP 局域网通信，实现基于国密算法的动态密钥协商与全密态文件传输。核心亮点是**香橙派端通过 Linux AF_ALG 接口直接调用 RK3588 硬件 Crypto 引擎加速 SM4 解密**，并提供实时性能对比 Dashboard。

## 1. 环境准备

### 1.1 香橙派 5 Plus (服务端)
- **操作系统**: 推荐使用官方 Ubuntu 22.04 / Debian 11 镜像。
- **Python**: Python 3.8+
- **依赖安装**:
  ```bash
  sudo apt update
  sudo apt install python3-pip
  pip3 install gmssl psutil
  ```
- **硬件加速自检**:
  运行 `python3 scripts/test_crypto.py`，如果输出包含 `检测到 AF_ALG 硬件后端`，说明内核已开启 SM4 硬件加速。如果提示不支持，系统会自动回退到纯软件实现，不影响流程演示。

### 1.2 Windows PC (客户端)
- **Python**: Python 3.8+
- **依赖安装**:
  ```cmd
  pip install gmssl psutil fastapi uvicorn python-multipart
  ```

## 2. 运行步骤

### 第一步：启动香橙派服务端
在香橙派终端执行：
```bash
cd orangepi_server
python3 server.py --host 0.0.0.0 --port 9000
```
*首次启动会在 `orangepi_server/data/` 下生成 `pi_identity.json` (服务端长期身份密钥)。*

### 第二步：启动 Windows 客户端
在 Windows 终端执行：
```cmd
cd pc_client
python app.py
```
启动后，浏览器访问 `http://127.0.0.1:8000`。
*首次启动会在 `pc_client/data/` 下生成 `pc_identity.json` (客户端长期身份密钥)。*

### 第三步：公钥互换 (模拟证书分发)
为了防止中间人攻击，双方需要知道对方的公钥：
1. 将香橙派上的 `orangepi_server/data/pi_identity.json` 复制到 PC 的 `pc_client/data/peer_pubkey.json`。
   *(或者在 PC 网页端点击"导入服务端公钥"，粘贴香橙派的公钥 JSON)*
2. 将 PC 上的 `pc_client/data/pc_identity.json` 复制到香橙派的 `orangepi_server/data/peer_pubkey.json`。

### 第四步：系统演示
1. **登录**: 在 PC 浏览器打开 `http://127.0.0.1:8000`，首次登录设置一个密码。
2. **连接**: 在"连接配置"中输入香橙派的局域网 IP，点击"连接"。
3. **协商**: 点击"发起握手"，观察状态面板的"当前密钥 ID"更新，表示 SM2 动态协商成功。
4. **传输**: 选择一个本地文件（建议 10MB~100MB），选择"硬件解密"或"软件解密"，点击"SM4 加密发送"。
5. **监控**: 观察右侧 ECharts 图表，对比软硬件解密的吞吐率和 CPU 占用差异。下方会实时滚动十六进制密文流。
6. **导出**: 演示结束后，点击"导出性能 CSV"，用 Excel 打开生成的 `performance_log.csv` 制作答辩图表。

## 3. 项目声明Project Statement
本项目的作者及单位:
The author and affiliation of this project:
- 项目名称(Project Name):HS-CDKN-FETS
- 项目作者 (Author) : Jing Huang, Donghong Cai
- 作者单位(Affiliation):暨南大学网络空间安全学院(College of Cyber Security,Jinan University)
