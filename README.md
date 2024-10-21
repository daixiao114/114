第1关：基本测试       根据S-DES算法编写和调试程序，提供GUI解密支持用户交互。输入可以是8bit的数据和10bit的密钥，输出是8bit的密文。
![image](https://github.com/user-attachments/assets/10460586-be04-4738-bbe8-fc78aa701448)
第2关：交叉测试考虑到是算法标准，所有人在编写程序的时候需要使用相同算法流程和转换单元(P-Box、S-Box等)，以保证算法和程序在异构的系统或平台上都可以正常运行。设有A和B两组位同学(选择相同的密钥K)；则A、B组同学编写的程序对明文P进行加密得到相同的密文C；或者B组同学接收到A组程序加密的密文C，使用B组程序进行解密可得到与A相同的P。
![image](https://github.com/user-attachments/assets/bb42c2a8-cc0a-4381-970e-f281ceae3756)
