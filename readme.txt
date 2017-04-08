Giải nén file mã nguồn và chạy lệnh make tại thư mục hiện hành
$ make


Để chạy chương trình tấn công 2 máy có địa chỉ IP là 192.168.1.2 và 192.168.1.3 trong mạng trên interface eth0, ta gọi tham số dòng lệnh như sau
$ sudo ./libnet -d eth0 -a 192.168.1.2 -b 192.168.1.3


Để debug lỗi memory leakage dùng valgrind, ta chạy lệnh như sau
$ sudo valgrind --leak-check=full --show-leak-kinds=all ./libnet -d eth0 -a 192.168.1.2 -b 192.168.1.3
