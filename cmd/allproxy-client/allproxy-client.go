package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/h2san/allproxy"
)

func main() {
	localListen, err := net.Listen("tcp", "192.168.1.160:8888")

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for {
		conn, err := localListen.Accept()
		//fmt.Println(conn.LocalAddr().String(), conn.RemoteAddr().String())
		if err != nil {
			fmt.Println(err)
			continue
		}
		method := "aes-256-cfb"
		cipher, err := allproxy.NewCipher(method, "NzQwMTk5ZW")
		if err != nil {
			fmt.Println(err)
			continue
		}
		go handleConn(conn, cipher)
	}
}

// Client type
const (
	HTTPType = iota
	Socks5   = 1
)

const (
	proxyNet = "tcp"
	//proxyAddr = "127.0.0.1:8002"
	proxyAddr = "45.78.18.160:443"
)

func handleConn(conn net.Conn, cipher *allproxy.Cipher) {

	defer func() {
		conn.Close()
	}()

	//创建与SOCKS5服务器的TCP连接后客户端需要先发送请求来协议版本及认证方式，格式为（以字节为单位）
	/*
		VER	NMETHODS	METHODS
		1	1	1-255
		VER是SOCKS版本，这里应该是0x05；
		NMETHODS是METHODS部分的长度；
		METHODS是客户端支持的认证方式列表，每个方法占1字节。当前的定义是：
		0x00 不需要认证
		0x01 GSSAPI
		0x02 用户名、密码认证
		0x03 - 0x7F由IANA分配（保留）
		0x80 - 0xFE为私人方法保留
		0xFF 无可接受的方法
	*/
	buf := make([]byte, 257)
	var err error
	if _, err = io.ReadFull(conn, buf[:2]); err != nil {
		fmt.Println(err)
		return
	}
	nmethod := int(buf[1])
	msgLen := nmethod + 2
	_, err = io.ReadFull(conn, buf[2:msgLen])
	if err != nil {
		fmt.Println(err)
		return
	}
	/*
		服务器从客户端提供的方法中选择一个并通过以下消息通知客户端（以字节为单位）：

		VER	METHOD
		1	1
		VER是SOCKS版本，这里应该是0x05；
		METHOD是服务端选中的方法。如果返回0xFF表示没有一个认证方法被选中，客户端需要关闭连接。
	*/
	_, err = conn.Write([]byte{0x05, 0})
	host, err := getRequest(conn)
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = askRequest(conn)
	if err != nil {
		fmt.Println(err)
		return
	}

	scocks5, err := allproxy.ShadowSocks5Dial(cipher, proxyNet, proxyAddr, nil, allproxy.Direct)
	perHost := allproxy.NewPerHost(scocks5, scocks5)
	perHost.AddFromString("202.197.74.49")
	perHost.AddFromString("*.google.com")
	perHost.AddFromString("*.youku.com")
	perHost.AddFromString("*.youtube.com")

	remote, err := perHost.Dial("tcp", host)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() {
		remote.Close()
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Add(-1)
		allproxy.PipeThenClose(remote, conn)
	}()

	wg.Add(1)
	go func() {
		defer wg.Add(-1)
		allproxy.PipeThenClose(conn, remote)
	}()
	wg.Wait()
}

/*
认证结束后客户端就可以发送请求信息。如果认证方法有特殊封装要求，请求必须按照方法所定义的方式进行封装。

SOCKS5请求格式（以字节为单位）：

VER	CMD	RSV	ATYP	DST.ADDR	DST.PORT
1	1	0x00	1	动态	2
VER是SOCKS版本，这里应该是0x05；
CMD是SOCK的命令码
0x01表示CONNECT请求
0x02表示BIND请求
0x03表示UDP转发
RSV 0x00，保留
ATYP DST.ADDR类型
0x01 IPv4地址，DST.ADDR部分4字节长度
0x03域名，DST ADDR部分第一个字节为域名长度，DST.ADDR剩余的内容为域名，没有\0结尾。
0x04 IPv6地址，16个字节长度。
DST.ADDR 目的地址
DST.PORT 网络字节序表示的目的端口
*/
func getRequest(conn net.Conn) (host string, err error) {

	buf := make([]byte, 300)
	if _, err = io.ReadFull(conn, buf[0:4]); err != nil {
		return
	}
	fmt.Println(buf[0:4])
	if int(buf[0]) != 0x05 {
		err = errors.New("不支持的socks version")
		return
	}

	if buf[1] != 0x01 {
		err = errors.New("CMD error" + strconv.Itoa(int(buf[1])))
		return
	}

	reqLen := 0
	startIndex := 0
	domainLen := 0
	switch buf[3] {
	case 0x01:
		reqLen = net.IPv4len + 2 //DST.ADDR+DST.PORT
		startIndex = 4
	case 0x04:
		reqLen = net.IPv6len + 2 //DST.ADDR+DST.PORT
		startIndex = 4
	case 0x03:
		if _, err = io.ReadFull(conn, buf[4:5]); err != nil {
			return
		}
		domainLen = int(buf[4])
		reqLen = domainLen + 2
		startIndex = 5
	default:
		err = errors.New("unsupport addr type")
		return
	}
	if _, err = io.ReadFull(conn, buf[startIndex:reqLen+startIndex]); err != nil {
		return
	}

	switch buf[3] {
	case 0x01:
		host = net.IP(buf[startIndex : net.IPv4len+startIndex]).String()
	case 0x04:
		host = net.IP(buf[startIndex : net.IPv6len+startIndex]).String()
	case 0x03:
		host = string(buf[startIndex : startIndex+domainLen])
	}
	port := binary.BigEndian.Uint16(buf[startIndex+reqLen-2 : startIndex+reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

/*
服务器按以下格式回应客户端的请求（以字节为单位）：

VER	REP	RSV	ATYP	BND.ADDR	BND.PORT
1	1	0x00	1	动态	2
VER是SOCKS版本，这里应该是0x05；
REP应答字段
0x00表示成功
0x01普通SOCKS服务器连接失败
0x02现有规则不允许连接
0x03网络不可达
0x04主机不可达
0x05连接被拒
0x06 TTL超时
0x07不支持的命令
0x08不支持的地址类型
0x09 - 0xFF未定义
RSV 0x00，保留
ATYP BND.ADDR类型
0x01 IPv4地址，DST.ADDR部分4字节长度
0x03域名，DST.ADDR部分第一个字节为域名长度，DST.ADDR剩余的内容为域名，没有\0结尾。
0x04 IPv6地址，16个字节长度。
BND.ADDR 服务器绑定的地址
BND.PORT 网络字节序表示的服务器绑定的端口
*/
func askRequest(conn net.Conn) (n int, err error) {
	data := []byte{
		0x05,
		0x00,
		0x00,
		0x01,
		0x00,
		0x00,
		0x00,
		0x00,
		0x80,
		0x43,
	}
	return conn.Write(data)
}
