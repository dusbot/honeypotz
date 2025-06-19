package module

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/dusbot/honeypotz/query"
	"golang.org/x/crypto/ssh"
)

const MODULE_NAME = "[ssh]"

type SSH struct {
	Query *query.Query
}

func NewSSH(q *query.Query) *SSH {
	return &SSH{
		Query: q,
	}
}

func (s *SSH) Init() error {
	accounts, err := s.Query.SSHAccount.Find()
	if err != nil {
		log.Printf("%s-查询SSH账户失败: %v", MODULE_NAME, err)
		return err
	}
	for _, account := range accounts {
		userDB[account.Username] = account.Password
		//暂不做用户命令权限区分
	}
	commands, err := s.Query.SSHCommand.Find()
	if err != nil {
		log.Printf("%s-查询SSH命令失败: %v", MODULE_NAME, err)
		return err
	}
	for _, command := range commands {
		commandResponses[command.Command] = command.Response
	}
	return nil
}

func (s *SSH) Serve(port int) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "%s-程序异常: %v\n", MODULE_NAME, r)
		}
	}()

	logFile, err := os.OpenFile("ssh_honeypot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	logger := log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags)

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			logger.Printf("%s-登录尝试: 用户: %s, 密码: %s, 远程地址: %s", MODULE_NAME, c.User(), string(pass), c.RemoteAddr().String())
			if storedPass, ok := userDB[c.User()]; ok && storedPass == string(pass) {
				logger.Printf("%s-成功登录: 用户: %s, 远程地址: %s", MODULE_NAME, c.User(), c.RemoteAddr().String())
				return nil, nil
			}
			return nil, fmt.Errorf("密码拒绝")
		},
	}

	privateKey, err := generatePrivateKey()
	if err != nil {
		logger.Fatalf("%s-生成私钥失败: %v", MODULE_NAME, err)
	}
	config.AddHostKey(privateKey)

	server := &sshServer{
		config: config,
		logger: logger,
	}

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Fatalf("%s-监听失败: %v", MODULE_NAME, err)
	}
	defer listener.Close()

	logger.Printf("%s-SSH蜜罐运行在 %s", MODULE_NAME, listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Printf("%s-接受连接失败: %v", MODULE_NAME, err)
			continue
		}
		logger.Printf("%s-收到新连接: %s", MODULE_NAME, conn.RemoteAddr())
		go server.handleConnection(conn)
	}
}

func (s *SSH) Shutdown() error {
	return nil
}

type sshServer struct {
	config *ssh.ServerConfig
	logger *log.Logger
}

// 默认值
var userDB = map[string]string{
	"guest": "guest123",
}

// 默认值
var commandResponses = map[string]string{
	"ls":       "file1.txt  file2.txt  dir1",
	"pwd":      "/home/guest",
	"whoami":   "guest",
	"uname":    "Linux",
	"uname -a": "Linux localhost 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux",
	"ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::20c:29ff:fea4:8d64  prefixlen 64  scopeid 0x20<link>\n        ether 00:0c:29:a4:8d:64  txqueuelen 1000  (Ethernet)",
	"ps":       "  PID TTY          TIME CMD\n    1 ?        00:00:00 init\n    2 ?        00:00:00 kthreadd\n    3 ?        00:00:00 rcu_gp",
}

func (s *sshServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		s.logger.Printf("%s-SSH握手失败: %v", MODULE_NAME, err)
		return
	}
	defer sshConn.Close()

	s.logger.Printf("%s-新SSH连接: 用户: %s, 远程地址: %s", MODULE_NAME, sshConn.User(), sshConn.RemoteAddr())

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "未知的通道类型")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			s.logger.Printf("%s-接受通道失败: %v", MODULE_NAME, err)
			continue
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell":
					if len(req.Payload) > 0 {
						// 忽略shell请求的payload
					}
					req.Reply(true, nil)
					go s.interactiveSession(channel)
				case "exec":
					payload := string(req.Payload[4:])
					s.logger.Printf("%s-执行命令: %s, 用户: %s, 远程地址: %s", MODULE_NAME, payload, sshConn.User(), sshConn.RemoteAddr())
					s.executeCommand(channel, payload)
					channel.Close()
				default:
					req.Reply(false, nil)
				}
			}
		}(requests)
	}
}

func (s *sshServer) interactiveSession(channel ssh.Channel) {
	defer channel.Close()

	channel.Write([]byte("Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-42-generic x86_64)\n\n"))

	prompt := "guest@localhost:~$ "

	for {
		channel.Write([]byte(prompt))

		buf := make([]byte, 1024)
		n, err := channel.Read(buf)
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("%s-读取错误: %v", MODULE_NAME, err)
			}
			return
		}

		cmd := strings.TrimSpace(string(buf[:n]))
		if cmd == "exit" {
			channel.Write([]byte("logout\n"))
			return
		}

		s.logger.Printf("%s-交互命令: %s", MODULE_NAME, cmd)
		s.executeCommand(channel, cmd)
	}
}

func (s *sshServer) executeCommand(channel ssh.Channel, cmd string) {
	switch cmd {
	case "":
		return
	case "clear":
		channel.Write([]byte("\033[H\033[2J"))
		return
	}

	if response, ok := commandResponses[cmd]; ok {
		channel.Write([]byte(response + "\n"))
		return
	}

	if strings.Contains(cmd, "|") || strings.Contains(cmd, ">") || strings.Contains(cmd, "<") {
		channel.Write([]byte("bash: Permission denied\n"))
		return
	}

	if strings.HasPrefix(cmd, "cd ") {
		channel.Write([]byte("bash: cd: Permission denied\n"))
		return
	}

	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "vim", "nano", "emacs":
		channel.Write([]byte("bash: " + parts[0] + ": Permission denied\n"))
	case "sudo":
		channel.Write([]byte("bash: sudo: Permission denied\n"))
	case "su":
		channel.Write([]byte("bash: su: Permission denied\n"))
	case "ssh":
		channel.Write([]byte("bash: ssh: Permission denied\n"))
	case "scp":
		channel.Write([]byte("bash: scp: Permission denied\n"))
	case "wget", "curl":
		channel.Write([]byte("bash: " + parts[0] + ": Permission denied\n"))
	default:
		// if output, err := execLocalCommand(cmd); err == nil {
		// 	channel.Write([]byte(output + "\n"))
		// } else {
		// 	channel.Write([]byte("bash: " + parts[0] + ": command not found\n"))
		// }
		channel.Write([]byte("bash: " + parts[0] + ": command not found\n"))
	}
}

func generatePrivateKey() (ssh.Signer, error) {
	// 生成2048位的RSA密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("%s-生成RSA密钥失败: %v", MODULE_NAME, err)
	}

	// 转换为SSH签名器
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%s-创建签名器失败: %v", MODULE_NAME, err)
	}

	return signer, nil
}

// 执行本地命令（仅用于演示）
func execLocalCommand(cmd string) (string, error) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "", fmt.Errorf("空命令")
	}

	var c *exec.Cmd
	if len(parts) == 1 {
		c = exec.Command(parts[0])
	} else {
		c = exec.Command(parts[0], parts[1:]...)
	}

	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out

	err := c.Run()
	return out.String(), err
}
