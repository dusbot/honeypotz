package model

import ()

type SSHAccount struct {
	ID       uint `gorm:"primarykey;autoIncrement"`
	Username string
	Password string
}

type SSHCommand struct {
	ID       uint `gorm:"primarykey;autoIncrement"`
	Command  string
	Response string
}

type SSHPermission struct {
	ID        uint `gorm:"primarykey;autoIncrement"`
	UserID    uint
	CommandID uint
}
