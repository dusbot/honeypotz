package init_

import (
	"path"

	"github.com/dusbot/honeypotz/model"
	"github.com/dusbot/honeypotz/query"
	"github.com/dusbot/honeypotz/utils"
	"github.com/dusbot/honeypotz/consts"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type DB struct {
	db    *gorm.DB
	Query *query.Query
}

func (d *DB) connect(dsn string) (err error) {
	d.db, err = gorm.Open(sqlite.Open(dsn))
	if err != nil {
		return
	}
	d.Query = query.Use(d.db)
	return
}

func (d *DB) autoMigrate() (err error) {
	models := []any{
		model.SSHAccount{},
		model.SSHCommand{},
		model.SSHPermission{},
	}
	return d.db.AutoMigrate(models...)
}

func InitQuery() *query.Query {
	db := new(DB)
	dirPath, err := utils.CreateDirUnderHomeIfNotExists(consts.APP_NAME)
	if err != nil {
		panic(err)
	}
	dbPath := path.Join(dirPath, consts.DB_NAME)
	if utils.FileExists(dbPath) {
		err = db.connect(dbPath)
		if err != nil {
			panic(err)
		}
		return db.Query
	}
	err = db.connect(dbPath)
	if err != nil {
		panic(err)
	}
	err = db.autoMigrate()
	if err != nil {
		panic(err)
	}
	return db.Query
}
