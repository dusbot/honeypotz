package app

import (
	"sync"

	"github.com/dusbot/honeypotz/module"
	"github.com/google/wire"
)

func ProvideModules(
	ssh *module.SSH,
	telnet *module.Telnet,
	mysql *module.Mysql,
) []module.Module {
	return []module.Module{ssh, telnet, mysql}
}

var ModuleSet = wire.NewSet(
	module.NewSSH,
	module.NewTelnet,
	module.NewMysql,
	ProvideModules,
)

var AppSet = wire.NewSet(
	ModuleSet,
	New,
)

type app struct {
	Modules []module.Module
}

func (a *app) Run() {
	var wg sync.WaitGroup
	for _, mod := range a.Modules {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer mod.Shutdown()
			mod.Init()
			mod.Serve(0)
		}()
	}
	wg.Wait()
}

func New(mods []module.Module) *app {
	return &app{
		Modules: mods,
	}
}
