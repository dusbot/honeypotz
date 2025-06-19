package module

type Module interface {
	Init() error
	Serve(port int) error
	Shutdown() error
}
