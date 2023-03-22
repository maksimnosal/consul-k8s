package apigateway

type Deployment struct {
	namespace string
	name      string
}

func (d *Deployment) Create() error {
	return nil
}

func (d *Deployment) Destroy() error {
	return nil
}
