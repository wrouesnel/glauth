// Module for the build system (magefile.go). GLAuth itself is the v2 module.
module github.com/glauth/glauth/build

go 1.27.1

require (
	github.com/integralist/go-findroot v0.0.0-20160518114804-ac90681525dc
	github.com/magefile/mage v1.17.2
	github.com/mholt/archiver v3.1.1+incompatible
	github.com/pkg/errors v0.9.1
	github.com/samber/lo v1.53.0
	golang.org/x/mod v0.42.0
)

require (
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/frankban/quicktest v1.14.6 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/nwaples/rardecode v1.1.3 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/ulikunitz/xz v0.5.17 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace go.yaml.in/yaml/v4 => github.com/wrouesnel/yaml.go-yaml/v4 v4.0.0-20260918015114-84d82f5038cd
