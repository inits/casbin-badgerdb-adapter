# casbin-badgerdb-adapter

```

package main

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/dgraph-io/badger/v2"
	badgerhold "github.com/inits/badgerholdv2"
	badgeradapter "github.com/inits/casbin-badgerdb-adapter"
)

// Ec ...
var Ec *casbin.Enforcer

func init() {

	// bts, err := ioutil.ReadFile("examples/rbac_policy.csv")
	// if err != nil {
	// 	fmt.Println(err)
	// }

	opts := badgerhold.DefaultOptions
	opts.Options = badger.DefaultOptions("/tmp/badgerhold/qms").WithEncryptionKey([]byte("1234567890123456"))
	store, err := badgerhold.Open(opts)
	if err != nil {
		fmt.Println(err)
	}

	a, err := badgeradapter.NewAdapter(store, "")
	fmt.Println("newadapter err:", err)

	Ec, err = casbin.NewEnforcer("examples/rbac_model.conf", a)
	fmt.Println("NewEnforcer err:", err)

	Ec.EnableAutoSave(true)
	// radd, err := Ec.AddPolicy("qiaos", "data1", "read")
	// fmt.Println("initial data:", radd, err)
	Ec.LoadPolicy()
}

func main() {

	rmul, err := Ec.AddPolicies([][]string{{"qiaos", "data1", "read"}, {"ming", "data2", "write"}, {"data2_admin1", "data2", "read"}, {"data2_admin1", "data2", "write"}, {"qiaos", "data1", "write"}})

	fmt.Println("rmul is:", rmul, err)
	Ec.LoadPolicy()
}

```
