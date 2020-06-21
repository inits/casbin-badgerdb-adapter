package badgeradapter

import (
	"encoding/csv"
	"errors"
	"reflect"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	badger "github.com/dgraph-io/badger/v2"
	badgerhold "github.com/inits/badgerholdv2"
)

// CasbinRule represents a Casbin rule line.
type CasbinRule struct {
	PType string `json:"p_type"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

// Adapter ...
type Adapter struct {
	db            *badgerhold.Store
	builtinPolicy string
}

/*
NewAdapter creates a new adapter. It assumes that the BadgerDB is already open.
represents the BadgerDB  to save the data into. like to save to. The builtinPolicy is a string representation
of a Casbin csv policy definition. If left builtinPolicy "" will not be used.
*/

// NewAdapter ...
func NewAdapter(db *badgerhold.Store, builtinPolicy string) (res *Adapter, err1 error) {
	Adapter := &Adapter{
		db:            db,
		builtinPolicy: builtinPolicy,
	}

	return Adapter, nil
}

/*
// LoadPolicy performs a scan on badgerdb and individually loads every line into the Casbin model.
// Not particularity efficient but should only be required on when you application starts up as this adapter can
// leverage auto-save functionality.
*/

// LoadPolicy ...
func (a *Adapter) LoadPolicy(model model.Model) error {
	if a.builtinPolicy != "" {
		for _, line := range strings.Split(a.builtinPolicy, "\n") {
			if err := loadCsvPolicyLine(strings.TrimSpace(line), model); err != nil {
				return err
			}
		}
	}

	var result []CasbinRule

	err := a.db.Find(&result, badgerhold.Where("PType").Ne(""))
	if err != nil {
		return err
	}
	//fmt.Printf("badgerdb find %+v:", result)
	if len(result) > 0 {
		for _, line := range result {
			loadPolicy(line, model)
		}
	}
	//return fmt.Errorf("%s", "find null")
	return err
}

// SavePolicy is not supported for this Adapter. Auto-save should be used.
func (a *Adapter) SavePolicy(model model.Model) error {
	return errors.New("not supported: must use auto-save with this Adapter")
}

// AddPolicy inserts or updates a rule.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) (err error) {

	line := convertRule(ptype, rule)

	err = a.db.Badger().Update(func(tx *badger.Txn) error {
		return a.db.TxInsert(tx, badgerhold.NextSequence(), line)

	})
	return err
}

// AddPolicies inserts or updates multiple rules by iterating over each one and inserting it into the badgerdb
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) (err error) {
	//fmt.Println("rules multi:", rules)
	for _, r := range rules {
		line := convertRule(ptype, r)
		a.db.Badger().Update(func(tx *badger.Txn) error {
			return a.db.TxInsert(tx, badgerhold.NextSequence(), line)
		})
	}
	return nil
}

/*
RemoveFilteredPolicy has an implementation that is slightly limited in that we can only find and remove elements

For example, if you have the following policy:
    p, subject-a, action-a, get
    p, subject-a, action-a, write
    p, subject-b, action-a, get
    p, subject-b, action-a, write

The following would remove all subject-a rules:
    enforcer.RemoveFilteredPolicy(0, "subject-a")
The following would remove all subject-a rules that contain action-a:
    enforcer.RemoveFilteredPolicy(0, "subject-a", "action-a")

The following does not work and will return an error:
    enforcer.RemoveFilteredPolicy(1, "action-a")

This is because we use badgerholdv2 to find object.
*/

// RemoveFilteredPolicy ...
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (err error) {

	if fieldIndex != 0 {
		return errors.New("fieldIndex != 0: adapter only supports filter by fieldValues")
	}

	//fmt.Println("removefilterpo:", fieldIndex, fieldValues)

	rule, arry := convertFilterRule(ptype, fieldValues)

	//fmt.Printf("qiaos%+v \n", rule)
	if len(arry) == 1 {
		refs := reflect.ValueOf(rule).FieldByName(arry[0]).String()
		//fmt.Println("refs is:", refs, arry)
		err = a.db.Badger().Update(func(txn *badger.Txn) error {
			return a.db.TxDeleteMatching(txn, &CasbinRule{}, badgerhold.Where("PType").Eq(rule.PType).And(arry[0]).Eq(refs))
		})
	}
	if len(arry) == 2 {
		refs1 := reflect.ValueOf(rule).FieldByName(arry[0]).String()
		refs2 := reflect.ValueOf(rule).FieldByName(arry[1]).String()
		err = a.db.Badger().Update(func(txn *badger.Txn) error {
			return a.db.TxDeleteMatching(txn, &CasbinRule{}, badgerhold.Where("PType").Eq(rule.PType).And(arry[0]).Eq(refs1).And(arry[1]).Eq(refs2))
		})
	}
	if len(arry) == 3 {
		refs1 := reflect.ValueOf(rule).FieldByName(arry[0]).String()
		refs2 := reflect.ValueOf(rule).FieldByName(arry[1]).String()
		refs3 := reflect.ValueOf(rule).FieldByName(arry[2]).String()
		err = a.db.Badger().Update(func(txn *badger.Txn) error {
			return a.db.TxDeleteMatching(txn, &CasbinRule{}, badgerhold.Where("PType").Eq(rule.PType).And(arry[0]).Eq(refs1).And(arry[1]).Eq(refs2).And(arry[2]).Eq(refs3))
		})
	}
	if len(arry) == 4 {
		refs1 := reflect.ValueOf(rule).FieldByName(arry[0]).String()
		refs2 := reflect.ValueOf(rule).FieldByName(arry[1]).String()
		refs3 := reflect.ValueOf(rule).FieldByName(arry[2]).String()
		refs4 := reflect.ValueOf(rule).FieldByName(arry[3]).String()
		err = a.db.Badger().Update(func(txn *badger.Txn) error {
			return a.db.TxDeleteMatching(txn, &CasbinRule{}, badgerhold.Where("PType").Eq(rule.PType).And(arry[0]).Eq(refs1).And(arry[1]).Eq(refs2).And(arry[2]).Eq(refs3).And(arry[3]).Eq(refs4))
		})
	}
	if len(arry) == 5 {
		refs1 := reflect.ValueOf(rule).FieldByName(arry[0]).String()
		refs2 := reflect.ValueOf(rule).FieldByName(arry[1]).String()
		refs3 := reflect.ValueOf(rule).FieldByName(arry[2]).String()
		refs4 := reflect.ValueOf(rule).FieldByName(arry[3]).String()
		refs5 := reflect.ValueOf(rule).FieldByName(arry[4]).String()
		err = a.db.Badger().Update(func(txn *badger.Txn) error {
			return a.db.TxDeleteMatching(txn, &CasbinRule{}, badgerhold.Where("PType").Eq(rule.PType).And(arry[0]).Eq(refs1).And(arry[1]).Eq(refs2).And(arry[2]).Eq(refs3).And(arry[3]).Eq(refs4).And(arry[4]).Eq(refs5))
		})
	}

	return err
}

// RemovePolicy removes a policy line that matches key
func (a *Adapter) RemovePolicy(sec string, ptype string, line []string) (err error) {
	rule := convertRule(ptype, line)
	err = a.db.Badger().Update(func(tx *badger.Txn) error {
		return a.db.TxDeleteMatching(tx, &CasbinRule{}, badgerhold.Where("PType").Eq(rule.PType).And("V0").Eq(rule.V0).And("V1").Eq(rule.V1).And("V2").Eq(rule.V2).And("V3").Eq(rule.V3).And("V4").Eq(rule.V4).And("V5").Eq(rule.V5))

	})
	return err
}

// RemovePolicies removes multiple policies.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) (err error) {
	for _, r := range rules {
		rule := convertRule(ptype, r)
		a.db.Badger().Update(func(tx *badger.Txn) error {
			return a.db.TxDeleteMatching(tx, &CasbinRule{}, badgerhold.Where("PType").Eq(rule.PType).And("V0").Eq(rule.V0).And("V1").Eq(rule.V1).And("V2").Eq(rule.V2).And("V3").Eq(rule.V3).And("V4").Eq(rule.V4).And("V5").Eq(rule.V5))

		})
	}
	return nil
}

func convertFilterRule(ptype string, line []string) (rulet CasbinRule, arry []string) {
	rule := CasbinRule{PType: ptype}

	rarry := []string{}

	l := len(line)
	if l > 0 {
		rule.V0 = line[0]
		if line[0] != "" {
			rarry = append(rarry, "V0")
		}
	}
	if l > 1 {
		rule.V1 = line[1]
		if line[1] != "" {
			rarry = append(rarry, "V1")
		}
	}
	if l > 2 {
		rule.V2 = line[2]
		if line[2] != "" {
			rarry = append(rarry, "V2")
		}
	}
	if l > 3 {
		rule.V3 = line[3]
		if line[3] != "" {
			rarry = append(rarry, "V3")
		}
	}
	if l > 4 {
		rule.V4 = line[4]
		if line[4] != "" {
			rarry = append(rarry, "V4")
		}
	}
	if l > 5 {
		rule.V5 = line[5]
		if line[5] != "" {
			rarry = append(rarry, "V5")
		}
	}
	return rule, rarry
}

func convertRule(ptype string, line []string) CasbinRule {
	rule := CasbinRule{PType: ptype}

	l := len(line)
	if l > 0 {
		rule.V0 = line[0]
	}
	if l > 1 {
		rule.V1 = line[1]
	}
	if l > 2 {
		rule.V2 = line[2]
	}
	if l > 3 {
		rule.V3 = line[3]
	}
	if l > 4 {
		rule.V4 = line[4]
	}
	if l > 5 {
		rule.V5 = line[5]
	}
	return rule
}

func loadPolicy(rule CasbinRule, model model.Model) {
	lineText := rule.PType

	if rule.V0 != "" {
		lineText += ", " + rule.V0
	}
	if rule.V1 != "" {
		lineText += ", " + rule.V1
	}
	if rule.V2 != "" {
		lineText += ", " + rule.V2
	}
	if rule.V3 != "" {
		lineText += ", " + rule.V3
	}
	if rule.V4 != "" {
		lineText += ", " + rule.V4
	}
	if rule.V5 != "" {
		lineText += ", " + rule.V5
	}

	persist.LoadPolicyLine(lineText, model)
}

func loadCsvPolicyLine(line string, model model.Model) error {
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	reader := csv.NewReader(strings.NewReader(line))
	reader.TrimLeadingSpace = true
	tokens, err := reader.Read()
	if err != nil {
		return err
	}

	key := tokens[0]
	sec := key[:1]
	model[sec][key].Policy = append(model[sec][key].Policy, tokens[1:])
	return nil
}
