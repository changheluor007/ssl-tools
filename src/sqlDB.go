package src

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	//Username string `gorm:"type:varchar(40);unique" json:"username,omitempty"`
	//Password string `gorm:"size:255" json:"password,omitempty"`
	Username string `gorm:"column:username"`
	Password string `gorm:"column:password"`
}

type Product struct {
	gorm.Model
	Attributes      bool
	certificate     *x509.Certificate
	rootCertificate *x509.Certificate
	caPrivKey       *rsa.PrivateKey
	rootPrivKey     *rsa.PrivateKey
	caPEM           *bytes.Buffer
	caPrivKeyPEM    *bytes.Buffer
}

func OpenDB() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("sslt.db"), &gorm.Config{})
	CheckErr(err)
	return db
}
func CANew(db *gorm.DB, tableName string, Attribute bool, certificate *x509.Certificate, rootCertificate *x509.Certificate, caPrivyKey *rsa.PrivateKey, rootPrivKey *rsa.PrivateKey, caPEM *bytes.Buffer, caPrivKeyPEM *bytes.Buffer) {

	// Migrate the schema
	//db.AutoMigrate(&Product{})
	db.Table(tableName).AutoMigrate(&Product{})
	// 插入内容
	db.Raw("CREATE TABLE IF NOT EXISTS t_user(uid integer primary key,uname varchar(20),mobile varchar(20))")
	db.Table(tableName).Create(&Product{Attributes: Attribute, certificate: certificate, rootCertificate: rootCertificate, caPrivKey: caPrivyKey, rootPrivKey: rootPrivKey, caPEM: caPEM, caPrivKeyPEM: caPrivKeyPEM})

	// 读取内容
	//var product Product
	//db.Table(tableName).First(&product, 1)                 // find product with integer primary key
	//db.Table(tableName).First(&product, "code = ?", "D42") // find product with code D42
	//
	//// 更新操作： 更新单个字段
	//db.Table(tableName).Model(&product).Update("Price", 2000)
	//
	//// 更新操作： 更新多个字段
	//db.Table(tableName).Model(&product).Updates(Product{Price: 2000, Code: "F42"}) // non-zero fields
	//db.Table(tableName).Model(&product).Updates(map[string]interface{}{"Price": 2000, "Code": "F42"})
	//
	//// 删除操作：
	//db.Table(tableName).Delete(&product, 1)
}

//func RootCANew() {
//
//}
